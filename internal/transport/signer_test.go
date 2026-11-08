package transport

// 测试锚定策略（「锚定测试」，跨实现双确认防自证）：
//  1. golden 向量期望值由 PowerShell .NET 独立计算（见 TestGoldenVector
//     注释），不从被测代码反推；
//  2. httptest 服务端校验逻辑从 server/internal/connect/interceptors.go
//     的 NewRPCHMACInterceptor（行 278-317）只读转写（含恒时比较、hex
//     解码、五项串拼装顺序、写接口 nonce 去重先于签名、client 未注册
//     与签名错误同响应），不从 Signer 反推；
//  3. 端到端用 rpcv1connect.NewTokenServiceClient 挂 Signer 打 httptest，
//     服务端按收到的字节校验，通过即证明签名的是真实上行字节。

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	rpcv1 "github.com/authloft/sdk-go/gen/go/api/rpc/v1"
	rpcv1connect "github.com/authloft/sdk-go/gen/go/api/rpc/v1/rpcv1connect"
)

const (
	goldenClientID    = "sdk-go-test-client"
	goldenNonce       = "fixed-nonce-0123456789abcdef"
	goldenSecret      = "test-client-secret"
	decodeProc        = "/api.rpc.v1.TokenService/DecodeSession"
	getProfileProc    = "/api.rpc.v1.UserService/GetUserProfile"
	updateProfileProc = "/api.rpc.v1.UserService/UpdateUserProfile"
	goldenSigNonEmpty = "821a60e173503a5ea1c78d8f39a90bcd7c8e2a6c838c0b93749de703afce8f01"
	goldenSigEmpty    = "b618768dc2eef8e0177d446212be2258d4af853895aa4dec813cbc4ad7c96ac9"
)

// TestGoldenVector 锚定跨实现一致性：固定五项 → 期望 HMAC hex。
//
// 期望值由 PowerShell .NET 独立计算（2026-11-04，Windows PowerShell，
// 与被测 Go 实现互为双确认）：
//
//	$h = New-Object System.Security.Cryptography.HMACSHA256
//	$h.Key = [System.Text.Encoding]::UTF8.GetBytes('test-client-secret')
//	$m1 = [System.Text.Encoding]::UTF8.GetBytes('sdk-go-test-client:fixed-nonce-0123456789abcdef:/api.rpc.v1.TokenService/DecodeSession:sessionToken-test-payload:test-client-secret')
//	($h.ComputeHash($m1) | ForEach-Object { $_.ToString('x2') }) -join ''
//	→ 821a60e173503a5ea1c78d8f39a90bcd7c8e2a6c838c0b93749de703afce8f01
//
//	空 body（接口文档 §7 行 1382：空 body 即空字符串）：
//	$m2 = [System.Text.Encoding]::UTF8.GetBytes('sdk-go-test-client:fixed-nonce-0123456789abcdef:/api.rpc.v1.UserService/GetUserProfile::test-client-secret')
//	→ b618768dc2eef8e0177d446212be2258d4af853895aa4dec813cbc4ad7c96ac9
func TestGoldenVector(t *testing.T) {
	rec := &recordingTransport{}
	signer := NewSigner(rec, goldenClientID, goldenSecret, func() string { return goldenNonce })

	// 向量 1：非空 body（Connect 裸 proto 消息字节）。
	body := []byte("sessionToken-test-payload")
	req, err := http.NewRequest(http.MethodPost, "http://authloft.invalid"+decodeProc, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	if got := rec.header.Get(HeaderClientID); got != goldenClientID {
		t.Errorf("X-Client-ID = %q, want %q", got, goldenClientID)
	}
	if got := rec.header.Get(HeaderNonceID); got != goldenNonce {
		t.Errorf("X-Nonce-ID = %q, want %q", got, goldenNonce)
	}
	if got := rec.header.Get(HeaderSignature); got != goldenSigNonEmpty {
		t.Errorf("X-Signature = %q, want %q", got, goldenSigNonEmpty)
	}
	if !bytes.Equal(rec.body, body) {
		t.Errorf("body 传给 base 前被改写: got %q, want %q", rec.body, body)
	}

	// 向量 2：空 body（req.Body == nil → 签名串 body 段为空串）。
	req2, err := http.NewRequest(http.MethodPost, "http://authloft.invalid"+getProfileProc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.RoundTrip(req2); err != nil {
		t.Fatal(err)
	}
	if got := rec.header.Get(HeaderSignature); got != goldenSigEmpty {
		t.Errorf("空 body X-Signature = %q, want %q", got, goldenSigEmpty)
	}
}

// recordingTransport 记录 Signer 交给 base 的请求（三头 + 回填 body）。
type recordingTransport struct {
	header http.Header
	body   []byte
}

func (rt *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
	}
	rt.header = req.Header.Clone()
	rt.body = body
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(nil)),
		Request:    req,
	}, nil
}

// fakeWriteProcedure 转写服务端 isRPCWriteProcedure
// （interceptors.go 行 199-215）——测试内独立实现，不复用被测
// IsWriteProcedure，防循环自证。
func fakeWriteProcedure(procedure string) bool {
	method := procedure
	if i := strings.LastIndex(procedure, "/"); i >= 0 {
		method = procedure[i+1:]
	}
	for _, prefix := range []string{"Update", "Delete", "Set", "Create", "Revoke"} {
		if strings.HasPrefix(method, prefix) {
			return true
		}
	}
	return false
}

// fakeRPCHMACInterceptor 从 NewRPCHMACInterceptor（行 278-317）只读转写：
//   - 三头缺任一 → 403；
//   - 写 procedure：nonce 去重先于签名（签名错的请求同样消耗 nonce）；
//   - client 未注册与签名错误同响应（防探测）；
//   - 五项串三段 Write：Write(clientID:nonce:procedure:) → Write(raw) →
//     Write(:secret)；
//   - hex 解码（大小写不敏感）后 hmac.Equal 恒时比较。
//
// procedure 取值：服务端用 req.Spec().Procedure（与挂载路径一致），
// HTTP 测试层等价于 r.URL.Path。
type fakeRPCHMACInterceptor struct {
	clientID string
	secret   string

	mu     sync.Mutex
	nonces map[string]bool // 写接口 nonce 去重（30s TTL 在测试内退化为进程内集合）
}

func newFakeInterceptor(clientID, secret string) *fakeRPCHMACInterceptor {
	return &fakeRPCHMACInterceptor{clientID: clientID, secret: secret, nonces: make(map[string]bool)}
}

// fakeSign 按服务端拼装逻辑生成签名（供 verify 与测试构造正例）。
func (f *fakeRPCHMACInterceptor) fakeSign(clientID, nonce, procedure string, raw []byte) string {
	mac := hmac.New(sha256.New, []byte(f.secret))
	mac.Write([]byte(clientID + ":" + nonce + ":" + procedure + ":"))
	mac.Write(raw)
	mac.Write([]byte(":" + f.secret))
	return hex.EncodeToString(mac.Sum(nil))
}

// verify 转写服务端校验：clientID/nonce/signature 为三头值，raw 为收到的
// 原始 body 字节，返回是否放行。
func (f *fakeRPCHMACInterceptor) verify(clientID, nonce, signature, procedure string, raw []byte) bool {
	if clientID == "" || nonce == "" || signature == "" {
		return false // 缺任一头 → 403
	}
	if fakeWriteProcedure(procedure) { // 写接口：nonce 去重先于签名
		f.mu.Lock()
		defer f.mu.Unlock()
		key := clientID + "\x00" + nonce
		if f.nonces[key] {
			return false // nonce 重放 → 403
		}
		f.nonces[key] = true // 签名校验尚未发生，但 nonce 已被消耗
	}
	if clientID != f.clientID { // client 未注册与签名错误同响应
		return false
	}
	mac := hmac.New(sha256.New, []byte(f.secret))
	mac.Write([]byte(clientID + ":" + nonce + ":" + procedure + ":"))
	mac.Write(raw)
	mac.Write([]byte(":" + f.secret))
	given, derr := hex.DecodeString(signature)
	if derr != nil || !hmac.Equal(given, mac.Sum(nil)) {
		return false
	}
	return true
}

type fakeRequestRecord struct {
	clientID  string
	nonce     string
	signature string
	path      string
	raw       []byte
}

// fakeRPCServer httptest 服务端：经转写校验，通过回 onOK，否则 403。
// 记录收到的每个请求供断言。
type fakeRPCServer struct {
	srv       *httptest.Server
	intercept *fakeRPCHMACInterceptor
	onOK      func(http.ResponseWriter)
	mu        sync.Mutex
	records   []fakeRequestRecord
}

func startFakeRPCServer(t *testing.T, clientID, secret string, onOK func(http.ResponseWriter)) *fakeRPCServer {
	t.Helper()
	s := &fakeRPCServer{intercept: newFakeInterceptor(clientID, secret), onOK: onOK}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var raw []byte
		if r.Body != nil {
			raw, _ = io.ReadAll(r.Body)
		}
		rec := fakeRequestRecord{
			clientID:  r.Header.Get(HeaderClientID),
			nonce:     r.Header.Get(HeaderNonceID),
			signature: r.Header.Get(HeaderSignature),
			path:      r.URL.Path,
			raw:       raw,
		}
		s.mu.Lock()
		s.records = append(s.records, rec)
		s.mu.Unlock()
		if !s.intercept.verify(rec.clientID, rec.nonce, rec.signature, rec.path, raw) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if s.onOK != nil {
			s.onOK(w)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *fakeRPCServer) requestRecords() []fakeRequestRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]fakeRequestRecord, len(s.records))
	copy(out, s.records)
	return out
}

// TestServerSideSemantics 用转写自服务端的 httptest 校验锚定语义：
// 合法签名放行、篡改拒绝、缺头拒绝、hex 大小写不敏感、
// 写 procedure 识别与 nonce 去重先于签名、读接口不去重。
func TestServerSideSemantics(t *testing.T) {
	const (
		clientID = "sdk-go-test-client"
		secret   = "test-client-secret"
	)
	post := func(t *testing.T, url, clientID, nonce, signature string, body []byte) int {
		t.Helper()
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequest(http.MethodPost, url, rd)
		if err != nil {
			t.Fatal(err)
		}
		if clientID != "" {
			req.Header.Set(HeaderClientID, clientID)
		}
		if nonce != "" {
			req.Header.Set(HeaderNonceID, nonce)
		}
		if signature != "" {
			req.Header.Set(HeaderSignature, signature)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	body := []byte("connect-unary-body")

	t.Run("三头齐全签名正确放行", func(t *testing.T) {
		s := startFakeRPCServer(t, clientID, secret, nil)
		sig := s.intercept.fakeSign(clientID, goldenNonce, decodeProc, body)
		if code := post(t, s.srv.URL+decodeProc, clientID, goldenNonce, sig, body); code != http.StatusOK {
			t.Errorf("status = %d, want %d", code, http.StatusOK)
		}
	})
	t.Run("大写hex签名同样放行", func(t *testing.T) {
		s := startFakeRPCServer(t, clientID, secret, nil)
		sig := strings.ToUpper(s.intercept.fakeSign(clientID, goldenNonce, decodeProc, body))
		if code := post(t, s.srv.URL+decodeProc, clientID, goldenNonce, sig, body); code != http.StatusOK {
			t.Errorf("status = %d, want %d（hex 大小写不敏感）", code, http.StatusOK)
		}
	})
	t.Run("篡改body拒绝", func(t *testing.T) {
		s := startFakeRPCServer(t, clientID, secret, nil)
		sig := s.intercept.fakeSign(clientID, goldenNonce, decodeProc, body)
		if code := post(t, s.srv.URL+decodeProc, clientID, goldenNonce, sig, []byte("tampered-body")); code != http.StatusForbidden {
			t.Errorf("status = %d, want %d", code, http.StatusForbidden)
		}
	})
	t.Run("篡改nonce头拒绝", func(t *testing.T) {
		s := startFakeRPCServer(t, clientID, secret, nil)
		sig := s.intercept.fakeSign(clientID, goldenNonce, decodeProc, body)
		if code := post(t, s.srv.URL+decodeProc, clientID, "other-nonce", sig, body); code != http.StatusForbidden {
			t.Errorf("status = %d, want %d", code, http.StatusForbidden)
		}
	})
	t.Run("缺任一头拒绝", func(t *testing.T) {
		s := startFakeRPCServer(t, clientID, secret, nil)
		sig := s.intercept.fakeSign(clientID, goldenNonce, decodeProc, body)
		if code := post(t, s.srv.URL+decodeProc, "", goldenNonce, sig, body); code != http.StatusForbidden {
			t.Errorf("缺 X-Client-ID: status = %d, want %d", code, http.StatusForbidden)
		}
		if code := post(t, s.srv.URL+decodeProc, clientID, "", sig, body); code != http.StatusForbidden {
			t.Errorf("缺 X-Nonce-ID: status = %d, want %d", code, http.StatusForbidden)
		}
		if code := post(t, s.srv.URL+decodeProc, clientID, goldenNonce, "", body); code != http.StatusForbidden {
			t.Errorf("缺 X-Signature: status = %d, want %d", code, http.StatusForbidden)
		}
	})
	t.Run("未知client与签名错误同响应", func(t *testing.T) {
		s := startFakeRPCServer(t, clientID, secret, nil)
		sig := s.intercept.fakeSign("unknown-client", goldenNonce, decodeProc, body)
		if code := post(t, s.srv.URL+decodeProc, "unknown-client", goldenNonce, sig, body); code != http.StatusForbidden {
			t.Errorf("status = %d, want %d", code, http.StatusForbidden)
		}
	})
	t.Run("写procedure重放nonce拒绝", func(t *testing.T) {
		s := startFakeRPCServer(t, clientID, secret, nil)
		sig := s.intercept.fakeSign(clientID, goldenNonce, updateProfileProc, body)
		if code := post(t, s.srv.URL+updateProfileProc, clientID, goldenNonce, sig, body); code != http.StatusOK {
			t.Errorf("首次 status = %d, want %d", code, http.StatusOK)
		}
		if code := post(t, s.srv.URL+updateProfileProc, clientID, goldenNonce, sig, body); code != http.StatusForbidden {
			t.Errorf("重放 status = %d, want %d", code, http.StatusForbidden)
		}
	})
	t.Run("写procedure签名错误也消耗nonce", func(t *testing.T) {
		s := startFakeRPCServer(t, clientID, secret, nil)
		if code := post(t, s.srv.URL+updateProfileProc, clientID, goldenNonce, "bad-signature", body); code != http.StatusForbidden {
			t.Fatalf("坏签名首次 status = %d, want %d", code, http.StatusForbidden)
		}
		// 同 nonce 的好签名也被拒：去重先于签名（interceptors.go 行 287-297）。
		sig := s.intercept.fakeSign(clientID, goldenNonce, updateProfileProc, body)
		if code := post(t, s.srv.URL+updateProfileProc, clientID, goldenNonce, sig, body); code != http.StatusForbidden {
			t.Errorf("nonce 已被坏签名消耗, status = %d, want %d", code, http.StatusForbidden)
		}
	})
	t.Run("读procedure同nonce可重放", func(t *testing.T) {
		s := startFakeRPCServer(t, clientID, secret, nil)
		sig := s.intercept.fakeSign(clientID, goldenNonce, decodeProc, body)
		for i := 0; i < 2; i++ {
			if code := post(t, s.srv.URL+decodeProc, clientID, goldenNonce, sig, body); code != http.StatusOK {
				t.Errorf("第 %d 次 status = %d, want %d（读接口不去重）", i+1, code, http.StatusOK)
			}
		}
	})
}

// TestConnectClientEndToEnd 用真实 rpcv1connect 客户端挂 Signer 打
// httptest：服务端按收到的字节校验，通过即证明 Signer 签的是真实上行
// 字节；另显式断言收到的字节 == 客户端序列化的裸 proto 消息双确认。
// 发两次请求验证 nonce 每请求新随机串。
func TestConnectClientEndToEnd(t *testing.T) {
	const (
		clientID = "sdk-e2e-client"
		secret   = "e2e-secret"
	)
	wantMsg := &rpcv1.SessionResponse{
		Id:           10086,
		Epoch:        3,
		Amr:          []string{"pwd"},
		Sid:          "sid-e2e",
		Iat:          1761800000,
		Exp:          1762404800,
		RenewedToken: "renewed-token-xyz",
	}
	wantBytes, err := proto.Marshal(wantMsg)
	if err != nil {
		t.Fatal(err)
	}
	s := startFakeRPCServer(t, clientID, secret, func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/proto")
		w.WriteHeader(http.StatusOK)
		w.Write(wantBytes)
	})
	client := rpcv1connect.NewTokenServiceClient(
		&http.Client{Transport: NewSigner(nil, clientID, secret, nil)},
		s.srv.URL,
	)
	for i := 0; i < 2; i++ {
		resp, err := client.DecodeSession(context.Background(),
			connect.NewRequest(&rpcv1.DecodeSessionRequest{SessionToken: "session-token-abc"}))
		if err != nil {
			t.Fatalf("第 %d 次调用: %v", i+1, err)
		}
		if !proto.Equal(resp.Msg, wantMsg) {
			t.Errorf("第 %d 次响应 = %v, want %v", i+1, resp.Msg, wantMsg)
		}
	}
	recs := s.requestRecords()
	if len(recs) != 2 {
		t.Fatalf("服务端记录请求数 = %d, want 2", len(recs))
	}
	if recs[0].nonce == "" || recs[0].nonce == recs[1].nonce {
		t.Errorf("nonce 每请求新随机串被违反: %q / %q", recs[0].nonce, recs[1].nonce)
	}
	// 服务端校验通过本身证明签名 == 真实上行字节；显式比对双确认。
	wantReq, err := proto.Marshal(&rpcv1.DecodeSessionRequest{SessionToken: "session-token-abc"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recs[0].raw, wantReq) {
		t.Errorf("服务端收到字节 ≠ 客户端序列化消息: got %x, want %x", recs[0].raw, wantReq)
	}
}
