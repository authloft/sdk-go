package sdk

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	rpcv1 "github.com/authloft/sdk-go/gen/go/api/rpc/v1"
	rpcv1connect "github.com/authloft/sdk-go/gen/go/api/rpc/v1/rpcv1connect"
	"github.com/authloft/sdk-go/internal/transport"
)

// reqCapture 捕获到达服务端的原始请求（协议版本 / 路径 / 签名三头 /
// body），供 h2c 通路断言；并发安全（测试 goroutine 与 handler goroutine
// 分离）。
type reqCapture struct {
	mu         sync.Mutex
	protoMajor int
	path       string
	clientID   string
	nonce      string
	signature  string
	body       []byte
}

// wrap 在 connect handler 之前捕获原始请求；body 读后回填，不影响下游。
func (c *reqCapture) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))
		c.mu.Lock()
		c.protoMajor = r.ProtoMajor
		c.path = r.URL.Path
		c.clientID = r.Header.Get(transport.HeaderClientID)
		c.nonce = r.Header.Get(transport.HeaderNonceID)
		c.signature = r.Header.Get(transport.HeaderSignature)
		c.body = body
		c.mu.Unlock()
		h.ServeHTTP(w, r)
	})
}

// TestH2CTransport 验证 http:// 明文 BaseURL 的完整 h2c 通路：SDK 侧
// prior-knowledge（x/net/http2
// AllowHTTP + 明文拨号）打 Go 1.26 原生 h2c 服务端（后端架构 §3.1 行
// 247-248 服务端口径），断言：
//  1. 服务端看到明文 HTTP/2（r.ProtoMajor == 2）；
//  2. 签名三头齐备、path 即 Connect procedure；
//  3. HMAC 五项串重算比对通过（测试内简易复刻服务端校验逻辑，接口文档
//     §7：client_id:nonce:path:body:client_secret → HMAC-SHA256 hex）；
//  4. Connect 响应正常解码（renewed_token 透传）。
func TestH2CTransport(t *testing.T) {
	cap := &reqCapture{}
	mux := http.NewServeMux()
	path, h := rpcv1connect.NewTokenServiceHandler(&fakeTokenService{})
	mux.Handle(path, h)

	ts := httptest.NewUnstartedServer(cap.wrap(mux))
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	ts.Config.Protocols = protocols
	ts.Start()
	t.Cleanup(ts.Close)

	s := mustNewSDK(t, Config{BaseURL: ts.URL, ClientID: testClientID, ClientSecret: testSecret})
	resp, err := s.DecodeSession(context.Background(), "session-token-h2c")
	if err != nil {
		t.Fatalf("h2c 通路 DecodeSession: %v", err)
	}
	if resp.RenewedToken != "renewed-abc" {
		t.Errorf("renewed_token = %q, want %q（h2c 响应透传）", resp.RenewedToken, "renewed-abc")
	}

	cap.mu.Lock()
	defer cap.mu.Unlock()
	if cap.protoMajor != 2 {
		t.Errorf("r.ProtoMajor = %d, want 2（h2c prior-knowledge 明文 HTTP/2）", cap.protoMajor)
	}
	if cap.path != rpcv1connect.TokenServiceDecodeSessionProcedure {
		t.Errorf("path = %q, want %q（BaseURL 纯 origin → 签名 path 段即 procedure）",
			cap.path, rpcv1connect.TokenServiceDecodeSessionProcedure)
	}
	if cap.clientID != testClientID || cap.nonce == "" || cap.signature == "" {
		t.Fatalf("签名三头缺失: clientID=%q nonce=%q signature=%q", cap.clientID, cap.nonce, cap.signature)
	}
	// HMAC 重算比对（与服务端 interceptors.go 校验逻辑同构）。
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write([]byte(testClientID + ":" + cap.nonce + ":" + cap.path + ":"))
	mac.Write(cap.body)
	mac.Write([]byte(":" + testSecret))
	want := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(cap.signature)) {
		t.Errorf("HMAC 五项签名比对失败: got %s, want %s", cap.signature, want)
	}
}

// TestH2CUserService 走 h2c 通路打 UserService（读写两方法与 TokenService
// 共用同一传输链，此处补写接口路径断言）。
func TestH2CUserService(t *testing.T) {
	cap := &reqCapture{}
	svc := &fakeUserService{}
	mux := http.NewServeMux()
	path, h := rpcv1connect.NewUserServiceHandler(svc)
	mux.Handle(path, h)

	ts := httptest.NewUnstartedServer(cap.wrap(mux))
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	ts.Config.Protocols = protocols
	ts.Start()
	t.Cleanup(ts.Close)

	s := mustNewSDK(t, Config{BaseURL: ts.URL, ClientID: testClientID, ClientSecret: testSecret})
	if _, err := s.GetUserProfile(context.Background(), 10086); err != nil {
		t.Fatalf("h2c GetUserProfile: %v", err)
	}
	if _, err := s.UpdateUserProfile(context.Background(), &rpcv1.UpdateUserProfileRequest{Uid: 10086}); err != nil {
		t.Fatalf("h2c UpdateUserProfile: %v", err)
	}

	cap.mu.Lock()
	defer cap.mu.Unlock()
	if cap.protoMajor != 2 {
		t.Errorf("r.ProtoMajor = %d, want 2", cap.protoMajor)
	}
	// 两次请求（Get + Update）都经同一 capture；path 逐次覆盖，最后一条
	// 应为写接口 procedure。
	if cap.path != rpcv1connect.UserServiceUpdateUserProfileProcedure {
		t.Errorf("path = %q, want %q", cap.path, rpcv1connect.UserServiceUpdateUserProfileProcedure)
	}
}
