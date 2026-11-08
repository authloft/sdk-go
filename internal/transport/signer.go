// Package transport 实现 Authloft SDK 的 HMAC 签名传输层（接口文档 §7）。
//
// Signer 是 http.RoundTripper 装饰器：对上行请求按统一五项串
// client_id:nonce:path:body:client_secret 计算 HMAC-SHA256（hex 编码），
// 注入 X-Client-ID / X-Nonce-ID / X-Signature 三头（接口文档 §7 行
// 1371-1384）。签名器传输无关——base RoundTripper 注入式，h1/h2c/h2
// 逐帧语义一致，不假设 *http.Transport；H2C 传输装配归后续实现。
package transport

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
)

// 鉴权请求头（接口文档 §7 行 1371-1377；与服务端
// server/internal/connect/interceptors.go 的 rpcHeader* 常量一致）。
const (
	HeaderClientID  = "X-Client-ID"
	HeaderNonceID   = "X-Nonce-ID"
	HeaderSignature = "X-Signature"
)

// NewNonce 返回每请求新随机 nonce：crypto/rand 16 字节 hex（32 字符）。
func NewNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// 熵源不可用属系统级故障：静默降级为可预测 nonce 会实质放弃防重放，
		// 直接 panic 暴露故障（crypto/rand.Read 实际几乎不可能失败）。
		panic("authloft/sdk-go/internal/transport: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// Signer 是 HMAC 签名 RoundTripper 装饰器。
//
// 重试语义：本包不做任何自动重试（零重试对读写都安全）；读写分流由
// IsWriteProcedure 提供硬保障——后续重试策略必须先判写前缀，写接口
// 永不自动重试（SDK-init §7 行 160；服务端写接口 nonce 去重 TTL 30s）。
type Signer struct {
	base         http.RoundTripper
	clientID     string
	clientSecret string
	nonceFunc    func() string
}

// NewSigner 构造签名器：base 为 nil 时用 http.DefaultTransport；nonceFunc
// 为 nil 时用 NewNonce（每请求新随机串，接口文档 §7 行 1376）。
func NewSigner(base http.RoundTripper, clientID, clientSecret string, nonceFunc func() string) *Signer {
	if base == nil {
		base = http.DefaultTransport
	}
	if nonceFunc == nil {
		nonceFunc = NewNonce
	}
	return &Signer{base: base, clientID: clientID, clientSecret: clientSecret, nonceFunc: nonceFunc}
}

// RoundTrip 读出真实上行字节、计算签名、注入三头后交给 base。
//
// path 段取 req.URL.Path——即 Connect procedure（形如
// /api.rpc.v1.TokenService/DecodeSession；BaseURL 为纯 origin 时与服务端
// req.Spec().Procedure 一致，connect-go 将 procedure 同时用作挂载路径）；
// body 段取真实上行字节（Connect 裸 proto 消息），空 body 即空串。
func (s *Signer) RoundTrip(req *http.Request) (*http.Response, error) {
	var raw []byte
	if req.Body != nil {
		var err error
		raw, err = io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, err
		}
	}
	// RoundTripper 契约：不修改调用方传入的请求，clone 后再注入。
	signed := req.Clone(req.Context())
	if req.Body != nil {
		signed.Body = io.NopCloser(bytes.NewReader(raw))
	}
	nonce := s.nonceFunc()
	signed.Header.Set(HeaderClientID, s.clientID)
	signed.Header.Set(HeaderNonceID, nonce)
	signed.Header.Set(HeaderSignature, sign(s.clientID, nonce, signed.URL.Path, raw, s.clientSecret))
	return s.base.RoundTrip(signed)
}

// sign 按服务端语义计算 HMAC-SHA256 hex（小写；服务端 hex 解码大小写
// 不敏感，接口文档 §7 + interceptors.go 行 310-311）。五项串与 server 侧
// NewRPCHMACInterceptor 的三段 Write 同构（HMAC 流式，等价整体拼接）：
// Write(clientID:nonce:procedure:) → Write(raw) → Write(:secret)。
func sign(clientID, nonce, procedure string, body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(clientID + ":" + nonce + ":" + procedure + ":"))
	mac.Write(body)
	mac.Write([]byte(":" + secret))
	return hex.EncodeToString(mac.Sum(nil))
}
