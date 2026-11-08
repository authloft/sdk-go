package sdk

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// probeTransport 记录到达用户注入 Transport 的请求（次数 + 签名三头是否
// 已注入），证明注入路径「用户 Transport 为 base、Signer 包其上」。
type probeTransport struct {
	mu       sync.Mutex
	calls    int
	sawSigns bool
}

func (p *probeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	p.mu.Lock()
	p.calls++
	if req.Header.Get("X-Client-ID") == testClientID &&
		req.Header.Get("X-Nonce-ID") != "" &&
		req.Header.Get("X-Signature") != "" {
		p.sawSigns = true
	}
	p.mu.Unlock()
	return http.DefaultTransport.RoundTrip(req)
}

func TestNewSDKValidation(t *testing.T) {
	valid := Config{BaseURL: "http://authloft.internal:8080", ClientID: "cid", ClientSecret: "sec"}
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"缺BaseURL", func(c *Config) { c.BaseURL = "" }},
		{"缺ClientID", func(c *Config) { c.ClientID = "" }},
		{"缺ClientSecret", func(c *Config) { c.ClientSecret = "" }},
		// 纯 origin 约束（BaseURL 带路径会使
		// 签名 path 段与服务端 Procedure 失配）。
		{"BaseURL带路径", func(c *Config) { c.BaseURL = "http://host:8080/api" }},
		{"BaseURL带查询", func(c *Config) { c.BaseURL = "http://host:8080?x=1" }},
		{"BaseURL带片段", func(c *Config) { c.BaseURL = "http://host:8080/#frag" }},
		// scheme 决定传输：非 http/https 无法构造。
		{"BaseURL非http协议", func(c *Config) { c.BaseURL = "ftp://host:8080" }},
		{"BaseURL无host", func(c *Config) { c.BaseURL = "http://" }},
		{"BaseURL解析失败", func(c *Config) { c.BaseURL = "://bad" }},
		// CookieSecure 非法值（自定义类型 + 常量：拼错值构造期即检出，
		// SDK-init §3 / §4.4）。
		{"CookieSecure非法值", func(c *Config) { c.CookieSecure = CookieSecureMode("yes") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid
			tc.mutate(&cfg)
			if _, err := NewSDK(cfg); err == nil {
				t.Errorf("NewSDK(%+v) 应构造期拒绝，得到 nil 错误", cfg)
			}
		})
	}
}

// TestNewSDKTrailingSlashTolerated：纯 origin 的尾斜杠无语义（connect-go
// 生成客户端对 baseURL 做 TrimRight("/")），不应拒绝。
func TestNewSDKTrailingSlashTolerated(t *testing.T) {
	if _, err := NewSDK(Config{BaseURL: "http://host:8080/", ClientID: "cid", ClientSecret: "sec"}); err != nil {
		t.Errorf("尾斜杠应容忍: %v", err)
	}
}

// TestNewSDKDefaults 断言 SDK-init §3 可选字段默认值逐字对齐。
func TestNewSDKDefaults(t *testing.T) {
	s := mustNewSDK(t, Config{BaseURL: "https://authloft.example", ClientID: "cid", ClientSecret: "sec"})
	cfg := s.Config()
	if cfg.EnableGateway {
		t.Errorf("EnableGateway 默认应为 false")
	}
	if cfg.GatewayPrefix != "X-Session-" {
		t.Errorf("GatewayPrefix = %q, want X-Session-", cfg.GatewayPrefix)
	}
	if cfg.CtxKey != "uid" {
		t.Errorf("CtxKey = %q, want uid", cfg.CtxKey)
	}
	if cfg.HeaderKey != "X-Authloft-Token" {
		t.Errorf("HeaderKey = %q, want X-Authloft-Token", cfg.HeaderKey)
	}
	if cfg.CookieName != "al_session" {
		t.Errorf("CookieName = %q, want al_session", cfg.CookieName)
	}
	if cfg.CookieDomain != "" {
		t.Errorf("CookieDomain = %q, want 空（默认走按请求 Host 自动推导，SDK-init §3 / §4.4）", cfg.CookieDomain)
	}
	if cfg.CookieSecure != CookieSecureTrue {
		t.Errorf("CookieSecure = %q, want %q（未配置零值空串 ≡ 默认 true，SDK-init §3）", cfg.CookieSecure, CookieSecureTrue)
	}
}

// TestNewSDKCookieSecureInvalid：CookieSecure 非法值（如 "yes"，拼错
// 形态）→ NewSDK 构造期 fail-fast，错误文案含三态合法值列表（SDK-init §3）。
func TestNewSDKCookieSecureInvalid(t *testing.T) {
	_, err := NewSDK(Config{
		BaseURL:      "http://authloft.internal:8080",
		ClientID:     "cid",
		ClientSecret: "sec",
		CookieSecure: CookieSecureMode("yes"),
	})
	if err == nil {
		t.Fatal(`CookieSecure="yes" 应构造期拒绝，得到 nil 错误`)
	}
	for _, want := range []string{"true", "false", "auto"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("错误文案 = %q, want 含合法值 %q", err.Error(), want)
		}
	}
}

// TestNewSDKCookieSecureExplicitPreserved：三态显式配置原样保留（不被
// 归一改写）；行为差异（强制写 / 强制不写 / 逐请求推断）由 adapter 测试
// 覆盖（SDK-init §4.4 三态表）。
func TestNewSDKCookieSecureExplicitPreserved(t *testing.T) {
	for _, mode := range []CookieSecureMode{CookieSecureTrue, CookieSecureFalse, CookieSecureAuto} {
		s := mustNewSDK(t, Config{
			BaseURL:      "http://authloft.internal:8080",
			ClientID:     "cid",
			ClientSecret: "sec",
			CookieSecure: mode,
		})
		if got := s.Config().CookieSecure; got != mode {
			t.Errorf("CookieSecure = %q, want 原样保留 %q", got, mode)
		}
	}
}

// TestNewSDKHTTPSConstructs：https:// → 标准传输（ALPN 自动协商 H2）；
// 仅验证构造成功——自建 https
// 传输走系统根证书，httptest 自签证书无法端到端打通（ALPN 协商属标准库
// 行为）；http:// 的 h2c 通路端到端见 h2c_test.go。
func TestNewSDKHTTPSConstructs(t *testing.T) {
	if _, err := NewSDK(Config{BaseURL: "https://authloft.example", ClientID: "cid", ClientSecret: "sec"}); err != nil {
		t.Errorf("https BaseURL 构造失败: %v", err)
	}
}

// TestNewSDKInjectsHTTPClient 验证注入路径：① 用户 *http.Client 本体不被修改
// （浅拷贝替换 Transport）；② 用户 Transport 确实被采用（请求经它发出）；③
// Signer 包在用户 Transport 之上（到达时三头已注入）。服务端为 h2c
// 服务端（Protocols 含 HTTP1，标准 h1 传输亦可打通）。
func TestNewSDKInjectsHTTPClient(t *testing.T) {
	ts := startTestServer(t, nil, &fakeUserService{})
	probe := &probeTransport{}
	userClient := &http.Client{Transport: probe}
	s := mustNewSDK(t, Config{
		BaseURL: ts.URL, ClientID: testClientID, ClientSecret: testSecret,
		HTTPClient: userClient,
	})

	if userClient.Transport == nil {
		t.Fatal("用户 *http.Client 的 Transport 被改写为 nil（不得修改用户本体）")
	}
	if _, ok := userClient.Transport.(*probeTransport); !ok {
		t.Errorf("用户 *http.Client.Transport 类型 = %T, want *probeTransport（浅拷贝语义，不动用户本体）", userClient.Transport)
	}

	if _, err := s.GetUserProfile(context.Background(), 10086); err != nil {
		t.Fatalf("GetUserProfile（经注入 client）: %v", err)
	}

	probe.mu.Lock()
	defer probe.mu.Unlock()
	if probe.calls == 0 {
		t.Error("用户 Transport 未被采用（请求未经过注入的传输）")
	}
	if !probe.sawSigns {
		t.Error("到达用户 Transport 的请求缺签名三头（Signer 应包在用户传输之外层）")
	}
}
