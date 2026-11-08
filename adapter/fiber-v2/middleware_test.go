package fiberadapter

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/gofiber/fiber/v2"

	"github.com/authloft/sdk-go"
	rpcv1 "github.com/authloft/sdk-go/gen/go/api/rpc/v1"
	rpcv1connect "github.com/authloft/sdk-go/gen/go/api/rpc/v1/rpcv1connect"
)

// 测试夹具常量：fake 服务端口径复刻核心 module client_test.go 已验证形态
// （token 非空即有效并回 renewed_token；badToken 回 401 unauthenticated）。
const (
	testClientID = "fiber-adapter-test-client"
	testSecret   = "fiber-adapter-test-secret"

	testUID     = int64(10086)
	testRenewed = "renewed-abc"

	headerToken = "header-token-abc" // Header 渠道有效令牌
	cookieToken = "cookie-token-abc" // Cookie 渠道有效令牌
	badToken    = "bad-token"        // fake 服务端回 401 的令牌
)

// fakeTokenService 是 TokenService 的测试服务端：DecodeSession 调用计数
// （网关采信「不回源」断言依据）；badToken 回 401 unauthenticated（§7.1
// 会话无效形态），其余令牌回固定 SessionResponse（含 renewed_token）。
// exp 是签发会话的过期时间（Unix 秒），0 = 默认 now+3600——Set-Cookie 的
// Max-Age=exp−now 断言（SDK-init §4.4）以它为基准，可写为过去时间制造
// 「exp 已过期」形态。
type fakeTokenService struct {
	rpcv1connect.UnimplementedTokenServiceHandler
	calls atomic.Int32
	exp   int64
}

func (f *fakeTokenService) DecodeSession(_ context.Context, req *connect.Request[rpcv1.DecodeSessionRequest]) (*connect.Response[rpcv1.SessionResponse], error) {
	f.calls.Add(1)
	if req.Msg.SessionToken == badToken {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("session token 无效"))
	}
	exp := f.exp
	if exp == 0 {
		exp = time.Now().Add(time.Hour).Unix()
	}
	return connect.NewResponse(&rpcv1.SessionResponse{
		Id:           testUID,
		Epoch:        3,
		Sid:          "sid-test",
		RenewedToken: testRenewed,
		Exp:          exp,
	}), nil
}

// startTestServer 起 Go 原生 h2c 测试服务端（同端口 HTTP/1.1 + H2C，与
// 后端架构 §3.1 行 247-248 服务端口径一致），形态复刻核心 module
// client_test.go 的 startTestServer。
func startTestServer(t *testing.T, tokens rpcv1connect.TokenServiceHandler) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	path, h := rpcv1connect.NewTokenServiceHandler(tokens)
	mux.Handle(path, h)
	ts := httptest.NewUnstartedServer(mux)
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	ts.Config.Protocols = protocols
	ts.Start()
	t.Cleanup(ts.Close)
	return ts
}

func mustNewSDK(t *testing.T, cfg sdk.Config) *sdk.SDK {
	t.Helper()
	s, err := sdk.NewSDK(cfg)
	if err != nil {
		t.Fatalf("NewSDK(%+v): %v", cfg, err)
	}
	return s
}

// newTestApp 装配 fiber 应用：被测中间件 + 回显 uid 的业务 handler（uid
// 缺失回 "anonymous"）。类型断言 .(int64) 同时锁定「int64 原生值」契约
// （与标准模式 SessionResponse.Id 同型，非字符串）。
func newTestApp(s *sdk.SDK) *fiber.App {
	// DisableStartupMessage：TLS 三态测试经 app.Listener 挂真实 listener，
	// 静音其启动 banner（纯测试输出整洁，无行为影响）。
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(Middleware(s))
	app.Get("/", func(c *fiber.Ctx) error {
		if uid, ok := c.Locals(s.Config().CtxKey).(int64); ok {
			return c.SendString(strconv.FormatInt(uid, 10))
		}
		return c.SendString("anonymous")
	})
	return app
}

func doGet(t *testing.T, app *fiber.App, req *http.Request) *http.Response {
	t.Helper()
	resp, err := app.Test(req, 10000)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	return resp
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读取响应体: %v", err)
	}
	return string(b)
}

// assertNoTokenHeaders 断言响应未写任何令牌相关头（fail-open：无效 / 调用
// 失败均不重签、不写存储——SDK-init §4.2 步骤 4、§5.1）。
func assertNoTokenHeaders(t *testing.T, resp *http.Response, cfg sdk.Config) {
	t.Helper()
	if v := resp.Header.Get(cfg.HeaderKey); v != "" {
		t.Errorf("响应头 %s = %q, want 未写（fail-open 不写任何令牌头）", cfg.HeaderKey, v)
	}
	for _, sc := range resp.Header.Values("Set-Cookie") {
		if strings.Contains(sc, cfg.CookieName+"=") {
			t.Errorf("Set-Cookie = %q, want 不含 %s（fail-open 不写存储）", sc, cfg.CookieName)
		}
	}
}

func defaultConfig(baseURL string) sdk.Config {
	return sdk.Config{BaseURL: baseURL, ClientID: testClientID, ClientSecret: testSecret}
}

// TestGatewayValidInjectsUID（网关采信·valid 注入）：EnableGateway 且携带
// <前缀>Status=valid → 采信 <前缀>ID 注入 int64 uid，不回源 DecodeSession。
func TestGatewayValidInjectsUID(t *testing.T) {
	svc := &fakeTokenService{}
	ts := startTestServer(t, svc)
	cfg := defaultConfig(ts.URL)
	cfg.EnableGateway = true
	app := newTestApp(mustNewSDK(t, cfg))

	req := httptest.NewRequest(fiber.MethodGet, "/", nil)
	req.Header.Set("X-Session-Status", "valid")
	req.Header.Set("X-Session-ID", strconv.FormatInt(testUID, 10))
	// 另带 Cookie 令牌：网关判定即终局，即使 Cookie 渠道也不产生
	// Set-Cookie（§4.1 / §9 条 15：采信不回源，无 renewedToken 可传播）。
	req.Header.Set("Cookie", "al_session="+cookieToken)

	resp := doGet(t, app, req)
	if got := readBody(t, resp); got != "10086" {
		t.Errorf("uid 注入: body = %q, want 10086（网关采信 <前缀>ID）", got)
	}
	if got := svc.calls.Load(); got != 0 {
		t.Errorf("DecodeSession 调用 %d 次, want 0（网关采信不回源）", got)
	}
	if sc := resp.Header.Values("Set-Cookie"); len(sc) != 0 {
		t.Errorf("Set-Cookie = %v, want 无（网关采信路径不回写 Cookie，§4.1 / §9 条 15）", sc)
	}
}

// TestGatewayNonValidAnonymous（网关非 valid 匿名）：Status 非 valid → 不注入
// uid、匿名放行，判定即终局（不回源）。
func TestGatewayNonValidAnonymous(t *testing.T) {
	svc := &fakeTokenService{}
	ts := startTestServer(t, svc)
	cfg := defaultConfig(ts.URL)
	cfg.EnableGateway = true
	s := mustNewSDK(t, cfg)
	cfg = s.Config() // 断言口径取 NewSDK 归一后的配置（默认值）
	app := newTestApp(s)

	req := httptest.NewRequest(fiber.MethodGet, "/", nil)
	req.Header.Set("X-Session-Status", "invalid")
	// 另带 Cookie 令牌：网关判定即终局（不回源、无 renewedToken 可传播，
	// 即使 Cookie 渠道也不产生 Set-Cookie，§4.1 / §9 条 15）。
	req.Header.Set("Cookie", "al_session="+cookieToken)

	resp := doGet(t, app, req)
	if got := readBody(t, resp); got != "anonymous" {
		t.Errorf("非 valid 应匿名放行: body = %q, want anonymous", got)
	}
	if got := svc.calls.Load(); got != 0 {
		t.Errorf("DecodeSession 调用 %d 次, want 0（网关判定即终局）", got)
	}
	assertNoTokenHeaders(t, resp, cfg)
}

// TestGatewayNoHeaderFallsBackToStandard（无网关头回落标准）：EnableGateway
// 但无 <前缀>Status 头 → 落回标准模式，带 token 回源 DecodeSession 并注入 uid。
func TestGatewayNoHeaderFallsBackToStandard(t *testing.T) {
	svc := &fakeTokenService{}
	ts := startTestServer(t, svc)
	cfg := defaultConfig(ts.URL)
	cfg.EnableGateway = true
	app := newTestApp(mustNewSDK(t, cfg))

	req := httptest.NewRequest(fiber.MethodGet, "/", nil)
	req.Header.Set("X-Authloft-Token", headerToken)

	resp := doGet(t, app, req)
	if got := readBody(t, resp); got != "10086" {
		t.Errorf("回落标准模式应注入 uid: body = %q, want 10086", got)
	}
	if got := svc.calls.Load(); got != 1 {
		t.Errorf("DecodeSession 调用 %d 次, want 1（无网关头回源）", got)
	}
}

// TestGatewayDisabledIgnoresGatewayHeaders（EnableGateway=false 完全不读网关
// 头）：即使携带 valid 网关头也不采信——无 token 匿名放行。
func TestGatewayDisabledIgnoresGatewayHeaders(t *testing.T) {
	svc := &fakeTokenService{}
	ts := startTestServer(t, svc)
	app := newTestApp(mustNewSDK(t, defaultConfig(ts.URL))) // EnableGateway 默认 false

	req := httptest.NewRequest(fiber.MethodGet, "/", nil)
	req.Header.Set("X-Session-Status", "valid")
	req.Header.Set("X-Session-ID", strconv.FormatInt(testUID, 10))

	resp := doGet(t, app, req)
	if got := readBody(t, resp); got != "anonymous" {
		t.Errorf("EnableGateway=false 不读网关头: body = %q, want anonymous", got)
	}
	if got := svc.calls.Load(); got != 0 {
		t.Errorf("DecodeSession 调用 %d 次, want 0（无 token 不回源）", got)
	}
}

// TestStandardValidRenewsTokenViaHeader（标准有效 + renewedToken·Header 渠道）：
// 令牌来自 HeaderKey → 同名响应头覆盖回写；不写 Set-Cookie。
func TestStandardValidRenewsTokenViaHeader(t *testing.T) {
	svc := &fakeTokenService{}
	ts := startTestServer(t, svc)
	cfg := defaultConfig(ts.URL)
	s := mustNewSDK(t, cfg)
	cfg = s.Config() // 断言口径取 NewSDK 归一后的配置（默认值）
	app := newTestApp(s)

	req := httptest.NewRequest(fiber.MethodGet, "/", nil)
	req.Header.Set("X-Authloft-Token", headerToken)

	resp := doGet(t, app, req)
	if got := readBody(t, resp); got != "10086" {
		t.Errorf("uid 注入: body = %q, want 10086", got)
	}
	if got := resp.Header.Get("X-Authloft-Token"); got != testRenewed {
		t.Errorf("响应头 X-Authloft-Token = %q, want %q（原渠道覆盖：Header→同名响应头）", got, testRenewed)
	}
	if sc := resp.Header.Values("Set-Cookie"); len(sc) != 0 {
		t.Errorf("Set-Cookie = %v, want 无（Header 渠道不写 Cookie）", sc)
	}
	if got := svc.calls.Load(); got != 1 {
		t.Errorf("DecodeSession 调用 %d 次, want 1", got)
	}
}

// TestStandardValidRenewsTokenViaCookie（标准有效 + renewedToken·Cookie 渠道）：
// 令牌来自 CookieName → Set-Cookie 覆盖回写（五属性逐项断言 = SDK-init
// §4.4 定稿：HttpOnly / Path=/ / Secure 默认 true（三态见 TestCookieSecure*）/
// SameSite 随 Secure 联动（默认 → None，联动分支见 TestCookieSecure*）/
// Max-Age=exp−now）；不写令牌响应头。httptest 请求 Host 默认 example.com
//（文档化行为）→ 推导 Domain=example.com；Domain 三分支见
// TestCookieDomain*，Max-Age 过期形态见 TestCookieMaxAgeExpiredDeletes。
func TestStandardValidRenewsTokenViaCookie(t *testing.T) {
	svc := &fakeTokenService{}
	ts := startTestServer(t, svc)
	cfg := defaultConfig(ts.URL)
	s := mustNewSDK(t, cfg)
	cfg = s.Config() // 断言口径取 NewSDK 归一后的配置（默认值）
	app := newTestApp(s)

	req := httptest.NewRequest(fiber.MethodGet, "/", nil)
	req.Header.Set("Cookie", "al_session="+cookieToken)

	resp := doGet(t, app, req)
	if got := readBody(t, resp); got != "10086" {
		t.Errorf("uid 注入: body = %q, want 10086", got)
	}
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Set-Cookie 数 = %d, want 1（仅令牌 Cookie）: %v", len(cookies), resp.Header.Values("Set-Cookie"))
	}
	ck := cookies[0]
	if ck.Name != cfg.CookieName || ck.Value != testRenewed {
		t.Errorf("Set-Cookie = %s=%s, want %s=%s（原渠道覆盖：Cookie→Set-Cookie）", ck.Name, ck.Value, cfg.CookieName, testRenewed)
	}
	if ck.Path != "/" {
		t.Errorf("Cookie Path = %q, want /（§4.4）", ck.Path)
	}
	if !ck.HttpOnly {
		t.Error("Cookie HttpOnly = false, want true（§4.4：令牌对页面 JS 不可读）")
	}
	if !ck.Secure {
		t.Error("Cookie Secure = false, want true（§4.4：默认 CookieSecure=true 强制写；三态见 TestCookieSecure*）")
	}
	if ck.SameSite != http.SameSiteNoneMode {
		t.Errorf("Cookie SameSite = %v, want None（§4.4：默认 CookieSecure=true → Secure=true → SameSite=None 联动）", ck.SameSite)
	}
	// Max-Age = exp − now：fake 服务端签发 exp = now+3600，跨秒请求取
	// [3590, 3600] 容差（fiber.Cookie.MaxAge 秒语义经 fasthttp 以
	// max-age=N 输出）。
	if ck.MaxAge < 3590 || ck.MaxAge > 3600 {
		t.Errorf("Cookie MaxAge = %d, want [3590, 3600]（Max-Age=exp−now 会话剩余寿命，§4.4）", ck.MaxAge)
	}
	// httptest.NewRequest 对相对路径 target 的 Host 默认 "example.com"
	//（文档化行为）→ 两段域名原样推导为根域名 example.com（§4.4）。
	if ck.Domain != "example.com" {
		t.Errorf("Cookie Domain = %q, want example.com（Host=example.com 自动推导）", ck.Domain)
	}
	if got := resp.Header.Get(cfg.HeaderKey); got != "" {
		t.Errorf("响应头 %s = %q, want 未写（Cookie 渠道不写响应头）", cfg.HeaderKey, got)
	}
}

// TestStandardHeaderPriority（Header 优先于 Cookie）：两渠道并存且 Cookie 为
// 无效令牌 → 取值走 HeaderKey（§4.2 步骤 1，与接口文档 §6 优先级一致），
// uid 注入成功且 renewedToken 按 Header 渠道回写响应头（误取 Cookie 会 401
// 匿名，用例即失败）。
func TestStandardHeaderPriority(t *testing.T) {
	svc := &fakeTokenService{}
	ts := startTestServer(t, svc)
	cfg := defaultConfig(ts.URL)
	s := mustNewSDK(t, cfg)
	cfg = s.Config() // 断言口径取 NewSDK 归一后的配置（默认值）
	app := newTestApp(s)

	req := httptest.NewRequest(fiber.MethodGet, "/", nil)
	req.Header.Set("X-Authloft-Token", headerToken)
	req.Header.Set("Cookie", "al_session="+badToken)

	resp := doGet(t, app, req)
	if got := readBody(t, resp); got != "10086" {
		t.Errorf("uid = %q, want 10086（Header 优先于 Cookie）", got)
	}
	if got := resp.Header.Get("X-Authloft-Token"); got != testRenewed {
		t.Errorf("响应头 X-Authloft-Token = %q, want %q（按取值来源传播）", got, testRenewed)
	}
	if sc := resp.Header.Values("Set-Cookie"); len(sc) != 0 {
		t.Errorf("Set-Cookie = %v, want 无（Header 来源不应写 Cookie）", sc)
	}
	if got := svc.calls.Load(); got != 1 {
		t.Errorf("DecodeSession 调用 %d 次, want 1", got)
	}
}

// TestSessionInvalidAnonymousNoHeaders（401 匿名不写头）：DecodeSession 回
// 401 unauthenticated → 匿名放行，不注入 uid、不写任何令牌相关响应头。
func TestSessionInvalidAnonymousNoHeaders(t *testing.T) {
	svc := &fakeTokenService{}
	ts := startTestServer(t, svc)
	cfg := defaultConfig(ts.URL)
	s := mustNewSDK(t, cfg)
	cfg = s.Config() // 断言口径取 NewSDK 归一后的配置（默认值）
	app := newTestApp(s)

	req := httptest.NewRequest(fiber.MethodGet, "/", nil)
	req.Header.Set("X-Authloft-Token", badToken)

	resp := doGet(t, app, req)
	if got := readBody(t, resp); got != "anonymous" {
		t.Errorf("401 应匿名放行: body = %q, want anonymous", got)
	}
	if got := svc.calls.Load(); got != 1 {
		t.Errorf("DecodeSession 调用 %d 次, want 1", got)
	}
	assertNoTokenHeaders(t, resp, cfg)
}

// TestStandardCookieInvalidTokenAnonymous：Cookie 来源的 401 同样匿名、
// 无 Set-Cookie、不写令牌响应头（不重签、不写存储）。
func TestStandardCookieInvalidTokenAnonymous(t *testing.T) {
	svc := &fakeTokenService{}
	ts := startTestServer(t, svc)
	cfg := defaultConfig(ts.URL)
	s := mustNewSDK(t, cfg)
	cfg = s.Config() // 断言口径取 NewSDK 归一后的配置（默认值）
	app := newTestApp(s)

	req := httptest.NewRequest(fiber.MethodGet, "/", nil)
	req.Header.Set("Cookie", "al_session="+badToken)

	resp := doGet(t, app, req)
	if got := readBody(t, resp); got != "anonymous" {
		t.Errorf("Cookie 401 应匿名放行: body = %q, want anonymous", got)
	}
	if got := svc.calls.Load(); got != 1 {
		t.Errorf("DecodeSession 调用 %d 次, want 1", got)
	}
	assertNoTokenHeaders(t, resp, cfg)
}

// TestCallFailedAnonymous（网络失败匿名 + 记录错误日志）：服务端不可达
// （h2c 拨号失败，复刻核心 module client_test.go 手法）→ 调用失败同样
// 匿名放行、不写任何令牌头，并记录错误日志（§5.1）。
func TestCallFailedAnonymous(t *testing.T) {
	svc := &fakeTokenService{}
	ts := startTestServer(t, svc)
	cfg := defaultConfig(ts.URL)
	s := mustNewSDK(t, cfg)
	cfg = s.Config() // 断言口径取 NewSDK 归一后的配置（默认值）
	app := newTestApp(s)
	ts.Close() // 模拟服务端不可达

	// 捕获标准日志以断言 §5.1「调用失败记录错误日志后匿名放行」。
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	req := httptest.NewRequest(fiber.MethodGet, "/", nil)
	req.Header.Set("X-Authloft-Token", headerToken)

	resp := doGet(t, app, req)
	if got := readBody(t, resp); got != "anonymous" {
		t.Errorf("网络失败应匿名放行: body = %q, want anonymous", got)
	}
	assertNoTokenHeaders(t, resp, cfg)
	logLine := strings.TrimSpace(buf.String())
	if !strings.Contains(logLine, "fiberadapter: GET /: DecodeSession 调用失败，fail-open 匿名放行") {
		t.Errorf("调用失败应记录错误日志, 实际: %q", logLine)
	}
	t.Logf("日志行: %s", logLine)
}

// TestNoTokenAnonymous（无 token 匿名）：Header / Cookie 两处皆空 → 匿名
// 放行，不回源 DecodeSession。
func TestNoTokenAnonymous(t *testing.T) {
	svc := &fakeTokenService{}
	ts := startTestServer(t, svc)
	app := newTestApp(mustNewSDK(t, defaultConfig(ts.URL)))

	resp := doGet(t, app, httptest.NewRequest(fiber.MethodGet, "/", nil))
	if got := readBody(t, resp); got != "anonymous" {
		t.Errorf("无 token 应匿名放行: body = %q, want anonymous", got)
	}
	if got := svc.calls.Load(); got != 0 {
		t.Errorf("DecodeSession 调用 %d 次, want 0（两空匿名不回源）", got)
	}
}

// TestCustomConfigKeys：Config 键名全链路生效（SDK-init §3：GatewayPrefix
// 整体替换、CtxKey / HeaderKey / CookieName 可配）。
func TestCustomConfigKeys(t *testing.T) {
	svc := &fakeTokenService{}
	ts := startTestServer(t, svc)
	cfg := defaultConfig(ts.URL)
	cfg.EnableGateway = true
	cfg.GatewayPrefix = "X-Gw-"
	cfg.CtxKey = "user_id"
	cfg.HeaderKey = "X-Token-Custom"
	cfg.CookieName = "sess"
	app := newTestApp(mustNewSDK(t, cfg))

	// 网关头走自定义前缀 → 注入到自定义 CtxKey。
	req := httptest.NewRequest(fiber.MethodGet, "/", nil)
	req.Header.Set("X-Gw-Status", "valid")
	req.Header.Set("X-Gw-ID", strconv.FormatInt(testUID, 10))
	resp := doGet(t, app, req)
	if got := readBody(t, resp); got != "10086" {
		t.Errorf("自定义前缀/CTX 键: body = %q, want 10086", got)
	}

	// 标准模式 Cookie 渠道：自定义 Cookie 名 → Set-Cookie 同名回写。
	req2 := httptest.NewRequest(fiber.MethodGet, "/", nil)
	req2.Header.Set("Cookie", "sess="+cookieToken)
	resp2 := doGet(t, app, req2)
	if got := readBody(t, resp2); got != "10086" {
		t.Errorf("自定义 Cookie 名取值: body = %q, want 10086", got)
	}
	cookies := resp2.Cookies()
	if len(cookies) != 1 || cookies[0].Name != "sess" || cookies[0].Value != testRenewed {
		t.Errorf("Set-Cookie = %v, want [{sess renewed-abc}]", resp2.Header.Values("Set-Cookie"))
	}
}

// TestGatewayValidMalformedIDAnonymous 锁定该行为：Status=valid 但
// <前缀>ID 非数字（网关侧契约破坏，SDK-init 未覆盖）→ 按 fail-open 精神
// 匿名放行、不回源。
func TestGatewayValidMalformedIDAnonymous(t *testing.T) {
	svc := &fakeTokenService{}
	ts := startTestServer(t, svc)
	cfg := defaultConfig(ts.URL)
	cfg.EnableGateway = true
	app := newTestApp(mustNewSDK(t, cfg))

	req := httptest.NewRequest(fiber.MethodGet, "/", nil)
	req.Header.Set("X-Session-Status", "valid")
	req.Header.Set("X-Session-ID", "not-a-number")

	resp := doGet(t, app, req)
	if got := readBody(t, resp); got != "anonymous" {
		t.Errorf("ID 非数字应匿名放行: body = %q, want anonymous", got)
	}
	if got := svc.calls.Load(); got != 0 {
		t.Errorf("DecodeSession 调用 %d 次, want 0（网关判定即终局，不回源）", got)
	}
	if sc := resp.Header.Values("Set-Cookie"); len(sc) != 0 {
		t.Errorf("Set-Cookie = %v, want 无（网关采信路径不回写 Cookie，§4.1 / §9 条 15）", sc)
	}
}

// --- Cookie 回写 Domain 三分支与 Max-Age 过期形态（SDK-init §4.4）---

// TestCookieDomainExplicit：CookieDomain 非空 → 强制使用、不推导——即使
// 请求 Host 本可推导出根域名，也原样写入配置值（§4.4 优先级 1，配置者
// 自行负责合法性）。
func TestCookieDomainExplicit(t *testing.T) {
	svc := &fakeTokenService{}
	ts := startTestServer(t, svc)
	cfg := defaultConfig(ts.URL)
	cfg.CookieDomain = "sso.example.com"
	app := newTestApp(mustNewSDK(t, cfg))

	req := httptest.NewRequest(fiber.MethodGet, "/", nil)
	req.Host = "a.b.example.com" // 可推导的 Host 存在也不推导
	req.Header.Set("Cookie", "al_session="+cookieToken)

	cookies := doGet(t, app, req).Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Set-Cookie 数 = %d, want 1: %v", len(cookies), cookies)
	}
	if got := cookies[0].Domain; got != "sso.example.com" {
		t.Errorf("Cookie Domain = %q, want sso.example.com（非空强制使用不推导，§4.4）", got)
	}
}

// TestCookieDomainDerived：CookieDomain 空 → 按业务应用请求 Host
//（c.Hostname()，可能带端口，先剥）取最后两段自动推导，不带前导点
//（§4.4 优先级 2）。
func TestCookieDomainDerived(t *testing.T) {
	svc := &fakeTokenService{}
	ts := startTestServer(t, svc)
	app := newTestApp(mustNewSDK(t, defaultConfig(ts.URL)))

	req := httptest.NewRequest(fiber.MethodGet, "/", nil)
	req.Host = "a.b.example.com:8443" // 带端口：推导前先剥
	req.Header.Set("Cookie", "al_session="+cookieToken)

	cookies := doGet(t, app, req).Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Set-Cookie 数 = %d, want 1: %v", len(cookies), cookies)
	}
	got := cookies[0].Domain
	if got != "example.com" {
		t.Errorf("Cookie Domain = %q, want example.com（最后两段，§4.4）", got)
	}
	if strings.HasPrefix(got, ".") {
		t.Errorf("Cookie Domain = %q, 不应带前导点（§4.4：RFC 6265 §5.2.3 规范写法）", got)
	}
}

// TestCookieDomainDegraded：请求 Host 为 IPv4 / localhost / 单段主机名 →
// 推导为空 → 不设 Domain，降级 host-only Cookie（§4.4 优先级 3）。
func TestCookieDomainDegraded(t *testing.T) {
	svc := &fakeTokenService{}
	ts := startTestServer(t, svc)
	app := newTestApp(mustNewSDK(t, defaultConfig(ts.URL)))

	for name, host := range map[string]string{
		"IPv4":      "192.168.1.10",
		"localhost": "localhost",
		"单段主机名":   "intranet",
	} {
		req := httptest.NewRequest(fiber.MethodGet, "/", nil)
		req.Host = host
		req.Header.Set("Cookie", "al_session="+cookieToken)

		cookies := doGet(t, app, req).Cookies()
		if len(cookies) != 1 {
			t.Fatalf("%s(%q): Set-Cookie 数 = %d, want 1: %v", name, host, len(cookies), cookies)
		}
		if got := cookies[0].Domain; got != "" {
			t.Errorf("%s(%q): Cookie Domain = %q, want 空（非域名形态降级 host-only，§4.4）", name, host, got)
		}
	}
}

// TestCookieMaxAgeExpiredDeletes：exp − now ≤ 0（会话已过期 / 时钟偏移
// 异常形态）→ 按字面语义写删除型 Cookie。fasthttp 仅在 MaxAge>0 时输出
// max-age 属性（<=0 均不写，无法像 gin 侧那样表达 Max-Age=0），删除语义
// 以过去 Expires 表达——与 gin 侧手法不同、语义一致（浏览器立即删除）。
func TestCookieMaxAgeExpiredDeletes(t *testing.T) {
	svc := &fakeTokenService{}
	ts := startTestServer(t, svc)
	svc.exp = time.Now().Add(-10 * time.Second).Unix() // 会话已过期
	app := newTestApp(mustNewSDK(t, defaultConfig(ts.URL)))

	req := httptest.NewRequest(fiber.MethodGet, "/", nil)
	req.Header.Set("Cookie", "al_session="+cookieToken)

	cookies := doGet(t, app, req).Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Set-Cookie 数 = %d, want 1（exp 过期仍按原渠道回写，删除型）: %v", len(cookies), cookies)
	}
	ck := cookies[0]
	if ck.Expires.IsZero() || !ck.Expires.Before(time.Now()) {
		t.Errorf("Cookie Expires = %v, want 过去时间（exp−now ≤ 0 → 删除型 Cookie，§4.4）", ck.Expires)
	}
	if ck.MaxAge != 0 {
		t.Errorf("Cookie MaxAge = %d, want 0（不写 max-age，删除经 Expires 表达）", ck.MaxAge)
	}
}

// --- Cookie Secure 三态（SDK-init §4.4）---

// selfSignedCert 生成测试用自签证书（ECDSA P-256，SAN 含 127.0.0.1）。
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成 ECDSA 私钥: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("签发自签证书: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startTLSAppListener 把 fiber app 挂到真实 TLS listener（自签证书）并返回
// 其 https 基址——fiber 的 app.Test 走内存假连接（非 *tls.Conn），中间件内
// c.Context().TLSConnectionState() 恒 nil，「请求自身 TLS 直连」形态只能经
// 真实 TLS 通道覆盖（auto 推断规则 2 的断言依据）。
func startTLSAppListener(t *testing.T, app *fiber.App) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听 127.0.0.1:0: %v", err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{selfSignedCert(t)},
	})
	go func() { _ = app.Listener(tlsLn) }() // 测试期常驻；cleanup 关 listener 即退出
	t.Cleanup(func() { _ = tlsLn.Close() })
	return "https://" + tlsLn.Addr().String()
}

// secureProbeTLS 经 InsecureSkipVerify 客户端（仅测试，信任上方自签证书）
// 向 TLS app 发携带令牌 Cookie 的 GET（可附 X-Forwarded-Proto 头），解析
// 回写 Cookie（供 Secure / SameSite 断言）。
func secureProbeTLS(t *testing.T, url string, xfp string) *http.Cookie {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // 测试专属：信任自签证书
	}}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	req.Header.Set("Cookie", "al_session="+cookieToken)
	if xfp != "" {
		req.Header.Set("X-Forwarded-Proto", xfp)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("TLS 请求 %s: %v", url, err)
	}
	defer resp.Body.Close()
	cookies := resp.Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Set-Cookie 数 = %d, want 1: %v", len(cookies), resp.Header.Values("Set-Cookie"))
	}
	return cookies[0]
}

// secureProbePlain 经 app.Test（内存假连接，无 TLS）发携带令牌 Cookie 的
// GET（可附 X-Forwarded-Proto 头），解析回写 Cookie（供 Secure / SameSite
// 断言）。
func secureProbePlain(t *testing.T, app *fiber.App, xfp string) *http.Cookie {
	t.Helper()
	req := httptest.NewRequest(fiber.MethodGet, "/", nil)
	req.Header.Set("Cookie", "al_session="+cookieToken)
	if xfp != "" {
		req.Header.Set("X-Forwarded-Proto", xfp)
	}
	cookies := doGet(t, app, req).Cookies()
	if len(cookies) != 1 {
		t.Fatalf("Set-Cookie 数 = %d, want 1: %v", len(cookies), cookies)
	}
	return cookies[0]
}

// TestCookieSecureTrueForceWrites：「true」强制写——明文（app.Test 假
// 连接）与 TLS 请求两态均带 Secure；BaseURL 恒 http（h2c fake 后端）反证
// 不以 BaseURL scheme 参与 Secure 判定（§4.4 三态表 +「推断来源」段；
// 与 gin adapter 同构）。SameSite 随 Secure 联动（2026-11-06 定稿）：
// Secure=true → None。
func TestCookieSecureTrueForceWrites(t *testing.T) {
	svc := &fakeTokenService{}
	ts := startTestServer(t, svc)
	cfg := defaultConfig(ts.URL)
	cfg.CookieSecure = sdk.CookieSecureTrue
	app := newTestApp(mustNewSDK(t, cfg))

	ck := secureProbePlain(t, app, "")
	if !ck.Secure {
		t.Error("http 请求: Cookie Secure = false, want true（true 强制写，§4.4）")
	}
	if ck.SameSite != http.SameSiteNoneMode {
		t.Errorf("http 请求: Cookie SameSite = %v, want None（Secure=true 联动 None，§4.4）", ck.SameSite)
	}
	ck = secureProbeTLS(t, startTLSAppListener(t, app), "")
	if !ck.Secure {
		t.Error("https 请求: Cookie Secure = false, want true（true 强制写，§4.4）")
	}
	if ck.SameSite != http.SameSiteNoneMode {
		t.Errorf("https 请求: Cookie SameSite = %v, want None（Secure=true 联动 None，§4.4）", ck.SameSite)
	}
}

// TestCookieSecureFalseNeverWrites：「false」强制不写——明文与 TLS 请求
// 两态均不带 Secure 属性（§4.4 三态表；与 gin adapter 同构）。SameSite
// 随 Secure 联动（2026-11-06 定稿）：Secure=false → Lax。
func TestCookieSecureFalseNeverWrites(t *testing.T) {
	svc := &fakeTokenService{}
	ts := startTestServer(t, svc)
	cfg := defaultConfig(ts.URL)
	cfg.CookieSecure = sdk.CookieSecureFalse
	app := newTestApp(mustNewSDK(t, cfg))

	ck := secureProbePlain(t, app, "")
	if ck.Secure {
		t.Error("http 请求: Cookie Secure = true, want false（false 强制不写，§4.4）")
	}
	if ck.SameSite != http.SameSiteLaxMode {
		t.Errorf("http 请求: Cookie SameSite = %v, want Lax（Secure=false 联动 Lax，§4.4）", ck.SameSite)
	}
	ck = secureProbeTLS(t, startTLSAppListener(t, app), "")
	if ck.Secure {
		t.Error("https 请求: Cookie Secure = true, want false（false 强制不写，§4.4）")
	}
	if ck.SameSite != http.SameSiteLaxMode {
		t.Errorf("https 请求: Cookie SameSite = %v, want Lax（Secure=false 联动 Lax，§4.4）", ck.SameSite)
	}
}

// TestCookieSecureAutoInfersPerRequest：「auto」按业务应用当前请求协议
// 逐请求推断（§4.4 推断规则）：X-Forwarded-Proto 头存在 → 逗号首值、
// 忽略大小写（https 写 / http 及其他任意值不写）；头缺失看请求自身 TLS
//（经真实 TLS listener，fasthttp TLSConnectionState 才非 nil）；头优先
// 于 TLS；无头无 TLS 兜底不写。BaseURL 恒 http——TLS 请求若被误按
// BaseURL 推断会得 false，反证推断来源是请求协议（§4.4）。SameSite
// 随 Secure 推断结果联动（2026-11-06 定稿）：推断 https → None、
// 推断明文 → Lax。
func TestCookieSecureAutoInfersPerRequest(t *testing.T) {
	svc := &fakeTokenService{}
	ts := startTestServer(t, svc)
	cfg := defaultConfig(ts.URL)
	cfg.CookieSecure = sdk.CookieSecureAuto
	app := newTestApp(mustNewSDK(t, cfg))
	tlsURL := startTLSAppListener(t, app) // TLS 直连形态用

	cases := []struct {
		name   string
		xfp    string
		tls    bool
		want   bool
		wantSS http.SameSite
	}{
		{"TLS 直连无头 → 写", "", true, true, http.SameSiteNoneMode},
		{"明文直连无头 → 兜底不写", "", false, false, http.SameSiteLaxMode},
		{"头 https 明文请求 → 写", "https", false, true, http.SameSiteNoneMode},
		{"头 http + TLS 直连 → 头优先不写", "http", true, false, http.SameSiteLaxMode},
		{"头其他值（grpc）→ 不写", "grpc", false, false, http.SameSiteLaxMode},
		{"头逗号列表取首值 https → 写", "https,http", false, true, http.SameSiteNoneMode},
		{"头逗号列表取首值 http → 不写", "http,https", false, false, http.SameSiteLaxMode},
		{"头大小写不敏感 HTTPS → 写", "HTTPS", false, true, http.SameSiteNoneMode},
	}
	for _, tc := range cases {
		var ck *http.Cookie
		if tc.tls {
			ck = secureProbeTLS(t, tlsURL, tc.xfp)
		} else {
			ck = secureProbePlain(t, app, tc.xfp)
		}
		if ck.Secure != tc.want {
			t.Errorf("%s: Cookie Secure = %v, want %v", tc.name, ck.Secure, tc.want)
		}
		if ck.SameSite != tc.wantSS {
			t.Errorf("%s: Cookie SameSite = %v, want %v（随 Secure 推断结果联动，§4.4）", tc.name, ck.SameSite, tc.wantSS)
		}
	}
}

// TestCookieSecureDefaultIsTrue：默认不传（Config 零值）≡ 显式 "true"——
// NewSDK 归一后行为与 TestCookieSecureTrueForceWrites 一致（§3
//「未配置 ≡ true」；归一值本身由核心 module TestNewSDKDefaults 锁定）；
// SameSite 联动同理：Secure=true → None。
func TestCookieSecureDefaultIsTrue(t *testing.T) {
	svc := &fakeTokenService{}
	ts := startTestServer(t, svc)
	app := newTestApp(mustNewSDK(t, defaultConfig(ts.URL))) // CookieSecure 零值空串

	ck := secureProbePlain(t, app, "")
	if !ck.Secure {
		t.Error("默认（零值）http 请求: Cookie Secure = false, want true（未配置 ≡ true，§3）")
	}
	if ck.SameSite != http.SameSiteNoneMode {
		t.Errorf("默认（零值）http 请求: Cookie SameSite = %v, want None（Secure=true 联动 None，§4.4）", ck.SameSite)
	}
	ck = secureProbeTLS(t, startTLSAppListener(t, app), "")
	if !ck.Secure {
		t.Error("默认（零值）https 请求: Cookie Secure = false, want true（未配置 ≡ true，§3）")
	}
	if ck.SameSite != http.SameSiteNoneMode {
		t.Errorf("默认（零值）https 请求: Cookie SameSite = %v, want None（Secure=true 联动 None，§4.4）", ck.SameSite)
	}
}
