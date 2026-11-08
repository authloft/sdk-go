package ginadapter

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/gin-gonic/gin"

	"github.com/authloft/sdk-go"
	rpcv1 "github.com/authloft/sdk-go/gen/go/api/rpc/v1"
	rpcv1connect "github.com/authloft/sdk-go/gen/go/api/rpc/v1/rpcv1connect"
)

// 测试常量：客户端凭据、令牌形态与假后端返回的会话载荷。
const (
	testClientID = "gin-adapter-test-client"
	testSecret   = "gin-adapter-test-secret"

	validToken   = "session-token-abc"
	invalidToken = "expired-token" // 假后端对该值回 401 unauthenticated
	renewedToken = "renewed-abc"
	decodedUID   = int64(10086)
)

// fakeTokenService 是 TokenService 测试服务端（模拟手法沿用核心包
// client_test.go）：validToken → 固定 SessionResponse（含 renewed_token）；
// invalidToken → 401（接口文档 §7.1 会话无效形态）；calls 计数到达次数
// （网关模式不回源 / 无 token 不调 RPC 的断言依据）；exp 是签发会话的过期
// 时间（Unix 秒），0 = 默认 now+3600——Set-Cookie 的 Max-Age=exp−now 断言
// （SDK-init §4.4）以它为基准，可写为过去时间制造「exp 已过期」形态。
type fakeTokenService struct {
	rpcv1connect.UnimplementedTokenServiceHandler
	calls atomic.Int32
	exp   int64
}

func (f *fakeTokenService) DecodeSession(_ context.Context, req *connect.Request[rpcv1.DecodeSessionRequest]) (*connect.Response[rpcv1.SessionResponse], error) {
	f.calls.Add(1)
	if req.Msg.SessionToken == invalidToken {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("session token 无效"))
	}
	exp := f.exp
	if exp == 0 {
		exp = time.Now().Add(time.Hour).Unix()
	}
	return connect.NewResponse(&rpcv1.SessionResponse{
		Id:           decodedUID,
		Epoch:        3,
		Amr:          []string{"pwd"},
		Sid:          "sid-test",
		RenewedToken: renewedToken,
		Exp:          exp,
	}), nil
}

// startTestServer 起 Go 1.26 原生 h2c 测试服务端（同端口 HTTP/1.1 + H2C，
// 与后端架构 §3.1 行 247-248 服务端口径一致），手法与核心包 client_test.go
// 相同：SDK 以 http:// BaseURL 打通即走 h2c prior-knowledge 通路。
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

// newTestSetup 起假后端 + 构造指向它的真实 *sdk.SDK + 挂载 Middleware 的
// gin 引擎。业务 handler（/probe）把 CtxKey 注入结果按 Go 类型回显，供
// 断言 uid 的值与类型；响应头由 httptest.ResponseRecorder 原样保留。
func newTestSetup(t *testing.T, cfg sdk.Config) (*gin.Engine, *fakeTokenService) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	svc := &fakeTokenService{}
	ts := startTestServer(t, svc)
	cfg.BaseURL = ts.URL
	cfg.ClientID = testClientID
	cfg.ClientSecret = testSecret
	s, err := sdk.NewSDK(cfg)
	if err != nil {
		t.Fatalf("NewSDK: %v", err)
	}
	probeCfg := s.Config()
	r := gin.New()
	r.Use(Middleware(s))
	r.GET("/probe", func(c *gin.Context) {
		v, ok := c.Get(probeCfg.CtxKey)
		if !ok {
			c.String(http.StatusOK, "anonymous")
			return
		}
		switch uid := v.(type) {
		case int64:
			c.String(http.StatusOK, "int64:%d", uid)
		case string:
			c.String(http.StatusOK, "string:%s", uid)
		default:
			c.String(http.StatusOK, "unexpected:%T", v)
		}
	})
	return r, svc
}

// probe 发起一次穿透中间件的请求：headers 进请求头，cookies 进 Cookie。
func probe(t *testing.T, r *gin.Engine, headers map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// findSetCookie 查找指定名字的 Set-Cookie 并返回完整值
// （name=value; Path=/; HttpOnly 形态），找不到返回空串。
func findSetCookie(w *httptest.ResponseRecorder, name string) string {
	for _, sc := range w.Header().Values("Set-Cookie") {
		if strings.HasPrefix(sc, name+"=") {
			return sc
		}
	}
	return ""
}

// --- 网关模式（SDK-init §4.1）---

// TestGatewayValid：Status=valid → 采信网关注入 <前缀>ID 头的值
// （strconv.ParseInt 还原为 int64，与标准模式 res.Id 同型），
// 不回源 RPC（网关模式存在的意义：省去每请求一次 DecodeSession）。
func TestGatewayValid(t *testing.T) {
	r, svc := newTestSetup(t, sdk.Config{EnableGateway: true})
	w := probe(t, r, map[string]string{
		"X-Session-Status": "valid",
		"X-Session-ID":     "42",
	})
	if got := w.Body.String(); got != "int64:42" {
		t.Errorf("uid = %q, want int64:42（网关采信 <前缀>ID，还原 int64）", got)
	}
	if got := svc.calls.Load(); got != 0 {
		t.Errorf("DecodeSession 到达 %d 次, want 0（网关模式不回源）", got)
	}
	if sc := findSetCookie(w, "al_session"); sc != "" {
		t.Errorf("意外出现 Set-Cookie: %q（网关采信不回源，无 renewedToken 可传播，§4.1 / §9 条 15）", sc)
	}
}

// TestGatewayValidMalformedIDAnonymous：Status=valid 但 <前缀>ID 头非数字
// 或缺失 → 匿名不注入、放行，不回源（网关头是 payload 的 HTTP 字符串
// 形态，注入必须还原 Go 原生 int64；无法还原即不注入）。
func TestGatewayValidMalformedIDAnonymous(t *testing.T) {
	r, svc := newTestSetup(t, sdk.Config{EnableGateway: true})
	for name, headers := range map[string]map[string]string{
		"非数字": {"X-Session-Status": "valid", "X-Session-ID": "not-a-number"},
		"缺失":  {"X-Session-Status": "valid"},
	} {
		w := probe(t, r, headers)
		if got := w.Body.String(); got != "anonymous" {
			t.Errorf("%s: uid = %q, want anonymous（valid 但 ID 无法还原 int64 → 不注入）", name, got)
		}
		if sc := findSetCookie(w, "al_session"); sc != "" {
			t.Errorf("意外出现 Set-Cookie: %q（网关采信不回源，无 renewedToken 可传播，§4.1 / §9 条 15）", sc)
		}
	}
	if got := svc.calls.Load(); got != 0 {
		t.Errorf("DecodeSession 到达 %d 次, want 0（采信网关结果，不回源）", got)
	}
}

// TestGatewayNonValid：Status 非 valid → 不注入、匿名放行，不回源；即使
// 请求另带有效令牌也不再回源（网关判定优先，直接采信网关结果）。
func TestGatewayNonValid(t *testing.T) {
	r, svc := newTestSetup(t, sdk.Config{EnableGateway: true})
	for _, status := range []string{"invalid", "expired"} {
		w := probe(t, r, map[string]string{"X-Session-Status": status})
		if got := w.Body.String(); got != "anonymous" {
			t.Errorf("status=%q: uid = %q, want anonymous（非 valid 不注入）", status, got)
		}
		if sc := findSetCookie(w, "al_session"); sc != "" {
			t.Errorf("status=%q: 意外出现 Set-Cookie: %q（网关采信路径不回写 Cookie，§4.1 / §9 条 15）", status, sc)
		}
	}
	// 带 Cookie 令牌 + 非 valid 网关头：网关判定即终局，不回源、无
	// renewedToken 可传播 → 即使 Cookie 渠道也不产生 Set-Cookie。
	w := probe(t, r, map[string]string{"X-Session-Status": "invalid"},
		&http.Cookie{Name: "al_session", Value: validToken})
	if got := w.Body.String(); got != "anonymous" {
		t.Errorf("uid = %q, want anonymous（网关非 valid 优先于令牌回源）", got)
	}
	if sc := findSetCookie(w, "al_session"); sc != "" {
		t.Errorf("意外出现 Set-Cookie: %q（网关采信路径不回写 Cookie，§4.1 / §9 条 15）", sc)
	}
	if got := svc.calls.Load(); got != 0 {
		t.Errorf("DecodeSession 到达 %d 次, want 0（采信网关结果，不回源）", got)
	}
}

// TestGatewayHeaderMissingFallsBack：EnableGateway=true 但无 Status 头 →
// 该请求未过网关，落回标准模式（令牌回源解码）。
func TestGatewayHeaderMissingFallsBack(t *testing.T) {
	r, svc := newTestSetup(t, sdk.Config{EnableGateway: true})
	w := probe(t, r, map[string]string{"X-Authloft-Token": validToken})
	if got := w.Body.String(); got != "int64:10086" {
		t.Errorf("uid = %q, want int64:10086（回落标准模式）", got)
	}
	if got := svc.calls.Load(); got != 1 {
		t.Errorf("DecodeSession 到达 %d 次, want 1（标准模式回源）", got)
	}
}

// TestGatewayDisabledIgnoresGatewayHeaders：EnableGateway=false 时完全不读
// 网关头——Status=valid 也不采信，走标准模式（此处无令牌 → 匿名）。
func TestGatewayDisabledIgnoresGatewayHeaders(t *testing.T) {
	r, svc := newTestSetup(t, sdk.Config{}) // EnableGateway 默认 false
	w := probe(t, r, map[string]string{
		"X-Session-Status": "valid",
		"X-Session-ID":     "42",
	})
	if got := w.Body.String(); got != "anonymous" {
		t.Errorf("uid = %q, want anonymous（EnableGateway=false 不读网关头）", got)
	}
	if got := svc.calls.Load(); got != 0 {
		t.Errorf("DecodeSession 到达 %d 次, want 0", got)
	}
}

// --- 标准模式（SDK-init §4.2）---

// TestStandardValidHeaderToken：默认配置，令牌来自 X-Authloft-Token →
// 回源解码有效，注入 int64 uid；renewedToken 原渠道覆盖 → 同名响应头。
func TestStandardValidHeaderToken(t *testing.T) {
	r, svc := newTestSetup(t, sdk.Config{})
	w := probe(t, r, map[string]string{"X-Authloft-Token": validToken})
	if got := w.Body.String(); got != "int64:10086" {
		t.Errorf("uid = %q, want int64:10086（SessionResponse.Id 原生 int64）", got)
	}
	if got := svc.calls.Load(); got != 1 {
		t.Errorf("DecodeSession 到达 %d 次, want 1", got)
	}
	if got := w.Header().Get("X-Authloft-Token"); got != renewedToken {
		t.Errorf("响应头 X-Authloft-Token = %q, want %q（Header 来源 → 同名响应头）", got, renewedToken)
	}
	if sc := findSetCookie(w, "al_session"); sc != "" {
		t.Errorf("意外出现 Set-Cookie: %q（Header 来源不应写 Cookie）", sc)
	}
}

// TestStandardValidCookieToken：令牌来自 al_session Cookie → 注入 uid；
// renewedToken → Set-Cookie（值按串替换不转义；五属性逐项断言 =
// SDK-init §4.4 定稿：HttpOnly / Path=/ / Secure 默认 true（三态见
// TestCookieSecure*） / SameSite 随 Secure 联动（默认 → None，联动
// 分支见 TestCookieSecure*） / Max-Age=exp−now）。httptest 请求
// Host 默认 example.com（文档化行为）→
// 推导 Domain=example.com；Domain 三分支见 TestCookieDomain*，Max-Age
// 过期形态见 TestCookieMaxAgeExpiredDeletes。
func TestStandardValidCookieToken(t *testing.T) {
	r, _ := newTestSetup(t, sdk.Config{})
	w := probe(t, r, nil, &http.Cookie{Name: "al_session", Value: validToken})
	if got := w.Body.String(); got != "int64:10086" {
		t.Errorf("uid = %q, want int64:10086", got)
	}
	sc := findSetCookie(w, "al_session")
	if sc == "" {
		t.Fatalf("缺少 Set-Cookie al_session（Cookie 来源 → Set-Cookie）")
	}
	if !strings.Contains(sc, "al_session="+renewedToken) {
		t.Errorf("Set-Cookie = %q, want 值 %q（串替换，不转义）", sc, renewedToken)
	}
	if got := w.Header().Get("X-Authloft-Token"); got != "" {
		t.Errorf("意外出现响应头 X-Authloft-Token = %q（Cookie 来源不应写响应头）", got)
	}

	// 五属性逐项（解析 Set-Cookie 头核对，§4.4 属性表）。
	cks := (&http.Response{Header: w.Header()}).Cookies()
	if len(cks) != 1 {
		t.Fatalf("Set-Cookie 解析出 %d 枚, want 1: %v", len(cks), w.Header().Values("Set-Cookie"))
	}
	ck := cks[0]
	if ck.Name != "al_session" || ck.Value != renewedToken {
		t.Errorf("Set-Cookie = %s=%s, want al_session=%s（原渠道覆盖）", ck.Name, ck.Value, renewedToken)
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
	// [3590, 3600] 容差。
	if ck.MaxAge < 3590 || ck.MaxAge > 3600 {
		t.Errorf("Cookie MaxAge = %d, want [3590, 3600]（Max-Age=exp−now 会话剩余寿命，§4.4）", ck.MaxAge)
	}
	// httptest.NewRequest 对相对路径 target 的 Host 默认 "example.com"
	//（文档化行为）→ 两段域名原样推导为根域名 example.com（§4.4）。
	if ck.Domain != "example.com" {
		t.Errorf("Cookie Domain = %q, want example.com（Host=example.com 自动推导）", ck.Domain)
	}
}

// TestStandardHeaderPriority：Header 与 Cookie 同时存在 → Header 优先
// （§4.2 步骤 1，与接口文档 §6 优先级一致），传播也按 Header 渠道。
func TestStandardHeaderPriority(t *testing.T) {
	r, _ := newTestSetup(t, sdk.Config{})
	w := probe(t, r,
		map[string]string{"X-Authloft-Token": validToken},
		&http.Cookie{Name: "al_session", Value: invalidToken},
	)
	if got := w.Body.String(); got != "int64:10086" {
		t.Errorf("uid = %q, want int64:10086（Header 优先于 Cookie）", got)
	}
	if got := w.Header().Get("X-Authloft-Token"); got != renewedToken {
		t.Errorf("响应头 X-Authloft-Token = %q, want %q（按取值来源传播）", got, renewedToken)
	}
	if sc := findSetCookie(w, "al_session"); sc != "" {
		t.Errorf("意外出现 Set-Cookie: %q（Header 来源不应写 Cookie）", sc)
	}
}

// --- 失败语义 fail-open（SDK-init §5.1）---

// TestStandardInvalidTokenAnonymous：401（Classify==Invalid）→ 匿名放行，
// 不写任何响应头（不重签、不写存储）。
func TestStandardInvalidTokenAnonymous(t *testing.T) {
	r, svc := newTestSetup(t, sdk.Config{})
	w := probe(t, r, map[string]string{"X-Authloft-Token": invalidToken})
	if got := w.Body.String(); got != "anonymous" {
		t.Errorf("uid = %q, want anonymous（401 无效 → 匿名放行）", got)
	}
	if got := w.Code; got != http.StatusOK {
		t.Errorf("status = %d, want 200（fail-open 放行）", got)
	}
	if got := svc.calls.Load(); got != 1 {
		t.Errorf("DecodeSession 到达 %d 次, want 1", got)
	}
	if hdr := w.Header().Get("X-Authloft-Token"); hdr != "" {
		t.Errorf("意外出现响应头 X-Authloft-Token = %q（无效不写任何响应头）", hdr)
	}
	if sc := findSetCookie(w, "al_session"); sc != "" {
		t.Errorf("意外出现 Set-Cookie: %q（无效不写任何响应头）", sc)
	}
}

// TestStandardCookieInvalidTokenAnonymous：Cookie 来源的 401 同样匿名、
// 无 Set-Cookie（不重签、不写存储）。
func TestStandardCookieInvalidTokenAnonymous(t *testing.T) {
	r, _ := newTestSetup(t, sdk.Config{})
	w := probe(t, r, nil, &http.Cookie{Name: "al_session", Value: invalidToken})
	if got := w.Body.String(); got != "anonymous" {
		t.Errorf("uid = %q, want anonymous", got)
	}
	if sc := findSetCookie(w, "al_session"); sc != "" {
		t.Errorf("意外出现 Set-Cookie: %q（无效不写任何响应头）", sc)
	}
}

// TestStandardCallFailedAnonymous：后端不可达（网络失败，Classify==
// CallFailed）→ 记录错误日志后同样匿名放行（§5.1），不写任何响应头。
func TestStandardCallFailedAnonymous(t *testing.T) {
	gin.SetMode(gin.TestMode)
	svc := &fakeTokenService{}
	ts := startTestServer(t, svc)
	ts.Close() // 模拟服务端不可达：h2c 拨号失败（连接拒绝）
	s, err := sdk.NewSDK(sdk.Config{BaseURL: ts.URL, ClientID: testClientID, ClientSecret: testSecret})
	if err != nil {
		t.Fatalf("NewSDK: %v", err)
	}
	r := gin.New()
	r.Use(Middleware(s))
	r.GET("/probe", func(c *gin.Context) {
		if _, ok := c.Get("uid"); !ok {
			c.String(http.StatusOK, "anonymous")
			return
		}
		c.String(http.StatusOK, "unexpected")
	})
	w := probe(t, r, map[string]string{"X-Authloft-Token": validToken})
	if got := w.Body.String(); got != "anonymous" {
		t.Errorf("uid = %q, want anonymous（调用失败 → fail-open 匿名放行）", got)
	}
	if got := w.Code; got != http.StatusOK {
		t.Errorf("status = %d, want 200（fail-open 放行）", got)
	}
	if hdr := w.Header().Get("X-Authloft-Token"); hdr != "" {
		t.Errorf("意外出现响应头 X-Authloft-Token = %q（调用失败不写任何响应头）", hdr)
	}
}

// TestStandardNoTokenAnonymous：Header 与 Cookie 两处皆空 → 匿名放行，
// 不调 RPC。
func TestStandardNoTokenAnonymous(t *testing.T) {
	r, svc := newTestSetup(t, sdk.Config{})
	w := probe(t, r, nil)
	if got := w.Body.String(); got != "anonymous" {
		t.Errorf("uid = %q, want anonymous（无令牌）", got)
	}
	if got := svc.calls.Load(); got != 0 {
		t.Errorf("DecodeSession 到达 %d 次, want 0（两处皆空不调 RPC）", got)
	}
}

// --- 自定义配置（SDK-init §3：GatewayPrefix 前缀整体替换等）---

// TestCustomConfigKeys：自定义 GatewayPrefix / CtxKey / HeaderKey /
// CookieName 全链路生效（网关注入键 + 令牌取值键 + renewed 传播键）。
func TestCustomConfigKeys(t *testing.T) {
	cfg := sdk.Config{
		EnableGateway: true,
		GatewayPrefix: "X-Auth-",
		CtxKey:        "user_id",
		HeaderKey:     "X-Api-Token",
		CookieName:    "sess",
	}
	r, svc := newTestSetup(t, cfg)

	// 网关模式：自定义前缀 + 自定义注入键（int64 还原）。
	w := probe(t, r, map[string]string{
		"X-Auth-Status": "valid",
		"X-Auth-ID":     "7",
	})
	if got := w.Body.String(); got != "int64:7" {
		t.Errorf("uid = %q, want int64:7（自定义前缀 / 注入键）", got)
	}
	if got := svc.calls.Load(); got != 0 {
		t.Errorf("DecodeSession 到达 %d 次, want 0", got)
	}

	// 标准模式 Header 来源：自定义取值键 + 同名响应头传播。
	w = probe(t, r, map[string]string{"X-Api-Token": validToken})
	if got := w.Body.String(); got != "int64:10086" {
		t.Errorf("uid = %q, want int64:10086（自定义 HeaderKey）", got)
	}
	if got := w.Header().Get("X-Api-Token"); got != renewedToken {
		t.Errorf("响应头 X-Api-Token = %q, want %q", got, renewedToken)
	}

	// 标准模式 Cookie 来源：自定义 Cookie 名 + Set-Cookie。
	w = probe(t, r, nil, &http.Cookie{Name: "sess", Value: validToken})
	if got := w.Body.String(); got != "int64:10086" {
		t.Errorf("uid = %q, want int64:10086（自定义 CookieName）", got)
	}
	sc := findSetCookie(w, "sess")
	if !strings.Contains(sc, "sess="+renewedToken) {
		t.Errorf("Set-Cookie = %q, want 含 sess=%q", sc, renewedToken)
	}
}

// --- Cookie 回写 Domain 三分支与 Max-Age 过期形态（SDK-init §4.4）---

// TestCookieDomainExplicit：CookieDomain 非空 → 强制使用、不推导——即使
// 请求 Host 本可推导出根域名，也原样写入配置值（§4.4 优先级 1，配置者
// 自行负责合法性）。
func TestCookieDomainExplicit(t *testing.T) {
	r, _ := newTestSetup(t, sdk.Config{CookieDomain: "sso.example.com"})
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Host = "a.b.example.com" // 可推导的 Host 存在也不推导
	req.AddCookie(&http.Cookie{Name: "al_session", Value: validToken})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	cks := (&http.Response{Header: w.Header()}).Cookies()
	if len(cks) != 1 {
		t.Fatalf("Set-Cookie 解析出 %d 枚, want 1: %v", len(cks), w.Header().Values("Set-Cookie"))
	}
	if got := cks[0].Domain; got != "sso.example.com" {
		t.Errorf("Cookie Domain = %q, want sso.example.com（非空强制使用不推导，§4.4）", got)
	}
}

// TestCookieDomainDerived：CookieDomain 空 → 按业务应用请求 Host（可能
// 带端口，先剥）取最后两段自动推导，不带前导点（§4.4 优先级 2）。
func TestCookieDomainDerived(t *testing.T) {
	r, _ := newTestSetup(t, sdk.Config{})
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Host = "a.b.example.com:8443"
	req.AddCookie(&http.Cookie{Name: "al_session", Value: validToken})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	cks := (&http.Response{Header: w.Header()}).Cookies()
	if len(cks) != 1 {
		t.Fatalf("Set-Cookie 解析出 %d 枚, want 1: %v", len(cks), w.Header().Values("Set-Cookie"))
	}
	got := cks[0].Domain
	if got != "example.com" {
		t.Errorf("Cookie Domain = %q, want example.com（最后两段，§4.4）", got)
	}
	if strings.HasPrefix(got, ".") {
		t.Errorf("Cookie Domain = %q, 不应带前导点（§4.4：RFC 6265 §5.2.3 规范写法）", got)
	}
}

// TestCookieDomainDegraded：请求 Host 为 IPv4 / IPv6 / localhost / 单段
// 主机名 → 推导为空 → 不设 Domain，降级 host-only Cookie（§4.4 优先级 3）。
func TestCookieDomainDegraded(t *testing.T) {
	r, _ := newTestSetup(t, sdk.Config{})
	for name, host := range map[string]string{
		"IPv4":      "192.168.1.10",
		"IPv6带端口":  "[::1]:8080",
		"localhost": "localhost",
		"单段主机名":   "intranet",
	} {
		req := httptest.NewRequest(http.MethodGet, "/probe", nil)
		req.Host = host
		req.AddCookie(&http.Cookie{Name: "al_session", Value: validToken})
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		cks := (&http.Response{Header: w.Header()}).Cookies()
		if len(cks) != 1 {
			t.Fatalf("%s(%q): Set-Cookie 解析出 %d 枚, want 1: %v", name, host, len(cks), w.Header().Values("Set-Cookie"))
		}
		if got := cks[0].Domain; got != "" {
			t.Errorf("%s(%q): Cookie Domain = %q, want 空（非域名形态降级 host-only，§4.4）", name, host, got)
		}
	}
}

// TestCookieMaxAgeExpiredDeletes：exp − now ≤ 0（会话已过期 / 时钟偏移
// 异常形态）→ 按字面语义写删除型 Cookie：gin 侧经 net/http 以 Max-Age=0
// 表达（RFC 6265 删除语义；与 fiber 侧过去 Expires 手法不同、语义一致）。
func TestCookieMaxAgeExpiredDeletes(t *testing.T) {
	r, svc := newTestSetup(t, sdk.Config{})
	svc.exp = time.Now().Add(-10 * time.Second).Unix() // 会话已过期
	w := probe(t, r, nil, &http.Cookie{Name: "al_session", Value: validToken})
	sc := findSetCookie(w, "al_session")
	if sc == "" {
		t.Fatalf("缺少 Set-Cookie al_session（exp 过期仍按原渠道回写，删除型）")
	}
	if !strings.Contains(sc, "Max-Age=0") {
		t.Errorf("Set-Cookie = %q, want 含 Max-Age=0（exp−now ≤ 0 → 删除型 Cookie，§4.4）", sc)
	}
}

// --- Cookie Secure 三态（SDK-init §4.4）---

// secureProbe 发起一次 Cookie 渠道请求（可指定 X-Forwarded-Proto 头与
// 请求自身 TLS 形态）并解析回写 Cookie（供 Secure / SameSite 断言）。
// gin 读 c.Request.TLS，测试直设 req.TLS 即可构造「TLS 直连」形态。
func secureProbe(t *testing.T, r *gin.Engine, xfp string, reqTLS bool) *http.Cookie {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	if reqTLS {
		req.TLS = &tls.ConnectionState{}
	}
	if xfp != "" {
		req.Header.Set("X-Forwarded-Proto", xfp)
	}
	req.AddCookie(&http.Cookie{Name: "al_session", Value: validToken})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	cks := (&http.Response{Header: w.Header()}).Cookies()
	if len(cks) != 1 {
		t.Fatalf("Set-Cookie 解析出 %d 枚, want 1: %v", len(cks), w.Header().Values("Set-Cookie"))
	}
	return cks[0]
}

// TestCookieSecureTrueForceWrites：「true」强制写——明文（http）与 TLS
//（https）请求两态均带 Secure；BaseURL 恒 http（h2c fake 后端）反证
// 不以 BaseURL scheme 参与 Secure 判定（§4.4 三态表 +「推断来源」段）。
// SameSite 随 Secure 联动（2026-11-06 定稿）：Secure=true → None。
func TestCookieSecureTrueForceWrites(t *testing.T) {
	r, _ := newTestSetup(t, sdk.Config{CookieSecure: sdk.CookieSecureTrue})
	for _, tc := range []struct {
		name   string
		reqTLS bool
		wantSS http.SameSite
	}{
		{"http 请求", false, http.SameSiteNoneMode},
		{"https 请求", true, http.SameSiteNoneMode},
	} {
		ck := secureProbe(t, r, "", tc.reqTLS)
		if !ck.Secure {
			t.Errorf("%s: Cookie Secure = false, want true（true 强制写，§4.4）", tc.name)
		}
		if ck.SameSite != tc.wantSS {
			t.Errorf("%s: Cookie SameSite = %v, want None（Secure=true 联动 None，§4.4）", tc.name, ck.SameSite)
		}
	}
}

// TestCookieSecureFalseNeverWrites：「false」强制不写——明文与 TLS 请求
// 两态均不带 Secure 属性（§4.4 三态表）。SameSite 随 Secure 联动
//（2026-11-06 定稿）：Secure=false → Lax。
func TestCookieSecureFalseNeverWrites(t *testing.T) {
	r, _ := newTestSetup(t, sdk.Config{CookieSecure: sdk.CookieSecureFalse})
	for _, tc := range []struct {
		name   string
		reqTLS bool
	}{
		{"http 请求", false},
		{"https 请求", true},
	} {
		ck := secureProbe(t, r, "", tc.reqTLS)
		if ck.Secure {
			t.Errorf("%s: Cookie Secure = true, want false（false 强制不写，§4.4）", tc.name)
		}
		if ck.SameSite != http.SameSiteLaxMode {
			t.Errorf("%s: Cookie SameSite = %v, want Lax（Secure=false 联动 Lax，§4.4）", tc.name, ck.SameSite)
		}
	}
}

// TestCookieSecureAutoInfersPerRequest：「auto」按业务应用当前请求协议
// 逐请求推断（§4.4 推断规则）：X-Forwarded-Proto 头存在 → 逗号首值、
// 忽略大小写（https 写 / http 及其他任意值不写）；头缺失看请求自身 TLS；
// 头优先于 TLS；无头无 TLS 兜底不写。BaseURL 恒 http——TLS 请求若被
// 误按 BaseURL 推断会得 false，反证推断来源是请求协议（§4.4）。
// SameSite 随 Secure 推断结果联动（2026-11-06 定稿）：推断 https →
// None、推断明文 → Lax。
func TestCookieSecureAutoInfersPerRequest(t *testing.T) {
	r, _ := newTestSetup(t, sdk.Config{CookieSecure: sdk.CookieSecureAuto})
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
		ck := secureProbe(t, r, tc.xfp, tc.tls)
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
	r, _ := newTestSetup(t, sdk.Config{}) // CookieSecure 零值空串
	for _, tc := range []struct {
		name   string
		reqTLS bool
	}{
		{"http 请求", false},
		{"https 请求", true},
	} {
		ck := secureProbe(t, r, "", tc.reqTLS)
		if !ck.Secure {
			t.Errorf("默认（零值）%s: Cookie Secure = false, want true（未配置 ≡ true，§3）", tc.name)
		}
		if ck.SameSite != http.SameSiteNoneMode {
			t.Errorf("默认（零值）%s: Cookie SameSite = %v, want None（Secure=true 联动 None，§4.4）", tc.name, ck.SameSite)
		}
	}
}
