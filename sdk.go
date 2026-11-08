// Package sdk 是 Authloft 统一用户中心的官方 Go SDK 核心。
//
// 封装层（SDK-init §7）：NewSDK 构造完整传输链——BaseURL scheme 决定
// 底层传输（http:// 明文 → h2c prior-knowledge；https:// → 标准传输
// ALPN 自动协商 H2，服务端口径
// 见后端架构 §3.1）→ internal/transport Signer（HMAC 五项签名 + 每请求
// 新 nonce，接口文档 §7）→ rpcv1connect 客户端（Connect 协议 + proto
// 编码，不暴露编码选项）。签名 / 错误归一 / 零自动重试均归封装层，
// 使用方零感知；rpc 域方法见 client.go。
package sdk

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/http2"

	rpcv1connect "github.com/authloft/sdk-go/gen/go/api/rpc/v1/rpcv1connect"
	"github.com/authloft/sdk-go/internal/transport"
)

// Config 可选字段的默认值（SDK-init §3 配置项表，逐字对齐）。
const (
	defaultGatewayPrefix = "X-Session-"
	defaultCtxKey        = "uid"
	defaultHeaderKey     = "X-Authloft-Token"
	defaultCookieName    = "al_session"

	// defaultRequestTimeout 是 SDK 自建传输的整体请求超时（连接 + 响应体
	// 读毕）。内部常量不进 Config（切片契约：Config 字段 = SDK-init §3
	// 九字段 + HTTPClient 注入口）；注入 HTTPClient 时本值不生效，超时
	// 归用户配置。
	defaultRequestTimeout = 10 * time.Second
)

// Config 是 SDK 配置：SDK-init §3 九字段 + HTTPClient 注入口。必填项缺失由
// NewSDK 构造期 fail-fast 拒绝。
type Config struct {
	// BaseURL 是 Authloft 服务基础地址（Connect 客户端以其拼 procedure
	// 路径 /api.rpc.v1.TokenService/DecodeSession 等），必填。
	//
	// 必须为纯 origin——不得带路径 / 查询 / 片段：签名 path 段取
	// req.URL.Path（即 Connect procedure），BaseURL 带路径前缀会使该段
	// 与服务端 Procedure 失配，NewSDK
	// 构造期校验拒绝（仅容忍无语义的尾斜杠，connect-go 生成客户端对
	// baseURL 做 TrimRight("/")）。
	//
	// scheme 决定底层传输：
	// http:// 明文 → h2c prior-knowledge（对应服务端未配 TLS 时同端口
	// HTTP/1.1 + H2C，后端架构 §3.1 行 247-248）；https:// → 标准传输
	// （ALPN 自动协商 H2）。
	BaseURL string

	// ClientID / ClientSecret 是管理后台手动创建的 SSO 客户端凭据
	// （需求 §4.4.4），参与 HMAC 五项签名（接口文档 §7）。必填。
	ClientID     string
	ClientSecret string

	// EnableGateway 是网关模式开关（SDK-init §4.1），默认 false。由
	// adapter 消费，封装层仅承载。
	EnableGateway bool

	// GatewayPrefix 是网关模式采信的响应头前缀，整体替换而非逐头指定
	// （SDK-init §3），默认 "X-Session-"。
	GatewayPrefix string

	// CtxKey 是有效会话时注入业务上下文的键名（SDK-init §3），默认
	// "uid"；只影响上下文键名，不涉契约。
	CtxKey string

	// HeaderKey 是令牌请求头键名（接口文档 §6 / §7.1），默认
	// "X-Authloft-Token"。
	HeaderKey string

	// CookieName 是令牌 Cookie 名（需求 §4.4.1），默认 "al_session"。
	CookieName string

	// CookieDomain 是 Cookie 回写的 Domain 属性（SDK-init §3 / §4.4）：
	// 空 = 按业务应用当前请求的 Host 自动推导根域名（多段取最后两段、
	// 不带前导点；推导与降级规则见 DeriveCookieDomain）；非空 = 强制
	// 使用、不推导（配置者自行负责合法性）。构造期不加校验——空值非
	// 错误，即默认走自动推导。
	CookieDomain string

	// CookieSecure 是 Cookie 回写 Secure 属性的三态开关（SDK-init §3 /
	// §4.4）：CookieSecureTrue 强制写 /
	// CookieSecureFalse 强制不写 / CookieSecureAuto 按业务应用当前请求
	// 协议逐请求自动推断（X-Forwarded-Proto 头优先、TLS 直连兜底，规则
	// 见 DeriveCookieSecure）。未配置（零值空串）经 NewSDK 归一为
	// CookieSecureTrue（≡ 默认 "true"）；非法值构造期 fail-fast。
	CookieSecure CookieSecureMode

	// HTTPClient 可选注入自定义 HTTP 客户端。nil = SDK 按 BaseURL
	// scheme 自建传输（http:// → h2c prior-knowledge，https:// → 标准
	// ALPN）；非 nil = 直接采用，不覆盖其传输 / 超时等配置，SDK 仅在其
	// Transport 外包 HMAC 签名器（浅拷贝替换 Transport 字段，不动调用
	// 方传入的 *http.Client 本体）。
	HTTPClient *http.Client
}

// SDK 是 rpc 域（TokenService / UserService）的封装层 client。构造见
// NewSDK；rpc 域方法见 client.go。
type SDK struct {
	cfg    Config
	tokens rpcv1connect.TokenServiceClient
	users  rpcv1connect.UserServiceClient
}

// NewSDK 校验配置、填充默认值并装配传输链：
//
//	底层传输（BaseURL scheme 决定 h2c / ALPN，或用户注入的 HTTPClient）
//	  → transport.Signer（HMAC 五项签名 + 每请求新 nonce）
//	  → rpcv1connect.NewTokenServiceClient / NewUserServiceClient
//
// 必填缺失（BaseURL / ClientID / ClientSecret）与 BaseURL 非纯 origin
// 均构造期 fail-fast 拒绝（带路径会使签名 path 段与服务端 Procedure
// 失配，请求必被服务端拒签）。
func NewSDK(cfg Config) (*SDK, error) {
	if cfg.BaseURL == "" {
		return nil, errors.New("authloft/sdk-go: BaseURL is required")
	}
	if cfg.ClientID == "" {
		return nil, errors.New("authloft/sdk-go: ClientID is required")
	}
	if cfg.ClientSecret == "" {
		return nil, errors.New("authloft/sdk-go: ClientSecret is required")
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("authloft/sdk-go: parse BaseURL %q: %w", cfg.BaseURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("authloft/sdk-go: BaseURL scheme must be http or https (http = h2c prior-knowledge, https = ALPN), got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("authloft/sdk-go: BaseURL must contain a host, got %q", cfg.BaseURL)
	}
	// 纯 origin 约束：签名 path 段 =
	// req.URL.Path = Connect procedure，BaseURL 带路径前缀会与服务端
	// Procedure 失配；查询 / 片段同样会使 URL 拼接失真。仅容忍尾斜杠。
	if strings.TrimSuffix(u.Path, "/") != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("authloft/sdk-go: BaseURL must be a pure origin without path/query/fragment (the signed path segment is the Connect procedure), got %q", cfg.BaseURL)
	}

	if cfg.GatewayPrefix == "" {
		cfg.GatewayPrefix = defaultGatewayPrefix
	}
	if cfg.CtxKey == "" {
		cfg.CtxKey = defaultCtxKey
	}
	if cfg.HeaderKey == "" {
		cfg.HeaderKey = defaultHeaderKey
	}
	if cfg.CookieName == "" {
		cfg.CookieName = defaultCookieName
	}
	// CookieSecure 三态校验（SDK-init §3 / §4.4）：空串归一为默认
	// "true"；非法值（拼错形态）构造期 fail-fast——自定义类型 +
	// 常量的意义即在此（裸 string 只能运行期静默落入错误分支）。
	switch cfg.CookieSecure {
	case "":
		cfg.CookieSecure = CookieSecureTrue // 未配置（零值空串）≡ "true"（§3）。
	case CookieSecureTrue, CookieSecureFalse, CookieSecureAuto:
		// 合法三态（§4.4 三态表）。
	default:
		return nil, fmt.Errorf("authloft/sdk-go: CookieSecure must be one of %q, %q or %q (unconfigured empty value = %q), got %q",
			CookieSecureTrue, CookieSecureFalse, CookieSecureAuto, CookieSecureTrue, string(cfg.CookieSecure))
	}

	var httpClient *http.Client
	if cfg.HTTPClient != nil {
		// 注入路径：直接采用用户客户端，不覆盖其传输 / 超时 / Jar 等
		// 配置；浅拷贝后仅替换 Transport 为 Signer(用户 Transport)。
		// 用户 Transport 为 nil 时 Signer 落 http.DefaultTransport
		// （transport.NewSigner 语义）。
		c := *cfg.HTTPClient
		c.Transport = transport.NewSigner(cfg.HTTPClient.Transport, cfg.ClientID, cfg.ClientSecret, nil)
		httpClient = &c
	} else {
		httpClient = &http.Client{
			Timeout: defaultRequestTimeout,
			Transport: transport.NewSigner(
				newBaseTransport(u.Scheme), cfg.ClientID, cfg.ClientSecret, nil),
		}
	}
	return &SDK{
		cfg:    cfg,
		tokens: rpcv1connect.NewTokenServiceClient(httpClient, u.String()),
		users:  rpcv1connect.NewUserServiceClient(httpClient, u.String()),
	}, nil
}

// newBaseTransport 按 BaseURL scheme 构造签名器之下的底层传输：仅
// NewSDK 自建路径使用；注入 HTTPClient 时不经本函数。
func newBaseTransport(scheme string) http.RoundTripper {
	if scheme == "https" {
		// 标准传输：ALPN 自动协商 H2（ForceAttemptHTTP2 为标准库默认，
		// 此处显式声明自文档化）；Clone 保留 DefaultTransport 的连接池
		// 与 TLS 握手超时等合理默认。
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.ForceAttemptHTTP2 = true
		return t
	}
	// http:// 明文 → h2c prior-knowledge：AllowHTTP 允许明文 HTTP/2，
	// DialTLSContext 做普通 TCP 拨号（不建 TLS）。h2 单连接多路复用是
	// http2.Transport 自带能力，不额外造连接池。
	return &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}
}

// Config 返回填充默认值后的配置副本。adapter 经此消费
// EnableGateway / GatewayPrefix / CtxKey / HeaderKey / CookieName /
// CookieDomain / CookieSecure（SDK-init §4.3 伪代码的 sdk.cfg.*）。
func (s *SDK) Config() Config {
	return s.cfg
}
