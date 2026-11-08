package ginadapter

import (
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/authloft/sdk-go"
)

// Middleware 返回挂载到 gin 引擎的 Authloft 会话中间件（SDK-init §4
// 运行时流程，逐行对照 §4.3 伪代码）。
//
// 网关模式（§4.1，Config.EnableGateway）：请求携带 <GatewayPrefix>Status
// 头（默认 X-Session-Status）即视为已过可信网关，直接采信网关结果、不再
// 回源 RPC——值为 valid → 以 <GatewayPrefix>ID 头的值（payload.id = 用户
// ID，经 strconv.ParseInt 还原为 int64 注入，与标准模式同型；非数字 /
// 缺失 → 匿名不注入）注入 CtxKey；非 valid → 不注入、匿名放行；头不存在
// → 落回标准模式（该请求未过网关）。EnableGateway=false 时完全不读网关头。
//
// 标准模式（§4.2）：令牌取值优先级 HeaderKey 请求头（默认
// X-Authloft-Token）→ CookieName Cookie（默认 al_session），并记录取值
// 来源；两处皆空 → 匿名放行（不调 RPC）；否则调 SDK.DecodeSession 回源
// （签名 / 超时 / 错误归一均由封装层负责）。会话有效 → 注入 uid
// （SessionResponse.Id，int64 原生值，业务侧 c.Get 后断言 int64）；
// renewedToken 非空 → 原渠道覆盖传播（接口文档 §7.1「按原渠道落盘」）：
// 来自请求头 → 写同名响应头，来自 Cookie → Set-Cookie（五属性与 Domain
// 口径 = SDK-init §4.4 定稿，见 propagateRenewed）。
//
// 失败语义 fail-open（§5.1）：会话无效（HTTP 401，经 sdk 包 FromError 归一
// 后 Classify==Invalid）与调用失败（网络失败 / 5xx / 429，Classify==
// CallFailed）均匿名放行、不写任何响应头（不重签、不写存储）；调用失败
// 额外记录错误日志（§5.1），401 属常规匿名流量不记。fail-closed 严格模式
// 本期不做（SDK-init §5.1 统一 fail-open：网关模式与标准模式一致，
// 调用失败一律匿名放行、不阻断业务请求，见 §9 汇总条目 11）。
func Middleware(s *sdk.SDK) gin.HandlerFunc {
	cfg := s.Config()
	return func(c *gin.Context) {
		// 网关判定先于标准模式（SDK-init §4.3）。
		if cfg.EnableGateway {
			if status := c.GetHeader(cfg.GatewayPrefix + "Status"); status != "" {
				if status == "valid" {
					// <前缀>ID = payload.id = 用户 ID（§4.1，int64）。网关头是
					// payload 的 HTTP 字符串形态，注入还原 Go 原生值（与标准模式 res.Id
					// 同型）；非数字 / 缺失 → 匿名不注入。
					if uid, perr := strconv.ParseInt(c.GetHeader(cfg.GatewayPrefix+"ID"), 10, 64); perr == nil {
						c.Set(cfg.CtxKey, uid)
					}
				}
				c.Next()
				return
			}
		}

		token, fromHeader := extractToken(c, cfg)
		if token == "" {
			c.Next() // 两处皆空：匿名放行，不调 RPC（§4.2 步骤 1）。
			return
		}

		res, err := s.DecodeSession(c.Request.Context(), token)
		if err != nil || res == nil {
			// fail-open（§5.1）：无效与调用失败均匿名放行、不写任何响应头；
			// 调用失败记录错误日志，401（Invalid）为常规匿名流量不记。
			if sdk.Classify(err) == sdk.CallFailed {
				log.Printf("ginadapter: %s %s: DecodeSession 调用失败，fail-open 匿名放行: %v",
					c.Request.Method, c.Request.URL.Path, err)
			}
			c.Next()
			return
		}

		if res.RenewedToken != "" {
			propagateRenewed(c, cfg, fromHeader, res.RenewedToken, res.GetExp())
		}
		c.Set(cfg.CtxKey, res.Id)
		c.Next()
	}
}

// extractToken 按 SDK-init §4.2 步骤 1 取令牌：优先级 HeaderKey 请求头 →
// CookieName Cookie（与接口文档 §6 优先级一致）；返回令牌与取值来源
// （后者是 renewedToken 原渠道覆盖传播的依据）。
func extractToken(c *gin.Context, cfg sdk.Config) (token string, fromHeader bool) {
	if token := c.GetHeader(cfg.HeaderKey); token != "" {
		return token, true
	}
	token, _ = c.Cookie(cfg.CookieName)
	return token, false
}

// propagateRenewed 做 renewedToken 的原渠道覆盖传播（SDK-init §4.2 步骤 3）：
// 令牌来自请求头 → 写同名响应头；来自 Cookie → Set-Cookie（五属性与
// Domain 口径 = SDK-init §4.4 定稿）。不经 gin.Context.SetCookie——它对值
// 做 url.QueryEscape，违背「业务侧对令牌始终不透明，只作串替换」（§4.2
// 步骤 3）。
//
// 五属性逐项（§4.4 属性表）：HttpOnly=true、Path=/、Secure 由
// CookieSecure 三态控制（默认 true 强制写；false 强制不写；auto 按
// 业务应用当前请求协议逐请求推断——X-Forwarded-Proto 头优先、TLS 直连
// 兜底，见 sdk.DeriveCookieSecure）、SameSite 随 Secure 联动（2026-11-06
// 定稿，取代恒 Lax 口径：Secure=true 含 auto 推断 https → None、
// Secure=false 含 auto 推断明文 → Lax，两分支均显式取值不省略）、
// Max-Age=exp−now
//（会话剩余寿命秒，与服务端续期滚动对齐）。exp 取自 DecodeSession 响应
//（SessionResponse.Exp，服务端重签后已刷新）。
//
// Domain 三分支（§4.4）：CookieDomain 非空 → 强制使用不推导；空 → 按
// 业务应用当前请求 Host（c.Request.Host，可能带端口，推导函数内剥）取
// 最后两段；推导为空（IP / localhost / 单段主机名）→ 不设 Domain，
// 降级 host-only Cookie。
func propagateRenewed(c *gin.Context, cfg sdk.Config, fromHeader bool, renewed string, exp int64) {
	if fromHeader {
		c.Header(cfg.HeaderKey, renewed)
		return
	}
	ck := &http.Cookie{
		Name:     cfg.CookieName,
		Value:    renewed,
		Path:     "/",
		HttpOnly: true,
	}
	// Secure 三态（§4.4）：true 强制写（默认）/
	// false 强制不写 / auto 按业务应用当前请求协议逐请求推断。推断来源是
	// 业务应用请求协议而非 BaseURL scheme——Cookie 随浏览器 ↔ 业务应用
	// 通道传输，与 SDK ↔ Authloft 通道协议无关（§4.4「推断来源」段）。
	switch cfg.CookieSecure {
	case sdk.CookieSecureFalse:
		ck.Secure = false
	case sdk.CookieSecureAuto:
		ck.Secure = sdk.DeriveCookieSecure(
			c.GetHeader("X-Forwarded-Proto"), c.Request.TLS != nil)
	default: // CookieSecureTrue（NewSDK 归一后的默认）。
		ck.Secure = true
	}
	// SameSite 随 Secure 联动（§4.4 属性表，2026-11-06 定稿，取代
	// 恒 Lax 口径）：Secure=true（含 auto 推断为 https）→ None（None 须配
	// Secure，无 Secure 的 None 被浏览器拒收）；Secure=false（含 auto 推断
	// 为明文）→ Lax 兜底（明文通道 None 不可用，允许顶级导航 GET 携带会话、
	// 阻断跨站 POST）；两分支均显式取值不省略，auto 分支由
	// DeriveCookieSecure 结果自然联动。
	if ck.Secure {
		ck.SameSite = http.SameSiteNoneMode
	} else {
		ck.SameSite = http.SameSiteLaxMode
	}
	if remaining := exp - time.Now().Unix(); remaining > 0 {
		ck.MaxAge = int(remaining)
	} else {
		// 会话剩余寿命 ≤ 0（exp 已过期 / 时钟偏移异常形态）：按 §4.4
		// Max-Age 字面语义写删除型 Cookie——net/http 对 MaxAge=0 不输出
		// Max-Age 属性（退化成会话 Cookie），故取 -1 使其序列化为
		// Max-Age=0（RFC 6265 删除语义）。
		ck.MaxAge = -1
	}
	if cfg.CookieDomain != "" {
		ck.Domain = cfg.CookieDomain // 非空 → 强制使用，不推导（§4.4）。
	} else if d := sdk.DeriveCookieDomain(c.Request.Host); d != "" {
		ck.Domain = d // 自动推导：最后两段、不带前导点（§4.4）。
	} // 推导为空 → 不设 Domain（host-only，§4.4 降级）。
	http.SetCookie(c.Writer, ck)
}
