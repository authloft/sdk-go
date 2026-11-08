package fiberadapter

import (
	"log"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v3"

	"github.com/authloft/sdk-go"
)

const (
	// gatewayStatusValid 是网关头 <GatewayPrefix>Status 的「会话有效」取值
	//（SDK-init §4.1）。
	gatewayStatusValid = "valid"
)

// Middleware 返回 Authloft 会话中间件（SDK-init §4 全流程，与 gin adapter
// 语义逐条同构，仅框架 API 适配 fiber v3）：
//
//	① 网关模式（§4.1）：EnableGateway 且请求携带 <GatewayPrefix>Status 头
//	   → 直接采信网关结果、不回源 DecodeSession——Status=valid 注入
//	   <GatewayPrefix>ID（payload.id，用户 ID）；非 valid 匿名放行；无该头
//	   → 落回标准模式。EnableGateway=false 完全不读网关头。
//	② 标准模式（§4.2）：令牌取值 HeaderKey 请求头 → CookieName Cookie
//	   （记录取值来源），两空匿名放行；DecodeSession 有效 → 注入 uid；
//	   renewedToken 非空 → 原渠道覆盖（Header 来源 → 同名响应头；Cookie
//	   来源 → Set-Cookie，五属性与 Domain 口径 = SDK-init §4.4 定稿，见
//	   propagateRenewed）。
//	③ fail-open（§5.1）：401 无效与调用失败均匿名放行，不写任何响应头；
//	   调用失败记录错误日志，401（Invalid）为常规匿名流量不记。
//
// uid 经 c.Locals(cfg.CtxKey, …) 注入，int64 原生值（标准模式的
// SessionResponse.Id 与网关 payload.id 同为 int64 语义）。
//
// fiber v3 与 v2 的唯一 API 差异（review/fiber-v3-plan.md §2.1）：
//   - fiber.Handler 签名由 func(*fiber.Ctx) error 变为 func(fiber.Ctx) error
//     （Ctx 在 v3 是接口，见 ctx_interface_gen.go）；
//   - RPC 传值 context 由 c.UserContext() → c.Context()（v3 中 c.Context()
//     返回 context.Context，是应用注入请求级 context 的桥；语义等价）；
//   - fasthttp 入口由 c.Context() → c.RequestCtx()（v3 中 c.Context()
//     已改为 context.Context，*fasthttp.RequestCtx 经 c.RequestCtx() 取）。
func Middleware(s *sdk.SDK) fiber.Handler {
	cfg := s.Config()
	return func(c fiber.Ctx) error {
		// ① 网关模式：无 <GatewayPrefix>Status 头时落回标准模式。
		if cfg.EnableGateway {
			if status := c.Get(cfg.GatewayPrefix + "Status"); status != "" {
				if status == gatewayStatusValid {
					// <前缀>ID = payload.id = 用户 ID（§4.1）：payload 字段
					// 语义为 int64（SessionResponse.Id），网关头是其字符串
					// 形态，解析回 int64 原生值注入。Status=valid 而 ID 非
					// 数字 = 网关侧契约破坏，SDK-init 未覆盖——按本中间件
					// fail-open 精神匿名放行（不注入、不回源）。
					if id, err := strconv.ParseInt(c.Get(cfg.GatewayPrefix+"ID"), 10, 64); err == nil {
						c.Locals(cfg.CtxKey, id)
					}
				}
				return c.Next()
			}
		}

		// ② 标准模式。
		token, fromHeader := extractToken(c, cfg)
		if token == "" {
			return c.Next()
		}

		// context 传值用 c.Context()：fiber v3 中 c.Context() 返回
		// context.Context（v2 的 c.UserContext()），是应用经 SetUserContext
		// 注入的取消 / 截止信号桥，随之传播给 DecodeSession 的 Connect 调用。
		// 注意：v3 中 c.RequestCtx() 才是 *fasthttp.RequestCtx 入口（用于
		// TLSConnectionState 判定，见 propagateRenewed）。
		res, err := s.DecodeSession(c.Context(), token)
		if err != nil || res == nil {
			// ③ fail-open（§5.1）：401 无效与调用失败（网络 / 5xx / 429）
			// 均匿名放行，不注入 uid、不写任何响应头（不重签、不写存储）；
			// 调用失败记录错误日志，401（Invalid）为常规匿名流量不记。
			if sdk.Classify(err) == sdk.CallFailed {
				log.Printf("fiberadapter: %s %s: DecodeSession 调用失败，fail-open 匿名放行: %v",
					c.Method(), c.Path(), err)
			}
			return c.Next()
		}

		if res.RenewedToken != "" {
			propagateRenewed(c, cfg, fromHeader, res.RenewedToken, res.GetExp())
		}
		c.Locals(cfg.CtxKey, res.Id)
		return c.Next()
	}
}

// extractToken 按 §4.2 步骤 1 优先级提取令牌：HeaderKey 请求头 →
// CookieName Cookie；返回 (token, fromHeader)，fromHeader=true 表示令牌
// 来自 Header 渠道（renewedToken 按同一渠道回写）。
func extractToken(c fiber.Ctx, cfg sdk.Config) (token string, fromHeader bool) {
	if token = c.Get(cfg.HeaderKey); token != "" {
		return token, true
	}
	return c.Cookies(cfg.CookieName), false
}

// propagateRenewed 按 §4.2 步骤 3 原渠道覆盖传播 renewedToken：Header 来源
// → 写同名响应头；Cookie 来源 → Set-Cookie（五属性与 Domain 口径 =
// SDK-init §4.4 定稿，与 gin adapter 同构）。
//
// 五属性逐项（§4.4 属性表）：HttpOnly=true、Path=/、Secure 由
// CookieSecure 三态控制（默认 true 强制写；false 强制不写；auto 按
// 业务应用当前请求协议逐请求推断——X-Forwarded-Proto 头优先、TLS 直连
// 兜底，见 sdk.DeriveCookieSecure）、SameSite 随 Secure 联动（2026-11-06
// 定稿，取代恒 Lax 口径：Secure=true 含 auto 推断 https → None、
// Secure=false 含 auto 推断明文 → Lax，两分支均显式取值不省略）、
// Max-Age=exp−now
//（会话剩余寿命秒，与服务端续期滚动对齐；fiber.Cookie.MaxAge 单位为秒，
// 经 fasthttp 以 max-age=N 输出）。exp 取自 DecodeSession 响应
//（SessionResponse.Exp，服务端重签后已刷新）。
//
// Domain 三分支（§4.4）：CookieDomain 非空 → 强制使用不推导；空 → 按
// 业务应用当前请求 Host（c.Hostname()，反向代理场景下优先 X-Forwarded-Host
// ——即浏览器实际访问的域名，与 Cookie 可见域一致）取最后两段；推导为空
//（IP / localhost / 单段主机名）→ 不设 Domain，降级 host-only Cookie。
func propagateRenewed(c fiber.Ctx, cfg sdk.Config, fromHeader bool, renewed string, exp int64) {
	if fromHeader {
		c.Set(cfg.HeaderKey, renewed)
		return
	}
	ck := &fiber.Cookie{
		Name:     cfg.CookieName,
		Value:    renewed,
		Path:     "/",
		HTTPOnly: true,
	}
	// Secure 三态（§4.4）：true 强制写（默认）/
	// false 强制不写 / auto 按业务应用当前请求协议逐请求推断。推断来源是
	// 业务应用请求协议而非 BaseURL scheme——Cookie 随浏览器 ↔ 业务应用
	// 通道传输，与 SDK ↔ Authloft 通道协议无关（§4.4「推断来源」段）。
	// TLS 直连形态经 fasthttp 的 TLSConnectionState 判定（非 TLS 连接
	// 返回 nil）；fiber v3 中 c.RequestCtx() 才是 *fasthttp.RequestCtx
	// 入口（c.Context() 已变为 context.Context）。
	switch cfg.CookieSecure {
	case sdk.CookieSecureFalse:
		ck.Secure = false
	case sdk.CookieSecureAuto:
		ck.Secure = sdk.DeriveCookieSecure(
			c.Get("X-Forwarded-Proto"), c.RequestCtx().TLSConnectionState() != nil)
	default: // CookieSecureTrue（NewSDK 归一后的默认）。
		ck.Secure = true
	}
	// SameSite 随 Secure 联动（§4.4 属性表，2026-11-06 定稿，取代
	// 恒 Lax 口径）：Secure=true（含 auto 推断为 https）→ None（None 须配
	// Secure，无 Secure 的 None 被浏览器拒收）；Secure=false（含 auto 推断
	// 为明文）→ Lax 兜底（明文通道 None 不可用，允许顶级导航 GET 携带会话、
	// 阻断跨站 POST）；两分支均显式取值不省略，auto 分支由
	// DeriveCookieSecure 结果自然联动（与 gin adapter 同构）。
	if ck.Secure {
		ck.SameSite = fiber.CookieSameSiteNoneMode
	} else {
		ck.SameSite = fiber.CookieSameSiteLaxMode
	}
	if cfg.CookieDomain != "" {
		ck.Domain = cfg.CookieDomain // 非空 → 强制使用，不推导（§4.4）。
	} else if d := sdk.DeriveCookieDomain(c.Hostname()); d != "" {
		ck.Domain = d // 自动推导：最后两段、不带前导点（§4.4）。
	} // 推导为空 → 不设 Domain（host-only，§4.4 降级）。
	if remaining := exp - time.Now().Unix(); remaining > 0 {
		ck.MaxAge = int(remaining) // fiber.Cookie.MaxAge 单位秒。
	} else {
		// 会话剩余寿命 ≤ 0（exp 已过期 / 时钟偏移异常形态）→ 按字面
		// 语义写删除型 Cookie。fasthttp 仅在 MaxAge>0 时输出 max-age
		// 属性（<=0 均不写，无法像 gin 侧那样表达 Max-Age=0），删除
		// 语义以过去 Expires 表达——浏览器见过期时间即删除，与 gin
		// 侧 Max-Age=0 手法不同、语义一致（§4.4 自洽决定）。
		ck.Expires = time.Now().Add(-time.Hour)
	}
	c.Cookie(ck)
}
