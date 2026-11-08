package sdk

import "strings"

// CookieSecureMode 是 Config.CookieSecure 的取值类型（SDK-init §3 / §4.4）：
// 自定义字符串类型而非裸 string——拼错值
//（如 "ture"）在 NewSDK 构造期即 fail-fast 检出，而非运行期静默落入
// 错误分支。
type CookieSecureMode string

// CookieSecure 三态常量（SDK-init §4.4 三态表）。未配置（零值空串）经
// NewSDK 归一为 CookieSecureTrue（≡ 默认 "true"）。
const (
	// CookieSecureTrue 强制写 Secure 属性（默认）。提示（仅此分支）：
	// 明文 HTTP 环境下浏览器不会保存 Secure Cookie，选此取值须保证
	// 浏览器 ↔ 业务应用通道为 TLS。
	CookieSecureTrue CookieSecureMode = "true"
	// CookieSecureFalse 强制不写 Secure 属性（属性整体缺省）。
	CookieSecureFalse CookieSecureMode = "false"
	// CookieSecureAuto 按业务应用当前请求协议逐请求自动推断，规则与
	// 兜底见 DeriveCookieSecure。
	CookieSecureAuto CookieSecureMode = "auto"
)

// DeriveCookieSecure 实现 SDK-init §4.4 的 auto 推断规则（写死，两
// adapter 同构共用；推断来源是业务应用请求协议而非 BaseURL scheme）：
//
//  1. X-Forwarded-Proto 头存在 → 取逗号分隔首个值、忽略大小写判定：
//     https → 写 Secure；http 及其他任意值 → 不写。
//  2. 头不存在 → 看请求自身 TLS：TLS 直连 → 写；无 TLS → 不写（兜底
//     ——该形态即明文直连（本地 / 内网调试主场景），写 Secure 会被
//     浏览器拒收、续期断链；反代漏传头属部署缺陷，应修反代补传头）。
//  3. 头优先于 TLS 判定：反代场景 TLS 终止在反代、应用侧收到明文 +
//     头，头是该场景唯一可靠来源；头与直连 TLS 并存且矛盾时以显式
//     头声明为准。
//
// 推断来源为何不是 BaseURL scheme：Cookie 落在业务应用自身域名上、随
// 浏览器 ↔ 业务应用通道传输；BaseURL 是 SDK ↔ Authloft 服务端通道，
// 两者协议可以不同（业务应用对外 HTTPS、内网回源明文 h2c），按
// BaseURL 推断会答错通道（§4.4）。
func DeriveCookieSecure(xForwardedProto string, requestTLS bool) bool {
	if xForwardedProto != "" {
		first := xForwardedProto
		if i := strings.IndexByte(first, ','); i >= 0 {
			first = first[:i]
		}
		return strings.EqualFold(strings.TrimSpace(first), "https")
	}
	return requestTLS
}
