package sdk

import (
	"net"
	"strings"
)

// DeriveCookieDomain 依 SDK-init §4.4 从业务应用当前请求的 Host 推导
// Cookie 回写的 Domain 属性值：多段域名取最后两段（a.b.example.com →
// example.com），不带前导点（RFC 6265 §5.2.3：前导点解析时剥除，不带点
// 为规范写法）。
//
// host 允许携带端口（"a.b.example.com:8443"、"192.168.1.10:8080"、
// "[::1]:8080"）——先经 net.SplitHostPort 剥端口（IPv6 字面量带端口的
// 括号形态一并覆盖），剥不出端口（无端口）时原样使用。
//
// 降级（SDK-init §4.4）：推导来源为 IPv4 / IPv6 字面量 / localhost /
// 单段主机名（非域名形态）时返回空串——调用方据此不设 Domain 属性，
// 落 host-only Cookie（仅当前主机可见）。
//
// 已知取舍（SDK-init §4.4，既定策略）：不引入 public suffix
// list（公有后缀表），多段 TLD（如 x.co.uk）会按「最后两段」推出
// co.uk——接受该误差，不为精确 TLD 判定扩依赖（零新增依赖，§9 条 13）。
func DeriveCookieDomain(host string) string {
	// Host 头由框架透传，先归一空白与大小写（Cookie domain 属性惯例
	// 小写，RFC 6265 域匹配不区分大小写）。
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return ""
	}
	// 剥端口：net.SplitHostPort 覆盖 "host:port" 与 "[v6]:port" 两种
	// 形态；无端口时报错 → 原样进入后续判定。报错路径下若为无端口的
	// IPv6 括号形态（"[::1]"，SplitHostPort 对其报 missing port），
	// 剥括号后按 IP 字面量降级。
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else {
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	}
	// FQDN 常见尾点形态（"a.b.example.com."）先剥：不剥则最后一段为
	// 空，「最后两段」取值失真（RFC 6265 §5.1.2 canonicalization 同款
	// 处理）。
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return ""
	}
	// 非域名形态降级：IP 字面量（IPv4 / IPv6 一并覆盖）→ host-only。
	if net.ParseIP(host) != nil {
		return ""
	}
	// localhost 与单段主机名（无 "."，含 "[::1]" 剥括号失败残留等
	// 畸形形态）非域名形态 → host-only。
	if !strings.Contains(host, ".") {
		return ""
	}

	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return ""
	}
	// 最后两段任一为空（"a..b" 类空段形态，非正常域名）→ 降级
	// host-only，不产出畸形 Domain。
	if parts[len(parts)-1] == "" || parts[len(parts)-2] == "" {
		return ""
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}
