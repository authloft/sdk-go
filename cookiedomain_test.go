package sdk

import "testing"

// TestDeriveCookieDomain 表测 §4.4 根域名推导：既定的六类输入 +
// IPv6 两形态 / 单段主机名 / 尾点 / 大小写等补充形态。
func TestDeriveCookieDomain(t *testing.T) {
	cases := []struct {
		name string
		host string
		want string
	}{
		// 既定的六类输入（§4.4；「CookieDomain 显式配置 →
		// 强制使用不推导」是 adapter 层的 Config 消费行为，见
		// adapter/{gin,fiber} 的 middleware 测试 Domain 三分支用例）。
		{"多段域名取最后两段", "a.b.example.com", "example.com"},
		{"两段域名原样", "example.com", "example.com"},
		{"localhost 降级", "localhost", ""},
		{"IPv4 字面量降级", "192.168.1.10", ""},
		{"带端口先剥再推导", "a.b.example.com:8443", "example.com"},
		// 补充形态（§4.4 降级清单与 Host 形态边界）。
		{"IPv6 裸字面量降级", "::1", ""},
		{"IPv6 括号带端口形态降级", "[::1]:8080", ""},
		{"IPv6 无端口括号形态降级", "[::1]", ""},
		{"IPv6 多段字面量降级", "fe80::1", ""},
		{"IPv6 带域内端口形态降级", "[2001:db8::1]:443", ""},
		{"单段主机名降级", "intranet", ""},
		{"IPv4 带端口降级", "192.168.1.10:8080", ""},
		{"空 Host 降级", "", ""},
		{"仅端口形态降级", ":8443", ""},
		{"尾点 FQDN 先剥再推导", "a.b.example.com.", "example.com"},
		{"大小写归一", "A.B.Example.COM", "example.com"},
		{"空段畸形形态降级", "a..b", ""},
	}
	for _, tc := range cases {
		if got := DeriveCookieDomain(tc.host); got != tc.want {
			t.Errorf("%s: DeriveCookieDomain(%q) = %q, want %q", tc.name, tc.host, got, tc.want)
		}
	}
}

// TestNewSDKCookieDomainPreserved：CookieDomain 显式配置 → 构造期原样
// 强制保留（不推导、不清洗；空值非错误即默认走自动推导，构造期不加
// 校验——SDK-init §3 / §4.4）。
func TestNewSDKCookieDomainPreserved(t *testing.T) {
	s := mustNewSDK(t, Config{
		BaseURL:      "http://authloft.internal:8080",
		ClientID:     "cid",
		ClientSecret: "sec",
		CookieDomain: "sso.example.com",
	})
	if got := s.Config().CookieDomain; got != "sso.example.com" {
		t.Errorf("CookieDomain = %q, want sso.example.com（非空强制保留，不推导）", got)
	}
}
