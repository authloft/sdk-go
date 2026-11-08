package sdk

import "testing"

// TestDeriveCookieSecure 表测 §4.4 auto 推断规则：X-Forwarded-Proto 头
// 优先（逗号取首值、忽略大小写、http 及其他任意值不写）、头缺失看请求
// 自身 TLS、无头无 TLS 兜底不写。
func TestDeriveCookieSecure(t *testing.T) {
	cases := []struct {
		name string
		xfp  string
		tls  bool
		want bool
	}{
		{"头 https 明文请求 → 写", "https", false, true},
		{"头 HTTPS 大小写不敏感 → 写", "HTTPS", false, true},
		{"头 http + TLS 直连 → 头优先不写", "http", true, false},
		{"头其他值（grpc）+ TLS → 不写", "grpc", true, false},
		{"头逗号列表取首值 https → 写", "https,http", false, true},
		{"头逗号列表取首值 http → 不写", "http,https", false, false},
		{"头首值带空白 → 写", " https , http", false, true},
		{"无头 TLS 直连 → 写", "", true, true},
		{"无头无 TLS（兜底）→ 不写", "", false, false},
	}
	for _, tc := range cases {
		if got := DeriveCookieSecure(tc.xfp, tc.tls); got != tc.want {
			t.Errorf("%s: DeriveCookieSecure(%q, %v) = %v, want %v",
				tc.name, tc.xfp, tc.tls, got, tc.want)
		}
	}
}
