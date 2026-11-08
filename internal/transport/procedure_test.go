package transport

import "testing"

// 用例语义来源：接口文档 §7 行 1369「命名决定校验」（Update/Delete/
// Set/Create/Revoke 前缀 = 写接口，其余 = 读接口）+ 服务端
// isRPCWriteProcedure 行为（server/internal/connect/interceptors.go
// 行 199-215，只读转写，不含本包实现）。
func TestIsWriteProcedure(t *testing.T) {
	cases := []struct {
		procedure string
		want      bool
	}{
		// rpc 域现有唯一写方法。
		{"/api.rpc.v1.UserService/UpdateUserProfile", true},
		// 五个写前缀逐一命中（末段方法名前缀判定）。
		{"/api.rpc.v1.UserService/Update", true},
		{"/api.rpc.v1.UserService/Delete", true},
		{"/api.rpc.v1.UserService/Set", true},
		{"/api.rpc.v1.UserService/Create", true},
		{"/api.rpc.v1.UserService/Revoke", true},
		// rpc 域现有读方法。
		{"/api.rpc.v1.TokenService/DecodeSession", false},
		{"/api.rpc.v1.UserService/GetUserProfile", false},
		// 前缀在 package.Service 段不参与判定（只取末段方法名）。
		{"/api.rpc.v1.CreateService/GetProfile", false},
		// 大小写敏感，与服务端 strings.HasPrefix 一致。
		{"/api.rpc.v1.UserService/updateUserProfile", false},
		// 空串（拦截链外直调、无 Spec）→ 读路径。
		{"", false},
		{"/", false},
		{"/api.rpc.v1.UserService/", false},
	}
	for _, c := range cases {
		if got := IsWriteProcedure(c.procedure); got != c.want {
			t.Errorf("IsWriteProcedure(%q) = %v, want %v", c.procedure, got, c.want)
		}
	}
}
