package transport

import "strings"

// writeMethodPrefixes 写接口方法名前缀集合（接口文档 §7 行 1369「命名
// 决定校验」；语义来源：server/internal/connect/interceptors.go 的
// rpcWriteMethodPrefixes——集中定义以便将来显式扩展前缀集合）。
var writeMethodPrefixes = []string{"Update", "Delete", "Set", "Create", "Revoke"}

// IsWriteProcedure 按 Connect procedure（形如 /api.rpc.v1.UserService/
// UpdateUserProfile，即服务端 req.Spec().Procedure / 本包 req.URL.Path）
// 判定写接口：取末段方法名（package.Service 段不参与判定），前缀命中
// 即写；procedure 为空串或方法名为空 → 读路径。与服务端
// isRPCWriteProcedure 同构（大小写敏感）。
//
// 重试硬保障（SDK-init §7 行 160）：读接口服务端不去重、幂等可安全重试；
// 写接口服务端做 nonce 去重（TTL 30s）→ 禁自动重试。后续任何重试策略
// 必须先经本函数判定，写前缀永不自动重试。
func IsWriteProcedure(procedure string) bool {
	method := procedure
	if i := strings.LastIndex(procedure, "/"); i >= 0 {
		method = procedure[i+1:]
	}
	for _, prefix := range writeMethodPrefixes {
		if strings.HasPrefix(method, prefix) {
			return true
		}
	}
	return false
}
