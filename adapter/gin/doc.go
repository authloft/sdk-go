// Package ginadapter 提供 Authloft SDK 的 Gin 框架适配：Middleware 返回
// 挂载到 gin 引擎的会话中间件（SDK-init §4 运行时流程：网关模式采信 /
// 标准模式回源解码 / renewedToken 原渠道覆盖传播 / fail-open 失败语义）。
package ginadapter
