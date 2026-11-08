// Package fiberadapter 提供 Authloft SDK 的 Fiber 框架适配：Middleware 把
// SDK-init §4 会话判定流程（网关采信 / 标准模式 / renewedToken 原渠道传播 /
// fail-open）接入 fiber v3 请求链，与 gin adapter、fiber v2 adapter
// 语义同构。
//
// 与 fiber v2 的唯一 API 差异（review/fiber-v3-plan.md §2.1）：
//   - handler 签名 *fiber.Ctx → fiber.Ctx（v3 中 Ctx 是接口）；
//   - 请求级 context 桥 c.UserContext() → c.Context()；
//   - fasthttp 入口 c.Context() → c.RequestCtx()。
package fiberadapter

import (
	_ "github.com/authloft/sdk-go"

	"github.com/gofiber/fiber/v3"
)

// 编译期引用：让 fiber 与核心 module 的依赖真实进入本 module 的 go.mod / go.sum，
// 隔离只来自 module 边界（docs/SDK-init.md §6.1）。
var _ = fiber.Version
