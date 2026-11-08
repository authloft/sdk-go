// Package fiberadapter 提供 Authloft SDK 的 Fiber 框架适配：Middleware 把
// SDK-init §4 会话判定流程（网关采信 / 标准模式 / renewedToken 原渠道传播 /
// fail-open）接入 fiber v2 请求链，与 gin adapter 语义同构。
package fiberadapter

import (
	_ "github.com/authloft/sdk-go"

	"github.com/gofiber/fiber/v2"
)

// 编译期引用：让 fiber 与核心 module 的依赖真实进入本 module 的 go.mod / go.sum，
// 隔离只来自 module 边界（docs/SDK-init.md §6.1）。
var _ = fiber.Version
