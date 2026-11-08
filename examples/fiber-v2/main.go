// Authloft Go SDK · fiber 接入示例。
//
// 与 gin 示例（examples/gin）语义逐条同构，仅框架 API 换为 fiber v2：
// NewSDK 配置（凭据从环境变量读取，不硬编码）→ 一行挂 fiberadapter
// 中间件 → 业务 handler 取 uid（int64 断言）→ UserService 调用
// （GetUserProfile）。
//
// 前置与验证方式同 gin 示例；运行（PowerShell 形态）：
//
//	cd examples/fiber-v2   # 仓库根目录下
//	$env:AUTHLOFT_BASE_URL="http://127.0.0.1:8080"
//	$env:AUTHLOFT_CLIENT_ID="<占位：你的 ClientID>"
//	$env:AUTHLOFT_CLIENT_SECRET="<占位：你的 ClientSecret>"
//	$env:GOWORK="off"
//	go run .
//
// 自测（无需服务端，仅验证可编译）：$env:GOWORK="off"; go build ./...
//
// 验证会话（携带 Authloft 签发的令牌）：
//
//	curl -H "X-Authloft-Token: <令牌>" http://127.0.0.1:8082/me
package main

import (
	"errors"
	"log"
	"os"

	"github.com/gofiber/fiber/v2"

	"github.com/authloft/sdk-go"
	fiberadapter "github.com/authloft/sdk-go/adapter/fiber-v2"
)

func main() {
	// 配置说明同 gin 示例：必填三项从环境变量读取（占位值见文件头注释）；
	// BaseURL 须为纯 origin——http:// 明文自动走 h2c prior-knowledge，
	// https:// 走标准 ALPN；缺必填时 NewSDK 构造期报错。
	s, err := sdk.NewSDK(sdk.Config{
		BaseURL:      os.Getenv("AUTHLOFT_BASE_URL"),
		ClientID:     os.Getenv("AUTHLOFT_CLIENT_ID"),
		ClientSecret: os.Getenv("AUTHLOFT_CLIENT_SECRET"),
	})
	if err != nil {
		log.Fatalf("NewSDK: %v", err)
	}

	app := fiber.New()
	// 一行装配（与 gin 版语义逐条同构）：令牌提取（HeaderKey 头 →
	// CookieName Cookie）→ DecodeSession 回源 → 有效会话注入 uid
	// （c.Locals），renewedToken 按原渠道覆盖传播（头来源 → 同名响应头；
	// Cookie 来源 → Set-Cookie，五属性与 Domain 口径 = SDK-init §4.4，
	// 其余可选配置项说明同 gin 示例）。无令牌 / 会话无效 / 调用失败均
	// 匿名放行（fail-open，SDK-init §5.1）。
	app.Use(fiberadapter.Middleware(s))

	// 业务 handler：取当前用户 + UserService 直调。
	app.Get("/me", func(c *fiber.Ctx) error {
		// fiber 经 c.Locals 注入（对应 gin 的 c.Set）；uid 是 int64 原生
		// 值（标准模式 = SessionResponse.Id；网关模式 = <前缀>ID 头经
		// ParseInt 还原 int64）。匿名请求时 Locals 返回 nil，断言不成立
		// 走匿名分支。
		uid, ok := c.Locals("uid").(int64)
		if !ok {
			return c.JSON(fiber.Map{
				"uid":     nil,
				"message": "匿名请求：无令牌或会话无效（fail-open 放行）",
			})
		}

		// UserService 直调：GetUserProfile 是读接口（服务端对 nonce 不去
		// 重，可安全重试）；写接口 UpdateUserProfile（Update 前缀命中
		// 「命名决定校验」五前缀）服务端 nonce 去重 TTL 30s，SDK 禁自动
		// 重试，失败由调用方自行决定后续动作。
		// fiber 的 c.Context() 是 *fasthttp.RequestCtx（非标准 context），
		// 传给 Connect 调用须用 c.UserContext()——取消 / 截止信号随之传播。
		profile, err := s.GetUserProfile(c.UserContext(), uid)
		if err != nil {
			// 错误归一（sdk.FromError）后 *sdk.Error 携带 Connect 码、
			// X-Request-Id 与 ErrorInfo；三态判定 sdk.Classify(err)：
			// Valid / Invalid（401）/ CallFailed（网络失败 / 5xx / 429）。
			var aerr *sdk.Error
			if errors.As(err, &aerr) {
				log.Printf("GetUserProfile: connect code=%s request_id=%s",
					aerr.Code(), aerr.RequestID())
				if info := aerr.ErrorInfo(); info != nil {
					// 业务码封闭集合见 sdk/codes.go 常量（接口文档 §1.6）。
					log.Printf("业务细分: domain=%s code=%s",
						info.GetDomain(), info.GetCode())
				}
			}
			return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
				"message": "查询用户资料失败",
			})
		}
		return c.JSON(fiber.Map{
			"uid":      profile.GetId(),
			"username": profile.GetUsername(),
			"nickname": profile.GetNickname(),
			// ProfileResponse 完整字段 = 接口文档 §3.1 口径，
			// 见 gen/go/api/rpc/v1。
		})
	})

	log.Println("fiber 示例监听 :8082")
	log.Fatal(app.Listen(":8082"))
}
