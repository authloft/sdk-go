// Authloft Go SDK · gin 接入示例。
//
// 演示最小闭环：NewSDK 配置（凭据从环境变量读取，不硬编码）→ 一行挂
// ginadapter 中间件 → 业务 handler 取 uid（标准模式为 int64 断言）→
// UserService 调用（GetUserProfile）。
//
// 前置：
//   - 可访问的 Authloft 服务端（rpc 域路由已部署）；
//   - 管理后台创建的 SSO 客户端凭据（ClientID / ClientSecret）。
//
// 运行（examples 为独立 module、未列入本仓 go.work，需 GOWORK=off，
// 由本 module 的 replace 解析核心与 adapter；PowerShell 形态）：
//
//	cd examples/gin   # 仓库根目录下
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
//	curl -H "X-Authloft-Token: <令牌>" http://127.0.0.1:8081/me
package main

import (
	"errors"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"

	"github.com/authloft/sdk-go"
	ginadapter "github.com/authloft/sdk-go/adapter/gin"
)

func main() {
	// 必填三项从环境变量读取（生产同理：配置中心 / K8s Secret 注入，
	// 不落代码不入库；占位值见文件头注释）。BaseURL 须为纯 origin：
	// http:// 明文自动走 h2c prior-knowledge，https:// 走标准 ALPN
	// （README「H2C」节）；缺必填或 BaseURL 带路径时 NewSDK 直接报错。
	s, err := sdk.NewSDK(sdk.Config{
		BaseURL:      os.Getenv("AUTHLOFT_BASE_URL"),
		ClientID:     os.Getenv("AUTHLOFT_CLIENT_ID"),
		ClientSecret: os.Getenv("AUTHLOFT_CLIENT_SECRET"),
		// 可选项零值即默认（README「Config 字段」节）：GatewayPrefix
		// "X-Session-" / CtxKey "uid" / HeaderKey "X-Authloft-Token" /
		// CookieName "al_session" / CookieDomain 空（按请求 Host 自动
		// 推导根域名）/ CookieSecure "true"（三态：true 强制写 /
		// false 强制不写 / auto 按请求协议推断，README「Cookie 回写
		// 口径」节）/ EnableGateway false / HTTPClient nil。
	})
	if err != nil {
		log.Fatalf("NewSDK: %v", err)
	}

	r := gin.New()
	// 一行装配：令牌提取（HeaderKey 头 → CookieName Cookie）→
	// DecodeSession 回源（签名 / h2c 传输 / 错误归一均在封装层）→ 有效
	// 会话注入 uid，renewedToken 自动按原渠道覆盖传播（头来源 → 同名
	// 响应头；Cookie 来源 → Set-Cookie，五属性与 Domain 口径 =
	// SDK-init §4.4）。无令牌 / 会话无效 / 调用失败均匿名放行
	//（fail-open，SDK-init §5.1）。
	r.Use(ginadapter.Middleware(s))

	// 业务 handler：取当前用户 + UserService 直调。
	r.GET("/me", func(c *gin.Context) {
		v, ok := c.Get("uid") // CtxKey 默认 "uid"，可经 Config.CtxKey 改名
		if !ok {
			c.JSON(http.StatusOK, gin.H{
				"uid":     nil,
				"message": "匿名请求：无令牌或会话无效（fail-open 放行）",
			})
			return
		}
		// 注入的是 int64 原生值（标准模式 = SessionResponse.Id；网关
		// 模式同为 int64：<前缀>ID 头经 ParseInt 还原），断言必须 int64。
		uid, ok := v.(int64)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "uid 类型异常"})
			return
		}

		// UserService 直调（SDK-init §7：不走中间件，业务代码经封装层
		// client 调用）。GetUserProfile 是读接口：nonce 参与签名但服务端
		// 不去重，幂等可安全重试；写接口 UpdateUserProfile（Update 前缀
		// 命中「命名决定校验」五前缀）服务端 nonce 去重 TTL 30s，SDK 禁
		// 自动重试，失败由调用方自行决定后续动作。
		profile, err := s.GetUserProfile(c.Request.Context(), uid)
		if err != nil {
			// 错误归一（sdk.FromError）后 *sdk.Error 携带 Connect 码、
			// X-Request-Id 与 ErrorInfo；三态判定用 sdk.Classify(err)：
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
			c.JSON(http.StatusBadGateway, gin.H{"message": "查询用户资料失败"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"uid":      profile.GetId(),
			"username": profile.GetUsername(),
			"nickname": profile.GetNickname(),
			// ProfileResponse 完整字段 = 接口文档 §3.1 口径，
			// 见 gen/go/api/rpc/v1。
		})
	})

	log.Println("gin 示例监听 :8081")
	log.Fatal(r.Run(":8081"))
}
