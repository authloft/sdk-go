# Authloft 官方 Go SDK（sdk-go）

Authloft 统一用户中心的官方 Go SDK：一行中间件接入会话校验（gin / fiber 三
adapter），附 rpc 域（`TokenService` / `UserService`）封装层 client 与错误归一。
协议为 Connect（接口文档 §7），报文类型全部来自生成产物（`gen/**`），SDK 不手写。

一句话边界（DESIGN.md §1）：**SDK 只把「会话令牌 → 当前用户身份」这一件事
在应用进程内做好**——登录、登出、资料维护、授权全部留在 Authloft 侧。服务对象是
**SSO 应用后端**（在管理后台创建 SSO 客户端、共享 Authloft 会话的内部系统，需求
§4.4.4）；OIDC 外部客户端接入不在本 SDK 范围（走接口文档 §4）。

**四个独立 go module（零污染设计，DESIGN.md §6.1）**：

| module path | 内容 |
|---|---|
| `github.com/authloft/sdk-go` | 核心 + 封装层：`NewSDK` / `Config` / rpc client（`DecodeSession` / `GetUserProfile` / `UpdateUserProfile`）、错误归一（`FromError` / `Classify`）、业务码常量（33 个，对齐接口文档 §1.6 封闭集合） |
| `github.com/authloft/sdk-go/adapter/gin` | `ginadapter.Middleware(s *sdk.SDK) gin.HandlerFunc`（一行装配） |
| `github.com/authloft/sdk-go/adapter/fiber-v2` | `fiberadapter.Middleware(s *sdk.SDK) fiber.Handler`（一行装配，与 gin 版语义逐条同构；fiber v2 系，给 Go < 1.25 的使用方） |
| `github.com/authloft/sdk-go/adapter/fiber-v3` | `fiberadapter.Middleware(s *sdk.SDK) fiber.Handler`（一行装配，与 gin / fiber v2 版语义逐条同构；fiber v3 系，要求使用方 Go ≥ 1.25） |

阅读路线：[快速开始](#快速开始最小可用示例) →
[安装与 module 引用](#安装与-module-引用) →
[Config 字段表](#config-字段表) →
[中间件行为](#中间件行为) →
[Cookie 回写口径](#cookie-回写口径set-cookie-五属性与-domain) →
[两种运行形态](#两种运行形态标准模式与网关模式) →
[网关集成契约](#网关集成契约网关侧照着配) →
[rpc 域 client](#rpc-域-client) →
[错误处理](#错误处理) →
[重试语义](#重试语义) →
[FAQ](#faq) →
[生成链（buf）](#生成链buf) →
[示例（examples/）](#示例examples) →
[服务端升级迁移 checklist](#服务端升级迁移-checklist)

## 快速开始（最小可用示例）

前置：可访问的 Authloft 服务端 + 管理后台创建的 SSO 客户端凭据
（ClientID / ClientSecret）。完整可运行版本见 [`examples/`](#示例examples)。

```go
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"

	"github.com/authloft/sdk-go"
	ginadapter "github.com/authloft/sdk-go/adapter/gin"
	rpcv1 "github.com/authloft/sdk-go/gen/go/api/rpc/v1"
)

func main() {
	// 必填三项从环境变量读取（生产同理：配置中心 / K8s Secret 注入，
	// 不落代码、不入库）。BaseURL 须为纯 origin：http:// 自动 h2c，
	// https:// 走 ALPN。
	s, err := sdk.NewSDK(sdk.Config{
		BaseURL:      os.Getenv("AUTHLOFT_BASE_URL"),
		ClientID:     os.Getenv("AUTHLOFT_CLIENT_ID"),
		ClientSecret: os.Getenv("AUTHLOFT_CLIENT_SECRET"),
	})
	if err != nil {
		log.Fatalf("NewSDK: %v", err) // 缺必填 / BaseURL 非纯 origin → 构造期 fail-fast
	}

	r := gin.New()
	r.Use(ginadapter.Middleware(s)) // 一行装配：令牌校验 + uid 注入 + 续期回写

	// 读接口直调：查当前用户资料。
	r.GET("/me", func(c *gin.Context) {
		v, ok := c.Get("uid") // CtxKey 默认 "uid"
		if !ok {
			c.JSON(http.StatusOK, gin.H{"uid": nil}) // 匿名（fail-open 放行）
			return
		}
		uid, ok := v.(int64) // 注入的是 int64 原生值，断言必须 int64
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "uid 类型异常"})
			return
		}
		profile, err := s.GetUserProfile(c.Request.Context(), uid)
		if err != nil {
			log.Printf("GetUserProfile: %v", err)
			c.JSON(http.StatusBadGateway, gin.H{"message": "查询用户资料失败"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"uid":      profile.GetId(),
			"username": profile.GetUsername(),
			"nickname": profile.GetNickname(),
			// ProfileResponse 完整字段 = 接口文档 §3.1 口径，见 gen/go/api/rpc/v1
		})
	})

	// 写接口直调：改当前用户昵称（写接口禁自动重试，见「重试语义」）。
	r.PATCH("/me/nickname", func(c *gin.Context) {
		v, ok := c.Get("uid")
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "请先登录"})
			return
		}
		uid, ok := v.(int64)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "uid 类型异常"})
			return
		}
		// 入参字段 = 接口文档 §3.2 口径：Uid + 三可改字段（proto3 optional，
		// 指针形态）：未设置（nil）= 不修改，显式设值（含空串 / 0）= 覆盖。
		nickname := "新昵称"
		if _, err := s.UpdateUserProfile(c.Request.Context(), &rpcv1.UpdateUserProfileRequest{
			Uid:      uid,
			Nickname: &nickname,
		}); err != nil {
			log.Printf("UpdateUserProfile: %v", err)
			c.JSON(http.StatusBadGateway, gin.H{"message": "更新资料失败"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	log.Println("监听 :8081")
	log.Fatal(r.Run(":8081"))
}
```

fiber v2 版仅装配与取值差异（RPC 直调同形）：

```go
app := fiber.New()
app.Use(fiberadapter.Middleware(s)) // 取 uid：uid, ok := c.Locals("uid").(int64)
// RPC 直调用 c.UserContext()：fiber 的 c.Context() 是 *fasthttp.RequestCtx
// （非标准 context），UserContext 才是标准 context 桥——
// s.GetUserProfile(c.UserContext(), uid)
```

fiber v3 版装配同形，仅两处 API 差异（review/fiber-v3-plan.md §2.1；
要求使用方 Go ≥ 1.25）：

```go
app := fiber.New()
app.Use(fiberadapter.Middleware(s)) // 取 uid 同 v2
// v3：Ctx 是接口（handler 签名 func(c fiber.Ctx) error）；
// 请求级 context 桥由 c.UserContext() 变为 c.Context()——
// s.GetUserProfile(c.Context(), uid)
```

运行与验证（PowerShell，详见「示例」节）：

```powershell
cd examples/gin   # 仓库根目录下
$env:AUTHLOFT_BASE_URL="http://127.0.0.1:8080"
$env:AUTHLOFT_CLIENT_ID="<占位：你的 ClientID>"
$env:AUTHLOFT_CLIENT_SECRET="<占位：你的 ClientSecret>"
$env:GOWORK="off"; go run .    # 监听 :8081；fiber v2 示例 :8082；fiber v3 示例 :8083

# 验证会话（携带 Authloft 签发的令牌）：
curl -H "X-Authloft-Token: <令牌>" http://127.0.0.1:8081/me
```

## 安装与 module 引用

sdk-go 已拆为独立仓库（未发布远端：当前形态本地联编，module path 已是最终形态）。业务
module **按需**引用核心 + 所需 adapter——只引核心就不带任何 gin / fiber 依赖（见本节末）。

### 方式一 · go.work（推荐，本地联编）

把业务 module 与所需 SDK module 并列入 go.work 的 `use` 列表，业务 go.mod 正常
require（workspace 内解析，无需 replace）：

```
go 1.26.1

use (
	./your-service
	./sdk-go
	./sdk-go/adapter/gin   // 按需；不 use 即不进依赖图
	// ./sdk-go/adapter/fiber-v2  // 按需；与 fiber-v3 二选一（同进程同引需 import 别名）
	// ./sdk-go/adapter/fiber-v3  // 按需；要求使用方 Go ≥ 1.25
)
```

### 方式二 · replace（无 go.work 时，GOWORK=off）

业务 go.mod：

```
require github.com/authloft/sdk-go v0.0.0
require github.com/authloft/sdk-go/adapter/gin v0.0.0 // 按需

replace github.com/authloft/sdk-go => ../sdk-go
replace github.com/authloft/sdk-go/adapter/gin => ../sdk-go/adapter/gin
```

（adapter module 自身的 go.mod 已内建 `replace github.com/authloft/sdk-go => ../..`
引核心，业务侧无需关心。）

### 将来形态：独立仓库 / 发布

module path 已是可发布的最终形态（核心 `github.com/authloft/sdk-go`、adapter
子路径 `github.com/authloft/sdk-go/adapter/{gin,fiber-v2,fiber-v3}`），搬出后**不需要改
path**，只需删 replace、引真实版本（细节见
[「服务端升级迁移 checklist」](#服务端升级迁移-checklist)）：

```
go get github.com/authloft/sdk-go
go get github.com/authloft/sdk-go/adapter/gin   # 按需；不引则 gin 不进依赖图
```

### 零污染：不引 adapter 就不带 gin/fiber 依赖

Go 依赖解析以 module 为边界：gin / fiber 只出现在三个 adapter module 的 go.mod；
核心 module 的 go.mod **不 require** 它们。只 import 核心包的项目，模块图走不到
adapter module，gin / fiber 及其传递依赖不可能进入依赖图与 go.sum。
**build tag 做不到这一点**（只隔离编译路径，单 module 的 go.mod 仍会 require、
进 go.sum 与模块图）——这是多 module 形态的原因（SDK-init §6.1）。

零污染门禁断言（对核心 module 执行，零命中 = 隔离未被破坏；CI 应接线，当前未接）：

```powershell
# 仓库根目录下执行
go list -deps ./... | Select-String 'gin-gonic|gofiber'   # 期望无输出
# bash 等价：go list -deps ./... | grep -cE 'gin-gonic|gofiber'   # 期望 0
```

## Config 字段表

（对齐 `sdk.go` 导出的十一字段。）

| 字段 | 必填 | 默认 | 说明 |
|---|---|---|---|
| `BaseURL` | 是 | — | 服务地址，**纯 origin**（禁路径 / 查询 / 片段，`NewSDK` 构造期校验拒绝——带路径会使签名 path 段与服务端 Procedure 失配，请求必被服务端拒签；仅容忍尾斜杠）；scheme 决定传输：`http://` → h2c、`https://` → ALPN（见 FAQ） |
| `ClientID` | 是 | — | SSO 客户端标识（管理后台创建，需求 §4.4.4） |
| `ClientSecret` | 是 | — | SSO 客户端密钥，与 ClientID 一起参与 HMAC 五项签名（**不是服务端 sign_key**，见 FAQ） |
| `EnableGateway` | 否 | `false` | 网关模式开关（见「两种运行形态」） |
| `GatewayPrefix` | 否 | `"X-Session-"` | 网关采信响应头**前缀，整体替换**而非逐头指定（见「网关集成契约」） |
| `CtxKey` | 否 | `"uid"` | 有效会话注入业务上下文的键名（gin `c.Set` / fiber `c.Locals`），不涉契约 |
| `HeaderKey` | 否 | `"X-Authloft-Token"` | 令牌请求头键名（取值与 renewedToken 回写同名） |
| `CookieName` | 否 | `"al_session"` | 令牌 Cookie 名 |
| `CookieDomain` | 否 | 空（自动推导） | Cookie 回写 `Domain` 属性：空 = 按业务应用请求 Host 自动推导根域名（多段取最后两段、不带前导点；IPv4 / IPv6 / `localhost` / 单段主机名降级为不设 `Domain`，host-only）；非空 = **强制使用，不推导**（配置者自行负责合法性）。规则速览见[「Cookie 回写口径」](#cookie-回写口径set-cookie-五属性与-domain) |
| `CookieSecure` | 否 | `"true"` | Cookie 回写 `Secure` 属性三态（SDK-init §4.4）：`"true"` 强制写（默认，未配置 ≡）/ `"false"` 强制不写 / `"auto"` 按业务应用请求协议逐请求推断（`X-Forwarded-Proto` 头优先、TLS 直连兜底，无头无 TLS 不写；**推断来源不是 BaseURL scheme**）。类型 `sdk.CookieSecureMode`，常量 `CookieSecureTrue` / `CookieSecureFalse` / `CookieSecureAuto`；非法值 `NewSDK` 构造期报错 |
| `HTTPClient` | 否 | `nil` | 注入自定义 `*http.Client`；nil = SDK 按 BaseURL scheme 自建传输（**整体超时 10s**）；注入后原样采用（超时归用户配置），SDK 仅在其 Transport 外包 HMAC 签名器（浅拷贝替换 Transport 字段，不动传入的本体） |

`NewSDK` 构造期 fail-fast：必填缺失 / BaseURL 非纯 origin / scheme 非
http(s) / `CookieSecure` 非法值均返回 error，不要忽略。`(s *SDK) Config()`
返回填充默认值后的配置副本。

## 中间件行为

| 框架 | import | 装配 | 取 uid |
|---|---|---|---|
| gin | `ginadapter "github.com/authloft/sdk-go/adapter/gin"` | `r.Use(ginadapter.Middleware(s))` | `v, ok := c.Get("uid"); uid, ok2 := v.(int64)`（`ok && ok2` 才是已登录） |
| fiber v2 | `fiberadapter "github.com/authloft/sdk-go/adapter/fiber-v2"` | `app.Use(fiberadapter.Middleware(s))` | `uid, ok := c.Locals("uid").(int64)`（`!ok` = 匿名，勿丢 ok 盲断言） |
| fiber v3 | `fiberadapter "github.com/authloft/sdk-go/adapter/fiber-v3"` | `app.Use(fiberadapter.Middleware(s))` | 同 fiber v2（v3 仅 handler 签名 `*fiber.Ctx`→`fiber.Ctx`、`c.UserContext()`→`c.Context()`） |

三版逐条同构（SDK-init §4 / §5.1）：fiber v2 / v3 装配形态同形、import 路径不同；同进程同时引 v2 与 v3 需 import 别名（`fiber2adapter` / `fiber3adapter`），一般二选一。

- 令牌提取优先级：`HeaderKey` 请求头 → `CookieName` Cookie；两空匿名放行（不调 RPC）；
- 有效会话：注入 uid（int64 原生值）；`renewedToken` 原渠道覆盖传播——头来源写同名
  响应头，Cookie 来源 `Set-Cookie`（五属性与 `Domain` 口径见下一节）。业务侧对令牌
  始终不透明，只作串替换；
- 会话无效（HTTP 401）与调用失败（网络失败 / 5xx / 429）均 **fail-open** 匿名放行、
  不写任何响应头（不重签、不写存储）；调用失败记错误日志，401 属常规匿名流量不记。
  fail-closed 严格模式本期不做：网关模式与标准模式统一 fail-open（SDK-init §5.1）。

## Cookie 回写口径（Set-Cookie 五属性与 Domain）

令牌来自 Cookie 时，`renewedToken` 经 `Set-Cookie` 原渠道覆盖回写。五属性取值与
`Domain` 推导规则以 **SDK-init §4.4**（SDK 侧定稿）为唯一真相，速览：

| 属性 | 取值 | 要点 |
|---|---|---|
| `HttpOnly` | `true` | 令牌对页面 JS 不可读 |
| `Path` | `/` | 根路径全站携带 |
| `Secure` | `CookieSecure` 三态（默认 `true` 强制写） | `"true"` 强制写 / `"false"` 强制不写 / `"auto"` 按业务应用请求协议逐请求推断：`X-Forwarded-Proto` 头（逗号首值、忽略大小写）优先——`https` 写、其余不写；头缺失看请求自身 TLS；无头无 TLS 兜底不写（明文直连场景）。**推断来源是业务应用请求协议而非 BaseURL scheme**（Cookie 随浏览器 ↔ 业务应用通道传输）；非法配置值 `NewSDK` 构造期报错（SDK-init §4.4） |
| `SameSite` | 随 `Secure` 联动（2026-11-06 定稿，取代恒 `Lax` 口径）：`Secure=true`（含 `auto` 推断为 https）→ `None`；`Secure=false`（含 `auto` 推断为明文）→ `Lax`；两分支均显式取值、不省略 | `None` 须配 `Secure`（无 `Secure` 的 `None` 被浏览器拒收），HTTPS 通道取 `None`；明文通道 `None` 不可用 → `Lax` 兜底（允许顶级导航 GET 携带会话、阻断跨站 POST 送达）；与服务端口径一致（https_deployment：true→Secure+None / false→Lax） |
| `Max-Age` | `exp − now`（秒） | 会话剩余寿命（`DecodeSession` 响应的 `exp`），持久 Cookie 与服务端滚动续期对齐；差值 ≤ 0 写删除型 Cookie |

`Domain`（配置项 `CookieDomain`）三分支：

1. 非空 → **强制使用，不推导**（配置者自行负责合法性）；
2. 空（默认）→ 按业务应用当前请求的 Host 自动推导：多段域名取**最后两段**为根域名、
   **不带前导点**（`a.b.example.com` → `example.com`；gin 取 `Request.Host`，
   fiber 取 `Hostname()`，反代场景下即浏览器实际访问的域名）；
3. Host 为 IPv4 / IPv6 / `localhost` / 单段主机名 → 推导为空 → **不设 `Domain`**
   （host-only Cookie，仅当前主机可见）。

已知取舍（零新增依赖）：不引入 public suffix list，多段 TLD（如 `x.co.uk`）会按
「最后两段」推出 `co.uk`，误差已知接受；根域名变更的运维影响（旧域 Cookie 不被
覆盖清除）见 SDK-init §4.4。

网关模式不回写 Cookie（SDK-init §4.1 / §9 条 15）：网关头采信即不回源、无
`renewedToken` 可传播，采信路径均不产生 `Set-Cookie`。

## 两种运行形态：标准模式与网关模式

| | 标准模式（默认） | 网关模式 |
|---|---|---|
| 开关 | `EnableGateway=false` | `EnableGateway=true` |
| 每请求流程 | 取令牌（`HeaderKey` 头 → `CookieName` Cookie）→ 回源 `TokenService/DecodeSession`（签名 / 超时 / 错误归一均在封装层，使用方零感知）→ 有效则注入 uid、`renewedToken` 原渠道回写；两空匿名放行 | 命中 `<GatewayPrefix>Status` 头 → **直接采信网关结果、不再回源**；头缺失的请求落回标准模式 |
| 每请求 RPC 成本 | 1 次 | 0 次 |
| 适用 | 简单接入 / 无网关 / 中低流量 | 高流量 / 已部署可信网关（网关统一调接口文档 §6 decode 回注头） |
| uid 来源 | `SessionResponse.Id`（int64 原生值） | `<前缀>ID` 头经 `ParseInt` 还原 int64 |

- 本期不做本地令牌缓存：令牌加密自包含，但 SDK 无密钥、不能本地校验——高频流量
  请走网关模式（SDK-init §4.2）。
- **注入 int64 口径**：两模式同型，业务侧断言一律 `int64`（网关头是 payload 的
  HTTP 字符串形态，SDK 注入前已还原）。

## 网关集成契约（网关侧照着配）

契约唯一真相 = 接口文档 §6；本节给网关侧一份可照抄的配置口径。

**网关需要做的**：

1. 持有 `X-Gateway-Token`（管理后台可配多个）。
2. 对需要会话判定的请求调 `ANY /api/gateway/decode`（令牌取值优先级
   `X-Authloft-Token` Header → `al_session` Cookie；**状态码恒为 200**），拿到
   `SessionTokenPayload` 的解码结果。
3. 把解码结果以 `<前缀>字段名` 响应头回注下游（默认前缀 `X-Session-`）：

| 响应头（默认前缀） | 含义 | SDK 侧用法 |
|---|---|---|
| `X-Session-Status` | `valid` / `invalid` | 采信判定依据（该头存在即采信） |
| `X-Session-ID` | **用户 ID**（= `payload.id`，数字串） | `valid` 时 `ParseInt` 还原 int64 注入 uid |
| `X-Session-SID` | 会话 ID（= `payload.sid`） | 透传，业务侧自取 |
| `X-Session-Epoch` | 用户安全版本号 | 透传 |
| `X-Session-AMR` | 认证方法数组 `amr`，**逗号分隔**（如 `pwd,otp`；空数组输出空值） | 透传 |

接口文档 §6 自声明「部分字段例（不完整列出，详见 `SessionTokenPayload`）」——
其余 payload 字段按同规则回注即可（头名 = 前缀 + payload 字段名大写）。

**SDK 侧采信规则**（`EnableGateway=true`）：

- 请求携带 `<前缀>Status` 头 → 视为已过可信网关，**直接采信、不再回源**；
- `Status=valid` → `<前缀>ID` 经 `ParseInt` 还原 int64 注入 uid；**非数字 / 缺失
  → 匿名不注入**（网关侧契约破坏，也不回源）；
- `Status` 非 `valid` → 匿名放行；
- 头不存在 → 落回标准模式（该请求未过网关，照常回源校验）；
- `EnableGateway=false` → 完全不读网关头（默认形态不受伪造网关头影响）。

**前缀可配**：网关重映射头名时，业务侧设 `Config.GatewayPrefix` **整体替换**
（如 `"X-Auth-"` → SDK 读 `X-Auth-Status` / `X-Auth-ID`…）；不配则默认
`X-Session-`，与接口文档 §6 契约一致。取整体替换而非逐头指定：网关重映射通常
统一换前缀，逐头指定会裂成每头一项、易漏配（SDK-init §3）。

**提示**：无效会话也请回注 `Status` 头（值非 `valid`）——否则该请求在 SDK 侧
落回标准模式，多花一次 DecodeSession RPC。

## rpc 域 client

`UserService` / `TokenService` 方法由业务代码经 SDK 直调（不走中间件）；中间件
只消费 `DecodeSession`（SDK-init §7）。

| 方法 | 读写 | 说明 |
|---|---|---|
| `(s *SDK) DecodeSession(ctx, token string) (*rpcv1.SessionResponse, error)` | 读 | 中间件内部同款调用；`renewedToken` 原样透传，续期回写归 adapter / 调用方；不携带用户信息（`include_user_info` 零值省略，请求体不带该字段） |
| `(s *SDK) DecodeSessionWithInfo(ctx, token string, includeUserInfo bool) (*rpcv1.SessionResponse, error)` | 读 | `DecodeSession` 的携带用户信息形态（接口文档 §7.1）：`true` → 会话有效时响应 `user_info`（`*rpcv1.ProfileResponse`，与 `GetUserProfile` 响应同构）原样透传；`false` → 请求体不带该字段（等价 `DecodeSession`）；session 无效仍 401。**中间件不调用本方法**（行为零变化），需要用户信息的业务代码直调 |
| `(s *SDK) GetUserProfile(ctx, uid int64) (*rpcv1.ProfileResponse, error)` | 读 | 响应为接口文档 §3.1 口径 Authloft 结构（`phone` / `email` 明文） |
| `(s *SDK) GetUserProfiles(ctx, ids []int64) (*rpcv1.GetUserProfilesResponse, error)` | 读 | 批量读用户资料（接口文档 §7.2）。**SDK 层三禁**：不替调用方补齐缺失 id、不改变顺序、不静默截断超限 ids——`ids` 原样透传、`profiles` 原样返回；上限 100（去重前计数）超限整单 `invalid_request`、缺失 id 跳过、重复 id 首现去重、返回顺序 = 入参去重后，**全部在服务端做** |
| `(s *SDK) UpdateUserProfile(ctx, req *rpcv1.UpdateUserProfileRequest) (*rpcv1.OkResponse, error)` | 写 | 入参同接口文档 §3.2：`Uid` + 三可改字段 `Nickname` / `AvatarUrl` / `Profile`。可改字段及 `Profile` 子字段（`Gender` / `Birthday` / `Locale` / `Timezone` / `Extra`）均为 **proto3 optional**（指针 + has 位）：**未设置（nil）= 不修改，显式设值（含空串 / 0）= 覆盖**，has 位区分「未设置」与「零值」；`gender` 取值 0/1/2 = 保密/男/女（ISO 5218），显式 `&0` 可改回保密；`req` 为 nil 或全字段 nil = 合法空操作 no-op；成功返回空响应 |

**批量 `GetUserProfiles` 用法**：

```go
resp, err := s.GetUserProfiles(c.Request.Context(), []int64{10086, 20001, 10086})
if err != nil {
	// 超限整单拒绝：invalid_request 经既有错误归一原样给上层（不吞不改写）。
	var aerr *sdk.Error
	if errors.As(err, &aerr) && aerr.ErrorInfo().GetCode() == sdk.CodeInvalidRequest {
		// ids 超过上限 100（去重前计数）——拆批或去重后重试
	}
	return
}
for _, p := range resp.GetProfiles() {
	// p 为 *rpcv1.ProfileResponse：缺失 id 跳过、重复 id 首现去重、
	// 顺序 = 入参去重后（服务端语义，SDK 不改写）。
}
```

> `ids` 传多少、什么顺序，服务端就收到多少、什么顺序——SDK 不去重、不排序、
> 不截断、不补齐。对入参做规整（去重 / 排序 / 拆批）是调用方自己的决定。

**签名（使用方零感知）**：HMAC 五项 `client_id:nonce:path:body:client_secret` →
三头 `X-Client-ID` / `X-Nonce-ID` / `X-Signature`（接口文档 §7），在 RoundTripper
层统一实现（每请求新 nonce），h1 / h2c / h2 逐帧语义一致。业务代码不需要、也不应该
自己拼签名。`rpcv1` import 路径：`github.com/authloft/sdk-go/gen/go/api/rpc/v1`。

## 错误处理

**三态判定 `sdk.Classify(err)`**——业务分流的标准姿势（adapter 内部亦按此三态
fail-open）：

```go
switch sdk.Classify(err) {
case sdk.Valid:
	// 调用成功（err == nil），会话有效
case sdk.Invalid:
	// Connect code unauthenticated（HTTP 401）：令牌无效 / 过期 → 引导重新登录
case sdk.CallFailed:
	// 其余（网络失败 / 5xx / 429 等）：读接口可稍后重试（见「重试语义」）
}
```

**细节归一 `sdk.FromError` → `*sdk.Error`**——需要 Connect 码、文案或排查信息时：

```go
var aerr *sdk.Error
if errors.As(err, &aerr) {
	log.Printf("code=%s request_id=%s message=%q",
		aerr.Code(), aerr.RequestID(), aerr.Message())
	if info := aerr.ErrorInfo(); info != nil {
		log.Printf("domain=%s code=%s retry_after=%d attempts_left=%d",
			info.GetDomain(), info.GetCode(),
			info.GetRetryAfter(), info.GetAttemptsLeft())
	}
}
```

- `*sdk.Error` 携带：`Code()`（`connect.Code` 标准码）、`Message()`（服务端文案）、
  `RequestID()`（`X-Request-Id` 响应头）、`ErrorInfo()`（错误体 details 中第一枚
  `ErrorInfo`，字段 `domain / code / message / retry_after / attempts_left`）；
  `Unwrap` 保留对底层 `*connect.Error` 的访问。
- 网络失败等无 Connect 语义的错误**原样返回**（不是 `*sdk.Error`），`Classify` 判为
  `CallFailed`。
- **`X-Request-Id` 排查用法**：服务端对所有响应（含错误响应）统一回写该头。拿
  `aerr.RequestID()` 的值去服务端日志按同一 ID 检索，即可对上那次调用的服务端处理
  记录（含错误细节）——这是接 SDK 与 Authloft 侧联排问题的标准通道。

**业务码常量**（`codes.go`）：与接口文档 §1.6 封闭集合逐字一致的 **33 个**常量
（`sdk.CodeXXX`，如 `CodeInvalidCredentials` / `CodeLocked` / `CodeCaptchaRequired`
/ `CodeUserNotFound`……覆盖流程态、扫码轮询态、限流、凭证校验、用户/资源/开关类）。
一套词汇、两个位置：登录流程域作响应顶层 `status`，其余域作 `ErrorInfo.code`。
另 `sdk.CodeUnknown` 兜底哨兵（未知取值归一，非协议词汇）与
`sdk.IsKnownCode` / `sdk.NormalizeCode`。

## 重试语义

读写判定按方法名前缀「命名决定校验」（接口文档 §7，长期口径，SDK 侧
`internal/transport.IsWriteProcedure` 同构实现）：

| 接口类别 | 判据 | 服务端 nonce 处理 | 重试 |
|---|---|---|---|
| 读接口（`DecodeSession` / `GetUserProfile` / `GetUserProfiles`） | 方法名前缀不在写前缀集合（`Get` 前缀归读，接口文档 §7.2） | 参与签名但**不去重**（允许重复请求） | **可安全重试**（幂等） |
| 写接口（`UpdateUserProfile` 等全部 rpc 域写方法） | 方法名以 `Update` / `Delete` / `Set` / `Create` / `Revoke` 开头 | **去重 TTL 30s** | **禁自动重试**：同一 `(client_id, nonce)` 在 TTL 内二次到达会被判重放 → HTTP 403 `permission_denied` |

- **SDK 默认零重试**（结构性零重试：传输链无重试框架，任何错误一次归一返回，
  失败由调用方自行决策）。
- 语义上禁的是「**自动**重试 / 重放已签名的同一请求」：签名器（RoundTripper）对
  每次 HTTP 请求生成新 nonce，自动重试在传输层重发同一签名请求时 nonce 不变，写接口
  即触发上述重放判定。业务侧重新调用一次 SDK 方法会生成新 nonce，不是重放——但
  重复写的业务语义（例如重复改资料）由调用方自行判断。
- 后续任何重试策略必须先经 `IsWriteProcedure` 判定，写前缀永不自动重试（SDK-init §7）。

## FAQ

### H2C / 明文（http:// BaseURL）

BaseURL 用 `http://` 时 SDK 自动走 **h2c prior-knowledge**（`x/net/http2`
AllowHTTP + 明文拨号），对应服务端未配 TLS 时**同端口 HTTP/1.1 + H2C 监听**
（后端架构 §3.1）——内网明文部署直接可用，零额外配置。签名在 RoundTripper 层取
逻辑值（procedure / body / 三头），h1 / h2c / h2 逐帧语义一致。

### TLS（https:// BaseURL）

BaseURL 用 `https://` 时走标准传输，ALPN 自动协商 H2。同样零配置；注入
`HTTPClient` 时由你的传输配置决定 TLS 细节。

### 令牌续期（renewedToken）怎么处理？

服务端「**会话校验通过即每次重签**」（接口文档 §7.1）。`DecodeSession` 响应带
`renewedToken`，中间件自动**原渠道覆盖传播**：令牌来自请求头 → 写同名响应头；
来自 Cookie → `Set-Cookie`（五属性与 `Domain` 口径见
[「Cookie 回写口径」](#cookie-回写口径set-cookie-五属性与-domain)）。业务侧对令牌
**始终不透明、只作串替换**：不要解析令牌
内容，也不要自己转发 renewedToken（中间件已做）。自己调 `DecodeSession` 时才需要
自行按原渠道落盘。

### id 和 sid 搞混了？

`payload.id` = **用户 ID**（注入 uid 的唯一来源）；`payload.sid` = **会话 ID**
（仅透传，业务一般用不到）。网关头里对应 `<前缀>ID` / `<前缀>SID`。如果 handler
里 uid 的值看起来像会话 ID，检查网关是否把 SID 塞进了 ID 头（对照
「网关集成契约」）。

### ClientSecret 配成了 sign_key？

SDK 的 `ClientSecret` 是**管理后台创建的 SSO 客户端凭据**（需求 §4.4.4），参与
HMAC 五项签名；与服务端配置里的 `sign_key`（服务端自己的令牌加密密钥）**无关**。
凭据配错 → 签名校验失败 → 403 `permission_denied`。拿 `X-Request-Id` 去服务端
日志对账（见「错误处理」）。

### 为什么拿不到 uid（匿名）？

fail-open 是有意设计（SDK-init §5.1）：无令牌 / 会话无效（401）/ 调用失败
（网络 / 5xx / 429）均匿名放行、不阻断业务请求。排查顺序：① 请求是否带
`X-Authloft-Token` 头或 `al_session` Cookie；② 应用日志里是否有 SDK 的
「调用失败」错误日志（CallFailed 才记日志，401 不记）；③ 按 `X-Request-Id`
去服务端日志对账。

## 生成链（buf）

生成产物已入库（`gen/**` 随仓走、**禁止手改**）。proto 唯一真相在主仓库
`server/proto/**`，由 CI（`.github/workflows/sync.yml`）拉取拷贝到本仓 `/proto`
（**不入库**，`.gitignore` 忽略）后再生成。本地再生成（仓库根目录下）：

```powershell
Copy-Item -Recurse <主仓库>/server/proto ./proto   # CI 之外的场景先拷 proto
buf generate
```

⚠️ **无参执行**：输入与 paths 过滤已固定在 `buf.gen.yaml` 的 `inputs`（rpc 域四件 +
传递依赖 + ErrorInfo）；带位置参数（如 `buf generate proto`）会替换 inputs、
丢失过滤，把 `/proto` 全部 proto 越范围生成进 `gen/`。产物 import path 由 managed
`go_package_prefix` 重映射为 `github.com/authloft/sdk-go/gen/go/...`（包名
rpcv1 / rpcv1connect / accountv1 / commonv1，与 server 侧零漂移）。

## 示例（examples/）

`examples/gin`、`examples/fiber-v2`、`examples/fiber-v3` 各为一个**独立 module**（与 adapter 同款零污染
形态：不进核心依赖图——嵌套 module 目录会被核心 `./...` 包遍历自动剪枝——故可安全
import gin / fiber 与 adapter）。每个示例：`NewSDK` 配置（凭据从环境变量读取，占位
见文件头注释，**不引真实凭据**）→ 一行挂中间件 → `/me` handler 取 uid（int64 断言）
→ `GetUserProfile` 直调（注释说明写接口禁自动重试）。

前置：可访问的 Authloft 服务端 + 管理后台创建的 SSO 客户端。构建 / 运行
（examples 未列入本仓 go.work，`GOWORK=off` 后由自身 replace 解析）：

```powershell
cd examples/gin   # 仓库根目录下
$env:GOWORK="off"; go build ./...          # 仅验证可编译
$env:AUTHLOFT_BASE_URL="http://127.0.0.1:8080"
$env:AUTHLOFT_CLIENT_ID="<占位：你的 ClientID>"
$env:AUTHLOFT_CLIENT_SECRET="<占位：你的 ClientSecret>"
$env:GOWORK="off"; go run .                # 监听 :8081；fiber v2 示例 :8082；fiber v3 示例 :8083
```

## 服务端升级迁移 checklist

### 服务端 proto / 升级跟进（接入方视角）

| 事项 | 做法 |
|---|---|
| SDK 与服务端版本关系 | 已拆独立仓库：proto 由 CI 从主仓库同步（sync.yml）后再生成，`gen/**` 随仓更新——升级服务端时等 CI 同步、拉取本仓最新 commit 即可，接入方零手工操作 |
| 服务端 proto 变更 | 走接口文档 §11 契约变更：先改 proto（`buf breaking` 只增字段、不改字段号），生成物随门禁更新，SDK 跟进；SDK 侧若需再生成：先拷 proto 到 `/proto`，仓库根目录下无参 `buf generate`（见「生成链」），产物 diff 随 commit 入库 |
| 序列化选项 | SDK 侧禁止自行改写（后端 §1.6）；报文类型一律来自生成链，不手写 |

### 迁移到独立仓库（发布形态）

| # | 事项 | 做法 |
|---|---|---|
| 1 | module path | **不变即可发布**：核心 `github.com/authloft/sdk-go` 与 adapter 子路径已是最终形态；核心包内 import（gen 产物 `github.com/authloft/sdk-go/gen/go/...`、adapter 引核心）与 module path 自洽，无需随迁改动 |
| 2 | replace 移除 | `adapter/{gin,fiber-v2,fiber-v3}/go.mod` 删 `replace github.com/authloft/sdk-go => ../..`，require 改真实版本（`go get github.com/authloft/sdk-go@vX.Y.Z`）；`examples/**/go.mod` 的两条 replace（`../..` 与 `../../adapter/*`）同理删除 |
| 3 | go.work 处置 | go.work 仅仓库内本地联编用、不进消费方依赖图（SDK-init §6.1）；本仓保留（核心 + adapter 联编用，内容全为相对路径，可入库）；消费方想把 SDK 与业务服务联编，自建不入库的 go.work |
| 4 | gen 产物自带 | `gen/**` 已入库、随仓走，`buf.gen.yaml` 一并带走；`inputs` 已指向本仓 `/proto`（gitignore、CI 从主仓库拉取，见「生成链」）——此项已落定 |
| 5 | CI 门禁 | sdk-go 门禁应含——四 module `go build ./...` / `go vet ./...` / `go test ./...`；核心零污染断言（`go list -deps ./...` 零 gin-gonic / gofiber 命中）；`buf generate` 后 `git diff --exit-code` 零 diff 门禁。接入 `.github/workflows/ci.yml` 属后端 CI 地盘，待后续接入 |
