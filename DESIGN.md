# SDK（Go）初始化与接入设计

> 文档定位：定义 Authloft 官方 Go SDK（sdk-go）的初始化与接入方式，服务对象是 **SSO 应用后端**（需求 §4.4.4 的 SSO 客户端：内部系统、无独立用户体系、共享 Authloft 会话）。契约依据接口文档 §6（网关）、§7 / §7.1（RPC 域）；本文只做 SDK 侧设计，不新增契约。

## 1. 目标与不目标

| 项 | 结论 |
|---|---|
| 目标 | 给 SSO 应用后端提供 **gin + fiber 中间件（同期交付；fiber 双版本 fiber-v2 / fiber-v3，见 §6.1）**：一行装配完成会话校验、`uid` 注入业务上下文、令牌续期回传；屏蔽 HMAC 签名、Connect 客户端、错误归一等细节。适配器**可选引接、零污染**：不引 adapter 时 gin / fiber 及其依赖不进依赖图（§6.1） |
| 范围 | 封装 rpc 域**全部方法**：`TokenService/DecodeSession`（含 `include_user_info` 可选用户信息携带，§5）+ `UserService/GetUserProfile` / `UserService/UpdateUserProfile`（含写接口）+ `UserService/GetUserProfiles`（批量；契约已由接口文档 §7.2 落定，服务端 proto 与实现尚未落地，SDK 侧待 proto 落地后开工，见 §5 / §7 / §9 条 12） |
| 不目标 | 不管网关自身实现（网关是 §6 decode 的调用方，与 SDK 二选一部署）；不管浏览器侧会话写入（由 Authloft 登录链路落 Cookie，需求 §4.4.1）；不管业务系统的用户体系与授权（RBAC 等）；不覆盖 OIDC 外部客户端场景（外部系统走接口文档 §4） |

一句话边界：**SDK 只把「会话令牌 → 当前用户身份」这一件事在应用进程内做好，其余（登录、登出、资料、授权）全部留在 Authloft 侧。**

## 2. 使用形态

```go
import (
  "log"

  "github.com/authloft/sdk-go"               // 核心包（必引）：NewSDK + rpc 域客户端封装
  "github.com/authloft/sdk-go/adapter/gin"   // 可选：独立 module，不引不进依赖图（§6.1）
)

s, err := sdk.NewSDK(sdk.Config{
  BaseURL:      "http://authloft.internal:8080", // Authloft 服务地址（须为纯 origin，见 §3）
  ClientID:     "123456",                        // 管理后台创建的 SSO 客户端（需求 §4.4.4）
  ClientSecret: "…",
  EnableGateway: false,                          // 网关模式开关，见 §4.1
  GatewayPrefix: "X-Session-",                   // 网关头前缀，可选，默认 X-Session-（§3）
})
if err != nil {
  log.Fatal(err) // 必填缺失 / BaseURL 非纯 origin：NewSDK 构造期 fail-fast
}

r := gin.New()
r.Use(ginadapter.Middleware(s)) // 之后业务 handler 里 c.Get("uid") 取当前用户（int64）

// fiber 双版本 adapter 同期交付、形态同构（各自独立 module，引了才进依赖图）：
//   import fiberadapter "github.com/authloft/sdk-go/adapter/fiber-v2"  // fiber v2 系
//   import fiberadapter "github.com/authloft/sdk-go/adapter/fiber-v3"  // fiber v3 系
// app := fiber.New()
// app.Use(fiberadapter.Middleware(s))
```

**fiber 双版本使用方式**：按 fiber 主版本二选一——`fiber-v2`（依赖 `github.com/gofiber/fiber/v2 v2.16.0`）或 `fiber-v3`（依赖 `github.com/gofiber/fiber/v3 v3.0.0`，最低可用版本口径），初始化同为 `fiberadapter.Middleware(s)` 一行装配、注入语义一致。v3 适配 fiber v3 的 API 差异：`Ctx` 为接口（handler 签名无指针）、请求上下文取 `c.Context()`（取代 v2 的 `c.UserContext()`）、fasthttp 入口为 `c.RequestCtx()`。**Go 工具链下限**：fiber v3 自身要求使用方 Go ≥ 1.25；Go 低于 1.25 的使用方继续用 `fiber-v2`——v2 adapter 长期保留，不随 v3 上线移除。

中间件只消费 `DecodeSession`；`UserService` 读写方法由业务代码经封装层 client 直接调用（§7），不走中间件。

## 3. 配置项

| 字段 | 必填 | 默认 | 说明 / 依据 |
|---|---|---|---|
| `BaseURL` | 是 | – | Authloft 服务基础地址，拼 Connect 路径 `/api.rpc.v1.TokenService/DecodeSession`；**须为纯 origin**（不带路径 / 查询 / 片段——签名 path 段即 Connect procedure，带路径会与服务端失配，构造期校验拒绝）；scheme 决定传输（`http://` → h2c、`https://` → ALPN，见 §7 传输层行） |
| `ClientID` / `ClientSecret` | 是 | – | 管理后台手动创建的 SSO 客户端凭据（需求 §4.4.4），参与 HMAC 五项签名（接口文档 §7） |
| `EnableGateway` | 否 | `false` | 网关模式开关，见 §4.1 |
| `GatewayPrefix` | 否 | `X-Session-` | 网关模式采信的响应头**前缀**，整体替换（§4.1）；未配置时即接口文档 §6 契约头名 |
| `CtxKey` | 否 | `uid` | 有效会话时注入 `c.Set(CtxKey, uid)`，只影响业务上下文键名，不涉契约 |
| `HeaderKey` | 否 | `X-Authloft-Token` | 令牌请求头键名，与服务端口径一致（接口文档 §6 / §7.1） |
| `CookieName` | 否 | `al_session` | 令牌 Cookie 名，默认值对齐需求 §4.4.1 |
| `CookieDomain` | 否 | 空 | Cookie 回写 `Domain` 属性：空 = 按业务应用请求 Host 自动推导根域名（最后两段）；非空 = **强制使用，不推导**；推导来源、降级规则与 `Set-Cookie` 五属性取值见 §4.4 |
| `CookieSecure` | 否 | `"true"` | `Secure` 属性三态：`"true"` 强制写 / `"false"` 强制不写 / `"auto"` 按业务应用请求协议自动推断（规则与兜底见 §4.4）；**类型为自定义字符串类型 + 三态常量**（非裸 string，拼错可检出），非法值 NewSDK 构造期 fail-fast；未配置（零值空串）≡ `"true"` |
| `HTTPClient` | 否 | SDK 自建传输 | 可选注入自定义 `http.Client`：nil 时 SDK 按 BaseURL scheme 自建传输（整体超时 10s）；注入后原样采用（超时归用户配置），SDK 仅在其 Transport 外包 HMAC 签名器 |

网关头前缀可配置（`GatewayPrefix`），取**前缀整体替换**而非逐头指定——网关层重映射头名时通常统一换前缀，一个配置项整体生效；逐头指定会裂成每头一项、易漏配且无独立语义。未配置时默认 `X-Session-`，与接口文档 §6 契约一致（SDK 按 `<前缀>Status` / `<前缀>ID` / … 拼头名读取）。令牌取值优先级 Header → Cookie 为固定行为，不提供开关。

## 4. 运行时流程

### 4.1 网关模式（EnableGateway = true）

- 适用：流量已经过可信网关——网关调接口文档 §6 `ANY /api/gateway/decode`，把解码结果以 `<前缀>*` 响应头（默认 `X-Session-*`）回注给下游。
- 判定：请求携带 `<前缀>Status` 头即视为「过了网关」，**直接采信网关结果，不再回源 RPC**——这是网关模式存在的意义（省去每请求一次 DecodeSession）。`EnableGateway = false` 时不读任何网关头。
- 行为：`<前缀>Status` 为 `valid` → 注入 uid 后放行；非 `valid` → 不注入 uid（匿名）放行；头不存在 → 落回标准模式（该请求未过网关）。
- Cookie 回写：**网关模式不回写 Cookie**（2026-11-05 写死，不留弹性）——网关头命中即采信、不回源 RPC，**没有 `renewedToken` 可传播**，`valid` / 非 `valid` 两条采信路径均不产生 `Set-Cookie`；头不存在落回标准模式（§4.2）后按标准模式回写，与网关采信路径无关（§4.4）。
- 头名与字段语义：头名 = `GatewayPrefix` + `SessionTokenPayload` 字段名大写（接口文档 §6 自身声明「不完整列出，详见 `SessionTokenPayload`」，映射以 payload 字段为准）。字段语义固定：**`id` = 用户 ID、`sid` = 会话 ID**——注入 uid 取 `<前缀>ID`（即 payload `id`，用户 ID）；`<前缀>SID` 为会话 ID、`<前缀>Epoch` 为安全版本号、`<前缀>AMR` 为认证方法（逗号分隔）。接口文档 §6 契约保持原样，本文档不提出任何修改。

### 4.2 标准模式（每请求回源）

1. 令牌取值优先级：`HeaderKey` 请求头 → `CookieName` Cookie（与接口文档 §6 优先级一致）；两处皆空 → 匿名放行。
2. 调 `TokenService/DecodeSession`（Connect 协议，签名由封装层负责，见 §5 / §7）；会话校验通过时响应携带 `renewedToken`。
3. `renewedToken` **原渠道覆盖传播**：令牌来自 Header → 写同名响应头；来自 Cookie → `Set-Cookie`（接口文档 §7.1「按原渠道落盘」；五属性与 `Domain` 推导口径见 §4.4）。业务侧对令牌始终不透明，只作串替换。
4. 会话有效 → 注入 uid（int64，`SessionResponse.Id`，业务侧断言 int64）；无效（HTTP 401 `unauthenticated`）→ 不注入 uid、**不写任何响应头**（不重签、不写存储，§7.1），匿名放行。
5. 本期不做本地令牌缓存：令牌加密自包含但 SDK 无密钥、不能本地校验；高频流量应走网关模式。

### 4.3 中间件伪代码（gin；fiber 同构）

```go
func ginMiddleware(sdk *SDK) gin.HandlerFunc {
  return func(c *gin.Context) {
    if sdk.cfg.EnableGateway {
      if status := c.GetHeader(sdk.cfg.GatewayPrefix + "Status"); status != "" {
        if status == "valid" {
          // <前缀>ID = payload.id = 用户 ID（§4.1）。网关头是 payload 的
          // HTTP 字符串形态，注入前 ParseInt 还原 int64（与标准模式
          // res.Id 同型）；非数字/缺失 → 匿名不注入
          //（语义规范优先于示意伪代码）
          if uid, perr := strconv.ParseInt(c.GetHeader(sdk.cfg.GatewayPrefix+"ID"), 10, 64); perr == nil {
            c.Set(sdk.cfg.CtxKey, uid)
          }
        }
        c.Next()
        return
      }
    }
    token, from := extractToken(c) // HeaderKey → CookieName，记录取值来源
    if token == "" {
      c.Next()
      return
    }
    res, err := sdk.DecodeSession(c, token) // 封装层公开方法：签名 / 超时 / 错误归一
    if err != nil || res == nil {
      c.Next() // 失败语义见 §5.1
      return
    }
    if res.RenewedToken != "" {
      propagate(c, from, res.RenewedToken) // 原渠道覆盖：SetHeader / SetCookie（Set-Cookie 属性与 Domain 口径见 §4.4）
    }
    c.Set(sdk.cfg.CtxKey, res.Id)
    c.Next()
  }
}
```

### 4.4 Cookie 回写属性与根域名口径（SDK 侧定稿；SameSite 联动 2026-11-06 修订）

`Set-Cookie` 五属性固定取值（回写时逐项写入，不留待定项）：

| 属性 | 取值 | 理由 / 取舍 |
|---|---|---|
| `HttpOnly` | `true` | 沿现状：令牌对页面 JS 不可读，防 XSS 窃取 |
| `Path` | `/` | 沿现状：根路径全站携带 |
| `Secure` | 由 `CookieSecure` 三态控制（§3，默认 `"true"`） | 三态行为与 `auto` 推断规则见表下条目；仅作用于标准模式回写路径（网关模式不回写 Cookie，§4.1，天然无涉） |
| `SameSite` | 随 `Secure` 联动（2026-11-06 定稿，取代 2026-11-05 恒 `Lax` 口径）：`Secure=true`（含 `auto` 推断为 https）→ `SameSite=None`；`Secure=false`（含 `auto` 推断为明文）→ `SameSite=Lax`；两分支均显式取值、不省略 | `None` 须配 `Secure`（无 `Secure` 的 `None` 被浏览器拒收），HTTPS 通道（写 `Secure`）取 `None`；明文通道 `None` 不可用 → `Lax` 兜底（允许顶级导航 GET 携带会话、阻断跨站 POST 送达）；与服务端 Cookie 联动口径一致（https_deployment：true→Secure+None / false→Lax） |
| `Max-Age` | 会话剩余寿命：`SessionResponse.exp − 当前时间`（秒） | 登录链路落的 `al_session` 是持久 Cookie（接口文档 §5.6 默认 7 天，键 `session_ttl`）；回写若不设 `Max-Age` 会把持久 Cookie 降级为会话级（关浏览器即丢会话），与服务端「每次重签续期」的滚动语义冲突。SDK 读 `DecodeSession` 响应的 `exp`（生成产物报文字段；服务端重签后 `exp` 已刷新）计算剩余寿命，续期一次、滚动一次，Cookie 寿命与服务端会话对齐 |

`Secure` 由配置项 `CookieSecure` 三态控制（§3；仅作用于标准模式回写路径，网关模式不回写 Cookie 天然无涉）：

| `CookieSecure` | 回写行为 |
|---|---|
| `"true"`（默认，未配置 ≡） | 强制写 `Secure`。提示（仅此分支）：明文 HTTP 环境下浏览器不会保存 Secure Cookie，选此取值须保证浏览器 ↔ 业务应用通道为 TLS |
| `"false"` | 强制不写 `Secure`（属性整体缺省） |
| `"auto"` | 按业务应用当前请求协议**逐请求自动推断**，规则与兜底见下 |

`auto` 推断规则（写死）：

1. 请求带 `X-Forwarded-Proto` 头 → 取逗号分隔**首个值**、忽略大小写判定：`https` → 写 `Secure`；`http` 及其他任意值 → 不写。
2. 头不存在 → 看请求自身 TLS（gin `c.Request.TLS != nil`，fiber 同构）：TLS 直连 → 写；无 TLS → 不写（**兜底**）。
3. 头优先于 TLS 判定：反代场景 TLS 终止在反代、应用侧收到明文 + 头，头是该场景唯一可靠来源；头与直连 TLS 并存且矛盾时，以显式头声明为准。

**兜底（无头且无 TLS → 不写）理由**：该形态即明文直连（本地 / 内网调试主场景），写 `Secure` 会被浏览器拒收、续期断链——明文环境不写正是 `auto` 的用途；反代漏传头属部署缺陷，应修反代补传头；对 `Secure` 有硬性要求的部署显式配 `"true"`。

**推断来源为何是业务应用请求协议而非 `BaseURL` scheme**：Cookie 落在**业务应用自身域名**上、随浏览器 ↔ 业务应用通道传输；`BaseURL` 是 SDK ↔ Authloft 服务端通道，两者协议可以不同（业务应用对外 HTTPS、内网回源明文 h2c），按 `BaseURL` 推断会答错通道。

`Domain` 属性优先级与推导（配置项 `CookieDomain`，§3）：

1. `CookieDomain` 非空 → **强制使用，不推导**（原样写入 `Domain` 属性，配置者自行负责合法性）。
2. 留空 → 自动推导：**取中间件所在业务应用当前请求的 Host**（剥端口后的主机名；反向代理场景下该 Host 即浏览器实际访问的域名，与 Cookie 可见域一致）**逐请求推导**——多段域名取**最后两段**为根域名（`a.b.example.com` → `example.com`），写入 `Domain=example.com`，**不带前导点**（RFC 6265 §5.2.3：解析时前导点会被剥除，两种写法等效，不带点为规范写法）。
3. 降级：推导来源为 **IPv4 / IPv6 字面量 / `localhost` / 单段主机名**（非域名形态）→ **不设 `Domain`**（host-only Cookie，仅当前主机可见）。

- **零新增依赖**：不引入 public suffix list（公有后缀表）。已知取舍：多段 TLD（如 `x.co.uk`）会按「最后两段」推出 `co.uk`——接受该误差，属既定取舍，不为精确 TLD 判定扩依赖。
- **运维提示（根域名变更）**：根域名变更后，旧根域下已签发的 Cookie 不会被新域 Cookie 覆盖清除（`Domain` 不同即两个独立 Cookie），需等其自然过期或由用户重新登录签发；切域前评估在线会话失效面。

## 5. 与 rpc 域契约对齐

| 项 | 口径 |
|---|---|
| 协议与路径 | Connect（接口文档 §1.0 / §7）：`POST /api.rpc.v1.TokenService/DecodeSession`、`POST /api.rpc.v1.UserService/<Method>`；客户端用生成产物 `rpcv1connect.NewTokenServiceClient` / `NewUserServiceClient` |
| 编码 | 推荐 `application/proto`（后端 §17「服务间调用推荐 Protobuf」）；SDK 对外不暴露编码选项 |
| 签名 | HMAC 五项 `client_id:nonce:path:body:client_secret`，请求头 `X-Client-ID` / `X-Nonce-ID` / `X-Signature`；**由封装层统一实现（RoundTripper 落地）**，SDK 使用方零感知（接口文档 §7） |
| 读写归类 | 按方法名前缀「命名决定校验」（接口文档 §7）：`DecodeSession` / `GetUserProfile` / `GetUserProfiles`（批量）= **读接口**（nonce 参与签名但不去重，可安全重试；`Get` 前缀不在写前缀集合 `Update` / `Delete` / `Set` / `Create` / `Revoke`，按命名决定校验归读——接口文档 §7.2 已定名）；`UpdateUserProfile` = **写接口**（服务端 nonce 去重 TTL 30s，SDK 禁自动重试） |
| 覆盖方法 | `TokenService/DecodeSession`（续期语义 §7.1）；`UserService/GetUserProfile`（响应为接口文档 §3.1 口径 Authloft 结构）、`UserService/UpdateUserProfile`（入参同接口文档 §3.2 `AccountService/UpdateProfile`）、`UserService/GetUserProfiles`（批量，契约要点见下，接口文档 §7.2 仍为唯一真相）——SDK 全量封装，使用方经封装层 client 直接调用 |
| 续期 | 服务端「校验通过即每次重签」，`renewedToken` 仅会话有效时返回（接口文档 §7.1）；SDK 侧只需收到即覆盖传播 |
| include_user_info | `DecodeSession` 可选用户信息携带（接口文档 §7.1）：请求 `DecodeSessionRequest.bool include_user_info = 2`、响应 `SessionResponse.ProfileResponse user_info = 8`（与 `GetUserProfile` 响应同构，复用 `ProfileResponse`）；session 无效仍 401 `unauthenticated`，该字段不改变失败分支。**SDK 中间件默认调用不携带该字段（protojson 省略零值），中间件行为零变化**——中间件只消费续期语义，不拉用户信息。`include_user_info=false` → 请求体**不得带**该字段；`true` → 响应按 protojson 标准口径解析 `user_info`。封装层如何暴露该参数（方法签名形态）归封装层实现设计，本文只写语义 |
| 错误体 | Connect 错误体 + `ErrorInfo`（接口文档 §1.5）；**init/adapter 层只消费标准码**（三态判定），**封装层做完整错误归一**（connect code + `X-Request-Id` + ErrorInfo detail 提取，见 §7）；批量方法复用既有归一层级、不预设新业务码（超限 `invalid_request` 属既有封闭集合） |

`UserService/GetUserProfiles` 契约要点（接口文档 §7.2 定稿；服务端 proto 与实现尚未落地，SDK 侧待 proto 落地后开工）：

- 入参 `GetUserProfilesRequest{ repeated int64 ids = 1 }`；出参 `GetUserProfilesResponse{ repeated ProfileResponse profiles = 1 }`——**复用既有 `ProfileResponse` 消息，不新增 profile 消息**（字段号均为 1）。
- 批量上限 **100（去重前计数）**；超限**整单** `invalid_request`（Connect 错误体 + ErrorInfo，接口文档 §1.5 / §1.6）。
- 缺失 id **跳过**（不占位、不补默认值、不报错、不终止整单）；返回顺序 = 入参**去重后**的顺序；重复 id 按**首现位置**去重；`ids` 缺省或空列表 → 空 `profiles` 不报错。
- **SDK 层三禁**：不得替调用方补齐缺失 id、不得改变顺序、不得静默截断超限 ids——超限直接把 `invalid_request` 经既有错误归一**原样**给上层。
- 读接口归类照旧（nonce 参与签名但不去重、可安全重试）；错误归一复用既有层级，`invalid_request` 属既有封闭集合，不新增业务码。

### 5.1 调用失败语义（fail-open）

`DecodeSession` 返回 401 → 会话无效，匿名放行；返回其他错误（网络失败 / 5xx / 429）→ 记录错误日志后同样匿名放行（不注入 uid、不写响应头）。SDK 不做 fail-closed 严格模式：网关模式与标准模式统一 fail-open，调用失败一律匿名放行、不阻断业务请求。

## 6. 与主仓库生成链的衔接

| 项 | 结论 |
|---|---|
| 唯一真相 | SDK 消费的报文 / 客户端类型全部来自 `server/proto/api/rpc/v1`（session.proto / token.proto）的生成产物，**SDK 不手写报文类型**（后端 §1.6「接口报文结构只定义一次」） |
| 落位 | 已拆独立仓库（原主仓库内 `sdk-go/` 迁出），**核心 module + 三个 adapter module**（结构见 §6.1）；SDK 在仓库根自有生成链（`buf.gen.yaml` 读本仓 `/proto`——CI 从主仓库拉取、不入库——`inputs.paths` 限定 rpc 域闭包）经 managed `go_package_prefix` 重映射为 `github.com/authloft/sdk-go/gen/go/**`，**产物入库 gen/、目录自包含**（`authloft` 裸名 module 不可 replace；搬独立仓须自带产物） |
| 入库与门禁 | 生成物已提交进 `server/gen/**`，受 CI 零 diff 门禁（`buf generate` 后 `git diff --exit-code`）与 `buf breaking`（基线 tag `pre-connect`）约束，仓库内落位下自动生效；SDK 侧另需新增 §6.1 零污染门禁步骤 |
| 版本对齐 | SDK 已拆独立仓库：proto 由 CI 从主仓库同步到本仓 `/proto` 再生成，`gen/**` 随仓走，版本经 CI 同步对齐 |
| proto 变更 | 走接口文档 §11 契约变更：先改 proto（`buf breaking` 只增字段、不改字段号），生成物随门禁更新，SDK 跟进；SDK 侧禁止自行改写序列化选项（后端 §1.6） |

### 6.1 工程形态与零污染隔离（gin / fiber-v2 / fiber-v3 adapter 可选引接）

目录结构：核心与三个 adapter **各自独立 go module**（fiber 双版本化，2026-11-07）。

```
go.work                        # 仅本地联编用，不进消费方依赖图
go.mod                         # module github.com/authloft/sdk-go（核心 + 封装层）
buf.gen.yaml                   # 自有生成链：读 /proto（CI 从主仓库同步、不入库），inputs.paths 限定 rpc 域闭包
gen/go/**                      # 生成产物：入库、目录自包含、禁止手改（与 server/gen 同纪律）
adapter/
  gin/      go.mod             # module github.com/authloft/sdk-go/adapter/gin
  fiber-v2/ go.mod             # module github.com/authloft/sdk-go/adapter/fiber-v2（gofiber/fiber/v2 v2.16.0）
  fiber-v3/ go.mod             # module github.com/authloft/sdk-go/adapter/fiber-v3（gofiber/fiber/v3 v3.0.0，要求使用方 Go ≥ 1.25）
examples/
  gin/                         # gin 示例
  fiber-v2/                    # fiber v2 示例（原 examples/fiber 改名）
  fiber-v3/                    # fiber v3 示例
```

- **go.mod 层面如何保证不引入**：gin / fiber 只出现在三个 adapter module 的 go.mod；核心 module 的 go.mod **不 require gin / fiber**。Go 依赖解析以 module 为边界——只 import 核心包的使用方，模块图走不到 adapter module，gin / fiber 及其传递依赖不可能进入依赖图与 go.sum。
- **为何不用 build tag**：build tag 只隔离编译路径，单 module 的 go.mod 仍会 require gin / fiber（进 go.sum 与模块图），达不到「依赖图零污染」；多 module 才是模块图层面的硬隔离。
- **CI 如何验证（零污染门禁）**：对核心 module 执行 `go list -deps ./...`，断言输出不含 `github.com/gin-gonic/` 与 `github.com/gofiber/`（如 `go list -deps ./... | grep -cE 'gin-gonic|gofiber'` 结果必须为 0）；另对三个 adapter module 各自 `go build ./...` 保证可编译。

## 7. 与 SDK 封装层的边界

SDK 分两层：**init/adapter 层**（本文）与**封装层**（connect client 封装，独立设计）。此处只定边界：

| 职责 | 归属 | 说明 |
|---|---|---|
| 配置装配、中间件注册、网关头采信 | init/adapter（本文） | §3 / §4 |
| 令牌提取 / renewedToken 传播 / uid 注入 | init/adapter（本文） | §4 |
| connect 客户端构造（BaseURL / 编码 / 超时） | 封装层 | 对 adapter 暴露 `DecodeSession(ctx, token)`（中间件 RPC 唯一依赖）与 `Config()`（配置只读）；`UserService` 方法由使用方经同一封装层 client 直接调用 |
| 传输层（H2C 兼容） | 封装层 | `http://` 明文 BaseURL → h2c prior-knowledge（`x/net/http2` AllowHTTP）；`https://` → 标准传输 ALPN 协商 H2；可注入自定义 `http.Client` 覆盖（服务端未配 TLS 时同端口 HTTP/1.1+H2C，后端架构 §3.1） |
| HMAC 五项签名 + nonce 生成 | 封装层（RoundTripper 落地） | 接口文档 §7；nonce 每请求新随机串 |
| 错误归一（Connect 错误体 → SDK 错误类型） | 封装层 | adapter 只区分「有效 / 无效 / 调用失败」三态 |
| 读写重试分流 | 封装层 | 读接口幂等、服务端不去重 → 可安全重试；写接口（`Update`/`Delete`/`Set`/`Create`/`Revoke` 前缀）禁自动重试 |
| 写接口（`UserService/UpdateUserProfile`） | 封装层 | 已纳入 SDK 范围：签名 / nonce 由封装层统一处理（RoundTripper 落地）；禁自动重试；错误归一同读接口 |
| 批量获取用户资料（`UserService/GetUserProfiles`） | 封装层 | 契约已由接口文档 §7.2 落定（服务端 proto 与实现尚未落地、SDK 侧待 proto 落地后开工）：读接口归类（nonce 参与签名但不去重、可安全重试）；入参 `ids`（`repeated int64`，字段号 1）/ 出参 `profiles`（`repeated ProfileResponse`，字段号 1，**复用既有消息不新增**）；上限 100（去重前计数）、超限整单 `invalid_request`；缺失 id 跳过、顺序 = 去重后顺序、重复 id 首现去重（要点全文见 §5）；**SDK 层三禁**：不替调用方补齐缺失 id、不改变顺序、不静默截断超限 ids——超限把 `invalid_request` 经既有错误归一**原样**给上层；错误归一复用既有 ErrorInfo 层级（`invalid_request` 属既有封闭集合）；生成链按 §6 既有口径（proto 唯一真相、自有生成链、禁手写产物），不重复展开 |

依赖方向：`adapter → 封装层 → sdk-go/gen`（生成产物 `github.com/authloft/sdk-go/gen/go/**`），不允许反向。

## 8. 多语言扩展

| 可复用（语言无关，直接照抄设计） | 不可复用（每语言重做） |
|---|---|
| 配置 schema 与默认值（§3） | connect-go 生成产物（各语言用各自 connect 生态生成） |
| 流程顺序：网关采信判定、令牌取值优先级、原渠道覆盖传播、失败三态 | gin / fiber adapter 与中间件注入方式 |
| 契约本身：§6 网关头、§7 签名串、§7.1 续期语义 | 封装层的签名 / 错误归一 / 重试实现 |
| 「读可重试、写禁重试」分流规则 | go module 工程与版本对齐机制 |
| 「核心 + 每框架一个独立 adapter module」的零污染隔离思路（各语言用其包管理器同构落地） | — |

扩展新语言的路径：proto 生成该语言 connect 客户端 → 实现封装层（签名 interceptor）→ 实现该语言主流框架的 adapter；三步各自独立验收。
