package sdk

// 业务码常量表：接口文档 §1.6「状态（status）与前端动作」词汇表的封闭集合。
// 一套词汇、两个位置（§1.6 行 267）：登录流程域作响应顶层 status（HTTP 200
// 数据，§1.3），其余域作 ErrorInfo.code（Connect 错误体 details，§1.5）。
// 新增取值必须先更新 §1.6（封闭集合，行 270），本表随之同步；禁止在错误响应
// 里塞第二个分支字段（行 270）。注释中的行号均指 docs/接口文档.md。

// 流程态（§1.6 行 232-235：登录流程信封顶层 status）。
const (
	CodeNext            = "next"             // 行 232：流程未结束，按 next_step 继续
	CodeMfaRequired     = "mfa_required"     // 行 233：主因子已过，需二次验证
	CodeBindingRequired = "binding_required" // 行 234：三方身份未绑定，需用户选择
	CodeSuccess         = "success"          // 行 235：完成登录
)

// 扫码轮询态（§1.6 行 236-238：轮询顶层 status 与 ticket.status 同步语义）。
const (
	CodePending = "pending" // 行 236：票据未扫码
	CodeScanned = "scanned" // 行 237：已扫码、未确认
	CodeExpired = "expired" // 行 238：票据已过期（终态）
)

// 通用失败与人机校验 / 限流类（§1.6 行 239-244）。
const (
	CodeFailed          = "failed"            // 行 239：通用失败（未知异常兜底）
	CodeCaptchaRequired = "captcha_required"  // 行 240：缺少人机校验凭据
	CodeCaptchaInvalid  = "captcha_invalid"   // 行 241：人机校验失败 / 已使用
	CodeTooManyRequests = "too_many_requests" // 行 242：发送冷却或日限额
	CodeTooManyAttempts = "too_many_attempts" // 行 243：验证码尝试次数超限
	CodeLocked          = "locked"            // 行 244：密码登录被临时禁止
)

// 请求 / 凭证 / 流程态校验类（§1.6 行 245-252）。
const (
	CodeInvalidRequest     = "invalid_request"     // 行 245：参数缺失 / 格式错误
	CodeInvalidCredentials = "invalid_credentials" // 行 246：账号或密码错误（与不存在同码）
	CodeInvalidCode        = "invalid_code"        // 行 247：验证码错误
	CodeCodeExpired        = "code_expired"        // 行 248：验证码过期 / 已作废
	CodeMethodDisabled     = "method_disabled"     // 行 249：登录方式已关闭
	CodeStepInvalid        = "step_invalid"        // 行 250：当前状态不允许该 step
	CodeTokenInvalid       = "token_invalid"       // 行 251：login_token 篡改
	CodeTokenExpired       = "token_expired"       // 行 251：login_token 过期
	CodeStateMismatch      = "state_mismatch"      // 行 252：三方回调 state 校验失败
)

// 用户 / 资源 / 开关类（§1.6 行 253-261）。
const (
	CodeUserDisabled       = "user_disabled"         // 行 253：账号被禁用
	CodeUserNotFound       = "user_not_found"        // 行 254：账号不存在 / 目标未绑定
	CodePasswordWeak       = "password_weak"         // 行 255：不满足密码策略
	CodeUsernameTaken      = "username_taken"        // 行 256：用户名占用于他人
	CodeTargetTaken        = "target_taken"          // 行 256：手机号 / 邮箱占用，或三方已绑他号
	CodeSignupDisabled     = "signup_disabled"       // 行 257：注册已关闭
	CodeResetDisabled      = "reset_disabled"        // 行 258：自助重置已关闭
	CodeProviderDisabled   = "provider_disabled"     // 行 259：提供方未启用 / 不允许登录
	CodeFileTooLarge       = "file_too_large"        // 行 260：上传超限
	CodeFileTypeNotAllowed = "file_type_not_allowed" // 行 260：上传类型不合规
	CodeInternalError      = "internal_error"        // 行 261：内部错误
)

// CodeUnknown 是 SDK 侧兜底哨兵，不是协议词汇：ErrorInfo.code 取值不在 §1.6
// 封闭集合时归一为此值（封闭集合不因此扩员，§1.6 行 270）。
const CodeUnknown = "unknown"

// knownCodes 是 §1.6 封闭集合成员表，与上方常量一一对应。
var knownCodes = map[string]struct{}{
	CodeNext:               {},
	CodeMfaRequired:        {},
	CodeBindingRequired:    {},
	CodeSuccess:            {},
	CodePending:            {},
	CodeScanned:            {},
	CodeExpired:            {},
	CodeFailed:             {},
	CodeCaptchaRequired:    {},
	CodeCaptchaInvalid:     {},
	CodeTooManyRequests:    {},
	CodeTooManyAttempts:    {},
	CodeLocked:             {},
	CodeInvalidRequest:     {},
	CodeInvalidCredentials: {},
	CodeInvalidCode:        {},
	CodeCodeExpired:        {},
	CodeMethodDisabled:     {},
	CodeStepInvalid:        {},
	CodeTokenInvalid:       {},
	CodeTokenExpired:       {},
	CodeStateMismatch:      {},
	CodeUserDisabled:       {},
	CodeUserNotFound:       {},
	CodePasswordWeak:       {},
	CodeUsernameTaken:      {},
	CodeTargetTaken:        {},
	CodeSignupDisabled:     {},
	CodeResetDisabled:      {},
	CodeProviderDisabled:   {},
	CodeFileTooLarge:       {},
	CodeFileTypeNotAllowed: {},
	CodeInternalError:      {},
}

// IsKnownCode 判断业务码是否在接口文档 §1.6 封闭集合内。
func IsKnownCode(code string) bool {
	_, ok := knownCodes[code]
	return ok
}

// NormalizeCode 把业务码归一为封闭集合内的值：未知取值（含空串）归一为
// CodeUnknown，不 panic（未知 code 兜底口径）。
func NormalizeCode(code string) string {
	if IsKnownCode(code) {
		return code
	}
	return CodeUnknown
}
