package sdk

import (
	"errors"

	"connectrpc.com/connect"

	commonv1 "github.com/authloft/sdk-go/gen/go/api/common/v1"
)

// requestIDHeader 是服务端 requestid 中间件统一回写的响应头：request_id
// 不在错误体内，所有响应（含错误响应）一律走该头（接口文档 §1.5 行 223）。
const requestIDHeader = "X-Request-Id"

// Error 是 SDK 的归一错误类型：包装 *connect.Error（保留 Unwrap，调用方
// errors.As 可取回 connect 原始错误），并携带 Connect 标准码、错误文案、
// X-Request-Id 响应头与 details 中第一枚 ErrorInfo（接口文档 §1.5）。
// ErrorInfo 以生成类型整体暴露（domain / code / message / retry_after /
// attempts_left，§1.5 行 213-221），不猜字段、不另造结构。
type Error struct {
	connectErr *connect.Error
	requestID  string
	info       *commonv1.ErrorInfo
}

// FromError 归一 Connect 客户端调用返回的错误：
//   - nil → nil；
//   - 含 *connect.Error（含经 fmt.Errorf("%w") 等包裹）→ *Error，提取
//     X-Request-Id（connect-go 错误的 Meta 为响应 headers 与 trailers 的
//     并集）与 details 中第一枚 ErrorInfo；
//   - 其余错误（网络失败等无 Connect 语义的调用失败）原样返回。
//
// ErrorInfo 解码依赖生成类型的全局 proto 注册（本包 import commonv1 即
// 完成注册）；无法解码的 detail（如未注册类型）跳过，不视为错误。
func FromError(err error) error {
	if err == nil {
		return nil
	}
	var cerr *connect.Error
	if !errors.As(err, &cerr) || cerr == nil {
		return err
	}
	e := &Error{
		connectErr: cerr,
		requestID:  cerr.Meta().Get(requestIDHeader),
	}
	for _, detail := range cerr.Details() {
		msg, derr := detail.Value()
		if derr != nil {
			continue
		}
		if info, ok := msg.(*commonv1.ErrorInfo); ok {
			e.info = info
			break
		}
	}
	return e
}

// Code 返回 Connect 标准码（接口文档 §1.5 的标准码 → HTTP 映射）。
func (e *Error) Code() connect.Code {
	if e == nil {
		return connect.CodeUnknown
	}
	return e.connectErr.Code()
}

// Message 返回服务端错误文案；服务端未提供时为空串。
func (e *Error) Message() string {
	if e == nil {
		return ""
	}
	return e.connectErr.Message()
}

// RequestID 返回 X-Request-Id 响应头；响应未携带时为空串。
func (e *Error) RequestID() string {
	if e == nil {
		return ""
	}
	return e.requestID
}

// ErrorInfo 返回错误体 details 中第一枚 ErrorInfo（接口文档 §1.5 行
// 213-221）；无该类 detail 时返回 nil。生成 getter（GetDomain 等）零值安全。
func (e *Error) ErrorInfo() *commonv1.ErrorInfo {
	if e == nil {
		return nil
	}
	return e.info
}

// Error 实现 error 接口：Connect 码 + 服务端文案，带 request id 时附加。
func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	msg := e.connectErr.Error()
	if e.requestID == "" {
		return msg
	}
	return msg + " (request_id: " + e.requestID + ")"
}

// Unwrap 保留对底层 *connect.Error 的访问（errors.Is / errors.As 直达）。
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.connectErr
}

// Validity 是三态判定结果（SDK-init §7 行 159：adapter 只区分
// 「有效 / 无效 / 调用失败」；fail-open 语义见 SDK-init §5.1：
// 无效与调用失败均匿名放行）。
type Validity int

const (
	// Valid：调用成功（err == nil），会话有效。
	Valid Validity = iota
	// Invalid：Connect code unauthenticated（HTTP 401，接口文档 §1.5），会话无效。
	Invalid
	// CallFailed：其余错误（网络失败 / 5xx / 429 等），调用失败。
	CallFailed
)

// String 提供三态的可读输出（日志与测试）。
func (v Validity) String() string {
	switch v {
	case Valid:
		return "valid"
	case Invalid:
		return "invalid"
	case CallFailed:
		return "call_failed"
	default:
		return "unknown"
	}
}

// Classify 做三态判定（SDK-init §7 行 159 口径）：nil → 有效；
// Connect code unauthenticated → 无效；其余任何错误 → 调用失败。
// 对裸 *connect.Error 与经 FromError 归一的 *Error（含被 %w 包裹）均适用。
func Classify(err error) Validity {
	if err == nil {
		return Valid
	}
	var cerr *connect.Error
	if errors.As(err, &cerr) && cerr != nil && cerr.Code() == connect.CodeUnauthenticated {
		return Invalid
	}
	return CallFailed
}
