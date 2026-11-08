package sdk

import (
	"errors"
	"fmt"
	"testing"

	"connectrpc.com/connect"

	commonv1 "github.com/authloft/sdk-go/gen/go/api/common/v1"
	"google.golang.org/protobuf/types/known/anypb"
)

// unauthenticatedErr 构造服务端会话 401 的真实形态：裸 connect.Error +
// X-Request-Id 响应头、无 ErrorInfo detail（服务端 401 不挂 detail，
// server/internal/connect/interceptors.go 同款）。
func unauthenticatedErr() *connect.Error {
	cerr := connect.NewError(connect.CodeUnauthenticated, errors.New("auth required"))
	cerr.Meta().Set(requestIDHeader, "req-401-abc")
	return cerr
}

// businessErr 构造带 ErrorInfo detail 的业务失败（§1.5 行 203-210 形态）：
// too_many_requests + retry_after（§1.6 行 242 倒计时口径）。
func businessErr() *connect.Error {
	cerr := connect.NewError(connect.CodeResourceExhausted, errors.New("发送冷却中"))
	cerr.Meta().Set(requestIDHeader, "req-429-xyz")
	detail, err := connect.NewErrorDetail(&commonv1.ErrorInfo{
		Domain:     "sso",
		Code:       CodeTooManyRequests,
		Message:    "发送太频繁，请稍后再试",
		RetryAfter: 60,
	})
	if err != nil {
		panic(err)
	}
	cerr.AddDetail(detail)
	return cerr
}

func TestFromErrorNil(t *testing.T) {
	if err := FromError(nil); err != nil {
		t.Fatalf("FromError(nil) = %v, want nil", err)
	}
	if got := Classify(nil); got != Valid {
		t.Fatalf("Classify(nil) = %v, want Valid", got)
	}
}

func TestFromErrorUnauthenticated(t *testing.T) {
	cerr := unauthenticatedErr()
	err := FromError(cerr)
	serr, ok := err.(*Error)
	if !ok {
		t.Fatalf("FromError(*connect.Error) 类型 = %T, want *sdk.Error", err)
	}
	if got := serr.Code(); got != connect.CodeUnauthenticated {
		t.Errorf("Code() = %v, want unauthenticated", got)
	}
	if got := serr.Message(); got != "auth required" {
		t.Errorf("Message() = %q, want %q", got, "auth required")
	}
	if got := serr.RequestID(); got != "req-401-abc" {
		t.Errorf("RequestID() = %q, want %q", got, "req-401-abc")
	}
	if got := serr.ErrorInfo(); got != nil {
		t.Errorf("ErrorInfo() = %v, want nil（服务端 401 不挂 detail）", got)
	}
	// Unwrap 保留 *connect.Error 直达。
	var back *connect.Error
	if !errors.As(err, &back) || back != cerr {
		t.Error("errors.As 未取回原 *connect.Error")
	}
	if got := Classify(err); got != Invalid {
		t.Fatalf("Classify(401) = %v, want Invalid", got)
	}
}

func TestFromErrorBusinessDetail(t *testing.T) {
	err := FromError(businessErr())
	serr, ok := err.(*Error)
	if !ok {
		t.Fatalf("类型 = %T, want *sdk.Error", err)
	}
	info := serr.ErrorInfo()
	if info == nil {
		t.Fatal("ErrorInfo() = nil, want detail")
	}
	if info.GetDomain() != "sso" || info.GetCode() != CodeTooManyRequests {
		t.Errorf("domain/code = %q/%q, want sso/%s", info.GetDomain(), info.GetCode(), CodeTooManyRequests)
	}
	if info.GetMessage() != "发送太频繁，请稍后再试" {
		t.Errorf("message = %q", info.GetMessage())
	}
	if got := info.GetRetryAfter(); got != 60 {
		t.Errorf("RetryAfter = %d, want 60", got)
	}
	if got := info.GetAttemptsLeft(); got != 0 {
		t.Errorf("AttemptsLeft = %d, want 0（零值省略）", got)
	}
	if got := serr.RequestID(); got != "req-429-xyz" {
		t.Errorf("RequestID() = %q, want req-429-xyz", got)
	}
	if got := Classify(err); got != CallFailed {
		t.Fatalf("Classify(resource_exhausted) = %v, want CallFailed", got)
	}
}

func TestFromErrorInternalNoHeader(t *testing.T) {
	err := FromError(connect.NewError(connect.CodeInternal, errors.New("boom")))
	serr, ok := err.(*Error)
	if !ok {
		t.Fatalf("类型 = %T, want *sdk.Error", err)
	}
	if got := serr.RequestID(); got != "" {
		t.Errorf("RequestID() = %q, want 空串（响应未携带）", got)
	}
	if got := serr.ErrorInfo(); got != nil {
		t.Errorf("ErrorInfo() = %v, want nil", got)
	}
	if got := Classify(err); got != CallFailed {
		t.Fatalf("Classify(internal) = %v, want CallFailed", got)
	}
}

func TestFromErrorPlainErrorPassthrough(t *testing.T) {
	plain := errors.New("network down")
	if got := FromError(plain); !errors.Is(got, plain) {
		t.Fatalf("非 connect 错误应原样返回, got %v", got)
	}
	if got := Classify(plain); got != CallFailed {
		t.Fatalf("Classify(普通错误) = %v, want CallFailed", got)
	}
}

func TestFromErrorWrappedChain(t *testing.T) {
	wrapped := fmt.Errorf("call UserService: %w", unauthenticatedErr())
	err := FromError(wrapped)
	serr, ok := err.(*Error)
	if !ok {
		t.Fatalf("包裹链中的 connect 错误应被归一, got %T", err)
	}
	if got := serr.RequestID(); got != "req-401-abc" {
		t.Errorf("RequestID() = %q, want req-401-abc", got)
	}
	if got := Classify(wrapped); got != Invalid {
		t.Fatalf("Classify(包裹 401) = %v, want Invalid", got)
	}
}

func TestFromErrorSkipsUndecodableDetail(t *testing.T) {
	cerr := connect.NewError(connect.CodeUnauthenticated, errors.New("x"))
	// 未注册类型的 Any：解码失败应跳过、不 panic，且不阻断后续 detail。
	bad, aerr := connect.NewErrorDetail(&anypb.Any{
		TypeUrl: "type.googleapis.com/api.common.v1.NoSuchMessage",
		Value:   []byte{0},
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	good, derr := connect.NewErrorDetail(&commonv1.ErrorInfo{Domain: "sso", Code: CodeInvalidCode})
	if derr != nil {
		t.Fatal(derr)
	}
	cerr.AddDetail(bad)
	cerr.AddDetail(good)
	serr, ok := FromError(cerr).(*Error)
	if !ok {
		t.Fatalf("类型 = %T, want *sdk.Error", serr)
	}
	if serr.ErrorInfo() == nil || serr.ErrorInfo().GetCode() != CodeInvalidCode {
		t.Fatalf("应跳过不可解码 detail 取到下一枚 ErrorInfo, got %+v", serr.ErrorInfo())
	}
}

func TestFromErrorIdempotent(t *testing.T) {
	once := FromError(businessErr())
	twice := FromError(once)
	s2, ok := twice.(*Error)
	if !ok {
		t.Fatalf("二次归一应保持 *Error, got %T", twice)
	}
	if s2.RequestID() != "req-429-xyz" || s2.ErrorInfo() == nil {
		t.Fatalf("二次归一字段漂移: requestID=%q info=%v", s2.RequestID(), s2.ErrorInfo())
	}
}

// allDocCodes 是 §1.6 封闭集合（行 232-261）的第二份独立拷贝，锚定文档、
// 防止常量表与成员表漂移。
func TestBusinessCodeClosedSet(t *testing.T) {
	allDocCodes := []string{
		"next", "mfa_required", "binding_required", "success",
		"pending", "scanned", "expired",
		"failed",
		"captcha_required", "captcha_invalid",
		"too_many_requests", "too_many_attempts", "locked",
		"invalid_request", "invalid_credentials", "invalid_code", "code_expired",
		"method_disabled", "step_invalid", "token_invalid", "token_expired",
		"state_mismatch",
		"user_disabled", "user_not_found", "password_weak",
		"username_taken", "target_taken", "signup_disabled", "reset_disabled",
		"provider_disabled", "file_too_large", "file_type_not_allowed",
		"internal_error",
	}
	if len(allDocCodes) != len(knownCodes) {
		t.Fatalf("封闭集合成员数漂移: 常量表 %d, 文档词表 %d", len(knownCodes), len(allDocCodes))
	}
	for _, c := range allDocCodes {
		if !IsKnownCode(c) {
			t.Errorf("IsKnownCode(%q) = false, want true", c)
		}
		if got := NormalizeCode(c); got != c {
			t.Errorf("NormalizeCode(%q) = %q, want 原值", c, got)
		}
	}
}

func TestUnknownCodeFallback(t *testing.T) {
	if IsKnownCode("no_such_code") {
		t.Error("IsKnownCode(未知) 应为 false")
	}
	if got := NormalizeCode("no_such_code"); got != CodeUnknown {
		t.Errorf("NormalizeCode(未知) = %q, want %q", got, CodeUnknown)
	}
	if got := NormalizeCode(""); got != CodeUnknown {
		t.Errorf("NormalizeCode(空串) = %q, want %q", got, CodeUnknown)
	}
	if IsKnownCode(CodeUnknown) {
		t.Error("CodeUnknown 是 SDK 哨兵，不应算入 §1.6 封闭集合")
	}
	if got := NormalizeCode(CodeUnknown); got != CodeUnknown {
		t.Errorf("NormalizeCode 哨兵应稳定: got %q", got)
	}
}
