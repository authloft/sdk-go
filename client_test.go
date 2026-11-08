package sdk

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	accountv1 "github.com/authloft/sdk-go/gen/go/api/account/v1"
	commonv1 "github.com/authloft/sdk-go/gen/go/api/common/v1"
	rpcv1 "github.com/authloft/sdk-go/gen/go/api/rpc/v1"
	rpcv1connect "github.com/authloft/sdk-go/gen/go/api/rpc/v1/rpcv1connect"
)

const (
	testClientID = "sdk-test-client"
	testSecret   = "sdk-test-secret"
	testReqID    = "req-test-42"
)

// fakeTokenService 是 TokenService 的测试服务端：token 非空即有效并返回
// 固定 SessionResponse（含 renewed_token）；token 为空返回 401
// unauthenticated（接口文档 §7.1 会话无效形态）。指针 receiver：记录
// 最近一次请求收到的 include_user_info 与「请求体编码是否与仅 SessionToken
// 形态逐字节等值」（proto3 零值省略断言依据，SDK-init §9 条 16）；
// IncludeUserInfo=true 时响应附带 UserInfo（field 8 透传断言依据）。
type fakeTokenService struct {
	rpcv1connect.UnimplementedTokenServiceHandler
	gotIncludeUserInfo bool // 最近一次请求收到的 include_user_info
	bodyEqualTokenOnly bool // 最近一次请求体 marshal 与「仅 SessionToken」逐字节等值
}

func (f *fakeTokenService) DecodeSession(_ context.Context, req *connect.Request[rpcv1.DecodeSessionRequest]) (*connect.Response[rpcv1.SessionResponse], error) {
	if req.Msg.SessionToken == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("session token 无效"))
	}
	f.gotIncludeUserInfo = req.Msg.GetIncludeUserInfo()
	// proto3 零值省略：include_user_info=false → Marshal 结果与「仅
	// SessionToken」形态逐字节等值（字段不占字节）；true → 多出 field 2。
	body, merr := proto.Marshal(req.Msg)
	tokenOnly, terr := proto.Marshal(&rpcv1.DecodeSessionRequest{SessionToken: req.Msg.SessionToken})
	f.bodyEqualTokenOnly = merr == nil && terr == nil && bytes.Equal(body, tokenOnly)
	resp := &rpcv1.SessionResponse{
		Id:           10086,
		Epoch:        3,
		Amr:          []string{"pwd", "otp"},
		Sid:          "sid-test",
		Iat:          1761800000,
		Exp:          1762404800,
		RenewedToken: "renewed-abc",
	}
	if req.Msg.GetIncludeUserInfo() {
		resp.UserInfo = &rpcv1.ProfileResponse{
			Id:       10086,
			Username: "alice",
			Nickname: "Alice",
			Epoch:    3,
		}
	}
	return connect.NewResponse(resp), nil
}

// fakeUserService 是 UserService 的测试服务端：uid==10086 返回固定资料，
// 其余 404；updateCalls 计数 UpdateUserProfile 到达次数（写接口零重试
// 断言依据），updateErr 非 nil 时返回该错误；GetUserProfiles 模拟服务端
// 语义（接口文档 §7.2）：lastIDs 记录最近一次收到的 ids（SDK 透传断言
// 依据）、上限 100（去重前计数）超限整单 invalid_request、缺失 id 跳过、
// 重复 id 首现去重、顺序 = 入参去重后。
type fakeUserService struct {
	rpcv1connect.UnimplementedUserServiceHandler
	updateCalls atomic.Int32
	updateErr   error
	lastIDs     []int64
}

func (f *fakeUserService) GetUserProfile(_ context.Context, req *connect.Request[rpcv1.GetUserProfileRequest]) (*connect.Response[rpcv1.ProfileResponse], error) {
	if req.Msg.Uid != 10086 {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("用户不存在"))
	}
	return connect.NewResponse(&rpcv1.ProfileResponse{
		Id:            10086,
		Username:      "alice",
		Nickname:      "Alice",
		Phone:         "13800138000",
		PhoneVerified: 1,
		Email:         "alice@example.com",
		UserStatus:    1,
		Epoch:         3,
	}), nil
}

func (f *fakeUserService) UpdateUserProfile(_ context.Context, _ *connect.Request[rpcv1.UpdateUserProfileRequest]) (*connect.Response[rpcv1.OkResponse], error) {
	f.updateCalls.Add(1)
	if f.updateErr != nil {
		return nil, f.updateErr
	}
	return connect.NewResponse(&rpcv1.OkResponse{}), nil
}

// GetUserProfiles 模拟服务端语义（接口文档 §7.2）：ids > 100（去重前计数）
// → 整单 invalid_request（invalid_argument + ErrorInfo，§1.5 错误体形态）；
// 缺失 id 跳过；重复 id 首现去重；顺序 = 入参去重后。
func (f *fakeUserService) GetUserProfiles(_ context.Context, req *connect.Request[rpcv1.GetUserProfilesRequest]) (*connect.Response[rpcv1.GetUserProfilesResponse], error) {
	f.lastIDs = req.Msg.GetIds()
	if len(req.Msg.GetIds()) > 100 {
		cerr := connect.NewError(connect.CodeInvalidArgument, errors.New("ids 超过上限 100"))
		if d, derr := connect.NewErrorDetail(&commonv1.ErrorInfo{
			Domain:  "user",
			Code:    "invalid_request",
			Message: "ids 数量超过上限 100（去重前计数）",
		}); derr == nil {
			cerr.AddDetail(d)
		}
		return nil, cerr
	}
	seen := make(map[int64]struct{}, len(req.Msg.GetIds()))
	var profiles []*rpcv1.ProfileResponse
	for _, id := range req.Msg.GetIds() {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		switch id {
		case 10086:
			profiles = append(profiles, &rpcv1.ProfileResponse{
				Id:            10086,
				Username:      "alice",
				Nickname:      "Alice",
				Phone:         "13800138000",
				PhoneVerified: 1,
				Email:         "alice@example.com",
				UserStatus:    1,
				Epoch:         3,
			})
		case 20001:
			profiles = append(profiles, &rpcv1.ProfileResponse{
				Id:       20001,
				Username: "bob",
				Epoch:    1,
			})
		}
	}
	return connect.NewResponse(&rpcv1.GetUserProfilesResponse{Profiles: profiles}), nil
}

// startTestServer 起一个 Go 1.26 原生 h2c 测试服务端（同端口 HTTP/1.1 +
// H2C，与后端架构 §3.1 行 247-248 服务端口径一致），并预置 X-Request-Id
// 响应头（接口文档 §1.5：所有响应一律回写该头）。SDK 以 http:// BaseURL
// 打通即走 h2c prior-knowledge 通路；h1 客户端亦可打（Protocols 含
// HTTP1），供注入 HTTPClient 用例复用。
func startTestServer(t *testing.T, tokens rpcv1connect.TokenServiceHandler, users rpcv1connect.UserServiceHandler) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	if tokens != nil {
		path, h := rpcv1connect.NewTokenServiceHandler(tokens)
		mux.Handle(path, h)
	}
	if users != nil {
		path, h := rpcv1connect.NewUserServiceHandler(users)
		mux.Handle(path, h)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(requestIDHeader, testReqID)
		mux.ServeHTTP(w, r)
	}))
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	ts.Config.Protocols = protocols
	ts.Start()
	t.Cleanup(ts.Close)
	return ts
}

func mustNewSDK(t *testing.T, cfg Config) *SDK {
	t.Helper()
	s, err := NewSDK(cfg)
	if err != nil {
		t.Fatalf("NewSDK(%+v): %v", cfg, err)
	}
	return s
}

func TestDecodeSessionSuccess(t *testing.T) {
	ts := startTestServer(t, &fakeTokenService{}, nil)
	s := mustNewSDK(t, Config{BaseURL: ts.URL, ClientID: testClientID, ClientSecret: testSecret})
	resp, err := s.DecodeSession(context.Background(), "session-token-abc")
	if err != nil {
		t.Fatalf("DecodeSession: %v", err)
	}
	want := &rpcv1.SessionResponse{
		Id:           10086,
		Epoch:        3,
		Amr:          []string{"pwd", "otp"},
		Sid:          "sid-test",
		Iat:          1761800000,
		Exp:          1762404800,
		RenewedToken: "renewed-abc",
	}
	if !proto.Equal(resp, want) {
		t.Errorf("SessionResponse = %v, want %v（字段透传，含 renewed_token）", resp, want)
	}
}

func TestDecodeSessionInvalid(t *testing.T) {
	ts := startTestServer(t, &fakeTokenService{}, nil)
	s := mustNewSDK(t, Config{BaseURL: ts.URL, ClientID: testClientID, ClientSecret: testSecret})
	resp, err := s.DecodeSession(context.Background(), "")
	if err == nil {
		t.Fatalf("期望 401 错误，得到响应 %v", resp)
	}
	if got := Classify(err); got != Invalid {
		t.Errorf("Classify = %v, want Invalid（401 unauthenticated → 会话无效）", got)
	}
	serr, ok := err.(*Error)
	if !ok {
		t.Fatalf("错误类型 = %T, want *sdk.Error（FromError 归一）", err)
	}
	if got := serr.Code(); got != connect.CodeUnauthenticated {
		t.Errorf("Code() = %v, want unauthenticated", got)
	}
	if got := serr.RequestID(); got != testReqID {
		t.Errorf("RequestID() = %q, want %q（X-Request-Id 提取）", got, testReqID)
	}
}

func TestDecodeSessionCallFailed(t *testing.T) {
	ts := startTestServer(t, &fakeTokenService{}, nil)
	s := mustNewSDK(t, Config{BaseURL: ts.URL, ClientID: testClientID, ClientSecret: testSecret})
	ts.Close() // 模拟服务端不可达：h2c 拨号失败（连接拒绝）
	resp, err := s.DecodeSession(context.Background(), "session-token-abc")
	if err == nil {
		t.Fatalf("期望网络错误，得到响应 %v", resp)
	}
	if got := Classify(err); got != CallFailed {
		t.Errorf("Classify = %v, want CallFailed（网络失败）", got)
	}
	// connect-go 把传输层错误包装为 CodeUnavailable 的 *connect.Error，
	// FromError 归一为 *sdk.Error；无响应即无 X-Request-Id（空串）。
	serr, ok := err.(*Error)
	if !ok {
		t.Fatalf("错误类型 = %T, want *sdk.Error（connect-go 网络错误包装为 unavailable）", err)
	}
	if got := serr.Code(); got != connect.CodeUnavailable {
		t.Errorf("Code() = %v, want unavailable", got)
	}
	if got := serr.RequestID(); got != "" {
		t.Errorf("RequestID() = %q, want 空串（无响应头）", got)
	}
}

func TestGetUserProfile(t *testing.T) {
	ts := startTestServer(t, nil, &fakeUserService{})
	s := mustNewSDK(t, Config{BaseURL: ts.URL, ClientID: testClientID, ClientSecret: testSecret})

	resp, err := s.GetUserProfile(context.Background(), 10086)
	if err != nil {
		t.Fatalf("GetUserProfile: %v", err)
	}
	want := &rpcv1.ProfileResponse{
		Id:            10086,
		Username:      "alice",
		Nickname:      "Alice",
		Phone:         "13800138000",
		PhoneVerified: 1,
		Email:         "alice@example.com",
		UserStatus:    1,
		Epoch:         3,
	}
	if !proto.Equal(resp, want) {
		t.Errorf("ProfileResponse = %v, want %v", resp, want)
	}

	// 未知 uid → 404，FromError 归一为 *Error；非 unauthenticated →
	// Classify = CallFailed（三态口径，SDK-init §7 行 159）。
	resp, err = s.GetUserProfile(context.Background(), 404)
	if err == nil {
		t.Fatalf("期望 404，得到响应 %v", resp)
	}
	serr, ok := err.(*Error)
	if !ok {
		t.Fatalf("错误类型 = %T, want *sdk.Error（FromError 归一）", err)
	}
	if got := serr.Code(); got != connect.CodeNotFound {
		t.Errorf("Code() = %v, want not_found", got)
	}
	if got := Classify(err); got != CallFailed {
		t.Errorf("Classify = %v, want CallFailed", got)
	}
}

func TestUpdateUserProfile(t *testing.T) {
	svc := &fakeUserService{}
	ts := startTestServer(t, nil, svc)
	s := mustNewSDK(t, Config{BaseURL: ts.URL, ClientID: testClientID, ClientSecret: testSecret})

	okResp, err := s.UpdateUserProfile(context.Background(), &rpcv1.UpdateUserProfileRequest{
		Uid: 10086, Nickname: proto.String("新昵称"),
	})
	if err != nil {
		t.Fatalf("UpdateUserProfile: %v", err)
	}
	if okResp == nil {
		t.Error("OkResponse 不应为 nil（成功为空响应）")
	}

	// 错误归一：500 → *Error，Code 正确传递。
	svc.updateErr = connect.NewError(connect.CodeInternal, errors.New("boom"))
	_, err = s.UpdateUserProfile(context.Background(), &rpcv1.UpdateUserProfileRequest{Uid: 10086})
	if err == nil {
		t.Fatal("期望错误，得到 nil")
	}
	serr, ok := err.(*Error)
	if !ok {
		t.Fatalf("错误类型 = %T, want *sdk.Error（FromError 归一）", err)
	}
	if got := serr.Code(); got != connect.CodeInternal {
		t.Errorf("Code() = %v, want internal", got)
	}
}

// TestUpdateUserProfileNoRetry 断言写接口零自动重试（接口文档 §7「命名
// 决定校验」+ SDK-init §7 行 160-161：写接口服务端 nonce 去重 TTL 30s，
// 禁自动重试）：服务端持续报错，请求恰好到达一次——结构性保证来自传输
// 链无重试框架，本用例锁定该行为防回归。
func TestUpdateUserProfileNoRetry(t *testing.T) {
	svc := &fakeUserService{updateErr: connect.NewError(connect.CodeInternal, errors.New("boom"))}
	ts := startTestServer(t, nil, svc)
	s := mustNewSDK(t, Config{BaseURL: ts.URL, ClientID: testClientID, ClientSecret: testSecret})

	_, err := s.UpdateUserProfile(context.Background(), &rpcv1.UpdateUserProfileRequest{Uid: 10086})
	if err == nil {
		t.Fatal("期望错误，得到 nil")
	}
	if got := svc.updateCalls.Load(); got != 1 {
		t.Errorf("服务端收到 %d 次请求, want 1（写接口零自动重试）", got)
	}
}

// TestUpdateUserProfileOptionalWireSemantics 锁定 proto3 optional 三态的
// 序列化行为（与服务端同步，接口文档 §3.2 行 837 / §7 行 1423）：
// 未设置（nil）字段不出现在序列化请求体；显式设值（含空串 / 0）出现，
// has 位区分「未设置」与「零值」——服务端按 has 位判定改不改，字段在
// wire 上是否出现即语义本身；gender 0/1/2 = 保密/男/女（ISO 5218），
// 显式 &0 = 改回保密。
func TestUpdateUserProfileOptionalWireSemantics(t *testing.T) {
	// 三态之一「未设置」：nickname / avatar_url / profile 全 nil（含
	// Profile 子字段全部不构造）→ 序列化体不出现任何 optional 字段。
	unset := &rpcv1.UpdateUserProfileRequest{Uid: 10086}
	b, err := protojson.Marshal(unset)
	if err != nil {
		t.Fatalf("protojson.Marshal(unset): %v", err)
	}
	for _, absent := range []string{"nickname", "avatar_url", "profile"} {
		if bytes.Contains(b, []byte(`"`+absent+`"`)) {
			t.Errorf("未设置字段 %s 不应出现在序列化体, got %s", absent, b)
		}
	}

	// 三态之二「显式零值」：显式空串 nickname + 显式 gender=0 →
	// 序列化体携带这两个字段（has 位为真）。
	explicit := &rpcv1.UpdateUserProfileRequest{
		Uid:      10086,
		Nickname: proto.String(""),
		Profile:  &accountv1.UserProfile{Gender: proto.Int64(0)},
	}
	b, err = protojson.Marshal(explicit)
	if err != nil {
		t.Fatalf("protojson.Marshal(explicit): %v", err)
	}
	for _, want := range []string{`"nickname":""`, `"gender":"0"`} {
		if !bytes.Contains(b, []byte(want)) {
			t.Errorf("显式零值应出现在序列化体（%s）, got %s", want, b)
		}
	}

	// wire 往返后 has 位保真：显式空串 / 显式 gender=0 解码回来仍是
	//「已设置」（非 nil），与「未设置」可区分。
	wire, err := proto.Marshal(explicit)
	if err != nil {
		t.Fatalf("proto.Marshal(explicit): %v", err)
	}
	rt := &rpcv1.UpdateUserProfileRequest{}
	if err := proto.Unmarshal(wire, rt); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	if rt.Nickname == nil {
		t.Error("显式空串 wire 往返后 has 位丢失（Nickname = nil）")
	} else if got := *rt.Nickname; got != "" {
		t.Errorf("Nickname = %q, want 空串", got)
	}
	if rt.Profile == nil || rt.Profile.Gender == nil {
		t.Error("显式 gender=0 wire 往返后 has 位丢失（Profile/Gender = nil）")
	} else if got := *rt.Profile.Gender; got != 0 {
		t.Errorf("Gender = %d, want 0（显式改回保密）", got)
	}
}

// --- GetUserProfiles（UserService/GetUserProfiles，接口文档 §7.2）---

// TestGetUserProfilesPassthrough：ids 乱序重复上送（[3,1,3,2]）→ SDK 零
// 预处理（三禁，SDK-init §5）：fake 服务端收到的 Ids 与入参逐元素相等
//（顺序不变、不去重、不截断、不补齐）；响应 profiles 原样透传（fake 按
// 服务端语义只回 10086/20001 的资料，缺失 id 跳过）。
func TestGetUserProfilesPassthrough(t *testing.T) {
	svc := &fakeUserService{}
	ts := startTestServer(t, nil, svc)
	s := mustNewSDK(t, Config{BaseURL: ts.URL, ClientID: testClientID, ClientSecret: testSecret})

	ids := []int64{3, 10086, 3, 20001, 1, 10086}
	resp, err := s.GetUserProfiles(context.Background(), ids)
	if err != nil {
		t.Fatalf("GetUserProfiles: %v", err)
	}
	// 透传断言：服务端收到的 ids 与入参逐元素相等（含重复与乱序原样）。
	if got, want := svc.lastIDs, ids; len(got) != len(want) {
		t.Errorf("服务端收到 ids = %v, want %v（长度一致：不截断不去重）", got, want)
	} else {
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("服务端收到 ids[%d] = %d, want %d（顺序不变）", i, got[i], want[i])
			}
		}
	}
	// 响应透传：fake 按服务端语义去重后返回 10086 与 20001 两枚（3/1 跳过、
	// 重复 10086 首现去重、顺序 = 入参去重后）。
	want := &rpcv1.GetUserProfilesResponse{Profiles: []*rpcv1.ProfileResponse{
		{Id: 10086, Username: "alice", Nickname: "Alice", Phone: "13800138000",
			PhoneVerified: 1, Email: "alice@example.com", UserStatus: 1, Epoch: 3},
		{Id: 20001, Username: "bob", Epoch: 1},
	}}
	if !proto.Equal(resp, want) {
		t.Errorf("GetUserProfilesResponse = %v, want %v（原样透传）", resp, want)
	}
}

// TestGetUserProfilesOverLimit：101 ids（超上限 100，去重前计数）→ 服务端
// 整单 invalid_request → SDK 既有错误归一原样给上层：*Error + Connect 码
// invalid_argument + ErrorInfo.code = invalid_request + X-Request-Id 提取
//（不吞、不改写、不预设新业务码——invalid_request 属既有封闭集合）。
func TestGetUserProfilesOverLimit(t *testing.T) {
	svc := &fakeUserService{}
	ts := startTestServer(t, nil, svc)
	s := mustNewSDK(t, Config{BaseURL: ts.URL, ClientID: testClientID, ClientSecret: testSecret})

	ids := make([]int64, 101)
	for i := range ids {
		ids[i] = int64(i + 1)
	}
	resp, err := s.GetUserProfiles(context.Background(), ids)
	if err == nil {
		t.Fatalf("期望超限错误，得到响应 %v", resp)
	}
	if len(svc.lastIDs) != 101 {
		t.Errorf("服务端收到 %d 个 ids, want 101（SDK 不截断直接透传）", len(svc.lastIDs))
	}
	serr, ok := err.(*Error)
	if !ok {
		t.Fatalf("错误类型 = %T, want *sdk.Error（FromError 归一）", err)
	}
	if got := serr.Code(); got != connect.CodeInvalidArgument {
		t.Errorf("Code() = %v, want invalid_argument（超限整单拒绝）", got)
	}
	if info := serr.ErrorInfo(); info == nil || info.GetCode() != CodeInvalidRequest {
		t.Errorf("ErrorInfo.code = %v, want %q（不预设新业务码）", serr.ErrorInfo(), CodeInvalidRequest)
	}
	if got := serr.RequestID(); got != testReqID {
		t.Errorf("RequestID() = %q, want %q（X-Request-Id 提取）", got, testReqID)
	}
}

// TestGetUserProfilesEmptyIDs：空 ids（含 nil）→ 请求合法，空 profiles
// 不报错（接口文档 §7.2：ids 缺省或空列表 → 空 profiles）。
func TestGetUserProfilesEmptyIDs(t *testing.T) {
	svc := &fakeUserService{}
	ts := startTestServer(t, nil, svc)
	s := mustNewSDK(t, Config{BaseURL: ts.URL, ClientID: testClientID, ClientSecret: testSecret})

	for name, ids := range map[string][]int64{"空切片": {}, "nil": nil} {
		resp, err := s.GetUserProfiles(context.Background(), ids)
		if err != nil {
			t.Fatalf("%s: GetUserProfiles: %v", name, err)
		}
		if len(resp.GetProfiles()) != 0 {
			t.Errorf("%s: profiles = %v, want 空（空 ids → 空 profiles 不报错）", name, resp.GetProfiles())
		}
	}
}

// --- DecodeSessionWithInfo（include_user_info，接口文档 §7.1）---

// TestDecodeSessionWithInfoFalseOmitsField：includeUserInfo=false → proto3
// 零值省略，请求体不带 include_user_info 字段——fake 侧以「marshal 与仅
// SessionToken 形态逐字节等值」断言（field 2 不占字节）；中间件默认路径
//（DecodeSession 委托 false）行为零变化（SDK-init §9 条 16）。
func TestDecodeSessionWithInfoFalseOmitsField(t *testing.T) {
	svc := &fakeTokenService{}
	ts := startTestServer(t, svc, nil)
	s := mustNewSDK(t, Config{BaseURL: ts.URL, ClientID: testClientID, ClientSecret: testSecret})

	if _, err := s.DecodeSessionWithInfo(context.Background(), "session-token-abc", false); err != nil {
		t.Fatalf("DecodeSessionWithInfo(false): %v", err)
	}
	if svc.gotIncludeUserInfo {
		t.Error("服务端收到 include_user_info = true, want false")
	}
	if !svc.bodyEqualTokenOnly {
		t.Error("请求体与「仅 SessionToken」形态不等值（false 应省略 include_user_info 字段，不占字节）")
	}

	// 既有 DecodeSession（委托 false）同样省略该字段——中间件行为零变化。
	if _, err := s.DecodeSession(context.Background(), "session-token-abc"); err != nil {
		t.Fatalf("DecodeSession: %v", err)
	}
	if svc.gotIncludeUserInfo || !svc.bodyEqualTokenOnly {
		t.Error("DecodeSession 默认路径应等价 false（请求体不带 include_user_info）")
	}
}

// TestDecodeSessionWithInfoTrueIncludesField：includeUserInfo=true → 请求
// 带 IncludeUserInfo（marshal 多出 field 2 字节）；响应 user_info（field 8，
// *ProfileResponse，与 GetUserProfile 响应同构）原样透传。
func TestDecodeSessionWithInfoTrueIncludesField(t *testing.T) {
	svc := &fakeTokenService{}
	ts := startTestServer(t, svc, nil)
	s := mustNewSDK(t, Config{BaseURL: ts.URL, ClientID: testClientID, ClientSecret: testSecret})

	resp, err := s.DecodeSessionWithInfo(context.Background(), "session-token-abc", true)
	if err != nil {
		t.Fatalf("DecodeSessionWithInfo(true): %v", err)
	}
	if !svc.gotIncludeUserInfo {
		t.Error("服务端收到 include_user_info = false, want true")
	}
	if svc.bodyEqualTokenOnly {
		t.Error("请求体与「仅 SessionToken」形态等值（true 应多出 include_user_info 字段字节）")
	}
	wantInfo := &rpcv1.ProfileResponse{Id: 10086, Username: "alice", Nickname: "Alice", Epoch: 3}
	if !proto.Equal(resp.GetUserInfo(), wantInfo) {
		t.Errorf("SessionResponse.user_info = %v, want %v（field 8 透传）", resp.GetUserInfo(), wantInfo)
	}
}

// TestDecodeSessionWithInfoInvalid：session 无效（token 为空 → 401）→ 与
// DecodeSession 失败分支一致（include_user_info 不改变失败分支，SDK-init
// §9 条 16）：Classify = Invalid，*Error + unauthenticated。
func TestDecodeSessionWithInfoInvalid(t *testing.T) {
	ts := startTestServer(t, &fakeTokenService{}, nil)
	s := mustNewSDK(t, Config{BaseURL: ts.URL, ClientID: testClientID, ClientSecret: testSecret})

	for _, include := range []bool{false, true} {
		resp, err := s.DecodeSessionWithInfo(context.Background(), "", include)
		if err == nil {
			t.Fatalf("include=%v: 期望 401，得到响应 %v", include, resp)
		}
		if got := Classify(err); got != Invalid {
			t.Errorf("include=%v: Classify = %v, want Invalid（401 不随该字段改变）", include, got)
		}
		serr, ok := err.(*Error)
		if !ok {
			t.Fatalf("include=%v: 错误类型 = %T, want *sdk.Error", include, err)
		}
		if got := serr.Code(); got != connect.CodeUnauthenticated {
			t.Errorf("include=%v: Code() = %v, want unauthenticated", include, got)
		}
	}
}
