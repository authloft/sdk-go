package sdk

import (
	"context"

	"connectrpc.com/connect"

	rpcv1 "github.com/authloft/sdk-go/gen/go/api/rpc/v1"
)

// DecodeSession 传入 Session Token 解码（TokenService/DecodeSession，接口
// 文档 §7.1），返回 *rpcv1.SessionResponse；renewed_token 字段原样透传——
// 续期回写（原渠道覆盖传播）归 adapter / 调用方（SDK-init §4.2 步骤 3、
// §7 封装层边界），本方法不做任何存储或响应头操作。不携带用户信息
//（include_user_info 零值省略，请求体不带该字段，SDK-init §9 条 16）。
//
// 读接口（Decode 前缀不在写前缀集合，接口文档 §7 命名决定校验）：nonce
// 参与签名但服务端不去重。错误一律经 FromError 归一（*connect.Error →
// *Error，携带 X-Request-Id 与 ErrorInfo；三态判定用 Classify：401 →
// Invalid，其余 → CallFailed）。
func (s *SDK) DecodeSession(ctx context.Context, token string) (*rpcv1.SessionResponse, error) {
	return s.DecodeSessionWithInfo(ctx, token, false)
}

// DecodeSessionWithInfo 是 DecodeSession 的携带用户信息形态（接口文档
// §7.1 include_user_info，SDK-init §9 条 16）：includeUserInfo=true → 请求
// 带 IncludeUserInfo，会话有效时响应 user_info 为 *rpcv1.ProfileResponse
//（与 GetUserProfile 响应同构，原样透传）；false → proto 编码省略零值，
// 请求体不带该字段（与 DecodeSession 等价）。session 无效仍 401
// unauthenticated，该字段不改变失败分支；三态判定 / 错误归一同
// DecodeSession。
//
// 中间件不调用本方法（仍调 DecodeSession，中间件行为零变化——SDK-init
// §5 include_user_info 行）；需要用户信息的业务代码直调本方法。
func (s *SDK) DecodeSessionWithInfo(ctx context.Context, token string, includeUserInfo bool) (*rpcv1.SessionResponse, error) {
	resp, err := s.tokens.DecodeSession(ctx,
		connect.NewRequest(&rpcv1.DecodeSessionRequest{
			SessionToken:    token,
			IncludeUserInfo: includeUserInfo,
		}))
	if err != nil {
		return nil, FromError(err)
	}
	return resp.Msg, nil
}

// GetUserProfile 读用户资料（UserService/GetUserProfile，接口文档 §7），
// 响应 *rpcv1.ProfileResponse 为 §3.1 口径的 Authloft 结构。读接口。
// 错误归一同 DecodeSession。
func (s *SDK) GetUserProfile(ctx context.Context, uid int64) (*rpcv1.ProfileResponse, error) {
	resp, err := s.users.GetUserProfile(ctx,
		connect.NewRequest(&rpcv1.GetUserProfileRequest{Uid: uid}))
	if err != nil {
		return nil, FromError(err)
	}
	return resp.Msg, nil
}

// GetUserProfiles 批量读用户资料（UserService/GetUserProfiles，接口文档
// §7.2；SDK-init §5 契约要点、§9 条 12），返回 *rpcv1.GetUserProfilesResponse。
//
// ids 原样透传（SDK 层三禁，SDK-init §5）：不补齐缺失 id、不改变顺序、
// 不去重、不静默截断超限——服务端语义：上限 100（去重前计数）超限整单
// invalid_request、缺失 id 跳过、返回顺序 = 入参去重后、重复 id 首现去重，
// 全部在服务端做，SDK 零预处理。响应 profiles 原样透传（不补默认值、
// 不吞缺失项、不排序）。超限 / 参数错误经既有 FromError 归一原样给上层
//（invalid_request 属既有封闭集合，不预设新业务码）。
//
// 读接口（Get 前缀归读，接口文档 §7.2 命名决定校验）：nonce 参与签名但
// 服务端不去重，可安全重试。
func (s *SDK) GetUserProfiles(ctx context.Context, ids []int64) (*rpcv1.GetUserProfilesResponse, error) {
	resp, err := s.users.GetUserProfiles(ctx,
		connect.NewRequest(&rpcv1.GetUserProfilesRequest{Ids: ids}))
	if err != nil {
		return nil, FromError(err)
	}
	return resp.Msg, nil
}

// UpdateUserProfile 改用户资料（UserService/UpdateUserProfile，接口文档
// §7）：入参 *rpcv1.UpdateUserProfileRequest（uid + §3.2 三可改字段
// nickname / avatar_url / profile），成功返回 *rpcv1.OkResponse（空响应）。
//
// proto3 optional 三态语义（§3.2 行 837 / §7 行 1423，与服务端同步）：
// nickname / avatar_url 及 Profile 子字段（gender / birthday / locale /
// timezone / extra）均为指针 + has 位形态——**未设置（nil）= 不修改，
// 显式设值（含空串 / 0）= 覆盖**，has 位区分「未设置」与「零值」；
// gender 取值 0/1/2 = 保密/男/女（ISO 5218），显式 &0 可改回保密。本方法
// 原样透传请求（零字段拷贝、零零值化），nil 字段序列化时不出现在请求体，
// 天然只发送调用方显式设置的字段；req 为 nil 时替换为全字段 nil 的空请求
// （uid=0 + 空 body），服务端已实装为合法空操作 no-op。
//
// 写接口（Update 前缀命中接口文档 §7「命名决定校验」五前缀）：服务端
// nonce 去重 TTL 30s → 禁自动重试。本 SDK 结构性零重试（传输链无重试
// 框架，SDK-init §7 行 160-161）：任何错误一次归一返回，调用方自行决定
// 后续动作。
func (s *SDK) UpdateUserProfile(ctx context.Context, req *rpcv1.UpdateUserProfileRequest) (*rpcv1.OkResponse, error) {
	if req == nil {
		req = &rpcv1.UpdateUserProfileRequest{}
	}
	resp, err := s.users.UpdateUserProfile(ctx, connect.NewRequest(req))
	if err != nil {
		return nil, FromError(err)
	}
	return resp.Msg, nil
}
