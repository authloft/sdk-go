module github.com/authloft/sdk-go/examples/gin

go 1.26.1

require (
	github.com/authloft/sdk-go v0.0.0
	github.com/authloft/sdk-go/adapter/gin v0.0.0
	github.com/gin-gonic/gin v1.12.0
)

require (
	connectrpc.com/connect v1.21.1 // indirect
	github.com/bytedance/gopkg v0.1.3 // indirect
	github.com/bytedance/sonic v1.15.0 // indirect
	github.com/bytedance/sonic/loader v0.5.0 // indirect
	github.com/cloudwego/base64x v0.1.6 // indirect
	github.com/gabriel-vasile/mimetype v1.4.12 // indirect
	github.com/gin-contrib/sse v1.1.0 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.30.1 // indirect
	github.com/goccy/go-json v0.10.5 // indirect
	github.com/goccy/go-yaml v1.19.2 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/quic-go/quic-go v0.59.0 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/ugorji/go/codec v1.3.1 // indirect
	go.mongodb.org/mongo-driver/v2 v2.5.0 // indirect
	golang.org/x/arch v0.22.0 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

// 示例是独立 module（docs/SDK-init.md §6.1 零污染形态的同款延伸）：嵌套
// module 目录会被核心 module 的 ./... 包遍历自动剪枝，示例的 gin import
// 不可能进入核心依赖图与 go.sum（核心零污染门禁不受影响）。
//
// 核心与 adapter 尚未发布远端（仓库内联编形态），经本地 replace 引用
// ——与 adapter go.mod 同款；本 module 未列入本仓 go.work，构建需
// GOWORK=off。迁移到独立仓库后删除 replace、改 go get（README「迁移」节）。
replace github.com/authloft/sdk-go => ../..

replace github.com/authloft/sdk-go/adapter/gin => ../../adapter/gin
