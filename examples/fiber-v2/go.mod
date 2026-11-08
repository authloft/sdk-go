module github.com/authloft/sdk-go/examples/fiber-v2

go 1.26.1

require (
	github.com/authloft/sdk-go v0.0.0
	github.com/authloft/sdk-go/adapter/fiber-v2 v0.0.0
	github.com/gofiber/fiber/v2 v2.52.16
)

require (
	connectrpc.com/connect v1.21.1 // indirect
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/rivo/uniseg v0.2.0 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasthttp v1.51.0 // indirect
	github.com/valyala/tcplisten v1.0.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

// 示例是独立 module（docs/SDK-init.md §6.1 零污染形态的同款延伸）：嵌套
// module 目录会被核心 module 的 ./... 包遍历自动剪枝，示例的 fiber import
// 不可能进入核心依赖图与 go.sum（核心零污染门禁不受影响）。
//
// 核心与 adapter 尚未发布远端（仓库内联编形态），经本地 replace 引用
// ——与 adapter go.mod 同款；本 module 未列入本仓 go.work，构建需
// GOWORK=off。迁移到独立仓库后删除 replace、改 go get（README「迁移」节）。
replace github.com/authloft/sdk-go => ../..

replace github.com/authloft/sdk-go/adapter/fiber-v2 => ../../adapter/fiber-v2
