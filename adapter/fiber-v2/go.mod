module github.com/authloft/sdk-go/adapter/fiber-v2

go 1.26.1

require (
	connectrpc.com/connect v1.21.1
	github.com/authloft/sdk-go v0.0.0
	github.com/gofiber/fiber/v2 v2.16.0
)

require (
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasthttp v1.51.0 // indirect
	github.com/valyala/tcplisten v1.0.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

// GOWORK=off 时经本地 replace 引核心 module（docs/SDK-init.md §6.1）。
replace github.com/authloft/sdk-go => ../..
