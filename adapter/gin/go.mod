module github.com/authloft/sdk-go/adapter/gin

go 1.26.1

require (
	connectrpc.com/connect v1.21.1
	github.com/authloft/sdk-go v0.0.0
	github.com/gin-gonic/gin v1.3.0
)

require (
	github.com/gin-contrib/sse v1.1.0 // indirect
	github.com/golang/protobuf v1.5.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/rogpeppe/go-internal v1.10.0 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	github.com/ugorji/go/codec v1.3.1 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/go-playground/assert.v1 v1.2.1 // indirect
	gopkg.in/go-playground/validator.v8 v8.18.2 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

// GOWORK=off 时经本地 replace 引核心 module（docs/SDK-init.md §6.1）。
replace github.com/authloft/sdk-go => ../..
