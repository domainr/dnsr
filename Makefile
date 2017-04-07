export GO_VERSION := 1.8.1
export GOROOT := /app/go
export GOPATH := /app/go2
export PATH := /app/go/bin:$(PATH)

install-go:
	./install-go.sh

update:
	go generate
