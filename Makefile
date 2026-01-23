.PHONY: test build

test:
	go test -race ./...

build:
	go build ./...
