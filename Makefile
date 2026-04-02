GO ?= go

.PHONY: test build lint

test:
	$(GO) test ./...

build:
	$(GO) build ./...

lint:
	golangci-lint run ./...
