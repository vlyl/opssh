BINARY := opssh
GO ?= go

.PHONY: build test lint race snapshot security-audit clean

build:
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -o bin/$(BINARY) .

test:
	$(GO) test -mod=readonly ./...

lint:
	golangci-lint run ./...

race:
	$(GO) test -mod=readonly -race ./...

security-audit:
	$(GO) test -mod=readonly ./internal/security ./internal/onepassword ./internal/process
	$(GO) run -mod=readonly . security audit

snapshot:
	goreleaser release --snapshot --clean

clean:
	rm -rf ./bin ./dist
