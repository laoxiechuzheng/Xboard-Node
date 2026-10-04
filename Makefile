.DEFAULT_GOAL := build

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.commit=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
XRAY_TASK_OVERLAY := $(CURDIR)/.xray-task-overlay/overlay.json
XRAY_BUILD_MODULE := $(CURDIR)/.xray-task-overlay/build.mod
XRAY_BUILD_FLAGS := -mod=readonly -modfile="$(XRAY_BUILD_MODULE)" -overlay="$(XRAY_TASK_OVERLAY)"

.PHONY: prepare-xray-task-overlay build clean test docker install build-linux build-linux-arm64 build-all

prepare-xray-task-overlay:
	go run ./tools/xray-task-overlay

# Build for current platform
build: prepare-xray-task-overlay
	go build $(XRAY_BUILD_FLAGS) -ldflags "$(LDFLAGS)" -tags "with_quic with_utls with_wireguard with_clash_api" -o xboard-node ./cmd/xboard-node
	go build $(XRAY_BUILD_FLAGS) -ldflags "$(LDFLAGS)" -o xbctl ./cmd/xbctl

# Build for Linux amd64
build-linux: prepare-xray-task-overlay
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(XRAY_BUILD_FLAGS) -ldflags "$(LDFLAGS)" -tags "with_quic with_utls with_wireguard with_acme with_clash_api" -o xboard-node-linux-amd64 ./cmd/xboard-node
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(XRAY_BUILD_FLAGS) -ldflags "$(LDFLAGS)" -o xbctl-linux-amd64 ./cmd/xbctl

# Build for Linux arm64
build-linux-arm64: prepare-xray-task-overlay
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(XRAY_BUILD_FLAGS) -ldflags "$(LDFLAGS)" -tags "with_quic with_utls with_wireguard with_acme with_clash_api" -o xboard-node-linux-arm64 ./cmd/xboard-node
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(XRAY_BUILD_FLAGS) -ldflags "$(LDFLAGS)" -o xbctl-linux-arm64 ./cmd/xbctl

# Build all platforms
build-all: build-linux build-linux-arm64

# Run tests
test: prepare-xray-task-overlay
	go test $(XRAY_BUILD_FLAGS) -v -race -count=1 ./tools/xray-task-overlay ./cmd/xbctl
	go test $(XRAY_BUILD_FLAGS) -v -race -count=1 '-gcflags=github.com/xtls/xray-core/proxy/vless/...=-d=checkptr=0' $$(go list $(XRAY_BUILD_FLAGS) ./internal/... | grep -v '/internal/kernel/singbox$$')
	# The sing-box package also runs its Hysteria2 QUIC tests, which need with_quic.
	go test $(XRAY_BUILD_FLAGS) -v -race -count=1 -tags with_quic ./internal/kernel/singbox

# Clean build artifacts
clean:
	rm -f xboard-node xbctl xboard-node-linux-* xbctl-linux-*

# Build Docker image
docker:
	docker build -t xboard-node:$(VERSION) -t xboard-node:latest .

# Install to system (single node, legacy compat)
install: build
	sudo cp xboard-node /usr/local/bin/
	sudo cp xbctl /usr/local/bin/
	sudo mkdir -p /etc/xboard-node
	@if [ ! -f /etc/xboard-node/config.yml ]; then \
		sudo cp config.yml.example /etc/xboard-node/config.yml; \
		echo "Config copied to /etc/xboard-node/config.yml - please edit it"; \
	fi
