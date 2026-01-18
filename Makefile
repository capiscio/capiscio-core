.PHONY: all build-cli build-python test clean proto docs docker docker-build docker-run

all: build-cli build-python

# =============================================================================
# Docker targets for capiscio/guard
# =============================================================================
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DOCKER_IMAGE := capiscio/guard

docker: docker-build  ## Build Docker image (alias)

docker-build:  ## Build Docker image locally
	@echo "Building Docker image $(DOCKER_IMAGE):$(VERSION)..."
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		-t $(DOCKER_IMAGE):$(VERSION) \
		-t $(DOCKER_IMAGE):latest \
		.

docker-run:  ## Run Docker image locally (example)
	@echo "Running $(DOCKER_IMAGE):latest..."
	@echo "Usage: make docker-run TARGET=http://localhost:3000"
	docker run --rm -p 8080:8080 $(DOCKER_IMAGE):latest \
		gateway start --port 8080 --target $(TARGET) --registry-url https://registry.capisc.io

docker-push:  ## Push Docker image to registry (requires docker login)
	docker push $(DOCKER_IMAGE):$(VERSION)
	docker push $(DOCKER_IMAGE):latest

# =============================================================================
# Build targets
# =============================================================================
proto:
	@echo "Generating protobuf files..."
	cd proto && buf generate

docs:
	@echo "Generating API documentation..."
	@command -v gomarkdoc >/dev/null 2>&1 || go install github.com/princjef/gomarkdoc/cmd/gomarkdoc@latest
	gomarkdoc --output docs/reference/api.md ./pkg/...

build-cli:
	@echo "Building CLI..."
	@mkdir -p bin
	go build -o bin/capiscio ./cmd/capiscio

build-python:
	@echo "Building Python bindings..."
	go build -buildmode=c-shared -o bindings/python/libcapiscio.so ./bindings/python

test:
	@echo "Running tests..."
	go test -v ./...

fmt:
	@echo "Formatting code..."
	gofmt -s -w .

fmt-check:
	@echo "Checking code formatting..."
	@if [ -n "$$(gofmt -s -l .)" ]; then \
		echo "The following files are not formatted:"; \
		gofmt -s -l .; \
		exit 1; \
	fi

clean:
	@echo "Cleaning..."
	rm -rf bin
	rm -f bindings/python/libcapiscio.so bindings/python/libcapiscio.h
