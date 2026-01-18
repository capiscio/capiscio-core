.PHONY: all build-cli build-python test clean proto docs

all: build-cli build-python

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
