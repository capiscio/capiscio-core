.PHONY: all build-cli build-python test clean proto

all: build-cli build-python

proto:
	@echo "Generating protobuf files..."
	cd proto && buf generate

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
