.PHONY: all build-cli build-python test clean

all: build-cli build-python

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

clean:
	@echo "Cleaning..."
	rm -rf bin
	rm -f bindings/python/libcapiscio.so bindings/python/libcapiscio.h
