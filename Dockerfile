# syntax=docker/dockerfile:1

# ============================================================================
# CapiscIO Guard - Security Sidecar for AI Agents
# ============================================================================
# Multi-stage build for a minimal, secure container image.
#
# Usage:
#   docker pull capiscio/guard
#   docker run -p 8080:8080 capiscio/guard \
#     gateway start --port 8080 --target http://your-agent:3000 --registry-url https://registry.capisc.io
#
# Build locally:
#   docker build -t capiscio/guard .
#   docker build --build-arg VERSION=v2.3.0 -t capiscio/guard:v2.3.0 .
# ============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Build
# -----------------------------------------------------------------------------
FROM golang:1.24-alpine AS builder

# Build arguments
ARG VERSION=dev
ARG COMMIT=unknown

# Install build dependencies
RUN apk add --no-cache git ca-certificates

WORKDIR /src

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build static binary with version info
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -o /capiscio \
    ./cmd/capiscio

# -----------------------------------------------------------------------------
# Stage 2: Runtime (distroless for security)
# -----------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

# Labels for container registry
LABEL org.opencontainers.image.title="CapiscIO Guard"
LABEL org.opencontainers.image.description="Security Sidecar for AI Agents - Universal Authority Layer"
LABEL org.opencontainers.image.url="https://capisc.io"
LABEL org.opencontainers.image.source="https://github.com/capiscio/capiscio-core"
LABEL org.opencontainers.image.vendor="CapiscIO"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Copy binary from builder
COPY --from=builder /capiscio /capiscio

# Expose default gateway port
EXPOSE 8080

# Health check - verify binary is runnable
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/capiscio", "--version"]

# Run as non-root user (distroless nonroot = uid 65532)
USER nonroot:nonroot

# Default entrypoint
ENTRYPOINT ["/capiscio"]

# Default command (show help)
CMD ["--help"]
