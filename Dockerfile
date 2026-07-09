# NothingDNS Dockerfile
# Multi-stage build for minimal image size
# Final image is FROM scratch with a stdlib-only static binary (no shared libraries)
# Supports multi-arch builds via docker buildx

# Build stage. L-12: tag-pinned for readability; for reproducible
# builds replace with a digest pin you've reviewed, e.g.
#   FROM golang:1.26.3-alpine@sha256:<digest> AS builder
# Renovate / Dependabot can keep a digest-pinned tag in sync. The
# final image is FROM scratch so build-stage drift only affects the
# binary, never the runtime surface.
FROM golang:1.26.5-alpine AS builder

# Install build dependencies (ca-certificates for TLS/DoH in final image)
RUN apk add --no-cache git make ca-certificates

# Set working directory
WORKDIR /build

# Copy go module files first (for layer caching) and verify module integrity
# against go.sum before building — fails the build if any cached module's hash
# does not match, closing a supply-chain tampering gap (V25).
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build binaries (uses TARGETARCH from buildx for multi-arch)
ARG TARGETARCH=amd64
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
    -trimpath \
    -ldflags "-s -w -extldflags '-static'" \
    -o nothingdns ./cmd/nothingdns

RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
    -trimpath \
    -ldflags "-s -w -extldflags '-static'" \
    -o dnsctl ./cmd/dnsctl

# Final stage - minimal scratch image
FROM scratch

# Metadata
LABEL org.opencontainers.image.title="NothingDNS"
LABEL org.opencontainers.image.description="Zero-dependency DNS server written in pure Go"
LABEL org.opencontainers.image.source="https://github.com/nothingdns/nothingdns"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Copy binaries from builder
COPY --from=builder /build/nothingdns /usr/local/bin/nothingdns
COPY --from=builder /build/dnsctl /usr/local/bin/dnsctl

# Copy CA certificates for TLS/DoH
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Create non-root user (using numeric ID for scratch compatibility)
USER 1000

# Expose DNS ports
# 53/udp - Standard DNS (UDP)
# 53/tcp - Standard DNS (TCP)
# 853/tcp - DNS over TLS (DoT)
# 443/tcp - DNS over HTTPS (DoH)
# 8080/tcp - REST API and Web Dashboard
# 9153/tcp - Prometheus metrics
EXPOSE 53/udp 53/tcp 853/tcp 443/tcp 8080/tcp 9153/tcp

# Set working directory
WORKDIR /data

# Volume for persistent data
VOLUME ["/data"]

# Default configuration path
ENV NOTHINGDNS_CONFIG=/etc/nothingdns/nothingdns.yaml

# Health check delegated to orchestrator (K8s/Docker Swarm) probes,
# OR run dnsctl in-image — it ships at /usr/local/bin/dnsctl and
# exits non-zero when the /health endpoint is unreachable. wget /
# curl are NOT in the scratch image (no shell either) so they cannot
# be used. See docker-compose.yml for the working pattern (M-9).
# Example:
#   healthcheck:
#     test: ["CMD", "/usr/local/bin/dnsctl", "server", "health"]
#     interval: 30s
#     timeout: 5s
#     retries: 3

# Entry point
ENTRYPOINT ["/usr/local/bin/nothingdns"]

# Default arguments
CMD ["-config", "/etc/nothingdns/nothingdns.yaml"]
