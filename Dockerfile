# NothingDNS Dockerfile
# Multi-stage build for minimal image size
# Final image is FROM scratch with zero dependencies
# Supports multi-arch builds via docker buildx

# Build stage
FROM golang:1.26.2-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

# Set working directory
WORKDIR /build

# Copy go module files
COPY go.mod ./

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

# Health check (using the dnsctl tool)
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/dnsctl", "-server", "http://localhost:8080", "server", "health"]

# Set working directory
WORKDIR /data

# Volume for persistent data
VOLUME ["/data"]

# Default configuration path
ENV NOTHINGDNS_CONFIG=/etc/nothingdns/nothingdns.yaml

# Entry point
ENTRYPOINT ["/usr/local/bin/nothingdns"]

# Default arguments
CMD ["-config", "/etc/nothingdns/nothingdns.yaml"]
