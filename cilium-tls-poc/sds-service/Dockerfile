# Multi-stage build for minimal final image
FROM golang:1.23-alpine AS builder

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source
COPY main.go ./

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a \
    -ldflags '-w -s -extldflags "-static"' \
    -o sds-service main.go

# Final minimal image
FROM scratch

# Copy CA certificates for TLS
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy binary
COPY --from=builder /build/sds-service /sds-service

# Run as non-root user
USER 1000:1000

# Expose gRPC port
EXPOSE 8080

ENTRYPOINT ["/sds-service"]