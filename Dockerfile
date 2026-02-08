# Multi-stage Dockerfile for jwtauth library
# Stage 1: Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Run tests with race detector
RUN go test -race ./...

# Build a minimal test binary (optional - for verification)
# When you add examples/server, this will build the actual service
# RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o /jwtauth-server ./examples/server

# Stage 2: Runtime stage
FROM alpine:latest

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy binary from builder (when available)
# COPY --from=builder /jwtauth-server .

# Create directory for keys
RUN mkdir -p /app/keys

# Expose port (when you have a server)
# EXPOSE 8080

# Health check (when you have a server)
# HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
#   CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Run the server (when available)
# CMD ["/app/jwtauth-server"]

# For now, just keep the container running for testing
CMD ["sh", "-c", "echo 'jwtauth container built successfully' && tail -f /dev/null"]
