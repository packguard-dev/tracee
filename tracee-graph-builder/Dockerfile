# Dockerfile for tracee-graph-builder CLI
#
# Build from this directory:
#   docker build -t pakaremon/tracee-graph-builder .
#
# Example:
#   docker run --rm -v "${PWD}/testdata:/data:ro" tracee-graph-builder \
#     -input /data/sample.ndjson -format table

# Stage 1: Build static binary (no CGO; gopacket pcapgo is pure Go)
FROM golang:1.26.2-alpine@sha256:27f829349da645e287cb195a9921c106fc224eeebbdc33aeb0f4fca2382befa6 AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/tracee-graph-builder \
    ./cmd/tracee-graph-builder

# Stage 2: Minimal runtime image
FROM alpine:3.23.3@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659

RUN apk add --no-cache ca-certificates \
    && rm -rf /var/cache/apk/*

COPY --from=builder /out/tracee-graph-builder /usr/local/bin/tracee-graph-builder

WORKDIR /data

ENTRYPOINT ["/usr/local/bin/tracee-graph-builder"]
