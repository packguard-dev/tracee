FROM docker.io/library/golang:1.26-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o /tracee-graph-builder ./cmd/tracee-graph-builder

FROM docker.io/library/alpine:latest
COPY --from=builder /tracee-graph-builder /tracee-graph-builder
ENTRYPOINT ["/tracee-graph-builder"]
