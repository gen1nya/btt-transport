FROM golang:1.23-alpine AS builder

WORKDIR /app
COPY go.mod ./
RUN go mod download 2>/dev/null; true
COPY . .
RUN go mod tidy && \
    CGO_ENABLED=0 go build -o /btt-server ./cmd/server && \
    CGO_ENABLED=0 go build -o /btt-client ./cmd/client && \
    CGO_ENABLED=0 go build -o /btt-relay ./cmd/relay

FROM alpine:3.20
COPY --from=builder /btt-server /usr/local/bin/btt-server
COPY --from=builder /btt-client /usr/local/bin/btt-client
COPY --from=builder /btt-relay /usr/local/bin/btt-relay
ENTRYPOINT ["btt-server"]
