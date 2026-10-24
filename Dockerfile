FROM golang:1.23-alpine@sha256:383395b794dffa5b53012a212365d40c8e37109a626ca30d6151c8348d380b5f AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/proxygo ./cmd/proxygo

FROM alpine@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN apk --no-cache add ca-certificates tzdata
RUN adduser -D -u 1000 appuser
WORKDIR /app
COPY --from=builder /app/proxygo .
COPY --from=builder /app/web ./web
RUN mkdir -p /app/data && chown -R appuser:appuser /app
USER appuser
ENV PORT=7860
ENV DATA_DIR=/app/data
ENV WEB_DIR=/app/web
EXPOSE 7860
CMD ["./proxygo"]
