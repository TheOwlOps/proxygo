FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/proxygo ./cmd/9router

FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/proxygo .
ENV PORT=7860
ENV DATA_DIR=/app/data
EXPOSE 7860
CMD ["./proxygo"]
