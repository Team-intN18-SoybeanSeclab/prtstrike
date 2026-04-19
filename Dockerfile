# ===== Build Stage =====
FROM golang:1.25.5-alpine AS builder

RUN apk add --no-cache git

WORKDIR /build

# 缓存依赖层
COPY go.mod go.sum* ./
RUN go mod download

# 复制源代码并编译
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o prtstrike .

# ===== Runtime Stage =====
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# 复制编译产物和必要的运行时文件
COPY --from=builder /build/prtstrike .
COPY --from=builder /build/static ./static
COPY --from=builder /build/implants ./implants
COPY --from=builder /build/tools ./tools

EXPOSE 8083

CMD ["./prtstrike"]