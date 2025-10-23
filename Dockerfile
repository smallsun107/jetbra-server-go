# 使用官方 golang 镜像作为构建环境
FROM golang:1.24 AS builder

# 设置工作目录
WORKDIR /app

# 复制 go.mod 和 go.sum 并下载依赖
COPY go.mod go.sum ./
RUN go mod download

# 复制源代码
COPY . .

# 构建可执行文件
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -o jetbra-server-go main.go

# 使用更小的基础镜像
FROM alpine:latest
WORKDIR /app

# 复制可执行文件
COPY --from=builder /app/jetbra-server-go .
COPY --from=builder /app/static ./static
COPY --from=builder /app/cert ./cert

# 暴露端口
EXPOSE 2333

# 启动服务
ENTRYPOINT ["./jetbra-server-go"]