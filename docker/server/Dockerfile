FROM m.daocloud.io/docker.io/library/golang:alpine AS build
ENV GOPROXY=https://goproxy.cn,direct
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o server cmd/server/main.go

FROM m.daocloud.io/docker.io/library/alpine:latest
WORKDIR /root/
COPY --from=build /app/server .
EXPOSE 8080/udp 8090
CMD ["./server", "-port", "8080"]