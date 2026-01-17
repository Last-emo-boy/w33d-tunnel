FROM golang:alpine AS build
ENV GOPROXY=https://goproxy.cn,direct
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Use Pure Go SQLite (no CGO needed)
ENV CGO_ENABLED=0
RUN go build -o manager cmd/manager/main.go

FROM alpine:latest
WORKDIR /root/
COPY --from=build /app/manager .
EXPOSE 2933
CMD ["./manager"]
