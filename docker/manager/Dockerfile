FROM golang:alpine AS build
ENV GOPROXY=https://goproxy.cn,direct
WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o manager cmd/manager/main.go

FROM alpine:latest
WORKDIR /root/
COPY --from=build /app/manager .
EXPOSE 2933
CMD ["./manager"]
