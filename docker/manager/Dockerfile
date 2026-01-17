FROM golang:alpine AS build
ENV GOPROXY=https://goproxy.cn,direct
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Need CGO for SQLite (or use CGO_ENABLED=0 with pure go sqlite if preferred, but standard driver needs CGO)
# Alpine needs gcc/musl-dev for CGO
RUN apk add --no-cache gcc musl-dev
ENV CGO_ENABLED=1
RUN go build -o manager cmd/manager/main.go

FROM alpine:latest
WORKDIR /root/
COPY --from=build /app/manager .
EXPOSE 2933
CMD ["./manager"]
