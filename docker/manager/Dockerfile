FROM golang:1.22-alpine as build
WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o manager cmd/manager/main.go

FROM alpine:latest
WORKDIR /root/
COPY --from=build /app/manager .
EXPOSE 3000
CMD ["./manager"]
