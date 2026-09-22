FROM golang:1.27.1-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /lockgate ./cmd/lockgate

FROM alpine:3.23
RUN apk add --no-cache ca-certificates && addgroup -g 10001 lockgate && adduser -D -u 10001 -G lockgate lockgate
COPY --from=build /lockgate /usr/local/bin/lockgate
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["lockgate"]
CMD ["serve"]
