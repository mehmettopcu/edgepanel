FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

# Copy source — web/templates are go:embed'd into the binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o edgepanel .

FROM alpine:3.19

# docker CLI is used to exec nginx -t / nginx -s reload in the nginx-edge container
RUN apk add --no-cache ca-certificates docker-cli

WORKDIR /app

COPY --from=builder /app/edgepanel /app/edgepanel

RUN mkdir -p /data /etc/nginx/conf.d/generated/routes /etc/nginx/conf.d/generated/iplists

EXPOSE 8080

ENTRYPOINT ["/app/edgepanel"]
