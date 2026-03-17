FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

# Copy source — web/templates are go:embed'd into the binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o edgepanel .

FROM alpine:3.19

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /app/edgepanel /app/edgepanel

RUN mkdir -p /data

EXPOSE 8080

ENTRYPOINT ["/app/edgepanel"]
