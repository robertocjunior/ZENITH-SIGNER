# Etapa 1: Builder
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache gcc musl-dev sqlite-dev git

WORKDIR /app

# Cache de dependências do Go
COPY go.mod go.sum ./
RUN go mod download

# Copia todo o código-fonte (templates, internal, etc.)
COPY . .

# Compila o binário estático/otimizado com CGO ativado para SQLite
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o zenith-signer .

# Etapa 2: Runner de produção enxuto e seguro para rodar 24/7
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata sqlite-libs wget su-exec && \
    addgroup -S appgroup && adduser -S -G appgroup -H appuser
ENV TZ=America/Sao_Paulo

WORKDIR /app

COPY --from=builder /app/zenith-signer /app/zenith-signer

RUN mkdir -p /app/data && chown -R appuser:appgroup /app

EXPOSE 8080

# Healthcheck nativo para monitoramento 24/7 e auto-restart pelo Docker
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/livez > /dev/null || exit 1

CMD ["sh", "-c", "DB_DIR=$(dirname \"${DB_PATH:-/app/data/signatures.db}\") && mkdir -p \"$DB_DIR\" && chown -R appuser:appgroup \"$DB_DIR\" && exec su-exec appuser:appgroup /app/zenith-signer"]