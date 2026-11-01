# Сервис подписания ГОСТ ЭП — тестовая сборка на КриптоПро CSP.
#
# Перед сборкой положите дистрибутив КриптоПро CSP 5.0 для Linux (x64, deb)
# в docker/cryptopro/ — файл вида linux-amd64_deb.tgz (скачивается с cryptopro.ru
# после регистрации). Без него образ не соберётся.

# ---------- 1. Сборка сервиса (Rust) ----------
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY sql sql
# без feature openssl-dev: в образ входит только провайдер КриптоПро
RUN cargo build --release --locked

# ---------- 2. Рабочий образ ----------
FROM debian:bookworm-slim
ARG CPRO_TGZ=linux-amd64_deb.tgz
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl util-linux procps \
    && rm -rf /var/lib/apt/lists/*

COPY docker/cryptopro/ /tmp/cryptopro/
RUN set -eux; \
    test -f "/tmp/cryptopro/${CPRO_TGZ}" || { echo "Нет docker/cryptopro/${CPRO_TGZ} — положите дистрибутив КриптоПро CSP"; exit 1; }; \
    cd /tmp/cryptopro && tar xzf "${CPRO_TGZ}" && cd linux-amd64_deb && ./install.sh; \
    rm -rf /tmp/cryptopro; \
    test -f /opt/cprocsp/lib/amd64/libcapi20.so

RUN useradd -r -m -u 10001 esign \
    && mkdir -p /var/opt/cprocsp/keys/esign /app/var \
    && chown esign:esign /var/opt/cprocsp/keys/esign /app/var && chmod 700 /var/opt/cprocsp/keys/esign

COPY --from=build /src/target/release/esign /usr/local/bin/esign
COPY docker/entrypoint.sh /entrypoint.sh
COPY docker/clients.json /app/clients.json
COPY docker/trust /app/trust
RUN chmod +x /entrypoint.sh
WORKDIR /app
ENV ESIGN_PROVIDER=cryptopro \
    ESIGN_CRYPTOPRO_LIB=/opt/cprocsp/lib/amd64 \
    ESIGN_CRYPTOPRO_KEYS_DIR=/var/opt/cprocsp/keys/esign \
    ESIGN_CLIENTS_FILE=/app/clients.json \
    ESIGN_LISTEN=0.0.0.0:8800 \
    RUST_LOG=info,sqlx=warn
EXPOSE 8800
HEALTHCHECK --interval=10s --timeout=3s --retries=12 CMD curl -fsS http://127.0.0.1:8800/api/v1/health || exit 1
ENTRYPOINT ["/entrypoint.sh"]
