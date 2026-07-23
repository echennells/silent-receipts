# Silent Receipts — reproducible build + demo runtime.
# Build:  docker compose build      (or: docker build -t silent-receipts .)
# Run:    docker compose up         → GUI on http://localhost:8552

FROM rust:1.85-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
RUN cargo build --release --locked || cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv curl jq ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -m venv /opt/ots \
 && /opt/ots/bin/pip install --no-cache-dir opentimestamps-client
WORKDIR /app
COPY --from=builder /build/target/release/receipt /usr/local/bin/receipt
COPY web ./web
COPY scripts ./scripts
ENV RECEIPT_BIN=/usr/local/bin/receipt \
    BUNDLE_DIR=/app/data/bundles \
    CACHE_DIR=/app/data/cache \
    OTS_DIR=/app/data/ots \
    OTS_BIN=/opt/ots/bin/ots \
    PORT=8552
EXPOSE 8552
CMD ["python3", "web/serve.py"]
