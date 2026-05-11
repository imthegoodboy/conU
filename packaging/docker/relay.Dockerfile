FROM rust:1.85-bookworm AS build

WORKDIR /src
COPY . .
RUN cargo build --release -p conu-relay

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin conu

COPY --from=build /src/target/release/conu-relay /usr/local/bin/conu-relay

USER conu
EXPOSE 8787

ENTRYPOINT ["conu-relay", "--serve", "0.0.0.0:8787"]
