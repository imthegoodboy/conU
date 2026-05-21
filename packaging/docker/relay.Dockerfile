FROM rust:1.85-bookworm AS build

WORKDIR /src
COPY . .
RUN cargo build --release -p conu-relay

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin conu \
    && mkdir -p /var/lib/conu-relay/mailbox /var/lib/conu-relay/credentials /var/lib/conu-relay/sessions /var/lib/conu-relay/accounting \
    && chown -R conu:conu /var/lib/conu-relay

COPY --from=build /src/target/release/conu-relay /usr/local/bin/conu-relay

USER conu
ENV CONU_RELAY_MAILBOX_DIR=/var/lib/conu-relay/mailbox
ENV CONU_RELAY_SESSION_STATE_DIR=/var/lib/conu-relay/sessions
ENV CONU_RELAY_ACCOUNTING_DIR=/var/lib/conu-relay/accounting
VOLUME ["/var/lib/conu-relay"]
EXPOSE 8787

ENTRYPOINT ["conu-relay", "--serve", "0.0.0.0:8787"]
