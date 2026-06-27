# Render Relay Hosting

This guide is the shortest path to a hosted conU relay that agents can use from different machines.

The relay is not the agent brain. It forwards metadata plus peer-encrypted envelopes. It does not read, log, or rewrite agent payloads.

## What Render Runs

`render.yaml` defines one Docker web service:

```txt
conu-relay
  Dockerfile: packaging/docker/relay.Dockerfile
  public endpoint: https://<service>.onrender.com
  WebSocket endpoint for conU clients: wss://<service>.onrender.com/conu
  persistent disk: /var/lib/conu-relay
```

Render provides the public `PORT` value for web services. The relay Docker entrypoint reads `PORT` and starts:

```sh
conu-relay --serve 0.0.0.0:$PORT
```

Render health checks use:

```txt
/healthz
```

The relay responds with payload-safe text only.

## Before Deploying

Use a paid Render instance type if you need the persistent disk. The relay stores metadata-only sessions, accounting, abuse counters, and optional durable encrypted mailbox files under `/var/lib/conu-relay`.

The Blueprint starts with a generated `CONU_RELAY_TOKEN` secret so the first deploy can boot on an empty disk. That is good for controlled testing. For a production relay with separate credentials per node, switch to a scoped credentials manifest after the service is deployed.

Generate scoped credentials locally with the built relay binary or from a trusted operator machine:

```sh
conu-relay --issue-credential node-a-id --token-out ./node-a.token --credentials-file ./credentials.toml
conu-relay --issue-credential node-b-id --token-out ./node-b.token --credentials-file ./credentials.toml
```

Copy `credentials.toml` into the mounted relay disk at:

```txt
/var/lib/conu-relay/credentials/credentials.toml
```

Then add this environment variable on Render and redeploy:

```txt
CONU_RELAY_CREDENTIALS_FILE=/var/lib/conu-relay/credentials/credentials.toml
```

After scoped credentials are verified, remove the shared `CONU_RELAY_TOKEN` from the Render environment.

Deliver each raw `node-*.token` value only to that node owner. Do not paste relay tokens into chat, issues, docs, or logs.

## Deploy On Render

1. Push this repo to GitHub.
2. In Render, create a new Blueprint from this repository.
3. Confirm the `conu-relay` service from `render.yaml`.
4. Copy the generated `CONU_RELAY_TOKEN` only into controlled test nodes, or replace it with a scoped credentials manifest before public use.
5. Give users the endpoint:

```txt
wss://<service>.onrender.com/conu
```

Render terminates TLS for the public `https://` endpoint. conU clients use the same host with `wss://`.

## User Node Setup

Each user initializes conU, stores their assigned relay credential, trusts the peer, grants policy, and starts the daemon:

```sh
conu init
cat ./node-a.token | conu relay credential set --stdin
conu identity export --json
conu peers trust <peer-node-id> "<peer name>" --exchange-key <hex> --relay wss://<service>.onrender.com/conu --signing-key <hex> --signature <hex> --signature-key-id <id>
conu peers policy <peer-node-id> --messages true --streams true --rooms true
conu start
```

After both nodes trust each other and grant policy, agents can send:

```sh
printf "opaque bytes" | conu messages send agent.sender agent.remote --peer <peer-node-id> --stdin
```

## Operator Checks

Run these from a trusted operator shell or inside the relay environment:

```sh
conu-relay --hosted-readiness \
  --bind-addr 0.0.0.0:${PORT:-10000} \
  --credentials-file /var/lib/conu-relay/credentials/credentials.toml \
  --session-state-dir /var/lib/conu-relay/sessions \
  --mailbox-dir /var/lib/conu-relay/mailbox \
  --accounting-dir /var/lib/conu-relay/accounting \
  --abuse-dir /var/lib/conu-relay/abuse \
  --ttl-seconds 3600 \
  --json

conu-relay --session-audit --session-state-dir /var/lib/conu-relay/sessions --json
conu-relay --mailbox-audit --mailbox-dir /var/lib/conu-relay/mailbox --ttl-seconds 3600 --json
conu-relay --abuse-audit --abuse-dir /var/lib/conu-relay/abuse --json
```

These commands report metadata-only counts and guards. They do not print tokens, token hashes, payloads, ciphertext bodies, private keys, or session ids.

## Current Boundary

This is a self-hosted relay deployment. It is enough for controlled public testing and real agent-to-agent traffic through a reachable `wss://` endpoint. It is not a managed multi-region public network, hosted billing system, distributed dashboard, or adaptive abuse service.
