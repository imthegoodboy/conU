# conU Relay Docker Template

This template builds and runs the current `conu-relay` service.

```sh
docker build -f packaging/docker/relay.Dockerfile -t conu-relay .
docker run --rm -p 8787:8787 -e CONU_RELAY_TOKEN=replace-me conu-relay
```

Current relay limits still apply:

- The client accepts `ws://` relay endpoints today.
- The relay forwards metadata plus peer-encrypted message bodies only.
- Hosted auth, rate limits, persistent relay sessions, `wss://` client support, stream byte routing, and offline mailbox delivery remain future hardening work.
