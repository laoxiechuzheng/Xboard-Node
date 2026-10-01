# xboard-node

Node backend for [Xboard](https://github.com/cedar2025/Xboard). Supports `sing-box` / `xray-core` dual kernels.

> **Disclaimer**: This project is for educational and learning purposes only.

## Features

- Protocols: V2Ray family, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS
- Sync: WebSocket push + REST polling dual channel
- User controls: speed limit, device limit, alive-IP tracking, hot update
- Deploy modes: node mode, machine mode, standalone mode
- Multi-instance: single process binding multiple panels / nodes

## Install

### Docker

```bash
docker run -d --restart=always --network=host \
  -e apiHost=https://panel.com -e apiKey=TOKEN -e nodeID=1 \
  ghcr.io/cedar2025/xboard-node:latest
```

### Docker Compose

```bash
git clone -b compose --depth 1 https://github.com/cedar2025/xboard-node.git
cd xboard-node
vim config/config.yml   # set panel.url / token / node_id
docker compose up -d
```

### Installer (Linux systemd)

```bash
# Node mode
curl -fsSL https://raw.githubusercontent.com/cedar2025/xboard-node/dev/install.sh | \
  sudo bash -s -- --mode node --panel https://panel.example.com --token TOKEN --node-id 1

# Machine mode
curl -fsSL https://raw.githubusercontent.com/cedar2025/xboard-node/dev/install.sh | \
  sudo bash -s -- --mode machine --panel https://panel.example.com --token TOKEN --machine-id 1

## xbctl

Run `xbctl` after installation for help. Common commands:

```bash
xbctl list                          # list all instances
xbctl status                        # running status
xbctl bind add-node --panel URL --token TOKEN --node-id 1
xbctl bind add-machine --panel URL --token TOKEN --machine-id 1
xbctl bind remove-node --panel URL --node-id 1
xbctl service restart
```

## Configuration

Legacy single-panel config is fully compatible. Appending bindings auto-migrates to `instances` format. See `config.yml.example`.

Set either logger's existing level to `none` to disable it:

```yaml
log:
  level: "none"
kernel:
  log_level: "none"
```

`log.level: none` disables xboard-node application logs without creating `log.output`. `kernel.log_level: none` disables xray/sing-box core logs. Startup failures before the configuration is loaded and Go runtime panics may still be written directly to stderr.

### Connection audit (Flux)

xboard-node can report every accepted connection (site, user ID, UUID, node ID, client IP, destination, core, protocol,
TCP/UDP) to a Flux audit endpoint. Both cores are covered, including sing-box Hysteria2 (`hy2` is reported as
`hysteria2`; QUIC handshakes and keepalives are not events). No traffic payload is collected.

Enable it by adding two lines to the top level of `config.yml`; every `instances[]` entry inherits them:

```yaml
audit:
  url: "https://flux.yihetang.icu/api/node-audit/v2/ingest"
  secret: "flux-ingest-secret"  # or secret_env: "AUDIT_SECRET"
```

Each instance reports under its panel domain (for example `98kjc.top`), and Flux maps panel domains to its site keys,
so one process can serve several panels. Set `audit.site` on an instance only to override that. Optional settings:
`agent_id` (default: hostname), `queue_size` (default 16384) and `batch_size` (default 512). `AUDIT_URL`,
`AUDIT_SITE`, `AUDIT_SECRET` and `AUDIT_AGENT_ID` override the top-level values. Different machines may report the
same UUIDs: Flux keeps events apart by site, user, node, agent and process instance.

Nothing is written to the node's disk and forwarding never waits on the upload. Events wait in a bounded in-memory queue
shared by the whole process and leave in gzip batches over HTTPS, authenticated with HMAC-SHA256. A failed upload keeps
its batch in memory and retries it with backoff (1 s up to 30 s) until Flux acknowledges it; shutdown flushes for up to
5 seconds. Only an outage longer than the queue can absorb, or a crash, loses events, and those losses are counted and
shown in Flux. `kernel.audit_log` is deprecated and no longer writes a file.

## Extensions

- Custom routes: [docs-custom-routes.md](docs-custom-routes.md)
- Custom outbounds: [docs-custom-outbounds.md](docs-custom-outbounds.md)
- DNS providers (ACME DNS-01): [docs-dns-providers.md](docs-dns-providers.md)

## License

MPL-2.0.
