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
  ghcr.io/laoxiechuzheng/xboard-node:latest
```

### Docker Compose

The upstream Compose template below is a starting point. For native Flux audit, change its node service image to
`ghcr.io/laoxiechuzheng/xboard-node:latest` and apply the Connection audit configuration before starting it.

```bash
git clone -b compose --depth 1 https://github.com/cedar2025/xboard-node.git
cd xboard-node
vim config/config.yml   # set panel.url / token / node_id
docker compose up -d
```

### Installer (Linux systemd)

These legacy upstream installer commands are retained for reference; they have not been verified to install this
fork or its native Flux audit release. Use this fork's published GHCR image for the deployment path documented below.

```bash
# Node mode
curl -fsSL https://raw.githubusercontent.com/cedar2025/xboard-node/dev/install.sh | \
  sudo bash -s -- --mode node --panel https://panel.example.com --token TOKEN --node-id 1

# Machine mode
curl -fsSL https://raw.githubusercontent.com/cedar2025/xboard-node/dev/install.sh | \
  sudo bash -s -- --mode machine --panel https://panel.example.com --token TOKEN --machine-id 1
```

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

### AnyTLS PROXY protocol

The sing-box AnyTLS inbound in this fork can accept PROXY protocol v1/v2 before its TLS handshake.
Enable it with the existing kernel option:

```yaml
kernel:
  type: "singbox"
  force_proxy_protocol: true
```

This forces PROXY-header acceptance even when the panel does not enable it. Panel
`accept_proxy_protocol: true` and `networkSettings.acceptProxyProtocol: true` also enable it.
Both IPv4 and IPv6 addresses are passed to user traffic, alive-IP, device-limit and audit tracking.
Plain TLS connections without a PROXY header remain accepted, matching the Xray acceptance mode.
The option enables acceptance; it does not require every connection to have a header.
Incomplete or malformed headers are rejected; header reads have a 10-second deadline.

The default is off. This sing-box support is limited to AnyTLS; other sing-box protocols are unchanged.
For a mixed-instance process, set the option under the intended instance's `kernel` section to limit its scope.
Use the published image containing this fork's AnyTLS support, not an upstream sing-box image.

PROXY headers are not authenticated. Restrict access to this backend listener to trusted forwarding
servers with a firewall or private network. An untrusted peer can otherwise forge a client source IP.
The forwarder must send its PROXY header before the original TLS handshake; no client-side setting is needed.
Enabling this configuration requires restarting the target node process. No panel/database change is required.


### Connection audit (Flux)

xboard-node natively records accepted, identified-user TCP connections and UDP sessions from Xray and sing-box,
including sing-box Hysteria2 (`hy2` is reported as `hysteria2`). No access-log parser or sidecar is needed.
Events contain site, user ID, UUID, node ID, client IP, destination, core and protocol, never traffic payloads.
QUIC handshakes, keepalives and individual UDP packets are not separate audit events.

#### Setup

Use `ghcr.io/laoxiechuzheng/xboard-node:latest` in the node services' original Compose file. Keep the existing
networking, config mounts, volumes and log rotation; no audit-specific Compose override is needed.
Add this to the top level of each mounted config file, alongside `panel` or `instances`:

```yaml
audit:
  url: "https://flux.yihetang.icu/api/node-audit/v2/ingest"
  secret: "REPLACE_WITH_FLUX_INGEST_SECRET"
```

Use the same ingest shared secret as Flux, not the panel API token. Alternatively replace `secret` with
`secret_env: "AUDIT_SECRET"` if that variable is passed to the node process/container. A host shell variable or
Compose `.env` alone does not pass it into a container. A nonempty `secret` takes precedence over `secret_env`.
Keep real secrets and private configs out of Git and shared diagnostics.

Every `instances[]` entry inherits top-level audit settings unless it overrides a field. Leave `audit.site` unset
at both levels: each instance uses its own `panel.url` hostname, lowercased and without a port or trailing dot.
Flux maps panel domains (for example `98kjc.top` and `mgjc.98kjc.top`) to site keys. Unmapped sites can be rejected.
Set an instance's `audit.site` only for an explicit override; without a panel URL, an explicit site is required.
A top-level site forces the same default site on all instances.

`agent_id` defaults to the process hostname. Preserve a stable hostname in the original Compose file, or set
`audit.agent_id: "jp-01"` to a deployment-unique value and keep it across upgrades/rollback. An automatically generated
container hostname may change on recreation. Allowed agent characters are `[a-zA-Z0-9_.:-]`, 1-128 characters.
Flux distinguishes site, user, node, agent and the uploader's new process-instance ID. `AUDIT_URL`, `AUDIT_SITE`,
`AUDIT_SECRET` and `AUDIT_AGENT_ID` override top-level values; explicit instance fields still take precedence.

#### Update And Rollback

Run from the existing Compose project directory, using its original file and project name. Check service names without
printing resolved private config, then update only the intended node service; repeat for other node services as needed:

```bash
docker compose config --services
SERVICE=xboard-node  # replace with the service name in your original Compose file
docker compose pull "$SERVICE"
docker compose up -d --no-deps "$SERVICE"
docker compose ps "$SERVICE"
```

Do not carry temporary canary image overrides into routine updates. `latest` is mutable. The verified audit build at
commit `04a39ff` has tag `sha-04a39ff` for Linux amd64/arm64. To pin it, use
`ghcr.io/laoxiechuzheng/xboard-node:sha-04a39ff` as the original service's `image`, or use an immutable
`ghcr.io/laoxiechuzheng/xboard-node@sha256:<verified-digest>`. Verify future tags/digests before deployment.

Before updating, retain the previous immutable image reference and a private config backup. To roll back, restore that
image reference and any required prior config, then run the same `pull` and `up -d --no-deps` commands.
Keep the hostname/`agent_id` stable. Recreating a node interrupts existing connections; an older image may not support
native audit. A running container alone does not verify end-to-end ingestion.

#### Bounds And Logs

Connection audit never writes local connection-log files. Recording does no disk/network I/O and never waits for an
upload. Instances with the same URL, secret, agent and queue/batch settings share one uploader per process;
different settings can create additional uploaders. Each holds at most `queue_size` queued events plus one batch.
Defaults are `queue_size: 16384`, `batch_size: 512`, with a 2-second flush interval. Maximums are 200000 and 5000;
a batch cannot exceed its queue. An omitted batch defaults to the smaller of 512 and the configured queue size.
Zero selects defaults, not an unlimited queue.

Batches use gzip over HTTPS with HMAC-SHA256. Transient failures retain an identical batch for retry with backoff
from 1 to 30 seconds; events older than 12 hours expire. Graceful shutdown drains for at most 5 seconds total.
Queue saturation, invalid metadata, expiry, receiver rejection, unrecoverable batch errors or an undrained shutdown
can lose events. A crash loses buffered events; any process restart resets volatile counters. There is no indefinite
zero-loss guarantee: later successful uploads can report observed drops, not prove that a crash lost nothing.
`kernel.audit_log` is deprecated and no longer creates a local audit file.

Application/kernel operational logs are separate and may still be persisted by Docker or `log.output`. Preserve the
original Compose log rotation (`logging.options.max-size` / `max-file`, if configured); it limits Docker logs, not
Flux retention. `log.level: none` and `kernel.log_level: none` silence their respective loggers without disabling
native audit. Startup failures and runtime panics may still reach stderr, as noted above.

#### Flux Verification

After an update, make a known-user test connection for each core/protocol in use, including real Hysteria2 TCP/UDP
traffic. In Flux, verify site, user ID/UUID, node, agent, source IP, destination and normalized protocol; inspect
queued/uploaded/dropped/retry counters and unknown-site rejections. An HTTPS response or a QUIC handshake alone is
not proof of a stored connection event.

Retention is controlled by Flux, not this node config. Flux v2 defaults to 30 retention days: a user-ID/UUID/email
search without dates uses the configured retention window, while an unfiltered search defaults to the last 24 hours.
Select the site and explicit dates when checking older events. Only ingested, retained records are searchable;
storage cleanup, collection losses and partial/scan-budget-limited results prevent a claim of complete history.

Probe/health-check classification is a metadata-only heuristic based on destination, frequency and target diversity.
It counts accepted connections/sessions, not HTTP requests. It cannot inspect URL paths, payloads or encrypted
content, and an IP-only destination may hide the domain. Shared/CDN destinations can produce false positives;
reused connections can hide repeated requests. Treat probe labels as investigation cues, not proof of intent or
complete coverage.

## Extensions

- Custom routes: [docs-custom-routes.md](docs-custom-routes.md)
- Custom outbounds: [docs-custom-outbounds.md](docs-custom-outbounds.md)
- DNS providers (ACME DNS-01): [docs-dns-providers.md](docs-dns-providers.md)

## License

MPL-2.0.
