# Shared REALITY Entry

The confirmed implementation adds a global public REALITY port alias, normally
443, while keeping every original node port. It works across multiple instances
in one process. Each node retains its original `nc.ServerPort`, such as 28443,
independent validator, routes, accounting, native statistics, Vision handling,
and native mux ledger.

The alias decrypts and verifies the REALITY Short ID before selecting a registered
node. It replays the buffered ClientHello into that node's original logical inbound
using the same `net.Conn`. `RemoteAddr` and the real client IP are preserved for
validation, device tracking, and audit. There is no loopback `net.Dial`, TCP relay,
or injected PROXY header. Direct original-port connections still use the normal
`reality.Server` path.

Unknown or invalid Short ID, key, or SNI combinations on the alias are actively
closed. The alias has no default mirror-site fallback. Original node ports retain
their ordinary REALITY behavior.

The extra entry is **process-local**, not a standalone port forwarder. All
participating instances and their original logical inbounds must run in the same
Xboard-Node process. It cannot be attached to existing nodes running in separate
processes, even on the same machine, or used to share their alias endpoint. Other
protocols and ordinary or sing-box configurations keep their existing behavior.

## Client and Panel Ports

- To use the alias, set the subscription/client connection port to 443, or the
  configured alias port. Keep that node's public key, SNI, and a valid Short ID.
- Keep the panel backend `server_port` at the original port, such as 28443. Do not
  change it to 443 just to advertise the alias: the original inbound must remain.
- While the alias is enabled, each original `ServerPort` must differ from
  `kernel.shared_reality.listen_port`. An external service already occupying 443
  causes alias startup to be rejected.
- With legacy `nodes` or single-node configuration, disabling the effective
  `shared_reality.enabled` removes alias participation. In compact-list mode,
  move an ID from `nodes_443` to `nodes_direct` to remove its alias participation.
  Original ports remain the ordinary REALITY entry points in either case.
  Switch alias clients back to an original port before disabling participation.

## Configuration

Use `kernel.type: xray` with two per-instance lists: `nodes_443` for nodes that
keep their original listener and also join the shared entry, and `nodes_direct`
for nodes that keep only their original listener. This two-site example uses
placeholder domains, IDs, environment references, and paths, not the currently
bound inventory or a migration. Keep existing panel bindings and original ports.
The panel node configurations still supply the REALITY parameters and Short IDs.
**No shared private key, SNI, or dest is required.** Every node may keep its own
`privateKey`, SNI, and `dest`, including nodes in the same instance. Sharing the
entry does not require changing panels to make these values match.
Original direct ports come from the panel nodes, not from `shared_reality`.

```yaml
kernel:
  type: xray
  shared_reality:
    listen_port: 443
instances:
  - panel:
      url: https://panel-a.example.com
      token_env: PANEL_A_TOKEN
    kernel:
      config_dir: /etc/xboard-node/site-a
    audit:
      site: site-a
    nodes_443: [101, 102]
    nodes_direct: [103]
    node_overrides:
      102:
        kernel:
          config_dir: /etc/xboard-node/site-a/region-special
          geo_data_dir: /etc/xboard-node/site-a/geo
          custom_config: /etc/xboard-node/site-a/region-special.json
        cert:
          cert_mode: file
          cert_file: /etc/xboard-node/site-a/example.crt
          key_file: /etc/xboard-node/site-a/example.key
          cert_dir: /etc/xboard-node/site-a/certs-special
  - panel:
      url: https://panel-b.example.com
      token_env: PANEL_B_TOKEN
    kernel:
      config_dir: /etc/xboard-node/site-b
    audit:
      site: site-b
    nodes_443: [201, 202]
    nodes_direct: []
```

`node_overrides` is optional. Omit it when no node needs an exceptional config
directory, geo-data directory, custom config file, or certificate configuration.
For an existing installation, preserve such paths rather than replacing them
with the example paths. Custom config and certificate files must already exist
where the actual configuration expects them.

For a `config.yml` using this structure, substitute existing panel URLs and IDs,
remove example exceptions that do not apply, and provide both panel tokens through
the environment. With an already
built binary, this Bash example reads tokens without echoing them or placing
literal secrets in shell history:

```bash
read -r -s -p "Panel A token: " PANEL_A_TOKEN
printf '\n'
read -r -s -p "Panel B token: " PANEL_B_TOKEN
printf '\n'
export PANEL_A_TOKEN PANEL_B_TOKEN
./xboard-node -c config.yml
```

The process needs permission to bind port 443, and that endpoint must be available.
With the alias enabled, an original node port must not equal
`kernel.shared_reality.listen_port`: with this example, keep direct ports such as
28443 and leave 443 for the global alias.
The feature does not migrate original ports or resolve conflicting bindings.
The placeholder domains and IDs are not a working public service. This example
does not update panel ports, credentials, or node bindings.

### Compact List Rules

- Both lists absent keeps the existing `panel.node_id` or `nodes:` behavior.
  Defining either list selects compact mode; `panel.node_id` is ignored in that
  mode, including when it refers to an otherwise unlisted node.
- The lists are authoritative: `nodes_443` forces sharing on even against an
  inherited `enabled: false`; `nodes_direct` forces sharing off even against an
  inherited `enabled: true`. Both groups keep their original panel-supplied ports.
  An ID absent from both lists is not started, not implicitly discovered.
- One explicit `[]` is valid if the other list contains IDs. Both empty, or a sole
  explicit empty list, is invalid; an empty compact selection never falls back
  to `panel.node_id`. `null` is not an explicit empty list; use `[]`.
- IDs must be positive and unique across both lists within a site, including
  duplicates within one list. Different sites have independent lists and may use
  the same numbers without merging their users, routes, accounting, or audit site.
- Do not mix compact lists with nonempty legacy `nodes:`, machine mode, or
  standalone mode. When `instances` exists, root-level lists or `node_overrides`
  are forbidden; define them inside the corresponding instance. Legacy single-site
  configuration may place them at its root.
- `node_overrides` is a mapping keyed by a listed positive ID. The key controls
  identity; omit `node_id` in the value. Overrides for unlisted IDs are rejected.
  `kernel.shared_reality` inside an override is forbidden: list membership controls
  `enabled`, while instance/root `kernel.shared_reality` supplies listener defaults.
- Use the panel's existing lookup rule: a node `code` has priority; use the actual
  database ID when no code is available. These are panel identifiers, not REALITY
  Short IDs. Existing global Short ID conflict checks remain unchanged.
- `xbctl` config rewrites retain the concise lists, explicit empty lists, and
  optional overrides. Expansion uses private grouped entries, not a public
  generated `nodes:` list. Expanded per-node configs clear all group fields.

### Legacy Settings and Listener Defaults

`KernelConfig.SharedReality` is an optional `*SharedRealityConfig`. Without compact
lists, omission or `enabled: false` at the top level disables sharing. Instances
inherit an omitted block from the top level; legacy nodes inherit an omitted
override from their instance. An explicit block replaces the whole inherited
setting, including `enabled: false`. Compact lists inherit the listener address
and port but override the enabled flag as described above. Inherited and expanded
settings are copied, not pointer aliases. `xbctl` binding rewrites preserve
top-level, instance, and legacy per-node settings.

When enabled, an empty `listen_ip` defaults to `0.0.0.0`, and `listen_port: 0`
defaults to `443`. The effective address must be an IP literal, the effective port
must be in `1..65535`, and the kernel type must be `xray`. Disabled settings are
not defaulted or validated. Without compact lists, an instance or legacy node can
opt out explicitly:

```yaml
kernel:
  shared_reality:
    enabled: false
```

## Eligibility and Registration

- Start automatically selects eligible Xray nodes: protocol `vless`, `TLS=2`
  (REALITY), and network empty, `tcp`, or `raw`. Only those nodes register with
  the additional alias entry.
- Ordinary non-REALITY VLESS, VMess, and other ineligible nodes keep their native
  code path and original listeners. They do not register an alias; enabling the
  global switch must not reject them solely for ineligibility or change their
  listening ports.
- Existing eligible nodes and eligible Xray REALITY nodes added or discovered
  dynamically later must register automatically. Original direct ports remain
  available for ordinary REALITY connections.
- `sharedLedger` final-traffic collection is enabled only for nodes that have
  actually registered an alias. The global enabled flag alone does not activate
  this mode. Ordinary protocols and other nodes retain their original native
  accounting behavior.
- A participating node may have multiple nonempty hex Short IDs; prefer 16 hex
  characters for each. Every ID must be **globally unique** after zero-padding to
  eight bytes, including IDs on the same node. For example, `abc123` becomes
  `abc1230000000000`; these two textual IDs collide and cannot both be registered.
  Duplicate or padded-byte collisions reject alias registration to prevent
  traffic from reaching another node's ledger.
- Verified Short ID selection must preserve each original node's independent
  validator, routes, accounting, native statistics, Vision, and native mux ledger.
  It is not a fake native `short_id` routing rule.
- Private keys and panel tokens must not be logged. Use environment references
  for credentials; do not put secrets in examples or diagnostics.

## Enable and Roll Back

These are configuration and client checks, not deployment commands or panel
writes. Keep the existing accounts, credentials, and panel node bindings.

1. Check that participating nodes run in one process, the alias endpoint is free,
   original ports differ from it, and all registered Short IDs are globally unique
   after padding. Keep each node's own key, SNI, dest, and original port.
2. In compact mode, put participating IDs in that site's `nodes_443` and all other
   running IDs in `nodes_direct`; configure the listener at the instance/root
   kernel level. Without compact lists, enable the effective Xray
   `shared_reality` block. Use the existing graceful configuration reload or normal
   Stop/restart path; do not use SIGKILL.
   Original direct ports remain available alongside the alias.
3. For alias access, change only the subscription/client connection port to the
   alias port. Keep its node-specific public key, SNI, and valid Short ID. Do not
   change the panel backend `server_port` to advertise the alias.
4. To roll back, switch alias clients to their original direct ports first. In
   compact mode, move every `nodes_443` ID into `nodes_direct` without duplicates,
   leaving `nodes_443: []` and a nonempty `nodes_direct`. Without compact lists,
   set `shared_reality.enabled: false` and disable any instance/node overrides
   that explicitly keep it enabled. Apply this through the graceful path. Original
   node ports and bindings remain; no panel migration is needed.

## Accounting Boundaries

Graceful reload and normal Stop preserve and collect final traffic tails for
nodes that actually registered an alias. Ordinary protocols retain their original
native accounting behavior; the global switch alone does not enable sharedLedger.

The existing reporting protocol has no batch idempotency guarantee. If the report
service accepts a traffic delta but the client never receives the response, a
retry can submit and count that delta again. Alias routing does not add batch
deduplication or an exactly-once billing guarantee.

SIGKILL or power loss can discard unpersisted, in-memory traffic before it is
reported. Graceful tail collection does not make these counters durable, and it
does not remove the existing acknowledgement/retry ambiguity.

## Building from Source

Use `make build-linux` or the repository Dockerfile. Shared REALITY requires the
native-task observer used to settle asynchronous copy counters before destroying
an old stats manager. A binary built with bare `go build` rejects shared-mode
startup with an explicit error instead of silently losing final traffic.

The build tool verifies the pinned Xray replacement version and source shape,
copies that source outside the module cache, and creates a derived build.mod and
build.sum in `.xray-task-overlay`. The Go overlay is applied to that private
source snapshot. Neither the repository go.mod/go.sum nor the module cache is
modified. The observer is only attached to participating logical inbounds;
ordinary inbounds keep native task behavior.

For manual test or build invocations:

```bash
go run ./tools/xray-task-overlay
go test -mod=readonly -modfile=.xray-task-overlay/build.mod \
  -overlay=.xray-task-overlay/overlay.json -count=1 -p 2 ./...
```

`make test` runs race checks. The pinned upstream VLESS Vision handlers use unsafe
pointer conversions incompatible with default checkptr instrumentation. That
recipe disables checkptr only for `github.com/xtls/xray-core/proxy/vless/...`;
race detection and this project's pointer checks remain enabled.

## Verification and Deployment Scope

The accompanying verification record lists the actual final commands and
results. The tests use 24 simulated nodes across three instances, eight regions
each, real REALITY handshakes, independent outbounds, alias and direct ports,
Vision TLS transfers, native Flux audit events and real client source IPs.
Reports go through the actual Tracker and panel.Client to isolated mock receivers.

The Linux binary smoke test exercises inherited multi-instance configuration,
both entry paths, separate regional routes, Vision, SIGTERM, final panel reports
and release of the listening ports. It does not use production accounts.

Production panel preflight uses read-only PDO SELECT and authenticated GETs,
without Laravel bootstrapping, file edits, database writes, panel service restarts
or synthetic traffic reports. The initial three-node preflight covered original
ports 28443, 38443 and 48443; those figures are historical, not the current node
inventory. See the release-specific deployment record for the active bindings,
shared enrollment and public-port checks. Credentials and user UUIDs are excluded
from source archives and diagnostics.

No production panel migration or restart is required. Test-host rollouts recreate
only the explicitly selected Xray service after configuration equivalence, build
and handshake checks, keeping the previous image/configuration available for
rollback. They must preserve sing-box and the original deployment files. Real
account settlement and production Flux storage require user acceptance testing;
isolated mock-receiver tests do not prove either production outcome.
