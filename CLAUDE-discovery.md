# dns_server.c — automatic service discovery (Kubernetes / Docker / Podman / Proxmox / QEMU): work plan

Companion to `CLAUDE.md` (hidden-master/secondary gap analysis),
`CLAUDE-loadbalance.md` and `CLAUDE-forwarder.md`.  Same conventions: line
numbers refer to the current 5173-line source, build command at the bottom
of `CLAUDE.md` applies unchanged.

## Goal

Any VM or container that comes up with an externally reachable interface
gets an FQDN automatically; the record disappears when the workload stops —
including ungraceful death.  Registrations flow **only to the hidden
master** (CLAUDE.md roles); the public secondaries serve the names.

## Architecture: the lease model

The server already has the right primitive.  RFC 2136 UPDATE stores
dynamic records as `ddns:A:<fqdn>` / `ddns:AAAA:<fqdn>` **with the
update's TTL as the Valkey key expiry** (3167/3174: `vk_set(k,ip,uttl)`),
and the query path serves the *remaining* expiry as the record TTL
(2786–2789 via `vk_ttl`).  So the discovery convention is:

- register with a short TTL (60–120 s; server clamps at ≥10 s, 4691),
- refresh at TTL/2 for as long as the workload lives,
- never explicitly deregister unless convenient — a crashed workload, a
  crashed registrar, or a partitioned host all converge to the record
  vanishing within one TTL.

Two equivalent registration interfaces exist today:

| Interface | Where | Auth |
|-----------|-------|------|
| RFC 2136 UPDATE (nsupdate-compatible) | `handle_update` 3119; add 3167/3174, delete 3216 | TSIG (`tsig_verify` via 3126) |
| REST `GET/POST /update?hostname=&ip=&ttl=` and `/delete` | 4687–4707 | `?key=<config:ddns_secret>` on HTTP, or mTLS client cert on the mgmt port (4683) |

## Per-platform registrars (glue, no server code)

| Platform | Mechanism |
|----------|-----------|
| Kubernetes | [external-dns](https://github.com/kubernetes-sigs/external-dns) with the `rfc2136` provider pointed at the hidden master + TSIG key.  Services/Ingresses annotated with `external-dns.alpha.kubernetes.io/hostname`.  No custom code. |
| Docker + Podman | One watcher daemon on each host subscribing to the events socket (Podman serves the Docker-compatible API, so one binary covers both): on `start`, inspect; if the container is on an externally routable network (macvlan/ipvlan/real bridge) **and** carries the opt-in label `dns.name=<host>`, register; refresh every TTL/2; on `die`, delete (best effort — lease expiry is the backstop).  ~100 lines of shell/Go, lives in `contrib/`. |
| Proxmox (QEMU + LXC) | Per-VM hookscript (`qm set <id> --hookscript`): on `post-start` poll `qm guest cmd <id> network-get-interfaces` (requires qemu-guest-agent in the guest — the only reliable way to learn a bridged VM's address from the host), register; cron/systemd-timer refresh; `pre-stop` delete.  LXC via `pct exec`/config. |
| libvirt / plain QEMU | `/etc/libvirt/hooks/qemu` + `virsh domifaddr <dom> --source agent`, same flow. |
| **DHCP backstop (covers everything)** | If the external addresses come from the LAN's DHCP (bridged VMs and macvlan containers usually do), configure Kea DHCP-DDNS (or dnsmasq/ISC dhcpd) to send RFC 2136 updates on lease grant/expiry using the guest's announced hostname.  One integration, every platform, including future ones.  The per-platform watchers then only matter for statically/CNI-addressed workloads. |

Name hygiene: put discovered names under a dedicated sub-domain
(`<name>.dyn.corp.local`) — see Gap 3.

---

## Server-side gaps

### Gap 1 — AXFR does not transfer runtime records **(blocker, also for CLAUDE.md)**

`axfr_thread`'s full-transfer path (3415–3448) sends only the
**compile-time `static_zone[]` array** (887–896), the DNSKEYs, and the
SOA.  Records provisioned at runtime — all `zone:*` keys and all `ddns:*`
keys, i.e. *everything the management API and DDNS ever wrote, including
every discovery registration* — are served locally (2784 ff.) but **never
leave the master in a zone transfer**.

This breaks the hidden-master deployment generally, not just discovery:
a secondary that pulls the zone (CLAUDE.md Gap 3) would receive a nearly
empty zone.

Fix: after the `static_zone[]` loop, enumerate `zone:*` and `ddns:*` with
`SCAN` (the KEYS-pattern plumbing exists at 4671; prefer SCAN to avoid
blocking Valkey), parse key → `(type, name)`, value → rdata using the same
per-type builders the static loop uses (3419–3428, extended to the types
the store supports — the inverse conversions listed in CLAUDE.md Gap 3
apply here too), TTL for `ddns:*` from `vk_ttl` (remaining lease).
Estimated ~80–120 lines.  **Do this before CLAUDE.md Gap 3**, otherwise
the transfer client has nothing real to test against.

### Gap 2 — lease expiry is invisible to replication

A `ddns:*` key expiring in Valkey is a *silent* deletion: no serial bump,
no IXFR journal entry, no NOTIFY.  Secondaries would keep serving a dead
workload's name until some unrelated change pushes a new serial.  Related
holes in the same area:

- explicit deletes don't journal either — the UPDATE delete path (3216)
  and REST `/delete` (4705) call `vk_del`/`serial_bump` but never
  `ixfr_journal_append` (its only callers are the two *add* paths,
  3169/3176);
- REST `/update` (4694) bumps the serial but doesn't journal the add.

Fix, master-role only:

1. `ddns_sweeper_thread` (start next to `pki_renewal_thread`, 4912):
   maintain a `ddns:index` SET of registered names (add on every
   registration); each sweep, `SCAN` the index, and for entries whose
   `ddns:*` key has vanished → remove from index, `serial_bump`,
   `ixfr_journal_append(prev,next,'D',name,...)`, batch one `notify_send`
   per sweep.  Interval ≈ min lease / 2 (default 30 s).
2. Journal deletes ('D') and REST adds at the three call sites above.

Estimated ~70 lines.

### Gap 3 — registration churn and authorization

**Serial churn:** every refresh calls `serial_bump` (4694; RFC 2136 path
likewise) even when the IP is unchanged.  A fleet of 200 workloads
refreshing at 30 s = 400 serial bumps/min, each growing the IXFR journal
and (after CLAUDE.md Gap 5) triggering NOTIFY.  Fix: compare the existing
value first (`vk_get`) and skip bump+journal when identical — the
`vk_set` must still happen to renew the lease.  ~10 lines at 3167/3174
and 4694/4697.

**Authorization:** one global TSIG key (`config:tsig_secret_b64`) and one
shared REST secret (`g_ddns_secret`) mean any registrant can overwrite
*any* name — including `www`, the apex, or another host's name.  Minimal
fix that matches the lease model: `config:ddns_allow_suffix` (e.g.
`.dyn.corp.local`) — when set, the DDNS paths (3167/3174/3216 and
4687/4701) accept only names under that suffix; everything else requires
the mgmt API (mTLS) or the RFC 2136 path with... the same key — so the
suffix check applies to both.  Static/infrastructure names stay outside
the suffix and are therefore immune.  ~20 lines.  Per-key TSIG ACLs
(multiple named keys, each with a name-pattern) are the thorough version —
phase 2, ~80 lines.

### Gap 4 — PTR / reverse DNS (optional, deferred)

Forward registrations don't create PTR records, and the server is
**single-zone** (`g_zone_name`, 439; out-of-zone → REFUSED, 2638) so it
cannot currently serve `in-addr.arpa` zones alongside the forward zone
anyway (the `zone_t` struct at 289–349 looks like multi-zone groundwork,
but nothing serves from it).  First pass: document that reverse DNS for
discovered hosts is out of scope; the DHCP-backstop variant gets PTR for
free if the DHCP server also manages the reverse zone elsewhere.  Revisit
after multi-zone support exists.

---

## Interaction with the other plans

- All registrars target the hidden master only; CLAUDE.md Gap 7 (refuse
  writes on secondaries) is what keeps a misconfigured agent from forking
  a secondary's zone.
- Discovered names replicate to secondaries via Gap 1 + Gap 2 here plus
  CLAUDE.md Gaps 3–6 (transfer client, refresh, NOTIFY).
- `CLAUDE-loadbalance.md` rotation applies to discovered names
  automatically once they're `zone:*`-style multi-IP — note that `ddns:*`
  keys are single-address per type; N replicas registering the same FQDN
  is a phase-2 question (last-writer-wins today).

## Suggested order

1. Gap 1 (AXFR completeness) — prerequisite for everything replicated;
   do it before CLAUDE.md Gap 3.
2. Gap 3 serial-churn fix (tiny, prevents journal bloat from day one).
3. Gap 2 (sweeper + journal coverage).
4. Gap 3 suffix ACL.
5. `contrib/` registrars: docker/podman watcher, proxmox hookscript, Kea
   snippet, external-dns values file.
6. Gap 4 only after multi-zone.

## End-to-end test

```bash
# lease lifecycle against the master:
nsupdate -y hmac-sha256:tsig-key:<b64> <<EOF
server master 53
update add web1.dyn.corp.local 60 A 10.0.0.42
send
EOF
dig @master web1.dyn.corp.local A        # answer, TTL counting down
dig @secondary web1.dyn.corp.local A     # same answer after NOTIFY round-trip
sleep 70                                  # let the lease lapse, no refresh
dig @master web1.dyn.corp.local A        # NXDOMAIN
dig @secondary web1.dyn.corp.local A     # NXDOMAIN after sweeper+NOTIFY
# suffix ACL:
nsupdate ... "update add www.corp.local 60 A 6.6.6.6"   # expect REFUSED
```
