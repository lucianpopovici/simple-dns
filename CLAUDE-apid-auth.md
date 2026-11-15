# apid.c — read and write authorisation on the HTTP API

Fix spec for audit findings **CSA-AUTH-003** (High) and **CSA-AUTH-004**
(High). Source: `SECURITY_AUDIT.md`, section 2026-11-15. Roadmap: Phase 0b
step 2.

All line anchors are against commit `0b4e2db`. Re-anchor before editing:

```sh
grep -n 'static int qs_get\|"/list"\|Auth for the write paths\|"/update"\|"/delete"\|"/zone") &&' apid.c
```

| Fix | Finding | Status |
|----:|---------|--------|
| 1 | CSA-AUTH-003 — `/list` dumps `zone:*` + `ddns:*` with no authentication | **Done** 2026-11-15 (`make check-apid-auth`) |
| 2 | CSA-AUTH-004 — the DDNS secret authorises arbitrary `zone:*` writes | **Done** 2026-11-15 (`make check-apid-auth`) |
| 3 | Input hygiene on the remaining DDNS path (suffix ACL, name/value charset, `qs_get` key boundaries) | **Done** 2026-11-15 (`make check-apid-auth`, `make check-wire`) |

Implementation note: with `config:mtls_ca_pem` set, the HTTPS listener
refuses the TLS handshake outright for a client with no certificate, so the
"HTTPS without a cert" case never reaches `/list` at all (the test accepts
either a refused handshake or 403). Verified that `check-apid-auth` fails
against the pre-fix apid (every case leaked) and passes after.

## Credentials today

apid has two credentials, and they are meant for different things:

| Credential | Where | Meant for |
|---|---|---|
| mTLS client cert verified against `config:mtls_ca_pem` (`is_mgmt=1`) | HTTPS listener only | Operator management: `/config`, `/zone*`, `/reverse/*`, `/enum/*` |
| `?key=<config:ddns_secret>` | Either listener, in the URL | A DDNS client updating **its own** A/AAAA (`/update`, `/delete`) |

The bug class is the second credential reaching the first one's endpoints.

---

## Fix 1: `/list` requires mgmt (CSA-AUTH-003)

### What it is

`/list` (`apid.c:701`) is handled above the auth check (`:730`), so any
client of the plain-HTTP listener gets every `zone:*` and `ddns:*` key and
value — full zone enumeration that bypasses the AXFR ACL and NSEC3.

### What to build

Answer `/list` only when `is_mgmt`; otherwise 403. The DDNS secret does
**not** unlock it — the secret is a per-host update credential, not a read
credential for the whole zone.

### Guardrail (do NOT)

- **Do NOT** leave `/list` reachable with the DDNS secret.
- **Do NOT** touch `/health`, `/metrics`, `/dns-query` — they stay open
  (metrics is a separate concern; DoH is public by design).

### Acceptance

- Plain HTTP `GET /list` → 403, no record data in the body.
- Plain HTTP `GET /list?key=<ddns_secret>` → 403.
- HTTPS with a verified client cert → 200 with the listing.

---

## Fix 2: `/zone` requires mgmt (CSA-AUTH-004)

### What it is

`/zone` POST/PUT (`:826`) and DELETE (`:875`) sit below the shared auth gate,
which accepts the DDNS secret. Reproduced: `POST /zone?key=<ddns_secret>`
wrote `NS` at the apex and `TXT` at `_acme-challenge` — a credential meant
for "update my A record" can delegate the zone away or obtain a certificate.

### What to build

`/zone` (all methods) answers only when `is_mgmt`; otherwise 403, same as
`/config`, `/zone/*`, `/reverse/*`, `/enum/*` already do. The only endpoints
the DDNS secret opens are `/update` and `/delete`, and those only touch
`ddns:<zone>:A|AAAA:<hostname>`.

### Guardrail (do NOT)

- **Do NOT** add a "zone write secret". Zone writes are an operator action:
  mTLS (or the dashboard, which writes Valkey directly).

### Acceptance

- Plain HTTP `POST /zone?key=<ddns_secret>` → 403, nothing written.
- Plain HTTP `DELETE /zone?key=<ddns_secret>&name=…` → 403, nothing deleted.
- HTTPS mgmt `POST /zone` → 201, written (unchanged behaviour).

---

## Fix 3: input hygiene on the DDNS path and `/zone`

### What it is

1. `config:ddns_allow_suffix` is enforced by dnsd for RFC 2136 UPDATE
   (`ddns_name_allowed`) but not by apid, so `/update?key=…&hostname=www.<zone>`
   overwrites infrastructure names the suffix ACL exists to protect.
2. `hostname`/`name`/`value` go straight into Valkey keys and pipe-encoded
   values. `:` in a name shifts the `zone:<zone>:<type>:<name>` key fields;
   `|` in a value adds pipe fields (e.g. a fake TTL or a second address);
   control bytes reach logs.
3. `qs_get` finds `key=` with `strstr`, so `xkey=…` or `…&value=akey=…`
   satisfies a lookup for `key`.

### What to build

1. Hoist dnsd's suffix matcher into `libdnswire` as
   `int dns_name_in_suffix(const char *name, const char *suffix)` (empty
   suffix = match everything — preserves the documented default) and point
   both dnsd's `ddns_name_allowed` and apid's `/update` + `/delete` at it.
   apid reads `config:ddns_allow_suffix` per request, applies it whether or
   not the caller is mgmt (dnsd applies it to TSIG-authenticated UPDATEs
   too), and answers 403 outside it.
2. Owner-name check for `hostname` (`/update`, `/delete`) and `name`
   (`/zone`): one optional trailing dot stripped; labels of `[a-z0-9_-]`,
   1–63 octets, total ≤ 253; `/zone` additionally allows a leading `*`
   label. Anything else → 400.
3. `/zone` `value`/`pref`: reject `|` and bytes `< 0x20` or `0x7f` → 400.
   `ttl` and `pref` must be all digits.
4. `qs_get` matches a key only at the start of the string or right after
   `&`.

### Guardrail (do NOT)

- **Do NOT** weaken the existing `/enum/provision` `|` check or the
  constant-time DDNS secret compare.
- **Do NOT** duplicate the suffix matcher in apid — one copy, in libdnswire.

### Acceptance

- `config:ddns_allow_suffix=dyn.example.local`: `/update` for
  `h1.dyn.example.local` → 200; for `www.example.local` → 403, not written;
  `/delete` for `www.example.local` → 403, not deleted.
- `/update` with `hostname=a:b.example.local` or `hostname=a|b…` → 400.
- mgmt `POST /zone` with `value=1.2.3.4|9.9.9.9` → 400, nothing written.
- `/update?xkey=<secret>&hostname=…` → 403.
- `make check-wire` covers `dns_name_in_suffix` (exact, child, sibling
  look-alike `xdyn.example.local`, empty suffix, leading-dot suffix).

## Test

New target `make check-apid-auth` (Valkey + openssl + curl), modelled on
`check-enum-provision`: start `apid_debug` with a throwaway CA, server cert,
client cert, `config:http_port`/`https_port` on test ports and a test
`config:ddns_secret`; drive every acceptance case above over plain HTTP and
over HTTPS with and without the client cert; assert HTTP codes **and** the
resulting Valkey keys; restore every key it touched.

## Release note

Plain-HTTP `/list` and DDNS-secret `/zone` writes stop working; use the mTLS
management listener (or the dashboard). DDNS `/update`/`/delete` now honour
`config:ddns_allow_suffix`.
