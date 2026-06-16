#!/usr/bin/env bash
#
# migrate-multizone.sh — migrate single-zone Valkey data to the multi-zone
# key layout introduced in migration Step 7.
#
#   Records   zone:<TYPE>:<name>   ->  zone:<zone>:<TYPE>:<name>
#   Dynamic   ddns:<TYPE>:<name>   ->  ddns:<zone>:<TYPE>:<name>
#
# <zone> is taken from config:zone_name (the single zone the monolith served).
# DNSSEC keys (dnssec:zsk, dnssec:ksk, ...) do NOT need migrating: dnsd adopts
# the legacy un-prefixed keys under dnssec:<zone>:* automatically on first
# start, preserving the existing DS / key tags.
#
# The script is idempotent (keys already carrying a <zone> segment are skipped)
# and defaults to a DRY RUN.  Re-run with --apply to perform the renames.
#
# Env: VALKEY_CLI (default: valkey-cli), DNS_VALKEY_HOST (127.0.0.1),
#      DNS_VALKEY_PORT (6379), DNS_VALKEY_PASSWORD (unset).
set -euo pipefail

CLI=${VALKEY_CLI:-valkey-cli}
HOST=${DNS_VALKEY_HOST:-127.0.0.1}
PORT=${DNS_VALKEY_PORT:-6379}
APPLY=0
[ "${1:-}" = "--apply" ] && APPLY=1

cli() {
    if [ -n "${DNS_VALKEY_PASSWORD:-}" ]; then
        "$CLI" -h "$HOST" -p "$PORT" -a "$DNS_VALKEY_PASSWORD" --no-auth-warning "$@"
    else
        "$CLI" -h "$HOST" -p "$PORT" "$@"
    fi
}

ZONE=$(cli GET config:zone_name | tr -d '"')
if [ -z "$ZONE" ]; then
    echo "error: config:zone_name is empty — cannot determine the zone to migrate into" >&2
    exit 1
fi
echo "Primary zone: $ZONE"
[ "$APPLY" = 1 ] && echo "Mode: APPLY" || echo "Mode: DRY RUN (pass --apply to execute)"

migrated=0
skipped=0

# A legacy key has exactly two colons (prefix:TYPE:name); a migrated key has
# three (prefix:zone:TYPE:name).  Names and types never contain ':'.
migrate_prefix() {
    local prefix=$1
    while IFS= read -r key; do
        [ -z "$key" ] && continue
        local colons=${key//[^:]/}
        if [ "${#colons}" -ne 2 ]; then
            skipped=$((skipped + 1))
            continue
        fi
        local rest=${key#${prefix}:} # TYPE:name
        local newkey="${prefix}:${ZONE}:${rest}"
        echo "  $key  ->  $newkey"
        if [ "$APPLY" = 1 ]; then
            # RENAME preserves any TTL and is atomic; skip if dest already set.
            if [ "$(cli EXISTS "$newkey")" = "1" ]; then
                echo "    (destination exists, leaving source in place)"
                skipped=$((skipped + 1))
                continue
            fi
            cli RENAME "$key" "$newkey" >/dev/null
        fi
        migrated=$((migrated + 1))
    done < <(cli --scan --pattern "${prefix}:*")
}

echo "Records (zone:*):"
migrate_prefix "zone"
echo "Dynamic records (ddns:*):"
migrate_prefix "ddns"

# Carry the SOA serial into the per-zone counter for clarity (primary keeps the
# legacy config:zone_serial too; both are accepted by dnsd/apid).
serial=$(cli GET config:zone_serial | tr -d '"' || true)
if [ -n "$serial" ]; then
    echo "Serial: config:zone_serial=$serial -> config:zone:${ZONE}:serial"
    [ "$APPLY" = 1 ] && cli SET "config:zone:${ZONE}:serial" "$serial" >/dev/null
fi

echo
echo "Done. $migrated key(s) $( [ "$APPLY" = 1 ] && echo migrated || echo would migrate ), $skipped skipped."
[ "$APPLY" = 1 ] || echo "Re-run with --apply to perform the migration."
