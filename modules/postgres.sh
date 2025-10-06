#!/usr/bin/env bash
set -euo pipefail

# ===== UI (tty-aware) =====
is_tty=0; [ -t 1 ] && is_tty=1
if [ "$is_tty" -eq 1 ]; then
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[1;34m'; NC='\033[0m'
else
  GREEN=''; YELLOW=''; RED=''; BLUE=''; NC=''
fi
say()  { printf "%b[+]%b %s\n" "$GREEN" "$NC" "$*"; }
warn() { printf "%b[!]%b %s\n" "$YELLOW" "$NC" "$*"; }
err()  { printf "%b[x]%b %s\n" "$RED" "$NC" "$*" >&2; }
line() { local ch="${1:-=}"; local w="${2:-72}"; printf '%*s\n' "$w" '' | tr ' ' "$ch"; }
banner(){ local title="$1"; local ch="${2:-=}"; local w="${3:-72}"; line "$ch" "$w"; printf "%b%s%b\n" "$BLUE" "$title" "$NC"; line "$ch" "$w"; }

trap 'err "Failed on line $LINENO"' ERR
[[ $EUID -eq 0 ]] || { err "Run as root (sudo)."; exit 1; }
export DEBIAN_FRONTEND=noninteractive

# ===== STATE =====
STATE_DIR="${STATE_DIR:-/var/lib/wafcontrol-installer}"
STATE_FILE="${STATE_FILE:-$STATE_DIR/state.env}"
mkdir -p "$STATE_DIR"; touch "$STATE_FILE"
state_append_array() { printf '%s+=(%q)\n' "$1" "$2" >> "$STATE_FILE"; }
state_put_map()  { printf '%s[%q]=%q\n' "$1" "$2" "$3" >> "$STATE_FILE"; }
state_put_flag() { printf 'FLAGS[%q]=%q\n' "$1" "$2" >> "$STATE_FILE"; }
# shellcheck disable=SC1090
source "$STATE_FILE" 2>/dev/null || true

# ===== INPUTS =====
DB_NAME="${DB_NAME:?}"
DB_USER="${DB_USER:?}"
DB_PASS="${DB_PASS:?}"
PG_VERSION="${PG_VERSION:-}"
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"

banner "PostgreSQL setup"

pgdg_add_repo() {
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor -o /etc/apt/keyrings/postgresql.gpg
  . /etc/os-release
  echo "deb [signed-by=/etc/apt/keyrings/postgresql.gpg] https://apt.postgresql.org/pub/repos/apt ${VERSION_CODENAME}-pgdg main" > /etc/apt/sources.list.d/pgdg.list
  apt update -y
}
ensure_postgres() {
  local v="$1"
  apt install -y "postgresql-${v}" "postgresql-client-${v}" libpq-dev "postgresql-server-dev-${v}"
  systemctl enable --now postgresql
  for _ in {1..30}; do pg_isready >/dev/null 2>&1 && break; sleep 1; done
}
find_pg_hba() {
  local v="$1" p
  p=$(find "/etc/postgresql/${v}" -maxdepth 3 -name pg_hba.conf 2>/dev/null | head -n1)
  [[ -z "$p" ]] && p=$(find /etc/postgresql -maxdepth 4 -name pg_hba.conf 2>/dev/null | head -n1)
  echo "$p"
}
find_postgresql_conf() {
  local v="$1" p
  p=$(find "/etc/postgresql/${v}" -maxdepth 3 -name postgresql.conf 2>/dev/null | head -n1)
  [[ -z "$p" ]] && p=$(find /etc/postgresql -maxdepth 4 -name postgresql.conf 2>/dev/null | head -n1)
  echo "$p"
}
extract_port_from_conf() {
  local conf="$1"
  [ -r "$conf" ] || { echo ""; return; }
  awk '
    /^[[:space:]]*#/ {next}
    /^[[:space:]]*port[[:space:]]*=/ {
      # capture the numeric value after "port ="
      gsub(/#.*/,""); sub(/.*port[[:space:]]*=[[:space:]]*/,""); gsub(/[[:space:]]/,"");
      if ($0 ~ /^[0-9]+$/) p=$0
    }
    END{ if (p) print p }' "$conf"
}

line "-" 72
if command -v psql >/dev/null 2>&1; then
  INSTALLED_MAJOR="$(psql -V | awk '{print $3}' | cut -d. -f1)"
  PG_VERSION="${INSTALLED_MAJOR}"
  say "Detected PostgreSQL ${PG_VERSION} (reuse)."
else
  [[ -n "$PG_VERSION" ]] || { err "PG_VERSION is required."; }
  say "Installing PostgreSQL ${PG_VERSION} from PGDG..."
  pgdg_add_repo
  ensure_postgres "$PG_VERSION"
fi

# Auto-detect DB_PORT
PG_CONF="$(find_postgresql_conf "$PG_VERSION")"
if [ -n "$PG_CONF" ]; then
  det_port="$(extract_port_from_conf "$PG_CONF")"
  if [[ -n "$det_port" && "$det_port" =~ ^[0-9]+$ ]]; then
    DB_PORT="$det_port"
    say "Detected PostgreSQL port: ${DB_PORT}"
  fi
fi

PG_HBA="$(find_pg_hba "$PG_VERSION")"
[[ -n "$PG_HBA" ]] || { err "pg_hba.conf not found for major ${PG_VERSION}"; }

# Ensure passwordless local access for postgres via peer (temporary)
NEED_RESTORE=0
if ! sudo -u postgres psql --no-password -tAc "SELECT 1" >/dev/null 2>&1; then
  bak="${PG_HBA}.bak.$(date +%s)"
  cp -a "$PG_HBA" "$bak"
  state_put_map BACKUPS "$PG_HBA" "$bak"
  NEED_RESTORE=1

  tmp="$(mktemp)"
  replaced=0
  # Replace method token for active lines matching "local ... postgres ..."
  awk '
    BEGIN{replaced=0}
    /^[[:space:]]*#/ { print; next }
    /^[[:space:]]*$/ { print; next }
    /^[[:space:]]*local[[:space:]]+/ {
      line=$0
      # tokenize by whitespace
      n=split($0, f, /[[:space:]]+/)
      # f[1]=local, f[2]=db, f[3]=user, f[4]=addr/method depending on type
      # For "local", format is: local  DATABASE  USER  METHOD  [OPTIONS...]
      # We only target lines where USER matches "postgres"
      # Find the user field:
      # Pattern allows comments after fields; comments already excluded.
      if (n >= 4) {
        # locate user token (should be f[3])
        user=f[3]
        if (user == "postgres") {
          # method is next non-empty token after user
          # Find index of method token
          # Since it's "local", there is no address field
          # So method should be f[4]
          f[4]="peer"
          # rebuild line preserving basic spacing
          out=f[1]"  "f[2]"  "f[3]"  "f[4]
          for (i=5;i<=n;i++) if (f[i]!="") out=out" "f[i]
          print out
          replaced=1
          next
        }
      }
    }
    { print }
    END{ if (replaced==1) exit 0; else exit 1 }
  ' "$PG_HBA" > "$tmp" || true

  if grep -q . "$tmp"; then
    mv "$tmp" "$PG_HBA"
  else
    # No matching line found; prepend a high-precedence peer rule
    {
      echo "local   all             postgres                                peer"
      cat "$PG_HBA"
    } > "${tmp}.2"
    mv "${tmp}.2" "$PG_HBA"
    rm -f "$tmp"
  fi

  systemctl reload postgresql || systemctl restart postgresql
  sudo -u postgres psql --no-password -tAc "SELECT 1" >/dev/null 2>&1 || { err "psql inaccessible even after temporary peer rule"; }
fi
line "-" 72

say "Creating role and database if missing..."
sudo -u postgres psql --no-password -v ON_ERROR_STOP=1 <<SQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='${DB_USER}') THEN
    EXECUTE format('CREATE USER %I WITH PASSWORD %L', '${DB_USER}', '${DB_PASS}');
  END IF;
END
\$\$;
ALTER ROLE ${DB_USER} SET client_encoding TO 'utf8';
ALTER ROLE ${DB_USER} SET default_transaction_isolation TO 'read committed';
ALTER ROLE ${DB_USER} SET timezone TO 'UTC';
SQL

EXISTS_DB=$(sudo -u postgres psql --no-password -tAc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" || true)
[[ "$EXISTS_DB" == "1" ]] || sudo -u postgres createdb --no-password -O "${DB_USER}" "${DB_NAME}"
sudo -u postgres psql --no-password -v ON_ERROR_STOP=1 -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};"

# Restore original pg_hba.conf if we modified it
if [[ $NEED_RESTORE -eq 1 ]]; then
  cp -f "${PG_HBA}.bak."* "$PG_HBA" 2>/dev/null || true
  systemctl reload postgresql || systemctl restart postgresql
fi

# Persist detected port
state_put_flag "pg_major" "$PG_VERSION"
state_put_flag "pg_port" "$DB_PORT"

banner "PostgreSQL ${PG_VERSION} ready (db=${DB_NAME}, user=${DB_USER}, port=${DB_PORT})" "=" 72
