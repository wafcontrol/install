#!/usr/bin/env bash
set -euo pipefail

# ===== UI (pure ASCII, tty-aware) =====
is_tty=0; [ -t 1 ] && is_tty=1
if [ "$is_tty" -eq 1 ]; then
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[1;34m'; NC='\033[0m'
else
  GREEN=''; YELLOW=''; RED=''; BLUE=''; NC=''
fi
say()  { printf "%b[+]%b %s\n" "$GREEN" "$NC" "$*"; }
warn() { printf "%b[!]%b %s\n" "$YELLOW" "$NC" "$*"; }
err()  { printf "%b[x]%b %s\n" "$RED" "$NC" "$*" >&2; }
ok()   { printf "%b[OK]%b %s\n" "$GREEN" "$NC" "$*"; }
line() { local ch="${1:-=}"; local w="${2:-72}"; printf '%*s\n' "$w" '' | tr ' ' "$ch"; }
banner(){ local title="$1"; local ch="${2:-=}"; local w="${3:-72}"; line "$ch" "$w"; printf "%b%s%b\n" "$BLUE" "$title" "$NC"; line "$ch" "$w"; }
section(){ local title="$1"; printf "\n== %s ==\n" "$title"; }

trap 'err "Failed on line $LINENO"' ERR
[[ $EUID -eq 0 ]] || { err "Run as root (sudo)."; exit 1; }
export DEBIAN_FRONTEND=noninteractive

# ===== Config =====
MODULE_BASE="${MODULE_BASE:-https://github.com/wafcontrol/install/tree/main/modules}"
STATE_DIR="${STATE_DIR:-/var/lib/wafcontrol-installer}"
STATE_FILE="${STATE_FILE:-$STATE_DIR/state.env}"

state_bootstrap() {
  mkdir -p "$STATE_DIR"
  if ! grep -q 'STATE_VERSION=' "$STATE_FILE" 2>/dev/null; then
    {
      echo 'STATE_VERSION=2'
      echo 'INSTALL_TIMESTAMP='"$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      echo 'APP_DIR_DEFAULT=/opt/WafControl'
      echo 'declare -a CREATED_FILES=()'
      echo 'declare -a CREATED_UNITS=()'
      echo 'declare -A BACKUPS=()'
      echo 'declare -a CRS_DIRS=()'
      echo 'declare -A FLAGS=()'
    } > "$STATE_FILE"
  fi
}
state_append_array() { printf '%s+=(%q)\n' "$1" "$2" >> "$STATE_FILE"; }
state_put_map()      { printf '%s[%q]=%q\n' "$1" "$2" "$3" >> "$STATE_FILE"; }
state_put_flag()     { printf 'FLAGS[%q]=%q\n' "$1" "$2" >> "$STATE_FILE"; }

fetch_and_run() {
  local mod="${1:?module name required}"
  local url="${MODULE_BASE}/${mod}"
  banner "Fetching module: ${mod}"
  curl -fsSL "$url" | bash
}

detect_os() { . /etc/os-release 2>/dev/null || true; echo "${ID:-}"; }
detect_codename() { . /etc/os-release 2>/dev/null || true; echo "${VERSION_CODENAME:-}"; }

ensure_debian_sources() {
  local codename; codename="$(detect_codename)"
  local sources="/etc/apt/sources.list"
  case "$codename" in
    bullseye)
      if [ ! -s "$sources" ]; then
        cat > "$sources" <<'EOF'
deb http://security.debian.org/debian-security bullseye-security main contrib non-free
deb-src http://security.debian.org/debian-security bullseye-security main contrib

deb http://deb.debian.org/debian bullseye main contrib non-free
deb-src http://deb.debian.org/debian bullseye main
deb http://deb.debian.org/debian bullseye-updates main contrib non-free
deb-src http://deb.debian.org/debian bullseye-updates main
deb http://deb.debian.org/debian bullseye-backports main
deb-src http://deb.debian.org/debian bullseye-backports main
EOF
        say "Created /etc/apt/sources.list for Debian 11 (bullseye)."
      fi
      ;;
    bookworm) : ;;
    trixie)
      if [ ! -s "$sources" ]; then
        cat > "$sources" <<'EOF'
deb http://deb.debian.org/debian trixie main contrib non-free non-free-firmware
deb http://deb.debian.org/debian trixie-updates main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security trixie-security main contrib non-free non-free-firmware
EOF
        say "Created /etc/apt/sources.list for Debian 13 (trixie)."
      fi
      ;;
    *) : ;;
  esac
}

detect_ubuntu() { [ "$(detect_os)" = "ubuntu" ]; }

ensure_python_ubuntu() {
  . /etc/os-release
  apt-get update -y
  apt-get install -y --no-install-recommends python3 python3-venv python3-dev python3-pip || true
  local ver
  ver="$(python3 -c 'import sys;print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo 0)"
  case "${VERSION_CODENAME:-}" in
    jammy|lunar|mantic|noble) : ;;
    focal)
      case "$ver" in
        3.10|3.11|3.12) : ;;
        *)
          apt-get install -y --no-install-recommends software-properties-common
          add-apt-repository -y ppa:deadsnakes/ppa
          apt-get update -y
          apt-get install -y --no-install-recommends python3.10 python3.10-venv python3.10-dev || \
          apt-get install -y --no-install-recommends python3.11 python3.11-venv python3.11-dev
          update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.10 2 || true
          update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1 || true
          ;;
      esac
      ;;
    *) : ;;
  esac
}

gen_pass() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 64 | tr -d '\n' | tr '/+=' '___' | tr -d "'" | cut -c1-50
  else
    LC_ALL=C tr -dc 'A-Za-z0-9!@#%^&*()_+=' </dev/urandom | head -c 50
  fi
}

# ===== Defaults =====
APP_USER="${APP_USER:-wafcontrol}"
APP_DIR="${APP_DIR:-/opt/WafControl}"
VENV_DIR="${VENV_DIR:-$APP_DIR/venv}"
RUNTIME_DIR="${RUNTIME_DIR:-/run/wafcontrol}"

SERVER="${SERVER:-}"
MODE="${MODE:-}"
DOMAIN="${DOMAIN:-}"
HTTP_PORT="${HTTP_PORT:-}"

DB_NAME="${DB_NAME:-wafcontrol}"
DB_USER="${DB_USER:-wafcontrol_user}"
DB_PASS="${DB_PASS:-}"
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"
PG_VERSION="${PG_VERSION:-}"

# Basic Auth defaults to avoid unbound with `set -u`
BASIC_AUTH_ENABLE="${BASIC_AUTH_ENABLE:-0}"
BASIC_AUTH_USER="${BASIC_AUTH_USER:-}"
BASIC_AUTH_PASS="${BASIC_AUTH_PASS:-}"

# ===== Intro =====
banner "WafControl Installer (Debian/Ubuntu)" "=" 72
cat <<'TXT'
This guided installer will set up:
  • WafControl application (Django, Gunicorn, Celery)
  • PostgreSQL database (reuse existing if found)
  • Your chosen web server (Nginx or Apache)
  • WAF layer:
      - Nginx: ModSecurity v3 (built against your exact Nginx version) + latest CRS
      - Apache: libapache2-mod-security2 + latest CRS
TXT
line "-" 72

# ===== Prompts =====
echo
section "Web server selection"
echo "Type 'nginx' to build ModSecurity v3 for your Nginx and apply latest CRS."
echo "Type 'apache' to enable ModSecurity2 and apply latest CRS."
read -rp "Choose [nginx/apache] (default: nginx): " SERVER
SERVER="${SERVER:-nginx}"
[[ "$SERVER" =~ ^(nginx|apache)$ ]] || { err "Invalid server: $SERVER"; }

echo
section "Run mode selection"
echo "'ip' mode: best for local/direct IP testing (relaxed CSRF/SESSION secure flags)."
echo "'domain' mode: use if you have a valid domain pointed to this host."
read -rp "Choose [ip/domain] (default: ip): " MODE
MODE="${MODE:-ip}"

if [[ "$MODE" == "domain" && -z "${DOMAIN:-}" ]]; then
  read -rp "Enter domain (e.g. waf.example.com): " DOMAIN
  [[ -z "$DOMAIN" ]] && { err "Domain is required for domain mode."; }
fi

SSL_ENABLE=0
CERTBOT_EMAIL="${CERTBOT_EMAIL:-}"
if [[ "$MODE" == "domain" ]]; then
  say "In domain mode the service will bind to :80 and optionally :443."
  read -rp "Enable SSL with Let's Encrypt? [y/N]: " SSL_CH
  [[ "$SSL_CH" =~ ^[Yy]$ ]] && SSL_ENABLE=1
else
  if [[ -z "$HTTP_PORT" ]]; then
    echo
    echo "HTTP listen port for the dashboard (default: 7000)."
    read -rp "Port [7000]: " HTTP_PORT
    HTTP_PORT="${HTTP_PORT:-7000}"
  fi
fi

echo
section "PostgreSQL detection"
if command -v psql >/dev/null 2>&1; then
  INSTALLED_MAJOR="$(psql -V | awk '{print $3}' | cut -d. -f1)"
  PG_VERSION="${INSTALLED_MAJOR}"
  say "PostgreSQL detected: version ${PG_VERSION} (will be reused)."
else
  echo "PostgreSQL not detected. Provide the major version to install (e.g. 17)."
  read -rp "PostgreSQL major version to install: " PG_VERSION
  [[ -z "$PG_VERSION" ]] && { err "PG_VERSION is required."; }
fi

read -rp "Database name [wafcontrol]: " IN_DBNAME
read -rp "Database user [wafcontrol_user]: " IN_DBUSER
read -srp "Database password [auto-generate if empty]: " IN_DBPASS; echo
DB_NAME="${IN_DBNAME:-$DB_NAME}"
DB_USER="${IN_DBUSER:-$DB_USER}"
DB_PASS="${IN_DBPASS:-$DB_PASS}"

if [[ "$MODE" == "domain" && $SSL_ENABLE -eq 1 ]]; then
  CERTBOT_EMAIL_DEFAULT="admin@${DOMAIN}"
  read -rp "Email for Let's Encrypt notifications [${CERTBOT_EMAIL_DEFAULT}]: " CERTBOT_EMAIL
  CERTBOT_EMAIL="${CERTBOT_EMAIL:-$CERTBOT_EMAIL_DEFAULT}"
fi

echo
section "Optional HTTP Basic Auth (extra layer before login)"
read -rp "Enable HTTP Basic Auth for dashboard? [y/N]: " BASIC_CH
if [[ "$BASIC_CH" =~ ^[Yy]$ ]]; then
  BASIC_AUTH_ENABLE=1
  while :; do
    read -rp "Basic Auth username: " BASIC_AUTH_USER
    [[ -n "$BASIC_AUTH_USER" && "$BASIC_AUTH_USER" != *:* ]] && break || warn "Username cannot be empty or contain ':'."
  done
  while :; do
    read -srp "Basic Auth password: " BASIC_AUTH_PASS; echo
    [[ -n "$BASIC_AUTH_PASS" ]] && break || warn "Password cannot be empty."
  done
  say "HTTP Basic Auth will be applied at web server level (separate from Django login)."
else
  BASIC_AUTH_ENABLE=0
  BASIC_AUTH_USER=""
  BASIC_AUTH_PASS=""
fi

echo
banner "Summary" "=" 72
echo "• Server:       $SERVER"
if [[ "$MODE" == "domain" ]]; then
  echo "• Mode:         domain (domain=$DOMAIN)"
  echo "• HTTP/S:       80$( [[ $SSL_ENABLE -eq 1 ]] && echo ' and 443 (SSL enabled)' || echo ' only' )"
else
  echo "• Mode:         ip"
  echo "• HTTP Port:    $HTTP_PORT"
fi
echo "• PostgreSQL:   $PG_VERSION  (db=$DB_NAME, user=$DB_USER)"
echo "• App Path:     $APP_DIR"
echo "• Basic Auth:   $([[ $BASIC_AUTH_ENABLE -eq 1 ]] && echo "enabled (user=$BASIC_AUTH_USER)" || echo "disabled")"
read -rp "Proceed with installation? [y/N]: " PROCEED
[[ "$PROCEED" =~ ^[Yy]$ ]] || { warn "Aborted."; exit 0; }

# ===== Prepare apt sources (Debian only) =====
if [ "$(detect_os)" = "debian" ]; then
  ensure_debian_sources
fi

# ===== State =====
state_bootstrap
state_put_flag "server" "$SERVER"
state_put_flag "mode" "$MODE"
state_put_flag "domain" "${DOMAIN:-}"
state_put_flag "port" "${HTTP_PORT:-80}"
state_put_flag "ssl_enable" "$SSL_ENABLE"
state_put_flag "certbot_email" "${CERTBOT_EMAIL:-}"
state_put_flag "pg_version" "$PG_VERSION"
state_put_flag "app_dir" "$APP_DIR"
state_put_flag "venv_dir" "$VENV_DIR"
state_put_flag "runtime_dir" "$RUNTIME_DIR"
state_put_flag "basic_auth_enable" "$BASIC_AUTH_ENABLE"
state_put_flag "basic_auth_user" "$BASIC_AUTH_USER"

# Export for modules (after values exist)
export BASIC_AUTH_ENABLE BASIC_AUTH_USER BASIC_AUTH_PASS
export SSL_ENABLE CERTBOT_EMAIL

# ===== Base packages =====
banner "Installing base packages" "=" 72
apt-get update -y

if apt-cache show gnupg2 >/dev/null 2>&1; then GPG_PKG=gnupg2; else GPG_PKG=gnupg; fi

if detect_ubuntu; then
  ensure_python_ubuntu
else
  apt-get install -y --no-install-recommends python3 python3-venv python3-dev python3-pip || true
fi

apt-get install -y --no-install-recommends \
  curl "$GPG_PKG" ca-certificates lsb-release debian-archive-keyring \
  build-essential git pkg-config jq wget tar sed grep procps \
  libpq-dev redis-server openssl

# ===== Project & venv =====
banner "Fetching project and preparing Python environment" "=" 72
mkdir -p "$APP_DIR"
if [[ -d "$APP_DIR/.git" || -f "$APP_DIR/manage.py" ]]; then
  warn "Project already present at ${APP_DIR}. Skipping clone."
else
  say "Cloning WafControl into ${APP_DIR}..."
  git clone "https://github.com/wafcontrol/wafcontrol.git" "$APP_DIR"
  state_append_array CREATED_FILES "$APP_DIR"
fi

if [[ ! -d "$VENV_DIR" ]]; then
  say "Creating virtualenv..."
  python3 -m venv "$VENV_DIR"
  state_append_array CREATED_FILES "$VENV_DIR"
fi
# shellcheck disable=SC1090
source "${VENV_DIR}/bin/activate"
python -m pip install --upgrade pip wheel setuptools
REQ_FILE="${APP_DIR}/requirements.txt"
if [[ -f "$REQ_FILE" ]]; then
  say "Installing Python requirements..."
  pip install -r "$REQ_FILE"
else
  warn "requirements.txt not found. Installing minimal stack..."
  pip install "Django>=5" gunicorn celery
fi
pip install django-environ "psycopg[binary]>=3.1" || pip install psycopg2-binary

export APP_USER APP_DIR VENV_DIR RUNTIME_DIR
export SERVER MODE DOMAIN HTTP_PORT
export DB_NAME DB_USER DB_PASS DB_HOST DB_PORT PG_VERSION
export STATE_DIR STATE_FILE MODULE_BASE SSL_ENABLE CERTBOT_EMAIL

if [[ -z "${DB_PASS:-}" ]]; then
  DB_PASS="$(gen_pass)"; export DB_PASS; say "Generated DB password for ${DB_USER}."
fi

# ===== PostgreSQL module =====
fetch_and_run "postgres.sh"

# ===== .env and Django setup =====
banner "Writing .env and preparing" "=" 72
SECRET_KEY_VALUE="$(gen_pass)"
CSRF_SEC=True; SESSION_SEC=True
[[ "$MODE" == "ip" ]] && CSRF_SEC=False && SESSION_SEC=False
ALLOWED_LIST="127.0.0.1,localhost"
if [[ "$MODE" == "domain" ]]; then
  ALLOWED_LIST="${ALLOWED_LIST},${DOMAIN},www.${DOMAIN}"
else
  IP=$(hostname -I | awk '{print $1}')
  [[ -n "$IP" ]] && ALLOWED_LIST="${ALLOWED_LIST},${IP}"
fi

cat > "${APP_DIR}/.env" <<EOF
SECRET_KEY=${SECRET_KEY_VALUE}
DEBUG=False
ALLOWED_HOSTS=${ALLOWED_LIST}

DB_ENGINE=django.db.backends.postgresql
DB_NAME=${DB_NAME}
DB_USER=${DB_USER}
DB_PASS=${DB_PASS}
DB_HOST=${DB_HOST}
DB_PORT=${DB_PORT}

CSRF_COOKIE_SECURE=${CSRF_SEC}
SESSION_COOKIE_SECURE=${SESSION_SEC}
SECURE_BROWSER_XSS_FILTER=True
SECURE_CONTENT_TYPE_NOSNIFF=True
X_FRAME_OPTIONS=DENY
EOF
state_append_array CREATED_FILES "${APP_DIR}/.env"

if [[ "$MODE" == "domain" && -n "${DOMAIN:-}" ]]; then
  {
    echo "CSRF_TRUSTED_ORIGINS=https://${DOMAIN},https://www.${DOMAIN}"
    echo "SECURE_PROXY_SSL_HEADER=HTTP_X_FORWARDED_PROTO,https"
    echo "USE_X_FORWARDED_HOST=True"
  } >> "${APP_DIR}/.env"
fi

banner "Verifying database connectivity" "=" 72
if ! PGPASSWORD="${DB_PASS}" psql -h "${DB_HOST}" -U "${DB_USER}" -d "${DB_NAME}" -c 'select 1;' >/dev/null 2>&1; then
  err "Database auth failed. Check DB_USER/DB_PASS/pg_hba.conf."
fi

banner "Applying migrations and collecting static files" "=" 72
"${VENV_DIR}/bin/python" "${APP_DIR}/manage.py" makemigrations wafinstaller || true
"${VENV_DIR}/bin/python" "${APP_DIR}/manage.py" migrate --noinput
mkdir -p "${APP_DIR}/frontend"
"${VENV_DIR}/bin/python" "${APP_DIR}/manage.py" collectstatic --noinput

# ===== Detect nginx group for units if server==nginx =====
NGX_GROUP_FALLBACK="www-data"
NGX_GROUP_VAL="$NGX_GROUP_FALLBACK"
if [[ "$SERVER" == "nginx" ]]; then
  NGX_MAIN="/etc/nginx/nginx.conf"
  detect_from_file() {
    local file="$1"
    [ -r "$file" ] || return 1
    grep -E '^[[:space:]]*user[[:space:]]+' "$file" \
      | sed -E 's/#.*$//' \
      | head -n1 \
      | sed -E 's/^[[:space:]]*user[[:space:]]+([^;[:space:]]+).*/\1/' \
      | tr -d '\n'
  }
  detect_nginx_user() {
    local u=""
    if [ -r "$NGX_MAIN" ]; then
      u="$(detect_from_file "$NGX_MAIN" || true)"
    fi
    if [ -z "$u" ] && command -v nginx >/dev/null 2>&1; then
      if timeout 3s nginx -T >/dev/null 2>&1; then
        u="$(nginx -T 2>/dev/null | grep -E '^[[:space:]]*user[[:space:]]+' | sed -E 's/#.*$//' | head -n1 | sed -E 's/^[[:space:]]*user[[:space:]]+([^;[:space:]]+).*/\1/' | tr -d '\n')" || true
      fi
    fi
    if [ -z "$u" ]; then
      u="$(ps -o user= -C nginx 2>/dev/null | head -n1 || true)"
    fi
    [ -n "$u" ] || u="nginx"
    echo "$u"
  }
  NGX_USER_DET="$(detect_nginx_user)"
  NGX_GROUP_VAL="$(id -gn "$NGX_USER_DET" 2>/dev/null || echo "$NGX_USER_DET")"
  say "Using web group for units: ${NGX_GROUP_VAL}"
fi

# ===== systemd units =====
banner "Creating and enabling systemd units" "=" 72
GUNI_UNIT="/etc/systemd/system/wafcontrol.service"
CELERYW_UNIT="/etc/systemd/system/wafcontrol-celery-worker.service"
CELERYB_UNIT="/etc/systemd/system/wafcontrol-celery-beat.service"

WEB_GROUP_LINE="Group=www-data"
if [[ "$SERVER" == "nginx" ]]; then
  WEB_GROUP_LINE="Group=${NGX_GROUP_VAL}"
fi

cat > "$GUNI_UNIT" <<EOF
[Unit]
Description=WafControl Gunicorn
After=network-online.target postgresql.service
Wants=network-online.target
[Service]
User=root
${WEB_GROUP_LINE}
WorkingDirectory=${APP_DIR}
Environment="DJANGO_SETTINGS_MODULE=WafControl.settings"
RuntimeDirectory=wafcontrol
RuntimeDirectoryMode=0755
UMask=0007
ExecStart=${VENV_DIR}/bin/gunicorn --workers 4 --timeout 120 --bind unix:${RUNTIME_DIR}/gunicorn.sock WafControl.wsgi:application
Restart=always
RestartSec=3
PrivateTmp=true
[Install]
WantedBy=multi-user.target
EOF

cat > "$CELERYW_UNIT" <<EOF
[Unit]
Description=WafControl Celery Worker
After=network-online.target redis-server.service
Wants=network-online.target
[Service]
User=root
${WEB_GROUP_LINE}
WorkingDirectory=${APP_DIR}
Environment="DJANGO_SETTINGS_MODULE=WafControl.settings"
ExecStart=${VENV_DIR}/bin/celery -A WafControl worker -l INFO
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF

cat > "$CELERYB_UNIT" <<EOF
[Unit]
Description=WafControl Celery Beat
After=network-online.target redis-server.service
Wants=network-online.target
[Service]
User=root
${WEB_GROUP_LINE}
WorkingDirectory=${APP_DIR}
Environment="DJANGO_SETTINGS_MODULE=WafControl.settings"
ExecStart=${VENV_DIR}/bin/celery -A WafControl beat -l INFO
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now wafcontrol.service wafcontrol-celery-worker.service wafcontrol-celery-beat.service
state_append_array CREATED_UNITS "$GUNI_UNIT"
state_append_array CREATED_UNITS "$CELERYW_UNIT"
state_append_array CREATED_UNITS "$CELERYB_UNIT"

# ===== Web server modules =====
if [[ "$SERVER" == "nginx" ]]; then
  fetch_and_run "waf-nginx.sh"
else
  fetch_and_run "waf-apache.sh"
fi

# ===== Create admin =====
echo
banner "Create Wafcontrol Admin" "=" 72
read -rp "Create now? [y/N]: " MKADMIN
if [[ "$MKADMIN" =~ ^[Yy]$ ]]; then
  source "${VENV_DIR}/bin/activate"
  "${VENV_DIR}/bin/python" "${APP_DIR}/manage.py" createsuperuser || warn "createsuperuser skipped."
fi

TARGET_HOST="${DOMAIN:-$(hostname -I | awk '{print $1}')}"
banner "Installation complete" "=" 72
if [[ "$MODE" == "domain" ]]; then
  echo "Open: http://${TARGET_HOST}/ (SSL $( [[ $SSL_ENABLE -eq 1 ]] && echo 'enabled' || echo 'disabled' ))"
else
  echo "Open: http://${TARGET_HOST}:${HTTP_PORT}/"
fi
echo "Services:"
echo "  systemctl status wafcontrol"
echo "  systemctl status wafcontrol-celery-worker"
echo "  systemctl status wafcontrol-celery-beat"
line "=" 72
