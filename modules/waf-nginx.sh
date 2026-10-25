#!/usr/bin/env bash
set -euo pipefail

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

STATE_DIR="${STATE_DIR:-/var/lib/wafcontrol-installer}"
STATE_FILE="${STATE_FILE:-$STATE_DIR/state.env}"
mkdir -p "$STATE_DIR"; touch "$STATE_FILE"
state_append_array() { printf '%s+=(%q)\n' "$1" "$2" >> "$STATE_FILE"; }
state_put_map()      { printf '%s[%q]=%q\n' "$1" "$2" "$3" >> "$STATE_FILE"; }
source "$STATE_FILE" 2>/dev/null || true

APP_DIR="${APP_DIR:?}"
VENV_DIR="${VENV_DIR:?}"
RUNTIME_DIR="${RUNTIME_DIR:?}"
HTTP_PORT="${HTTP_PORT:-7000}"
MODE="${MODE:?}"
DOMAIN="${DOMAIN:-}"
SSL_ENABLE="${SSL_ENABLE:-0}"
CERTBOT_EMAIL="${CERTBOT_EMAIL:-}"
STATIC_DIR="${APP_DIR}/frontend"

BASIC_AUTH_ENABLE="${BASIC_AUTH_ENABLE:-0}"
BASIC_AUTH_USER="${BASIC_AUTH_USER:-}"
BASIC_AUTH_PASS="${BASIC_AUTH_PASS:-}"

banner "Nginx + ModSecurity v3 + CRS" "=" 72

if ! command -v nginx >/dev/null 2>&1; then
  say "Installing Nginx from nginx.org..."
  curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
  . /etc/os-release
  echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/${ID} ${VERSION_CODENAME} nginx" > /etc/apt/sources.list.d/nginx.list
  apt update -y
  apt install -y nginx
  systemctl enable --now nginx
else
  say "Nginx detected."
fi

NGX_MAIN="/etc/nginx/nginx.conf"
[[ -f "$NGX_MAIN" ]] || { err "nginx.conf not found"; exit 1; }

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
  u="$(detect_from_file "$NGX_MAIN" || true)"
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
NGX_USER="$(detect_nginx_user)"
NGX_GROUP="$(id -gn "$NGX_USER" 2>/dev/null || echo "$NGX_USER")"
say "Detected nginx user: $NGX_USER (group: $NGX_GROUP)"

apt update -y
# libmodsecurity-dev pulls in the correct runtime package, including the
# libmodsecurity3t64 rename on Ubuntu 24.04 and Debian 13.
apt install -y build-essential pkg-config libpcre2-dev zlib1g-dev libssl-dev git curl jq wget
apt install -y libmodsecurity-dev || warn "Packaged ModSecurity unavailable; trying a source build."

if ! pkg-config --exists modsecurity; then
  say "Building libmodsecurity from source..."
  . /etc/os-release 2>/dev/null || true
  PCRE_PKGS="libpcre3 libpcre3-dev"
  XML2_PKGS="libxml2 libxml2-dev"
  if { [ "${ID:-}" = "debian" ] && [ "${VERSION_CODENAME:-}" = "trixie" ]; } || \
     { [ "${ID:-}" = "ubuntu" ] && [ "${VERSION_CODENAME:-}" = "noble" ]; }; then
    PCRE_PKGS="libpcre2-dev"
  elif [ "${ID:-}" = "debian" ] && [ "${VERSION_CODENAME:-}" = "bookworm" ]; then
    PCRE_PKGS="libpcre3 libpcre3-dev libpcre2-dev"
  fi

  if { [ "${ID:-}" = "ubuntu" ] && [ "${VERSION_CODENAME:-}" = "resolute" ]; }; then
  	XML2_PKGS="libxml2-dev"
   	PCRE_PKGS="libpcre2-dev"
  fi
  apt install -y make gcc autoconf automake libtool gettext pkg-config \
    libcurl4-openssl-dev liblua5.3-dev $PCRE_PKGS \
    $XML2_PKGS libyajl-dev doxygen libgeoip-dev libssl-dev \
    zlib1g-dev libxslt1-dev liblmdb-dev libgd-dev git uuid-dev

  # Use a release, so its configuration files can be retrieved by the same tag.
  MODSEC_SOURCE=/usr/local/src/ModSecurity-v3.0.17
  test -d "$MODSEC_SOURCE" || git clone --depth 1 --recursive -b v3.0.17 \
    https://github.com/owasp-modsecurity/ModSecurity.git "$MODSEC_SOURCE"
  cd "$MODSEC_SOURCE"
  git submodule sync --recursive
  git submodule update --init --recursive
  ./build.sh
  ./configure
  make -j"$(nproc)"
  make install
  ldconfig
  export PKG_CONFIG_PATH="/usr/local/modsecurity/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
  say "libmodsecurity built and installed."
else
  say "libmodsecurity present via packages."
fi

MODSEC_VERSION="$(pkg-config --modversion modsecurity)"
[[ "$MODSEC_VERSION" =~ ^3\.[0-9]+\.[0-9]+$ ]] || { err "Unsupported ModSecurity version: $MODSEC_VERSION"; exit 1; }
# Make the connector use the same library whose version selects the template.
export MODSECURITY_INC="$(pkg-config --variable=includedir modsecurity)"
export MODSECURITY_LIB="$(pkg-config --variable=libdir modsecurity)"
say "Using ModSecurity v${MODSEC_VERSION} (${MODSECURITY_LIB})."

test -d /usr/local/src/ModSecurity-nginx || git clone --depth 1 https://github.com/owasp-modsecurity/ModSecurity-nginx.git /usr/local/src/ModSecurity-nginx
NVER="$(nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')" || NVER=""
[[ -n "$NVER" ]] || { err "Cannot detect Nginx version."; exit 1; }

detect_modules_dir() {
  local mp=""
  mp="$(nginx -V 2>&1 | sed -n 's/.*--modules-path=\([^ ]*\).*/\1/p' | tail -n1 || true)"
  if [[ -n "$mp" ]]; then
    echo "$mp"
    return 0
  fi
  for d in /usr/lib/nginx/modules /usr/lib64/nginx/modules /usr/share/nginx/modules /etc/nginx/modules; do
    if [[ -d "$d" ]]; then
      echo "$d"
      return 0
    fi
  done
  echo "/usr/lib/nginx/modules"
  return 0
}

MOD_DIR="$(detect_modules_dir)"
say "Using modules dir: $MOD_DIR"

mkdir -p /usr/local/src/nginx && cd /usr/local/src/nginx
if [[ ! -d "nginx-${NVER}" ]]; then
  say "Fetching nginx source: ${NVER}"
  wget -q "https://nginx.org/download/nginx-${NVER}.tar.gz"
  tar -xzf "nginx-${NVER}.tar.gz"
fi

apt-get build-dep -y nginx || true
cd "nginx-${NVER}"
./configure --with-compat --add-dynamic-module=/usr/local/src/ModSecurity-nginx
make modules

install -d -m 0755 "$MOD_DIR"
cp -f objs/ngx_http_modsecurity_module.so "$MOD_DIR/ngx_http_modsecurity_module.so"
state_append_array CREATED_FILES "$MOD_DIR/ngx_http_modsecurity_module.so"
say "Dynamic module built."

TS="$(date +%s)"

find_http_file() {
  if grep -q '^[[:space:]]*http[[:space:]]*{' "$NGX_MAIN"; then
    echo "$NGX_MAIN"; return
  fi
  awk 'BEGIN{h=0}/^[[:space:]]*http[[:space:]]*$/ {h=1} h && /^[[:space:]]*{/ {print FILENAME; exit}' "$NGX_MAIN" >/dev/null 2>&1 && { echo "$NGX_MAIN"; return; }
  local f
  f="$(grep -RIl --include='*.conf' '^[[:space:]]*http[[:space:]]*{' /etc/nginx 2>/dev/null | head -n1 || true)"
  [[ -n "$f" ]] && { echo "$f"; return; }
  f="$(awk 'FNR==1{fname=FILENAME}/^[[:space:]]*http[[:space:]]*$/ {h=1} h && /^[[:space:]]*{/ {print fname; exit}' /etc/nginx/*.conf /etc/nginx/*/*.conf 2>/dev/null | head -n1 || true)"
  [[ -n "$f" ]] && { echo "$f"; return; }
  echo ""
}
HTTP_FILE="$(find_http_file)"
[[ -n "$HTTP_FILE" ]] || { err "Could not locate a file containing the http { } block."; exit 1; }

MDIR="/etc/nginx/modsec"
mkdir -p "$MDIR"

fetch_modsecurity_defaults() {
  local staging asset
  staging="$(mktemp -d "$MDIR/.defaults.XXXXXX")" || return 1
  for asset in modsecurity.conf-recommended unicode.mapping; do
    if ! curl -fLsS --retry 3 --connect-timeout 15 --max-time 120 \
      "https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v${MODSEC_VERSION}/${asset}" \
      -o "$staging/$asset" || [[ ! -s "$staging/$asset" ]]; then
      rm -rf "$staging"
      err "Cannot fetch ${asset} for ModSecurity v${MODSEC_VERSION}."
      return 1
    fi
  done
  if [[ ! -f "$MDIR/modsecurity.conf" ]]; then
    cp "$staging/modsecurity.conf-recommended" "$MDIR/modsecurity.conf"
  fi
  [[ -f "$MDIR/unicode.mapping" ]] || cp "$staging/unicode.mapping" "$MDIR/unicode.mapping"
  rm -rf "$staging"
}

if [[ ! -f "$MDIR/modsecurity.conf" || ! -f "$MDIR/unicode.mapping" ]]; then
  fetch_modsecurity_defaults
  say "ModSecurity defaults prepared from matching v${MODSEC_VERSION} release."
fi

# Repair the template copied by earlier installers without replacing local
# settings or removing rule 200003 (multipart strict validation). This variable
# was added in v3.0.17; on older engines only its diagnostic text is unsupported.
if dpkg --compare-versions "$MODSEC_VERSION" lt 3.0.17 && \
   grep -qE 'DH[[:blank:]]+%\{MULTIPART_DUPLICATE_PART_HEADER\},' "$MDIR/modsecurity.conf"; then
  cp -a "$MDIR/modsecurity.conf" "$MDIR/modsecurity.conf.bak.${TS}"
  state_put_map BACKUPS "$MDIR/modsecurity.conf" "$MDIR/modsecurity.conf.bak.${TS}"
  sed -i -E 's/DH[[:blank:]]+%\{MULTIPART_DUPLICATE_PART_HEADER\},[[:blank:]]*//g' "$MDIR/modsecurity.conf"
  say "Repaired incompatible multipart log variable for ModSecurity v${MODSEC_VERSION}."
fi

# Nginx's prefix is not the ModSecurity configuration directory.
sed -i -E "s|^([[:blank:]]*SecUnicodeMapFile[[:blank:]]+)unicode.mapping([[:blank:]]+)|\1${MDIR}/unicode.mapping\2|" "$MDIR/modsecurity.conf"

sed -i -E 's/^\s*SecRuleEngine\s+DetectionOnly/SecRuleEngine On/i' "$MDIR/modsecurity.conf" || true
grep -qE '^\s*SecRuleEngine\s+' "$MDIR/modsecurity.conf" || echo "SecRuleEngine On" >> "$MDIR/modsecurity.conf"

MAIN="$MDIR/main.conf"
if [[ ! -f "$MAIN" ]]; then
  { echo "# WAFCONTROL main config"; echo "Include $MDIR/modsecurity.conf"; } > "$MAIN"
fi
state_append_array CREATED_FILES "$MAIN"
state_append_array CREATED_FILES "$MDIR/modsecurity.conf"
state_append_array CREATED_FILES "$MDIR/unicode.mapping"

# Parse the base configuration with the actual connector before enabling it in
# nginx.conf, so an incompatible template fails before changing the load setup.
validate_modsecurity_conf() {
  local staging result=0
  staging="$(mktemp -d -t wafcontrol-nginx-check-XXXXXX)" || return 1
  cat > "$staging/nginx.conf" <<CONF
load_module ${MOD_DIR}/ngx_http_modsecurity_module.so;
pid ${staging}/nginx.pid;
error_log stderr;
events {}
http {
    access_log off;
    modsecurity on;
    modsecurity_rules_file ${MDIR}/modsecurity.conf;
}
CONF
  nginx -t -e stderr -p "$staging/" -c "$staging/nginx.conf" || result=$?
  rm -rf "$staging"
  return "$result"
}
if ! validate_modsecurity_conf; then
  err "ModSecurity v${MODSEC_VERSION} rejected its base configuration. Nginx was not restarted."
  exit 1
fi

if ! grep -q 'ngx_http_modsecurity_module.so' "$NGX_MAIN" 2>/dev/null; then
  cp -a "$NGX_MAIN" "${NGX_MAIN}.bak.${TS}"
  state_put_map BACKUPS "$NGX_MAIN" "${NGX_MAIN}.bak.${TS}"
  sed -i "1iload_module ${MOD_DIR}/ngx_http_modsecurity_module.so;" "$NGX_MAIN"
  say "Injected load_module into nginx.conf"
fi

if ! grep -q 'WAFCONTROL-BEGIN' "$HTTP_FILE"; then
  cp -a "$HTTP_FILE" "${HTTP_FILE}.bak.${TS}"
  state_put_map BACKUPS "$HTTP_FILE" "${HTTP_FILE}.bak.${TS}"
  awk '
  BEGIN{done=0; seen_http=0}
  {
    if (done) { print; next }
    if ($0 ~ /^[[:space:]]*http[[:space:]]*{/ && !done) {
      print
      print "    # WAFCONTROL-BEGIN"
      print "    modsecurity on;"
      print "    modsecurity_rules_file /etc/nginx/modsec/main.conf;"
      print "    # WAFCONTROL-END"
      done=1; next
    }
    if (!done && $0 ~ /^[[:space:]]*http[[:space:]]*$/) { print; seen_http=1; next }
    if (!done && seen_http && $0 ~ /^[[:space:]]*{/ ) {
      print
      print "    # WAFCONTROL-BEGIN"
      print "    modsecurity on;"
      print "    modsecurity_rules_file /etc/nginx/modsec/main.conf;"
      print "    # WAFCONTROL-END"
      done=1; seen_http=0; next
    }
    print
  }' "$HTTP_FILE" > "${HTTP_FILE}.new"
  mv "${HTTP_FILE}.new" "$HTTP_FILE"
  say "Inserted WAF block into: $HTTP_FILE"
else
  warn "WAF block already present in $HTTP_FILE; skipping insert."
fi

say "Fetching latest CRS..."
TAG="$(curl -s https://api.github.com/repos/coreruleset/coreruleset/releases/latest | jq -r '.tag_name' || true)"
CRS_DIR=""
if [[ -n "$TAG" && "$TAG" != "null" ]]; then
  NUM="${TAG#v}"
  CRS_DIR="$MDIR/coreruleset-${NUM}"
  if [[ ! -d "$CRS_DIR" ]]; then
    TMPD="$(mktemp -d -t crs-XXXXXX)"
    wget -q "https://github.com/coreruleset/coreruleset/archive/refs/tags/${TAG}.tar.gz" -O "$TMPD/crs.tgz"
    tar -xzf "$TMPD/crs.tgz" -C "$TMPD"
    mv "$TMPD/coreruleset-${NUM}" "$CRS_DIR"
    rm -rf "$TMPD"
    say "CRS downloaded: ${TAG}"
  else
    say "CRS already present: ${CRS_DIR}"
  fi
else
  if [[ -d /usr/share/modsecurity-crs/rules ]]; then
    CRS_DIR="$MDIR/coreruleset-packaged"
    [[ -d "$CRS_DIR" ]] || cp -a /usr/share/modsecurity-crs "$CRS_DIR"
    say "CRS fallback to packaged copy."
  else
    err "Failed to resolve latest CRS and no packaged CRS found."
  fi
fi
[[ -d "$CRS_DIR" ]] || { err "CRS directory missing: $CRS_DIR"; exit 1; }
[[ -f "$CRS_DIR/crs-setup.conf" ]] || { [[ -f "$CRS_DIR/crs-setup.conf.example" ]] && cp "$CRS_DIR/crs-setup.conf.example" "$CRS_DIR/crs-setup.conf"; }
for f in REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf; do
  [[ -f "$CRS_DIR/rules/$f" ]] || { [[ -f "$CRS_DIR/rules/${f}.example" ]] && cp "$CRS_DIR/rules/$f.example" "$CRS_DIR/rules/${f}" || true; }
done
EXCL="$CRS_DIR/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf"
if ! grep -q '/crs/rules/save/' "$EXCL" 2>/dev/null; then
  cat >> "$EXCL" <<'EOR'
SecRule REQUEST_URI "@beginsWith /crs/rules/save/"        "id:1500010,phase:1,nolog,pass,ctl:ruleEngine=Off"
SecRule REQUEST_URI "@beginsWith /dashboard/crs/settings/" "id:1500011,phase:1,nolog,pass,ctl:ruleEngine=Off"
EOR
fi
sed -i '/Include .*crs-setup.conf/d' "$MAIN" || true
sed -i '/Include .*rules\/\*.conf/d' "$MAIN" || true
{
  echo "Include $CRS_DIR/crs-setup.conf"
  echo "Include $CRS_DIR/rules/*.conf"
} >> "$MAIN"
state_append_array CRS_DIRS "$CRS_DIR"
say "CRS wired: $(basename "$CRS_DIR")"

VHOST="/etc/nginx/conf.d/wafcontrol.conf"
AUTH_SNIPPET=""
if [[ "${BASIC_AUTH_ENABLE}" = "1" && -n "${BASIC_AUTH_USER}" && -n "${BASIC_AUTH_PASS}" ]]; then
  HTPASS="/etc/nginx/.htpasswdwaf"
  HASH="$(openssl passwd -apr1 "${BASIC_AUTH_PASS}")"
  printf '%s:%s\n' "${BASIC_AUTH_USER}" "${HASH}" > "${HTPASS}"
  chown root:"$NGX_GROUP" "${HTPASS}" || true
  chmod 640 "${HTPASS}" || true
  AUTH_SNIPPET=$'    auth_basic "Restricted WAF Dashboard";\n    auth_basic_user_file /etc/nginx/.htpasswdwaf;'
fi

if [[ "$MODE" == "domain" ]]; then
  cat > "$VHOST" <<NGX
server {
    listen 80;
    server_name ${DOMAIN} www.${DOMAIN};

    access_log /var/log/nginx/wafcontrol_access.log;
    error_log  /var/log/nginx/wafcontrol_error.log;

    location /static/ {
        alias ${STATIC_DIR}/static/;
        autoindex off;
    }

    location / {
${AUTH_SNIPPET}
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 120s;
        proxy_connect_timeout 120s;
        proxy_pass http://unix:${RUNTIME_DIR}/gunicorn.sock;
    }
}
NGX
  state_append_array CREATED_FILES "$VHOST"
  say "App vhost written: $VHOST (port 80)"

  if [[ "$SSL_ENABLE" -eq 1 ]]; then
    say "Installing certbot and enabling SSL for ${DOMAIN}"
    apt install -y certbot python3-certbot-nginx
    EMAIL="${CERTBOT_EMAIL:-admin@${DOMAIN}}"
    certbot --nginx -d "$DOMAIN" -d "www.$DOMAIN" --non-interactive --agree-tos -m "$EMAIL" --redirect || warn "Certbot failed"
  fi
else
  cat > "$VHOST" <<NGX
server {
    listen ${HTTP_PORT};
    server_name _;

    access_log /var/log/nginx/wafcontrol_access.log;
    error_log  /var/log/nginx/wafcontrol_error.log;

    location /static/ {
        alias ${STATIC_DIR}/static/;
        autoindex off;
    }

    location / {
${AUTH_SNIPPET}
        proxy_set_header Host \$http_host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 120s;
        proxy_connect_timeout 120s;
        proxy_pass http://unix:${RUNTIME_DIR}/gunicorn.sock;
    }
}
NGX
  state_append_array CREATED_FILES "$VHOST"
  say "App vhost written: $VHOST (port ${HTTP_PORT})"
fi

if nginx -t; then
  systemctl restart nginx
  say "Nginx WAF ready (ModSecurity v3 + CRS)."
else
  err "nginx -t failed. Check the configuration."
  exit 1
fi
