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
# shellcheck disable=SC1090
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

# shellcheck source=/dev/null
. /etc/os-release
case "${ID:-}:${VERSION_CODENAME:-}" in
  ubuntu:jammy|ubuntu:noble|ubuntu:resolute|debian:bookworm|debian:trixie) ;;
  *) err "Unsupported distribution: ${ID:-unknown} ${VERSION_ID:-unknown}. Expected Ubuntu 22.04/24.04/26.04 or Debian 12/13."; exit 1 ;;
esac

# Keep backups for every configuration/module path changed below. An unsuccessful
# run restores files before attempting to activate any previous configuration.
BACKUP_DIR=$(mktemp -d "$STATE_DIR/nginx-backup.XXXXXXXX")
BUILD_TMP=$(mktemp -d -t wafcontrol-nginx-build-XXXXXXXX)
declare -A SAVED_PATHS=()
declare -a SAVED_FILES=() SAVED_EXISTING=()
DEPLOYED=0; ACTIVATION_ATTEMPTED=0; NGINX_WAS_ACTIVE=0
if systemctl is-active --quiet nginx; then NGINX_WAS_ACTIVE=1; fi
backup_nginx_file() {
  local path=$1 index=${#SAVED_FILES[@]}
  [[ ! ${SAVED_PATHS[$path]+saved} ]] || return 0
  [[ ! -d "$path" || -L "$path" ]] || { err "Expected a file, got a directory: $path"; return 1; }
  SAVED_PATHS[$path]=1; SAVED_FILES+=("$path"); SAVED_EXISTING+=(0)
  if [[ -e "$path" || -L "$path" ]]; then
    cp -a -- "$path" "$BACKUP_DIR/$index"
    SAVED_EXISTING[index]=1
    [[ "$path" == "$STATE_FILE" ]] || state_put_map BACKUPS "$path" "$BACKUP_DIR/$index"
  else state_append_array CREATED_FILES "$path"; fi
}
finish_nginx_install() {
  local result=$? index path temporary
  trap - EXIT INT TERM
  if [[ $DEPLOYED == 0 ]]; then
    for ((index=${#SAVED_FILES[@]}-1; index>=0; index--)); do
      path=${SAVED_FILES[$index]}
      if [[ ${SAVED_EXISTING[$index]} == 1 ]]; then
        temporary=$(mktemp "$path.restore.XXXXXX")
        rm -f -- "$temporary"
        cp -a -- "$BACKUP_DIR/$index" "$temporary"
        mv -Tf -- "$temporary" "$path"
      else rm -f -- "$path"; fi
    done
    if [[ $ACTIVATION_ATTEMPTED == 1 ]]; then
      if [[ $NGINX_WAS_ACTIVE == 1 ]]; then
        if nginx -t; then systemctl restart nginx; else err 'Previous files restored, but their configuration needs administrator review.'; fi
      else systemctl stop nginx; fi
    fi
    err "Installation failed; previous configuration restored. Backups: $BACKUP_DIR"
    [[ $result != 0 ]] || result=1
  fi
  rm -rf -- "$BUILD_TMP"
  exit "$result"
}
trap finish_nginx_install EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
backup_nginx_file "$STATE_FILE"

if ! command -v nginx >/dev/null 2>&1; then
  say "Installing Nginx from nginx.org..."
  curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
  echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/${ID} ${VERSION_CODENAME} nginx" > /etc/apt/sources.list.d/nginx.list
  apt update -y
  apt install -y nginx
  systemctl enable nginx
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
# Development packages resolve runtime names (t64, libxml2-16) per distribution.
# Do not install libmodsecurity-dev: finding its metadata does not prove that
# its engine supports the selected template.
apt install -y build-essential pkg-config libpcre2-dev libxml2-dev zlib1g-dev libssl-dev git curl jq wget
MODSEC_VERSION=3.0.17
MODSEC_PREFIX="/usr/local/modsecurity/$MODSEC_VERSION"
MODSEC_SHA256=f283b33d5c21130fd3a15c84a93a1abe12bd1949edaf44288b12af571b671a50
curl --proto '=https' -fLsS --retry 3 \
  "https://github.com/owasp-modsecurity/ModSecurity/releases/download/v${MODSEC_VERSION}/modsecurity-v${MODSEC_VERSION}.tar.gz" \
  -o "$BUILD_TMP/modsecurity.tar.gz"
printf '%s  %s\n' "$MODSEC_SHA256" "$BUILD_TMP/modsecurity.tar.gz" | sha256sum -c -
tar --no-same-owner -xzf "$BUILD_TMP/modsecurity.tar.gz" -C "$BUILD_TMP"
MODSEC_SOURCE="$BUILD_TMP/modsecurity-v$MODSEC_VERSION"

verify_modsecurity() {
  local include=$1 library=$2 linked identity
  [[ -f "$include/modsecurity/modsecurity.h" && -f "$library/libmodsecurity.so.3" ]] || return 1
  cc -x c - -I"$include" -L"$library" -Wl,-rpath,"$library" -lmodsecurity -o "$BUILD_TMP/engine-check" <<'C' || return 1
#include <stdio.h>
#include <modsecurity/modsecurity.h>
int main(void) {
    ModSecurity *engine = msc_init();
    if (!engine) return 1;
    puts(msc_who_am_i(engine));
    msc_cleanup(engine);
    return 0;
}
C
  linked=$(ldd "$BUILD_TMP/engine-check" | awk '$1=="libmodsecurity.so.3" {print $3}') || return 1
  [[ $(readlink -f "$linked") == "$(readlink -f "$library/libmodsecurity.so.3")" ]] || return 1
  identity=$("$BUILD_TMP/engine-check") || return 1
  [[ "$identity" == "ModSecurity v$MODSEC_VERSION "* ]] || return 1
  say "Verified actual engine: $identity ($library)."
}

if verify_modsecurity "$MODSEC_PREFIX/include" "$MODSEC_PREFIX/lib"; then
  MODSECURITY_INC="$MODSEC_PREFIX/include"; MODSECURITY_LIB="$MODSEC_PREFIX/lib"
elif pkg-config --exists modsecurity && \
     [[ $(pkg-config --modversion modsecurity) == "$MODSEC_VERSION" ]] && \
     verify_modsecurity "$(pkg-config --variable=includedir modsecurity)" "$(pkg-config --variable=libdir modsecurity)"; then
  MODSECURITY_INC=$(pkg-config --variable=includedir modsecurity)
  MODSECURITY_LIB=$(pkg-config --variable=libdir modsecurity)
else
  say "Existing pkg-config engine: $(pkg-config --modversion modsecurity 2>/dev/null || echo absent); building verified v$MODSEC_VERSION."
  [[ ! -e "$MODSEC_PREFIX" ]] || { err "Unverified/partial engine prefix exists: $MODSEC_PREFIX; review it before retrying."; exit 1; }
  apt install -y autoconf automake libtool gettext libcurl4-openssl-dev \
    liblua5.4-dev libyajl-dev liblmdb-dev libmaxminddb-dev libfuzzy-dev
  (
    cd "$MODSEC_SOURCE"
    ./configure --prefix="$MODSEC_PREFIX" --with-pcre2 --with-libxml --with-yajl --disable-static --disable-examples
    make -j"${BUILD_JOBS:-2}"
    make DESTDIR="$BUILD_TMP/install" install
  )
  verify_modsecurity "$BUILD_TMP/install$MODSEC_PREFIX/include" "$BUILD_TMP/install$MODSEC_PREFIX/lib" || {
    err 'The built ModSecurity library failed runtime verification.'; exit 1;
  }
  install -d -m 0755 "$(dirname "$MODSEC_PREFIX")"
  mv "$BUILD_TMP/install$MODSEC_PREFIX" "$MODSEC_PREFIX"
  ldconfig -n "$MODSEC_PREFIX/lib"
  MODSECURITY_INC="$MODSEC_PREFIX/include"; MODSECURITY_LIB="$MODSEC_PREFIX/lib"
fi
export MODSECURITY_INC MODSECURITY_LIB
MODSEC_LIBRARY=$(readlink -f "$MODSECURITY_LIB/libmodsecurity.so.3")
# The connector's RUNPATH selects this library without changing the global
# loader configuration or the library chosen by other applications.
verify_modsecurity "$MODSECURITY_INC" "$MODSECURITY_LIB" || { err 'Selected runtime library changed unexpectedly.'; exit 1; }
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
NGX_MODULE="$MOD_DIR/wafcontrol/${MODSEC_VERSION}-${NVER}-$(sha256sum "$(command -v nginx)" | cut -c1-16)/ngx_http_modsecurity_module.so"
if dpkg --compare-versions "$NVER" lt 1.21.5; then apt install -y libpcre3-dev; fi
# Replay plain feature switches as argv, never evaluate nginx -V as shell code.
read -r -a NGINX_ARGUMENTS <<< "$(nginx -V 2>&1 | sed -n 's/^configure arguments: //p')"
NGINX_FEATURES=()
for argument in "${NGINX_ARGUMENTS[@]}"; do
  if [[ "$argument" =~ ^--(with|without)-[A-Za-z0-9_-]+$ && "$argument" != --with-compat ]]; then NGINX_FEATURES+=("$argument"); fi
done
for feature in "${NGINX_FEATURES[@]}"; do
  case "$feature" in
    --with-http_xslt_module) apt install -y libxslt1-dev ;;
    --with-http_image_filter_module) apt install -y libgd-dev ;;
    --with-http_perl_module) apt install -y libperl-dev ;;
    --with-http_geoip_module|--with-stream_geoip_module) apt install -y libgeoip-dev ;;
  esac
done

mkdir -p /usr/local/src/nginx && cd /usr/local/src/nginx
if [[ ! -d "nginx-${NVER}" ]]; then
  say "Fetching nginx source: ${NVER}"
  wget -q "https://nginx.org/download/nginx-${NVER}.tar.gz"
  tar --no-same-owner -xzf "nginx-${NVER}.tar.gz"
fi

cd "nginx-${NVER}"
./configure "${NGINX_FEATURES[@]}" --with-compat \
  --with-ld-opt="-Wl,-rpath,$MODSECURITY_LIB" --add-dynamic-module=/usr/local/src/ModSecurity-nginx
make -B modules
LINKED_LIBRARY=$(ldd objs/ngx_http_modsecurity_module.so | awk '$1=="libmodsecurity.so.3" {print $3}')
[[ $(readlink -f "$LINKED_LIBRARY") == "$MODSEC_LIBRARY" ]] || { err 'Connector links an unexpected ModSecurity library.'; exit 1; }

install -d -m 0755 "$(dirname "$NGX_MODULE")"
backup_nginx_file "$NGX_MODULE"
MODULE_TMP=$(mktemp "$NGX_MODULE.XXXXXX")
install -m 0644 objs/ngx_http_modsecurity_module.so "$MODULE_TMP"
mv -Tf -- "$MODULE_TMP" "$NGX_MODULE"
say "Dynamic module built."

find_http_file() {
  if grep -q '^[[:space:]]*http[[:space:]]*{' "$NGX_MAIN"; then
    echo "$NGX_MAIN"; return
  fi
  awk 'BEGIN{h=0}/^[[:space:]]*http[[:space:]]*$/ {h=1} h && /^[[:space:]]*{/ {found=1; exit} END {exit !found}' "$NGX_MAIN" && { echo "$NGX_MAIN"; return; }
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
    if ! cp "$MODSEC_SOURCE/$asset" "$staging/$asset" || [[ ! -s "$staging/$asset" ]]; then
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

backup_nginx_file "$MDIR/modsecurity.conf"
backup_nginx_file "$MDIR/unicode.mapping"
if [[ ! -f "$MDIR/modsecurity.conf" || ! -f "$MDIR/unicode.mapping" ]]; then
  fetch_modsecurity_defaults
  say "ModSecurity defaults prepared from matching v${MODSEC_VERSION} release."
fi

# Retain strict multipart validation and restore diagnostics removed by older
# installers. The actual engine has already been verified to implement them.
STRICT_ID_PATTERN="id:[[:space:]]*['\"]?200003([^0-9]|$)"
if ! grep -qE '^[[:space:]]*SecRule[[:space:]]+MULTIPART_STRICT_ERROR[[:space:]]' "$MDIR/modsecurity.conf"; then
  if grep -qE "$STRICT_ID_PATTERN" "$MDIR/modsecurity.conf"; then
    err 'Custom rule 200003 conflicts with strict multipart validation.'; exit 1
  fi
  awk '/^SecRule MULTIPART_STRICT_ERROR /{copy=1} copy {print; if ($0 !~ /\\$/) exit}' \
    "$MODSEC_SOURCE/modsecurity.conf-recommended" >> "$MDIR/modsecurity.conf"
fi
if ! grep -Fq '%{MULTIPART_DUPLICATE_PART_HEADER}' "$MDIR/modsecurity.conf"; then
  sed -i 's/DA %{MULTIPART_DATA_AFTER},[[:blank:]]*\\$/DA %{MULTIPART_DATA_AFTER}, DH %{MULTIPART_DUPLICATE_PART_HEADER}, \\/' "$MDIR/modsecurity.conf"
fi
STRICT_RULE=$(awk '/^[[:space:]]*SecRule[[:space:]]+MULTIPART_STRICT_ERROR[[:space:]]/{copy=1} copy {print; if ($0 !~ /\\$/) exit}' "$MDIR/modsecurity.conf")
if ! grep -qE "$STRICT_ID_PATTERN" <<< "$STRICT_RULE" || ! grep -qw deny <<< "$STRICT_RULE"; then
  err 'Strict multipart rule 200003 must remain active with a deny action.'; exit 1
fi

# Nginx's prefix is not the ModSecurity configuration directory.
sed -i -E "s|^([[:blank:]]*SecUnicodeMapFile[[:blank:]]+)unicode.mapping([[:blank:]]+)|\1${MDIR}/unicode.mapping\2|" "$MDIR/modsecurity.conf"

sed -i -E 's/^\s*SecRuleEngine\s+DetectionOnly/SecRuleEngine On/i' "$MDIR/modsecurity.conf"
grep -qE '^\s*SecRuleEngine\s+' "$MDIR/modsecurity.conf" || echo "SecRuleEngine On" >> "$MDIR/modsecurity.conf"
if grep -qiE '^[[:space:]]*SecRuleEngine[[:space:]]+Off\b' "$MDIR/modsecurity.conf" || \
   ! grep -qiE '^[[:space:]]*SecRequestBodyAccess[[:space:]]+On\b' "$MDIR/modsecurity.conf"; then
  err 'Existing settings disable WAF/body inspection; administrator review is required.'; exit 1
fi

MAIN="$MDIR/main.conf"
backup_nginx_file "$MAIN"
if [[ ! -f "$MAIN" ]]; then
  { echo "# WAFCONTROL main config"; echo "Include $MDIR/modsecurity.conf"; } > "$MAIN"
fi

# Parse the base configuration with the actual connector before enabling it in
# nginx.conf, so an incompatible template fails before changing the load setup.
validate_modsecurity_conf() {
  local staging result=0
  staging="$(mktemp -d -t wafcontrol-nginx-check-XXXXXX)" || return 1
  cat > "$staging/nginx.conf" <<CONF
load_module ${NGX_MODULE};
user ${NGX_USER};
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

# Replace old connector loads, including packaged modules-enabled includes, and
# load exactly one versioned module. Other dynamic modules are untouched.
MODSEC_LOAD_PATTERN="^[[:space:]]*load_module[[:space:]]+[^;]*ngx_http_modsecurity_module\.so[\"']?[[:space:]]*;"
while IFS= read -r -d '' config; do
  backup_nginx_file "$config"
  sed -i -E "\\|$MODSEC_LOAD_PATTERN|d" "$config"
done < <(grep -RIlZ --include='*.conf' -E "$MODSEC_LOAD_PATTERN" /etc/nginx || true)
backup_nginx_file "$NGX_MAIN"
sed -i "1iload_module ${NGX_MODULE};" "$NGX_MAIN"
say "Configured one load_module in nginx.conf"

if ! grep -q 'WAFCONTROL-BEGIN' "$HTTP_FILE"; then
  backup_nginx_file "$HTTP_FILE"
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

CRS_DIR=$(sed -n 's|^[[:space:]]*Include[[:space:]]*\(.*\)/crs-setup\.conf[[:space:]]*$|\1|p' "$MAIN" | head -n1)
if [[ -n "$CRS_DIR" && -d "$CRS_DIR/rules" ]]; then
  say "Preserving existing CRS: $CRS_DIR"
else
say "Fetching latest CRS..."
TAG="$(curl -s https://api.github.com/repos/coreruleset/coreruleset/releases/latest | jq -r '.tag_name' || true)"
CRS_DIR=""
if [[ -n "$TAG" && "$TAG" != "null" ]]; then
  NUM="${TAG#v}"
  CRS_DIR="$MDIR/coreruleset-${NUM}"
  if [[ ! -d "$CRS_DIR" ]]; then
    TMPD="$(mktemp -d -t crs-XXXXXX)"
    wget -q "https://github.com/coreruleset/coreruleset/archive/refs/tags/${TAG}.tar.gz" -O "$TMPD/crs.tgz"
    tar --no-same-owner -xzf "$TMPD/crs.tgz" -C "$TMPD"
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
fi
[[ -d "$CRS_DIR" ]] || { err "CRS directory missing: $CRS_DIR"; exit 1; }
[[ -f "$CRS_DIR/crs-setup.conf" ]] || { backup_nginx_file "$CRS_DIR/crs-setup.conf"; [[ -f "$CRS_DIR/crs-setup.conf.example" ]] && cp "$CRS_DIR/crs-setup.conf.example" "$CRS_DIR/crs-setup.conf"; }
for f in REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf; do
  if [[ ! -f "$CRS_DIR/rules/$f" && -f "$CRS_DIR/rules/${f}.example" ]]; then
    backup_nginx_file "$CRS_DIR/rules/$f"
    cp "$CRS_DIR/rules/$f.example" "$CRS_DIR/rules/$f"
  fi
done
EXCL="$CRS_DIR/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf"
if ! grep -q '/crs/rules/save/' "$EXCL" 2>/dev/null; then
  backup_nginx_file "$EXCL"
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
  backup_nginx_file "$HTPASS"
  HASH="$(openssl passwd -apr1 "${BASIC_AUTH_PASS}")"
  printf '%s:%s\n' "${BASIC_AUTH_USER}" "${HASH}" > "${HTPASS}"
  chown root:"$NGX_GROUP" "${HTPASS}" || true
  chmod 640 "${HTPASS}" || true
  AUTH_SNIPPET=$'    auth_basic "Restricted WAF Dashboard";\n    auth_basic_user_file /etc/nginx/.htpasswdwaf;'
fi

if [[ -f "$VHOST" ]]; then
  say "Preserving existing app vhost: $VHOST"
elif [[ "$MODE" == "domain" ]]; then
  backup_nginx_file "$VHOST"
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
  say "App vhost written: $VHOST (port 80)"

else
  backup_nginx_file "$VHOST"
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
  say "App vhost written: $VHOST (port ${HTTP_PORT})"
fi

if nginx -t; then
  ACTIVATION_ATTEMPTED=1
  if systemctl is-active --quiet nginx; then
    PID=$(systemctl show nginx -p MainPID --value)
    # A reload retains an already loaded library with the same SONAME.
    LOADED_LIBRARY=$(awk '$6 ~ /\/libmodsecurity\.so/ {print $6; exit}' "/proc/$PID/maps")
    if [[ "$LOADED_LIBRARY" != "$MODSEC_LIBRARY" ]]; then systemctl restart nginx
    else systemctl reload nginx; fi
  else systemctl start nginx; fi
  systemctl is-active --quiet nginx
  PID=$(systemctl show nginx -p MainPID --value)
  awk -v library="$MODSEC_LIBRARY" '$6==library {found=1} END {exit !found}' "/proc/$PID/maps" || {
    err "Nginx has not loaded the verified library: $MODSEC_LIBRARY"; exit 1;
  }
  DEPLOYED=1
  say "Nginx WAF ready (verified ModSecurity v$MODSEC_VERSION + CRS)."
else
  err "nginx -t failed; restoring the previous configuration."
  exit 1
fi

if [[ "$MODE" == domain && "$SSL_ENABLE" -eq 1 ]]; then
  say "Installing certbot and enabling SSL for ${DOMAIN}"
  apt install -y certbot python3-certbot-nginx
  EMAIL="${CERTBOT_EMAIL:-admin@${DOMAIN}}"
  certbot --nginx -d "$DOMAIN" -d "www.$DOMAIN" --non-interactive --agree-tos -m "$EMAIL" --redirect || warn "Certbot failed"
fi
