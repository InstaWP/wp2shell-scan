#!/usr/bin/env bash
# =============================================================================
# wp2shell-scan — detect & clean up wp2shell (CVE-2026-63030) compromise
# across one or many WordPress sites.
#
# wp2shell is the pre-auth RCE fixed in WordPress 7.0.2 / 6.9.5 / 6.8.6
# (2026-07-17). Post-exploitation it typically leaves:
#   * a rogue administrator  user_login=wpsvc_<hex>, email @wordpress-svc.internal
#     (or @wordpress-noreply.net / *.internal)
#   * a webshell disguised as a plugin  wp-content/plugins/<name>-<6hex>/<same>.php
#     (tiny PHP file, fake "Author: WordPress.org Community" header, ?c=<cmd>&t=<token>)
#
# Modes:
#   (default) scan  — READ ONLY. Report compromise. Never changes anything.
#   --clean         — Quarantine + remove backdoors (rogue admins, webshells),
#                     rotate wp-config salts. Requires --yes (or prompts).
#
# Bulk: point it at a base dir (--base) to auto-discover every WP install,
#       or pass --path for a single site. Repeatable.
#
# Requires: bash, find, grep, php-readable wp-config, and a `mysql`/`mariadb`
#           client. WP-CLI is used when present (nicer user deletion) but is
#           NOT required. Webshell detection is pure filesystem — no DB needed.
#
# License: MIT.  Use at your own risk; SNAPSHOT the site before --clean.
# =============================================================================
set -uo pipefail
VERSION="1.0.0"

MODE="scan"; FORMAT="text"; ASSUME_YES=0; ROTATE_SALTS=1
SINCE="2026-07-16 00:00:00"
QUAR="${WP2SHELL_QUARANTINE:-./wp2shell-quarantine-$(date +%Y%m%d-%H%M%S 2>/dev/null || echo run)}"
declare -a BASES=() ROOTS=()

c_red=$'\033[31m'; c_yel=$'\033[33m'; c_grn=$'\033[32m'; c_dim=$'\033[2m'; c_off=$'\033[0m'
[ -t 1 ] || { c_red=; c_yel=; c_grn=; c_dim=; c_off=; }

usage(){ cat <<USG
wp2shell-scan v$VERSION — detect & clean wp2shell (CVE-2026-63030) compromise.

  wp2shell-scan.sh [--base DIR]... [--path WP_ROOT]... [options]

Discovery (pick one or more; repeatable):
  --base DIR     Auto-discover every WordPress install under DIR (finds wp-load.php).
  --path DIR     A single WordPress root (contains wp-load.php / wp-config.php).
  (none)         Tries common layouts: /var/www/*, /home/*/public_html, /home/*/web/*/public_html, /srv/www/*

Actions:
  (default)      scan  — read-only report.
  --clean        Quarantine & remove backdoors, then rotate salts. Needs --yes.
  --no-rotate    With --clean: do NOT rotate wp-config salts.
  --yes          Non-interactive; proceed with --clean without prompting.

Output:
  --json         Machine-readable JSON to stdout.
  --since 'Y-M-D H:M:S'   Admin-registration window start (default $SINCE).
  --quarantine DIR        Where removed artifacts are backed up (default ./wp2shell-quarantine-*).

Exit: 0 clean, 1 compromise found (scan) / cleaned (clean), 2 usage/error.
USG
}

while [ $# -gt 0 ]; do case "$1" in
  --base) BASES+=("$2"); shift 2;;
  --path) ROOTS+=("$2"); shift 2;;
  --clean) MODE="clean"; shift;;
  --no-rotate) ROTATE_SALTS=0; shift;;
  --yes|-y) ASSUME_YES=1; shift;;
  --json) FORMAT="json"; shift;;
  --since) SINCE="$2"; shift 2;;
  --quarantine) QUAR="$2"; shift 2;;
  -h|--help) usage; exit 0;;
  *) echo "unknown arg: $1" >&2; usage; exit 2;;
esac; done

log(){ [ "$FORMAT" = json ] || echo "$@" >&2; }

# ---- discovery -------------------------------------------------------------
discover(){
  local d
  for d in "${ROOTS[@]:-}"; do [ -n "$d" ] && [ -f "$d/wp-load.php" ] && echo "$d"; done
  for d in "${BASES[@]:-}"; do [ -n "$d" ] && find "$d" -maxdepth 6 -name wp-load.php -not -path '*/wp-content/*' 2>/dev/null | sed 's#/wp-load.php$##'; done
  if [ ${#ROOTS[@]} -eq 0 ] && [ ${#BASES[@]} -eq 0 ]; then
    for d in /var/www/* /var/www/*/htdocs /home/*/public_html /home/*/web/*/public_html /srv/www/*; do
      [ -f "$d/wp-load.php" ] && echo "$d"
    done 2>/dev/null
  fi
}

# ---- wp-config helpers -----------------------------------------------------
cfg_get(){ grep -m1 -E "define\(\s*['\"]$1['\"]" "$2" 2>/dev/null | sed -E "s/.*define\(\s*['\"]$1['\"]\s*,\s*['\"]([^'\"]*)['\"].*/\1/"; }
cfg_prefix(){ grep -m1 -E '\$table_prefix' "$1" 2>/dev/null | sed -E "s/.*=\s*['\"]([^'\"]*)['\"].*/\1/"; }

# Run a SELECT and print raw rows (tab separated). Uses site DB creds from wp-config.
db_query(){ # $1=wproot $2=sql
  local cfg="$1/wp-config.php" dbn dbu dbp dbh
  dbn=$(cfg_get DB_NAME "$cfg"); dbu=$(cfg_get DB_USER "$cfg"); dbp=$(cfg_get DB_PASSWORD "$cfg"); dbh=$(cfg_get DB_HOST "$cfg")
  [ -n "$dbn" ] || return 1
  local host="${dbh:-localhost}" sock="" port=""
  case "$host" in *:*) port="--port=${host##*:}"; host="${host%%:*}";; esac
  # As root on a hosting box, socket auth often works with no creds; try creds first, then socket.
  mysql --skip-column-names --batch -h "$host" $port -u "$dbu" -p"$dbp" "$dbn" -e "$2" 2>/dev/null \
    || mysql --skip-column-names --batch "$dbn" -e "$2" 2>/dev/null
}

# ---- detection: backdoor admins -------------------------------------------
find_backdoor_admins(){ # $1=wproot  -> rows: ID<TAB>login<TAB>email<TAB>registered
  local pfx; pfx=$(cfg_prefix "$1/wp-config.php"); [ -n "$pfx" ] || pfx="wp_"
  db_query "$1" "SELECT u.ID,u.user_login,u.user_email,u.user_registered
    FROM \`${pfx}users\` u JOIN \`${pfx}usermeta\` m ON u.ID=m.user_id
    WHERE m.meta_key='${pfx}capabilities' AND m.meta_value LIKE '%administrator%'
      AND ( u.user_login LIKE 'wpsvc\\_%'
         OR u.user_email LIKE '%@wordpress-svc.internal'
         OR u.user_email LIKE '%@wordpress-noreply.net'
         OR u.user_email LIKE '%@%.internal' );"
}

# ---- detection: webshells (filesystem, no DB) ------------------------------
find_webshells(){ # $1=wproot -> one path per line
  local wc="$1/wp-content"
  [ -d "$wc" ] || return 0
  # (a) plugin folders named like a real plugin but ending in -<6 hex>
  find "$wc/plugins" -maxdepth 1 -type d -regextype posix-extended -regex '.*-[0-9a-f]{6}$' 2>/dev/null \
    | while read -r d; do find "$d" -maxdepth 1 -name '*.php' 2>/dev/null; done
  # (b) any small PHP under wp-content taking a command via $_GET and a token/exec sink
  find "$wc" -type f -name '*.php' -size -8k 2>/dev/null | while read -r f; do
    if grep -qE "\\\$_(GET|POST|REQUEST)\[['\"]c['\"]\]" "$f" 2>/dev/null \
       && grep -qE "hash_equals\(|(system|shell_exec|passthru|proc_open|popen|exec|eval|assert)\s*\(" "$f" 2>/dev/null; then
      echo "$f"
    fi
  done
}

# ---- cleanup ---------------------------------------------------------------
quarantine(){ mkdir -p "$QUAR" 2>/dev/null; }
clean_admin(){ # $1=wproot $2=userID $3=login
  local pfx; pfx=$(cfg_prefix "$1/wp-config.php"); [ -n "$pfx" ] || pfx="wp_"
  quarantine
  db_query "$1" "SELECT * FROM \`${pfx}users\` WHERE ID=$2; SELECT * FROM \`${pfx}usermeta\` WHERE user_id=$2;" \
    > "$QUAR/admin_${3}_$(basename "$1").sql.txt" 2>/dev/null
  if command -v wp >/dev/null 2>&1; then
    local owner; owner=$(stat -c '%U' "$1" 2>/dev/null)
    sudo -u "${owner:-root}" -- wp --path="$1" user delete "$2" --yes --network >/dev/null 2>&1 \
      || sudo -u "${owner:-root}" -- wp --path="$1" user delete "$2" --yes >/dev/null 2>&1 \
      || db_query "$1" "DELETE FROM \`${pfx}users\` WHERE ID=$2; DELETE FROM \`${pfx}usermeta\` WHERE user_id=$2;"
  else
    db_query "$1" "DELETE FROM \`${pfx}users\` WHERE ID=$2; DELETE FROM \`${pfx}usermeta\` WHERE user_id=$2;"
  fi
}
clean_webshell(){ # $1=wproot $2=phpfile
  quarantine
  local dir; dir=$(dirname "$2")
  # if it's an isolated disguised-plugin dir, quarantine the whole dir; else just the file
  if echo "$dir" | grep -qE '/plugins/[^/]+-[0-9a-f]{6}$'; then
    mv "$dir" "$QUAR/" 2>/dev/null || rm -rf "$dir"
  else
    mkdir -p "$QUAR/files" 2>/dev/null; mv "$2" "$QUAR/files/" 2>/dev/null || rm -f "$2"
  fi
}
rotate_salts(){ # $1=wproot
  local cfg="$1/wp-config.php"; [ -w "$cfg" ] || return 1
  if command -v wp >/dev/null 2>&1; then
    local owner; owner=$(stat -c '%U' "$1" 2>/dev/null)
    sudo -u "${owner:-root}" -- wp --path="$1" config shuffle-salts >/dev/null 2>&1 && return 0
  fi
  local k rnd; cp -a "$cfg" "$QUAR/wp-config.$(basename "$1").bak" 2>/dev/null
  for k in AUTH_KEY SECURE_AUTH_KEY LOGGED_IN_KEY NONCE_KEY AUTH_SALT SECURE_AUTH_SALT LOGGED_IN_SALT NONCE_SALT; do
    rnd=$(head -c 64 /dev/urandom | base64 | tr -d '\n/+=' | head -c 64)
    if grep -qE "define\(\s*['\"]$k['\"]" "$cfg"; then
      sed -i -E "s|(define\(\s*['\"]$k['\"]\s*,\s*['\"]).*(['\"]\s*\)\s*;)|\1${rnd}\2|" "$cfg"
    fi
  done
}

# ---- per-site processing ---------------------------------------------------
TOTAL=0; CLEAN=0; SUSP=0; COMP=0; CLEANED=0
JSON_ROWS=()
process(){ # $1=wproot
  local root="$1" name status="clean"; name=$(basename "$(dirname "$root")")/$(basename "$root")
  [ -f "$root/wp-config.php" ] || name=$(basename "$root")
  TOTAL=$((TOTAL+1))
  local admins webshells; admins=$(find_backdoor_admins "$root"); webshells=$(find_webshells "$root" | sort -u)
  local nA=0 nW=0; [ -n "$admins" ] && nA=$(printf '%s\n' "$admins" | grep -c .); [ -n "$webshells" ] && nW=$(printf '%s\n' "$webshells" | grep -c .)

  if [ "$nA" -gt 0 ] || [ "$nW" -gt 0 ]; then status="COMPROMISED"; COMP=$((COMP+1)); fi

  if [ "$FORMAT" = json ]; then
    local aj wj; aj=$(printf '%s\n' "$admins" | awk 'NF{printf "{\"id\":\"%s\",\"login\":\"%s\",\"email\":\"%s\",\"registered\":\"%s %s\"},",$1,$2,$3,$4,$5}' | sed 's/,$//')
    wj=$(printf '%s\n' "$webshells" | awk 'NF{printf "\"%s\",",$0}' | sed 's/,$//')
    JSON_ROWS+=("{\"site\":\"$root\",\"status\":\"$status\",\"backdoor_admins\":[${aj}],\"webshells\":[${wj}]}")
  else
    if [ "$status" = COMPROMISED ]; then
      echo "${c_red}[COMPROMISED]${c_off} $root  — ${nA} backdoor admin(s), ${nW} webshell(s)"
      printf '%s\n' "$admins" | awk 'NF{print "      admin: ID="$1" "$2" <"$3"> ("$4" "$5")"}'
      printf '%s\n' "$webshells" | awk 'NF{print "      webshell: "$0}'
    else
      echo "${c_grn}[clean]${c_off} ${c_dim}$root${c_off}"
      CLEAN=$((CLEAN+1))
    fi
  fi

  if [ "$MODE" = clean ] && [ "$status" = COMPROMISED ]; then
    printf '%s\n' "$admins" | while IFS=$'\t' read -r id login email reg; do [ -n "$id" ] && clean_admin "$root" "$id" "$login"; done
    printf '%s\n' "$webshells" | while read -r f; do [ -n "$f" ] && clean_webshell "$root" "$f"; done
    [ "$ROTATE_SALTS" = 1 ] && rotate_salts "$root"
    CLEANED=$((CLEANED+1))
    log "  ${c_yel}cleaned${c_off} $root (artifacts quarantined in $QUAR)"
  fi
}

# ---- main ------------------------------------------------------------------
mapfile -t SITES < <(discover | awk 'NF' | sort -u)
[ ${#SITES[@]} -gt 0 ] || { log "No WordPress installs found. Use --path or --base."; exit 2; }

if [ "$MODE" = clean ] && [ "$ASSUME_YES" != 1 ]; then
  log "${c_yel}--clean will DELETE rogue admins + webshells and rotate salts on ${#SITES[@]} site(s).${c_off}"
  log "SNAPSHOT first. Continue? type: yes"
  read -r ans; [ "$ans" = yes ] || { log "aborted."; exit 2; }
fi

log "wp2shell-scan v$VERSION — mode=$MODE, ${#SITES[@]} site(s), since='$SINCE'"
for s in "${SITES[@]}"; do process "$s"; done

if [ "$FORMAT" = json ]; then
  printf '{"version":"%s","mode":"%s","scanned":%s,"compromised":%s,"cleaned":%s,"sites":[%s]}\n' \
    "$VERSION" "$MODE" "$TOTAL" "$COMP" "$CLEANED" "$(IFS=,; echo "${JSON_ROWS[*]:-}")"
else
  echo "----------------------------------------------------------------"
  echo "scanned=$TOTAL  ${c_grn}clean=$CLEAN${c_off}  ${c_red}compromised=$COMP${c_off}  cleaned=$CLEANED"
  [ "$COMP" -gt 0 ] && [ "$MODE" = scan ] && echo "Re-run with ${c_yel}--clean --yes${c_off} to remediate (snapshot first)."
  [ "$CLEANED" -gt 0 ] && echo "Quarantined artifacts: $QUAR  |  Next: update WP core to 7.0.2/6.9.5/6.8.6 + reset admin passwords."
fi
[ "$COMP" -gt 0 ] && exit 1 || exit 0
