#!/bin/bash
# HTTP(S) rewrite (MITM) sidecar helper, shared by init.d and LuCI.
. /lib/functions.sh
. /usr/share/openclash/log.sh
. /usr/share/openclash/uci.sh
. /usr/share/openclash/openclash_curl.sh
. /usr/share/openclash/openclash_ps.sh

MITM_BIN="/etc/openclash/core/openclash_mitm"
MITM_DIR="/etc/openclash/mitm"
MITM_OVERRIDE_DIR="${MITM_DIR}/overrides"
MITM_CA_CERT="${MITM_DIR}/ca.crt"
MITM_CA_KEY="${MITM_DIR}/ca.key"
MITM_CUSTOM="/etc/openclash/custom/openclash_custom_mitm.stoverride"
MITM_LOG="/tmp/openclash_mitm.log"

mitm_enabled() {
   [ "$(uci_get_config "mitm_enable" || echo 0)" = "1" ]
}

# Names are often non-ASCII, so a hash keeps sanitised file names unique.
mitm_override_file() {
   local safe hash
   safe=$(printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_' | cut -c1-48)
   hash=$(printf '%s' "$1" | md5sum | cut -c1-8)
   echo "${MITM_OVERRIDE_DIR}/${safe}_${hash}.stoverride"
}

# A custom override that only holds comments must not count as an override.
mitm_custom_in_use() {
   [ -s "$MITM_CUSTOM" ] && grep -qvE '^[[:space:]]*(#|$)' "$MITM_CUSTOM"
}

mitm_lan_ip() {
   local ip
   ip=$(uci -q get network.lan.ipaddr 2>/dev/null | awk -F '/' '{print $1}' | awk '{print $1}')
   [ -z "$ip" ] && ip="0.0.0.0"
   echo "$ip"
}

update_override() {
   local section="$1" force="$2" enabled name url file
   config_get_bool enabled "$section" "enabled" 1
   config_get name "$section" "name"
   config_get url "$section" "url"
   [ "$enabled" -eq 1 ] || return 0
   [ -n "$name" ] && [ -n "$url" ] || return 0
   file=$(mitm_override_file "$name")
   [ "$force" != "1" ] && [ -s "$file" ] && return 0
   mkdir -p "$MITM_OVERRIDE_DIR"
   LOG_OUT "Downloading MITM Override【${name}】..."
   DOWNLOAD_FILE_CURL "$url" "$file" "$file"
   case "$?" in
      0) LOG_OUT "MITM Override【${name}】Download Successful" ;;
      2) LOG_OUT "MITM Override【${name}】Not Modified" ;;
      *) LOG_ERROR "MITM Override【${name}】Download Failed" ;;
   esac
}

collect_override() {
   local section="$1" enabled name file
   config_get_bool enabled "$section" "enabled" 1
   config_get name "$section" "name"
   [ "$enabled" -eq 1 ] && [ -n "$name" ] || return 0
   file=$(mitm_override_file "$name")
   [ -s "$file" ] && OVERRIDE_ARGS+=(--override "$file")
   return 0
}

build_override_args() {
   OVERRIDE_ARGS=()
   mitm_custom_in_use && OVERRIDE_ARGS+=(--override "$MITM_CUSTOM")
   config_load "openclash"
   config_foreach collect_override "mitm_override"
   local hosts
   hosts=$(uci_get_config "mitm_hosts")
   [ -n "$hosts" ] && OVERRIDE_ARGS+=(--hosts "$hosts")
}

ensure_ca() {
   [ -s "$MITM_CA_CERT" ] && [ -s "$MITM_CA_KEY" ] && return 0
   mkdir -p "$MITM_DIR"
   chmod 700 "$MITM_DIR"
   if "$MITM_BIN" gen-ca --cert "$MITM_CA_CERT" --key "$MITM_CA_KEY" >/dev/null 2>&1; then
      LOG_TIP "MITM Root Certificate Generated, Please Install And Trust It On Your Devices"
      return 0
   fi
   LOG_ERROR "MITM Root Certificate Generate Failed"
   return 1
}

# Patch the mihomo config in place. Returns non-zero when MITM is not active.
cmd_patch() {
   local config="$1" src out line
   mitm_enabled || return 1
   if [ ! -x "$MITM_BIN" ]; then
      LOG_WARN "MITM Engine Not Found【${MITM_BIN}】, Please Download It In The HTTP(S) Rewrite Page, Skip..."
      return 1
   fi
   ensure_ca || return 1
   config_load "openclash"
   config_foreach update_override "mitm_override" 0
   build_override_args
   if [ ${#OVERRIDE_ARGS[@]} -eq 0 ]; then
      LOG_WARN "No MITM Override Or Hostname Configured, Skip HTTP(S) Rewrite..."
      return 1
   fi
   src=$(uci_get_config "mitm_src")
   out=$("$MITM_BIN" clash-patch --config "$config" "${OVERRIDE_ARGS[@]}" \
      --src "$src" \
      --engine-port "$(uci_get_config "mitm_port" || echo 7899)" \
      --out-port "$(uci_get_config "mitm_out_port" || echo 7898)" \
      --block-quic="$([ "$(uci_get_config "mitm_block_quic" || echo 1)" = "1" ] && echo true || echo false)" 2>&1)
   local ret=$?
   while IFS= read -r line; do
      [ -z "$line" ] && continue
      case "$line" in
         WARN*) LOG_WARN "MITM: ${line#WARN }" ;;
         OK*) LOG_OUT "MITM Config Patched:【${line#OK }】" ;;
         *) LOG_ERROR "MITM: ${line}" ;;
      esac
   done <<EOF
$out
EOF
   [ "$ret" -eq 0 ] || return 1
   grep -q "openclash-mitm-out" "$config"
}

# Replaces the shell so procd supervises the engine itself.
cmd_run() {
   local cert_port max_body skip_verify
   build_override_args
   cert_port=$(uci_get_config "mitm_cert_port" || echo 7900)
   max_body=$(uci_get_config "mitm_max_body_size" || echo 4)
   skip_verify=$(uci_get_config "mitm_skip_cert_verify" || echo 0)
   local cert_listen=""
   [ "$cert_port" != "0" ] && cert_listen="$(mitm_lan_ip):${cert_port}"
   mkdir -p "${MITM_DIR}/scripts" "${MITM_DIR}/store"
   exec "$MITM_BIN" run \
      --listen "127.0.0.1:$(uci_get_config "mitm_port" || echo 7899)" \
      --upstream "127.0.0.1:$(uci_get_config "mitm_out_port" || echo 7898)" \
      --cert-listen "$cert_listen" \
      --ca-cert "$MITM_CA_CERT" --ca-key "$MITM_CA_KEY" \
      --max-body-size "$((max_body * 1024 * 1024))" \
      --skip-server-cert-verify="$([ "$skip_verify" = "1" ] && echo true || echo false)" \
      --script-dir "${MITM_DIR}/scripts" \
      --store-dir "${MITM_DIR}/store" \
      --log-file "$MITM_LOG" \
      --log-level "$(uci_get_config "mitm_log_level" || echo info)" \
      "${OVERRIDE_ARGS[@]}"
}

engine_pids() {
   unify_ps_pids "${MITM_BIN} run"
}

# procd respawns the instance with the new binary or certificate.
restart_engine() {
   local pid
   for pid in $(engine_pids); do
      kill "$pid" 2>/dev/null
   done
}

cmd_regen_ca() {
   [ -x "$MITM_BIN" ] || { LOG_ERROR "MITM Engine Not Found【${MITM_BIN}】"; return 1; }
   mkdir -p "$MITM_DIR"
   chmod 700 "$MITM_DIR"
   if "$MITM_BIN" gen-ca --force --cert "$MITM_CA_CERT" --key "$MITM_CA_KEY" >/dev/null 2>&1; then
      LOG_TIP "MITM Root Certificate Regenerated, Please Reinstall And Trust It On Your Devices"
      restart_engine
   else
      LOG_ERROR "MITM Root Certificate Regenerate Failed"
      return 1
   fi
}

cmd_update() {
   config_load "openclash"
   config_foreach update_override "mitm_override" 1
   return 0
}

# Remove downloaded overrides that no longer have a UCI section.
cmd_clean() {
   local keep="" f
   collect_name() {
      local name
      config_get name "$1" "name"
      [ -n "$name" ] && keep="${keep} $(mitm_override_file "$name")"
      return 0
   }
   config_load "openclash"
   config_foreach collect_name "mitm_override"
   for f in "$MITM_OVERRIDE_DIR"/*.stoverride; do
      [ -e "$f" ] || continue
      case " $keep " in
         *" $f "*) ;;
         *) rm -f "$f" ;;
      esac
   done
}

cmd_core_download() {
   local cpu branch cdn url tmp="/tmp/openclash_mitm.tar.gz"
   cpu=$(uci_get_config "core_version" || echo 0)
   if [ "$cpu" = "0" ]; then
      LOG_ERROR "Please Select The Core Compiled Version In Plugin Settings First"
      return 1
   fi
   branch=$(uci_get_config "release_branch" || echo master)
   cdn=$(uci_get_config "github_address_mod" || echo 0)
   url="${2:-$(uci_get_config "mitm_engine_url")}"
   url="${url//\{arch\}/$cpu}"
   if [ -z "$url" ]; then
      case "$cdn" in
         0|*raw.githubusercontent.com*) url="https://raw.githubusercontent.com/vernesong/OpenClash/core/${branch}/mitm/openclash-mitm-${cpu}.tar.gz" ;;
         https://cdn.jsdelivr.net/|https://fastly.jsdelivr.net/|https://testingcf.jsdelivr.net/)
            url="${cdn}gh/vernesong/OpenClash@core/${branch}/mitm/openclash-mitm-${cpu}.tar.gz" ;;
         *) url="${cdn}https://raw.githubusercontent.com/vernesong/OpenClash/core/${branch}/mitm/openclash-mitm-${cpu}.tar.gz" ;;
      esac
   fi
   LOG_TIP "MITM Engine Downloading..."
   rm -f "$tmp"
   SHOW_DOWNLOAD_PROGRESS=1 DOWNLOAD_FILE_CURL "$url" "$tmp" "$MITM_BIN"
   case "$?" in
      0) ;;
      2) LOG_TIP "MITM Engine Has Not Been Updated"; return 0 ;;
      *) LOG_ERROR "MITM Engine Download Failed, Please Download And Upload Manually"; return 1 ;;
   esac
   rm -rf /tmp/openclash_mitm_extract && mkdir -p /tmp/openclash_mitm_extract
   if ! tar zxf "$tmp" -C /tmp/openclash_mitm_extract 2>/dev/null || ! /tmp/openclash_mitm_extract/openclash-mitm version >/dev/null 2>&1; then
      LOG_ERROR "MITM Engine Verification Failed"
      rm -rf "$tmp" /tmp/openclash_mitm_extract
      return 1
   fi
   mkdir -p "$(dirname "$MITM_BIN")"
   mv -f /tmp/openclash_mitm_extract/openclash-mitm "$MITM_BIN" && chmod 755 "$MITM_BIN"
   rm -rf "$tmp" /tmp/openclash_mitm_extract
   LOG_TIP "MITM Engine Update Successful【$("$MITM_BIN" version)】"
   restart_engine
}

cmd_status() {
   local version="" running=0
   [ -x "$MITM_BIN" ] && version=$("$MITM_BIN" version 2>/dev/null)
   [ -n "$(engine_pids)" ] && running=1
   echo "version=${version}"
   echo "running=${running}"
   [ -s "$MITM_CA_CERT" ] && [ -s "$MITM_CA_KEY" ] && [ -x "$MITM_BIN" ] && \
      "$MITM_BIN" ca-info --cert "$MITM_CA_CERT" --key "$MITM_CA_KEY" 2>/dev/null
}

case "$1" in
   patch) cmd_patch "$2" ;;
   run) cmd_run ;;
   update) cmd_update ;;
   clean) cmd_clean ;;
   regen-ca) cmd_regen_ca ;;
   core-download) cmd_core_download "$@" ;;
   status) cmd_status ;;
   enabled) mitm_enabled && [ -x "$MITM_BIN" ] ;;
   *)
      echo "usage: $0 {patch <config>|run|update|clean|regen-ca|core-download [url]|status|enabled}"
      exit 2
      ;;
esac
