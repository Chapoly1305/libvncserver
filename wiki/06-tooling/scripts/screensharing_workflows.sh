#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TOOLS_PY="$SCRIPT_DIR/screensharing_tools.py"
VIEWER_FRIDA="$SCRIPT_DIR/frida_screen_sharing.js"
DAEMON_FRIDA="$SCRIPT_DIR/frida_screensharingd.js"
LLDB_TOOLS="$SCRIPT_DIR/lldb/screensharing_tools.py"
APP="/System/Applications/Utilities/Screen Sharing.app/Contents/MacOS/Screen Sharing"

usage() {
  cat <<'EOF'
usage: screensharing_workflows.sh <command> ...

commands:
  viewer-frida <transport|dynamic-resolution|promode|promode-transport|auth-rewrite> [host] [user] [password] [seconds]
  viewer-lldb <trace|bypass|force-hp|patch-hp>
  daemon-frida <transport|hp|srpkey>
  capture <proxy-trace|promode-proxy-trace|promode-direct|dynamic-resolution|runtime|comprehensive|auth-matrix> ...
  auth33 <applehpdebug|stream|live-view|hp-probe|localhost-proxy> ...
  pcap analyze <pcap> <output_dir> [host_filter]
  logs snapshot <scenario_name> [log_path]
  bn batch <targets_file> <output_dir> [keywords_file]
  tools <subcommand> ...

legacy mapping:
  run_screen_sharing_frida_transport.sh          -> viewer-frida transport
  run_screen_sharing_frida_dynamic_resolution.sh -> viewer-frida dynamic-resolution
  run_screen_sharing_frida_promode.sh            -> viewer-frida promode
  run_screen_sharing_lldb_*.sh                   -> viewer-lldb ...
  run_screensharingd_frida_*.sh                  -> daemon-frida ...
  run_auth33_*.sh                                -> auth33 ...
  analyze_encrypted_pcap.sh                      -> pcap analyze
EOF
}

require_file() {
  [[ -f "$1" ]] || { echo "missing file: $1" >&2; exit 1; }
}

resolve_frida_bin() {
  local candidate user_base
  if [[ -n "${FRIDA_BIN:-}" && -x "${FRIDA_BIN}" ]]; then
    printf '%s\n' "${FRIDA_BIN}"
    return 0
  fi
  candidate="$(command -v frida 2>/dev/null || true)"
  if [[ -n "$candidate" && -x "$candidate" ]]; then
    printf '%s\n' "$candidate"
    return 0
  fi
  user_base="$(python3 -m site --user-base 2>/dev/null || true)"
  candidate="${user_base}/bin/frida"
  if [[ -n "$user_base" && -x "$candidate" ]]; then
    printf '%s\n' "$candidate"
    return 0
  fi
  for candidate in /opt/homebrew/bin/frida /usr/local/bin/frida "$HOME"/Library/Python/*/bin/frida; do
    [[ -x "$candidate" ]] && { printf '%s\n' "$candidate"; return 0; }
  done
  return 1
}

render_frida_script() {
  local src="$1"
  local mode="$2"
  local tmp="$3"
  local auth_types="${4:-}"
  python3 - "$src" "$mode" "$tmp" "$auth_types" <<'PY'
from pathlib import Path
import sys
src = Path(sys.argv[1]).read_text()
mode = sys.argv[2]
out = Path(sys.argv[3])
auth_types = sys.argv[4]
src = src.replace("__MODE__", mode)
src = src.replace("__AUTH_TYPES__", auth_types)
out.write_text(src)
PY
}

viewer_frida() {
  local mode="${1:-transport}"
  local host="${2:-Alexs-Mac-mini.local}"
  local user_name="${3:-testuser}"
  local password="${4:-changeme}"
  local seconds="${5:-25}"
  local frida_bin trace_dir trace_file tmp_script pid frida_pid=""

  require_file "$VIEWER_FRIDA"
  frida_bin="$(resolve_frida_bin)" || { echo "missing frida binary" >&2; exit 1; }
  trace_dir="${VIEWER_TRACE_DIR:-$ROOT/runtime_traces/viewer_${mode}_$(date +%Y%m%d_%H%M%S)}"
  trace_file="${VIEWER_TRACE_FILE:-$trace_dir/viewer_${mode}.ndjson}"
  mkdir -p "$trace_dir"
  tmp_script="$(mktemp /tmp/frida_viewer_${mode}.XXXXXX).js"
  render_frida_script "$VIEWER_FRIDA" "$mode" "$tmp_script" "${SS_REWRITE_AUTH_TYPES:-}"
  trap 'if [[ -n "${frida_pid:-}" ]]; then kill "$frida_pid" >/dev/null 2>&1 || true; wait "$frida_pid" >/dev/null 2>&1 || true; fi; rm -f "${tmp_script:-}"' RETURN

  if [[ "$mode" == "dynamic-resolution" ]]; then
    if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
      echo "run as root: sudo $0 viewer-frida dynamic-resolution" >&2
      exit 1
    fi
    pid=""
    for _ in {1..300}; do
      pid="$(pgrep -x 'Screen Sharing' | head -n1 || true)"
      [[ -n "$pid" ]] && break
      sleep 0.2
    done
    [[ -n "$pid" ]] || { echo "Screen Sharing pid not found" >&2; exit 1; }
    echo "[*] attaching viewer frida mode=$mode pid=$pid"
    echo "[*] trace file: $trace_file"
    exec "$frida_bin" -q -t inf -p "$pid" -l "$tmp_script" --output "$trace_file"
  fi

  osascript -e 'tell application "Screen Sharing" to quit' >/dev/null 2>&1 || true
  sleep 1
  echo "[*] trace file: $trace_file"
  echo "[*] target: vnc://$user_name:***@$host"
  "$frida_bin" -q -t inf -f "$APP" -l "$tmp_script" --output "$trace_file" &
  frida_pid=$!
  sleep 3
  open "vnc://$user_name:$password@$host"
  sleep "$seconds"
  osascript -e 'tell application "Screen Sharing" to quit' >/dev/null 2>&1 || true
  sleep 2
}

viewer_lldb() {
  local mode="${1:-trace}"
  local trace_dir="$ROOT/runtime_traces/viewer_lldb_${mode}_$(date +%Y%m%d_%H%M%S)"
  local trace_file="$trace_dir/viewer_lldb_${mode}.ndjson"
  local command=""
  mkdir -p "$trace_dir"
  require_file "$LLDB_TOOLS"
  case "$mode" in
    trace) command="ssviewer-trace $trace_file" ;;
    bypass) command="ssviewer-bypass $trace_file" ;;
    force-hp) command="ssviewer-force-hp $trace_file" ;;
    patch-hp) command="ssviewer-patch-hp $trace_file" ;;
    *) echo "unknown viewer-lldb mode: $mode" >&2; exit 1 ;;
  esac
  echo "[*] lldb trace file: $trace_file" >&2
  exec lldb \
    -o "command script import $LLDB_TOOLS" \
    -o "$command" \
    -o "run" \
    -o "continue" \
    -- "$APP"
}

daemon_frida() {
  local mode="${1:-transport}"
  local frida_bin pid tmp_script
  require_file "$DAEMON_FRIDA"
  frida_bin="$(resolve_frida_bin)" || { echo "missing frida binary" >&2; exit 1; }
  [[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "run as root: sudo $0 daemon-frida $mode" >&2; exit 1; }
  launchctl kickstart -k system/com.apple.screensharing >/dev/null 2>&1 || true
  for _ in {1..50}; do
    pid="$(pgrep -x screensharingd | head -n1 || true)"
    [[ -n "$pid" ]] && break
    sleep 0.1
  done
  [[ -n "${pid:-}" ]] || { echo "screensharingd pid not found" >&2; exit 1; }
  tmp_script="$(mktemp /tmp/frida_daemon_${mode}.XXXXXX).js"
  render_frida_script "$DAEMON_FRIDA" "$mode" "$tmp_script"
  trap 'rm -f "$tmp_script"' RETURN
  echo "[*] attaching daemon frida mode=$mode pid=$pid"
  exec "$frida_bin" -q -t inf -p "$pid" -l "$tmp_script"
}

capture_proxy_trace() {
  local mode="$1"
  local host="${2:-Alexs-Mac-mini.local}"
  local user_name="${3:-testuser}"
  local password="${4:-changeme}"
  local seconds="${5:-30}"
  local listen_host="${LISTEN_HOST:-127.0.0.1}"
  local listen_port="${LISTEN_PORT:-5901}"
  local upstream_port="${UPSTREAM_PORT:-5900}"
  local stamp out_dir proxy_log proxy_stdout viewer_stdout
  stamp="$(date +%Y%m%d_%H%M%S)"
  out_dir="$ROOT/runtime_traces/${mode}_$stamp"
  proxy_log="$out_dir/proxy.ndjson"
  proxy_stdout="$out_dir/proxy.stdout.log"
  viewer_stdout="$out_dir/viewer.stdout.log"
  mkdir -p "$out_dir"
  python3 "$TOOLS_PY" proxy \
    --listen-host "$listen_host" \
    --listen-port "$listen_port" \
    --upstream-host "$host" \
    --upstream-port "$upstream_port" \
    --log "$proxy_log" >"$proxy_stdout" 2>&1 &
  local proxy_pid=$!
  trap 'kill "$proxy_pid" >/dev/null 2>&1 || true; wait "$proxy_pid" >/dev/null 2>&1 || true' EXIT
  for _ in {1..50}; do
    grep -q "listening on" "$proxy_stdout" 2>/dev/null && break
    sleep 0.2
  done
  [[ "$mode" == "capture_native_screen_sharing_proxy_trace" ]] || export LISTEN_HOST="$listen_host" LISTEN_PORT="$listen_port"
  if [[ "$mode" == "capture_native_screen_sharing_promode_proxy_trace" ]]; then
    viewer_frida "promode-transport" "${listen_host}:${listen_port}" "$user_name" "$password" "$seconds" | tee "$viewer_stdout"
  else
    viewer_frida "transport" "${listen_host}:${listen_port}" "$user_name" "$password" "$seconds" | tee "$viewer_stdout"
  fi
}

capture_runtime() {
  local scenario="$1"
  local peer="$2"
  local root="$ROOT/runtime_traces/${scenario}"
  mkdir -p "$root"
  launchctl print system/com.apple.screensharing > "$root/launchctl_system_screensharing.txt" 2>&1 || true
  launchctl print "gui/${UID}/com.apple.screensharing.agent" > "$root/launchctl_gui_agent.txt" 2>&1 || true
  launchctl print "gui/${UID}/com.apple.screensharing.MessagesAgent" > "$root/launchctl_gui_messagesagent.txt" 2>&1 || true
  nettop -P -L 1 -m tcp,udp > "$root/nettop_snapshot.txt" 2>&1 || true
  log stream --style ndjson --predicate '(process == "screensharingd" OR process == "ScreensharingAgent" OR process == "AppleVNCServer" OR eventMessage CONTAINS[c] "ProMode" OR eventMessage CONTAINS[c] "supports60FPS" OR eventMessage CONTAINS[c] "viewer" OR eventMessage CONTAINS[c] "UDP" OR eventMessage CONTAINS[c] "session not accelerated")' > "$root/log_stream.ndjson" 2>&1 &
  local log_pid=$!
  sudo tcpdump -i any -w "$root/packet_capture.pcapng" "host ${peer}" >/dev/null 2>&1 &
  local tcpdump_pid=$!
  trap 'kill $log_pid $tcpdump_pid 2>/dev/null || true; wait $log_pid 2>/dev/null || true; wait $tcpdump_pid 2>/dev/null || true' EXIT INT TERM
  echo "[*] running. reproduce scenario now, then press Ctrl-C to stop"
  while true; do sleep 1; done
}

capture_dynamic_resolution() {
  local scenario="$1"
  local peer="$2"
  local root="$ROOT/runtime_traces/${scenario}"
  local viewer_log_pid="" host_log_pid="" tcpdump_pid="" frida_pid=""
  mkdir -p "$root"
  [[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "run as root: sudo $0 capture dynamic-resolution <scenario> <peer>" >&2; exit 1; }
  log stream --style ndjson --info --debug --predicate 'process == "Screen Sharing" OR processImagePath CONTAINS[c] "Screen Sharing.app"' > "$root/shared-screen-viewer.ndjson" 2>&1 &
  viewer_log_pid=$!
  log stream --style ndjson --info --debug --predicate 'process == "screensharingd" OR process == "ScreensharingAgent" OR process == "AppleVNCServer" OR processImagePath CONTAINS[c] "screensharingd" OR processImagePath CONTAINS[c] "ScreensharingAgent" OR processImagePath CONTAINS[c] "AppleVNCServer"' > "$root/screensharing-host.ndjson" 2>&1 &
  host_log_pid=$!
  tcpdump -i any -w "$root/capture.pcapng" "host ${peer}" >/dev/null 2>&1 &
  tcpdump_pid=$!
  "$0" viewer-frida dynamic-resolution > "$root/viewer_frida_dynamic_resolution.ndjson" 2> "$root/viewer_frida_dynamic_resolution.stderr.log" &
  frida_pid=$!
  trap 'for pid in "${viewer_log_pid:-}" "${host_log_pid:-}" "${tcpdump_pid:-}" "${frida_pid:-}"; do [[ -n "$pid" ]] && kill "$pid" >/dev/null 2>&1 || true; done; for pid in "${viewer_log_pid:-}" "${host_log_pid:-}" "${tcpdump_pid:-}" "${frida_pid:-}"; do [[ -n "$pid" ]] && wait "$pid" >/dev/null 2>&1 || true; done' RETURN INT TERM
  while true; do sleep 1; done
}

capture_comprehensive() {
  local out_dir="${1:-$ROOT/runtime_traces/comprehensive_capture_$(date +%Y%m%d_%H%M%S)}"
  local host="${2:-Alexs-Mac-mini.local}"
  local user_name="${3:-testuser}"
  local password="${4:-changeme}"
  local seconds="${5:-60}"
  local remote_ssh_target="${6:-testuser@test-host.local}"
  local iface="${IFACE:-en0}"
  local pcap_path="$out_dir/${iface}_capture.pcapng"
  local analysis_dir="$out_dir/pcap_analysis"
  local local_viewer_log_pid="" local_system_log_pid="" remote_log_pid="" tshark_pid=""
  mkdir -p "$out_dir"
  log stream --style ndjson --info --debug --predicate 'process == "Screen Sharing" OR processImagePath CONTAINS[c] "Screen Sharing.app"' > "$out_dir/local_screen_sharing.ndjson" 2>&1 &
  local_viewer_log_pid=$!
  log stream --style ndjson --info --debug --predicate 'process == "screensharingd" OR process == "ScreensharingAgent" OR process == "AppleVNCServer" OR processImagePath CONTAINS[c] "screensharingd" OR processImagePath CONTAINS[c] "ScreensharingAgent" OR processImagePath CONTAINS[c] "AppleVNCServer"' > "$out_dir/local_related_processes.ndjson" 2>&1 &
  local_system_log_pid=$!
  ssh "$remote_ssh_target" "/usr/bin/log stream --style ndjson --info --debug --predicate 'process == \"screensharingd\" OR process == \"ScreensharingAgent\" OR process == \"AppleVNCServer\"'" > "$out_dir/remote_host.ndjson" 2> "$out_dir/remote_host.stderr.log" &
  remote_log_pid=$!
  tshark -i "$iface" -w "$pcap_path" ${EXTRA_TSHARK_ARGS:-} > "$out_dir/tshark.stdout.log" 2> "$out_dir/tshark.stderr.log" &
  tshark_pid=$!
  trap 'for pid in "${local_viewer_log_pid:-}" "${local_system_log_pid:-}" "${remote_log_pid:-}" "${tshark_pid:-}"; do [[ -n "$pid" ]] && kill "$pid" >/dev/null 2>&1 || true; done; for pid in "${local_viewer_log_pid:-}" "${local_system_log_pid:-}" "${remote_log_pid:-}" "${tshark_pid:-}"; do [[ -n "$pid" ]] && wait "$pid" >/dev/null 2>&1 || true; done' RETURN INT TERM
  VIEWER_TRACE_DIR="$out_dir" \
  VIEWER_TRACE_FILE="$out_dir/viewer_frida_transport.ndjson" \
  "$0" viewer-frida transport "$host" "$user_name" "$password" "$seconds" > "$out_dir/viewer_open.stdout.log" 2> "$out_dir/viewer_frida_transport.stderr.log"
  for pid in "${local_viewer_log_pid:-}" "${local_system_log_pid:-}" "${remote_log_pid:-}" "${tshark_pid:-}"; do
    [[ -n "$pid" ]] && kill "$pid" >/dev/null 2>&1 || true
  done
  for pid in "${local_viewer_log_pid:-}" "${local_system_log_pid:-}" "${remote_log_pid:-}" "${tshark_pid:-}"; do
    [[ -n "$pid" ]] && wait "$pid" >/dev/null 2>&1 || true
  done
  local_viewer_log_pid=""
  local_system_log_pid=""
  remote_log_pid=""
  tshark_pid=""
  if [[ -f "$pcap_path" ]]; then
    pcap_analyze "$pcap_path" "$analysis_dir" || true
    python3 "$TOOLS_PY" extract-rfb-security-types \
      --pcap "$pcap_path" \
      --out-json "$analysis_dir/rfb_security_types.json" \
      --out-md "$analysis_dir/rfb_security_types.md" \
      > "$analysis_dir/rfb_security_types.stdout.txt" 2> "$analysis_dir/rfb_security_types.stderr.txt" || true
  fi
}

capture_auth_matrix() {
  local scenario="${1:-auth_matrix_$(date +%Y%m%d_%H%M%S)}"
  local host="${2:-Alexs-Mac-mini.local}"
  local user_name="${3:-testuser}"
  local password="${4:-changeme}"
  local seconds="${5:-10}"
  local listen_host="${LISTEN_HOST:-127.0.0.1}"
  local listen_port="${LISTEN_PORT:-5901}"
  local upstream_port="${UPSTREAM_PORT:-5900}"
  local out_dir="$ROOT/runtime_traces/${scenario}"
  mkdir -p "$out_dir"
  for auth_type in 30 31 32 33 34 35 36; do
    local run_dir="$out_dir/type_${auth_type}"
    local proxy_log="$run_dir/proxy.ndjson"
    local proxy_stdout="$run_dir/proxy.stdout.log"
    local viewer_stdout="$run_dir/viewer.stdout.log"
    local viewer_stderr="$run_dir/viewer.stderr.log"
    mkdir -p "$run_dir"
    python3 "$TOOLS_PY" proxy \
      --listen-host "$listen_host" \
      --listen-port "$listen_port" \
      --upstream-host "$host" \
      --upstream-port "$upstream_port" \
      --advertise-types "$auth_type" \
      --selection-idle-timeout-ms 500 \
      --log "$proxy_log" >"$proxy_stdout" 2>&1 &
    local proxy_pid=$!
    for _ in {1..50}; do
      grep -q "listening on" "$proxy_stdout" 2>/dev/null && break
      sleep 0.2
    done
    VIEWER_TRACE_DIR="$run_dir" \
    VIEWER_TRACE_FILE="$run_dir/viewer_frida_transport.ndjson" \
    "$0" viewer-frida transport "${listen_host}:${listen_port}" "$user_name" "$password" "$seconds" > "$viewer_stdout" 2> "$viewer_stderr" || true
    kill "$proxy_pid" >/dev/null 2>&1 || true
    wait "$proxy_pid" >/dev/null 2>&1 || true
  done
}

capture_mode() {
  local mode="${1:-}"
  shift || true
  case "$mode" in
    proxy-trace) capture_proxy_trace "capture_native_screen_sharing_proxy_trace" "$@" ;;
    promode-proxy-trace) capture_proxy_trace "capture_native_screen_sharing_promode_proxy_trace" "$@" ;;
    promode-direct) viewer_lldb patch-hp ;;
    dynamic-resolution) capture_dynamic_resolution "$@" ;;
    runtime) capture_runtime "$@" ;;
    comprehensive) capture_comprehensive "$@" ;;
    auth-matrix) capture_auth_matrix "$@" ;;
    *) echo "unknown capture mode: $mode" >&2; exit 1 ;;
  esac
}

auth33_mode() {
  local mode="${1:-}"
  shift || true
  case "$mode" in
    applehpdebug)
      local host="${1:?host required}"
      local port="${2:-5900}"
      local seconds="${3:-120}"
      local bin="/Volumes/Tools/ScreenSharingWorkspace/libvncserver/build/examples/client/applehpdebug"
      [[ -x "$bin" ]] || { echo "missing binary: $bin" >&2; exit 1; }
      exec "$bin" "$host" "$port" "$seconds"
      ;;
    stream)
      local host="${1:?host required}"
      local port="${2:-5900}"
      local seconds="${3:-30}"
      local outdir="$ROOT/runtime_traces/stream_working_$(date +%Y%m%d_%H%M%S)"
      local log="$outdir/client.log"
      local frame="$outdir/first_frame.ppm"
      local frames_dir="$outdir/frames"
      mkdir -p "$frames_dir"
      VNC_AUTH_SCHEMES=33 \
      VNC_AUTH33_REPLAY=1 \
      VNC_AUTH33_SELECTOR_TYPE=33 \
      VNC_AUTH33_PACKET_VERSION=0x0100 \
      VNC_AUTH33_AUTHTYPE=2 \
      VNC_AUTH33_AUXTYPE=0x0100 \
      VNC_AUTH33_X_MODE="${VNC_AUTH33_X_MODE:-srp_emptyuser_colon_pbkdf2pass}" \
      VNC_AUTH33_PBKDF2_DKLEN="${VNC_AUTH33_PBKDF2_DKLEN:-128}" \
      VNC_AUTH33_M1_MODE="${VNC_AUTH33_M1_MODE:-rfc5054_emptyuser}" \
      VNC_AUTH33_HELPER="${VNC_AUTH33_HELPER_OVERRIDE:-$TOOLS_PY}" \
      VNC_DUMP_FIRST_FRAME="$frame" \
      VNC_DUMP_FRAME_DIR="$frames_dir" \
      VNC_DUMP_EVERY_N=5 \
      "$0" auth33 applehpdebug "$host" "$port" "$seconds" > "$log" 2>&1 || true
      echo "$log"
      ;;
    live-view)
      VNC_LIVE_VIEW=1 VNC_CLIENT_INIT_FLAGS="${VNC_CLIENT_INIT_FLAGS:-0xC1}" "$0" auth33 stream "$@"
      ;;
    hp-probe)
      local scenario="${1:?scenario required}"
      local host="${2:?host required}"
      local port="${3:-5900}"
      local seconds="${4:-20}"
      local outdir="$ROOT/runtime_traces/${scenario}_$(date +%Y%m%d_%H%M%S)"
      local log_pid=""
      mkdir -p "$outdir"
      log stream --style compact --info --debug --predicate 'process == "screensharingd" OR process == "ScreensharingAgent" OR process == "AppleVNCServer" OR subsystem CONTAINS "screensharing" OR eventMessage CONTAINS[c] "ProMode" OR eventMessage CONTAINS[c] "supports60FPS" OR eventMessage CONTAINS[c] "UDP" OR eventMessage CONTAINS[c] "session not accelerated"' > "$outdir/log_stream.compact" 2>&1 &
      log_pid=$!
      trap '[[ -n "${log_pid:-}" ]] && kill "$log_pid" 2>/dev/null || true; [[ -n "${log_pid:-}" ]] && wait "$log_pid" 2>/dev/null || true' RETURN
      "$0" auth33 stream "$host" "$port" "$seconds" > "$outdir/probe_stdout.txt" 2>&1 || true
      ;;
    localhost-proxy)
      local host="${1:-Alexs-Mac-mini.local}"
      local port="${2:-5900}"
      python3 "$TOOLS_PY" proxy --listen-host 127.0.0.1 --listen-port 5901 --upstream-host "$host" --upstream-port "$port" --log "$ROOT/runtime_traces/localhost_proxy_$(date +%Y%m%d_%H%M%S).ndjson"
      ;;
    *) echo "unknown auth33 mode: $mode" >&2; exit 1 ;;
  esac
}

pcap_analyze() {
  local pcap="$1"
  local outdir="$2"
  local host_filter="${3:-}"
  local tshark_bin="${TSHARK_BIN:-/Applications/Wireshark.app/Contents/MacOS/tshark}"
  local display_filter=""
  mkdir -p "$outdir"
  [[ -f "$pcap" ]] || { echo "pcap not found: $pcap" >&2; exit 1; }
  [[ -n "$host_filter" ]] && display_filter="ip.addr == ${host_filter} or ipv6.addr == ${host_filter}"
  run_tshark() {
    local args=("$tshark_bin" -r "$pcap")
    [[ -n "$display_filter" ]] && args+=(-Y "$display_filter")
    args+=("$@")
    "${args[@]}"
  }
  run_tshark -q -z io,phs > "$outdir/protocol_hierarchy.txt" || true
  run_tshark -q -z endpoints,ip > "$outdir/endpoints_ipv4.txt" || true
  run_tshark -q -z endpoints,ipv6 > "$outdir/endpoints_ipv6.txt" || true
  run_tshark -q -z conv,tcp > "$outdir/conversations_tcp.txt" || true
  run_tshark -q -z conv,udp > "$outdir/conversations_udp.txt" || true
  run_tshark -T fields -E header=y -E separator=, -E quote=d -e frame.number -e frame.time_epoch -e frame.time_relative -e frame.len -e ip.src -e tcp.srcport -e udp.srcport -e ip.dst -e tcp.dstport -e udp.dstport -e ip.proto -e _ws.col.Protocol -e tls.record.content_type -e tls.handshake.type -e quic -e dtls > "$outdir/packet_timeline.csv" || true
  run_tshark -Y "tls.handshake or quic or dtls or tcp.flags.syn==1 or tcp.flags.fin==1 or tcp.flags.reset==1" -T fields -E header=y -E separator=, -E quote=d -e frame.number -e frame.time_epoch -e frame.time_relative -e ip.src -e tcp.srcport -e udp.srcport -e ip.dst -e tcp.dstport -e udp.dstport -e _ws.col.Protocol -e tls.handshake.type -e tls.record.content_type -e quic.long.packet_type > "$outdir/handshake_timeline.csv" || true
  run_tshark -q -z io,stat,1 > "$outdir/io_stat_1s.txt" || true
}

logs_snapshot() {
  local scenario="$1"
  local src_log="${2:-/tmp/screensharing.log}"
  local root="$ROOT/runtime_traces/${scenario}"
  local out_log="$root/screensharing.log"
  local markers="$root/hp_markers.txt"
  local summary="$root/hp_summary.txt"
  mkdir -p "$root"
  cp "$src_log" "$out_log"
  {
    echo "# Source"
    echo "$src_log"
    echo
    echo "# Bytes"
    wc -c < "$out_log"
    echo
    echo "# Lines"
    wc -l < "$out_log"
  } > "$summary"
  rg -n -i "ProMode|UDP|accelerated|stream config|supports60FPS|viewer->udp|AVC|RTP|RTCP|session not accelerated|connectionDoesNotSupportProMode|Release UDP Streaming" "$out_log" > "$markers" || true
}

main() {
  local cmd="${1:-}"
  [[ -n "$cmd" ]] || { usage; exit 2; }
  shift || true
  case "$cmd" in
    viewer-frida) viewer_frida "$@" ;;
    viewer-lldb) viewer_lldb "$@" ;;
    daemon-frida) daemon_frida "$@" ;;
    capture) capture_mode "$@" ;;
    auth33) auth33_mode "$@" ;;
    pcap)
      [[ "${1:-}" == "analyze" ]] || { echo "usage: $0 pcap analyze <pcap> <output_dir> [host_filter]" >&2; exit 2; }
      shift
      pcap_analyze "$@"
      ;;
    logs)
      [[ "${1:-}" == "snapshot" ]] || { echo "usage: $0 logs snapshot <scenario_name> [log_path]" >&2; exit 2; }
      shift
      logs_snapshot "$@"
      ;;
    bn)
      [[ "${1:-}" == "batch" ]] || { echo "usage: $0 bn batch <targets_file> <output_dir> [keywords_file]" >&2; exit 2; }
      shift
      python3 "$TOOLS_PY" bn-batch "$@"
      ;;
    tools) python3 "$TOOLS_PY" "$@" ;;
    help|-h|--help) usage ;;
    *) echo "unknown command: $cmd" >&2; usage; exit 2 ;;
  esac
}

main "$@"
