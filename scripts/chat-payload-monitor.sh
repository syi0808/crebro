#!/usr/bin/env bash
set -u -o pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/chat-payload-monitor.sh [-- child-command ...]
  scripts/chat-payload-monitor.sh --self-test

Default child command:
  codex

Environment overrides:
  CREBRO_MONITOR_HOST=chatgpt.com
  CREBRO_MONITOR_IFACE=en0
  CREBRO_MONITOR_BPF_FILTER='tcp port 443'
  CREBRO_MONITOR_DISPLAY_FILTER='websocket.payload.text || http.file_data || data-text-lines || http2.data.data'
  CREBRO_MONITOR_SKIP_BUILD=1
  CREBRO_BIN=/absolute/path/to/crebro

The script starts live tshark payload extraction with Crebro TLS key logging,
runs Crebro around the child command, and prints decrypted chat/API payloads as
they arrive. TLS keys and tshark scratch data are kept in a temporary directory
and deleted on exit.
USAGE
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

RESET=$'\033[0m'
BOLD=$'\033[1m'
DIM=$'\033[2m'
CYAN=$'\033[36m'
SELF_TEST=0
if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
elif [[ "${1:-}" == "--self-test" ]]; then
  SELF_TEST=1
  shift
fi

if [[ "${1:-}" == "--" ]]; then
  shift
fi

if [[ "$#" -gt 0 ]]; then
  CHILD_CMD=("$@")
else
  CHILD_CMD=("codex")
fi

require_tool() {
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: $tool is not installed or not in PATH" >&2
    exit 127
  fi
}

find_tshark() {
  if command -v tshark >/dev/null 2>&1; then
    command -v tshark
    return 0
  fi
  if [[ -x /Applications/Wireshark.app/Contents/MacOS/tshark ]]; then
    printf '%s\n' /Applications/Wireshark.app/Contents/MacOS/tshark
    return 0
  fi
  return 1
}

highlight_crebro() {
  perl -pe '
    s/(\{\{CREBRO_SECRET:v1:[^}]+\}\})/\e[1;35m$1\e[0m/g;
    s/(<\/?cb>)/\e[1;31m$1\e[0m/g;
    s/(Crebro replaced local secrets with safe placeholders)/\e[1;36m$1\e[0m/g;
    s/\b(crebro-local-placeholder|sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16})\b/\e[1;31m$1\e[0m/g;
  '
}

decode_hex_field() {
  local value="$1"
  local compact="$value"
  compact="${compact//:/}"
  compact="${compact//[[:space:]]/}"
  if [[ -z "$compact" || ! "$compact" =~ ^[0-9A-Fa-f]+$ ]]; then
    return 1
  fi
  if (( ${#compact} % 2 != 0 )); then
    return 1
  fi
  printf '%s' "$compact" | perl -MEncode=decode,FB_CROAK -ne '
    chomp;
    my $bytes = pack("H*", $_);
    exit 1 if $bytes =~ /[\x00-\x08\x0b\x0c\x0e-\x1f]/;
    eval { print decode("UTF-8", $bytes, FB_CROAK); 1 } or exit 1;
  '
}

decode_bytes_or_text() {
  local value="$1"
  local decoded
  if decoded="$(decode_hex_field "$value" 2>/dev/null)"; then
    printf '%s' "$decoded"
  else
    printf '%s' "$value"
  fi
}

is_json() {
  printf '%s' "$1" | jq -e . >/dev/null 2>&1
}

print_json_or_text() {
  local payload="$1"
  if [[ -z "$payload" ]]; then
    return 0
  fi
  if is_json "$payload"; then
    printf '%s' "$payload" | jq -C . | highlight_crebro
  else
    printf '%s\n' "$payload" | highlight_crebro
  fi
}

is_sse_payload() {
  local payload="$1"
  [[ "$payload" == data:* || "$payload" == event:* || "$payload" == id:* || "$payload" == *$'\ndata:'* ]]
}

print_sse_payload() {
  local payload="$1"
  local line data
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    if [[ -z "$line" ]]; then
      continue
    fi
    if [[ "$line" == data:* ]]; then
      data="${line#data:}"
      data="${data# }"
      printf '%sdata:%s\n' "$DIM" "$RESET"
      if [[ "$data" == "[DONE]" ]]; then
        printf '  %s\n' "$data" | highlight_crebro
      else
        print_json_or_text "$data" | while IFS= read -r pretty_line || [[ -n "$pretty_line" ]]; do
          printf '  %s\n' "$pretty_line"
        done
      fi
    else
      printf '%s%s%s\n' "$DIM" "$line" "$RESET" | highlight_crebro
    fi
  done <<<"$payload"
}

print_payload() {
  local payload="$1"
  if is_sse_payload "$payload"; then
    print_sse_payload "$payload"
  else
    print_json_or_text "$payload"
  fi
}

print_record() {
  local line="$1"
  local frame time stream src sport dst dport proto host method uri h2_authority h2_path ws_payload http_payload text_lines h2_payload
  local field_separator=$'\037'
  line="${line//$'\t'/$field_separator}"
  IFS=$field_separator read -r frame time stream src sport dst dport proto host method uri h2_authority h2_path ws_payload http_payload text_lines h2_payload _ <<<"$line"

  local kind="" payload="" endpoint="" authority="" path=""
  if [[ -n "${ws_payload:-}" ]]; then
    kind="websocket"
    payload="$ws_payload"
  elif [[ -n "${http_payload:-}" ]]; then
    kind="http"
    payload="$(decode_bytes_or_text "$http_payload")"
  elif [[ -n "${text_lines:-}" ]]; then
    kind="text"
    payload="$text_lines"
  elif [[ -n "${h2_payload:-}" ]]; then
    kind="http2"
    if ! payload="$(decode_hex_field "$h2_payload" 2>/dev/null)"; then
      return 0
    fi
  else
    return 0
  fi

  if [[ -z "$payload" ]]; then
    return 0
  fi

  authority="${host:-$h2_authority}"
  path="${uri:-$h2_path}"
  if [[ -n "$method" || -n "$authority" || -n "$path" ]]; then
    endpoint=" ${method}${method:+ }${authority}${path}"
  fi

  printf '\n%s[%sframe=%s stream=%s %s %s:%s -> %s:%s%s%s\n' \
    "$DIM" "$CYAN" "${frame:-?}" "${stream:-?}" "${proto:-?}" \
    "${src:-?}" "${sport:-?}" "${dst:-?}" "${dport:-?}" \
    "${endpoint}" "$RESET"
  printf '%s%s%s\n' "$BOLD" "$kind payload" "$RESET"
  print_payload "$payload"
}

format_stream() {
  local line
  while IFS= read -r line || [[ -n "$line" ]]; do
    print_record "$line"
  done
}

to_hex() {
  perl -0ne 'print unpack("H*", $_)'
}

run_self_test() {
  require_tool jq
  require_tool perl

  local placeholder='{{CREBRO_SECRET:v1:OPENAI_API_KEY:s_demo}}'
  local json_payload
  json_payload="$(printf '{"messages":[{"role":"user","content":"use %s and <cb>manual-secret</cb>"}]}' "$placeholder")"
  print_record $'1\tMay 27, 2026 21:00:00.000000000 KST\t3\t127.0.0.1\t55555\t1.2.3.4\t443\tHTTP2\t\tPOST\t\tapi.openai.com\t/v1/chat/completions\t\t\t\t'"$(printf '%s' "$json_payload" | to_hex)"

  local sse_payload
  sse_payload='data: {"delta":"Crebro replaced local secrets with safe placeholders","content":"'"$placeholder"'"}'
  print_record $'2\tMay 27, 2026 21:00:01.000000000 KST\t3\t1.2.3.4\t443\t127.0.0.1\t55555\tHTTP\tapi.openai.com\t\t/v1/chat/completions\t\t\t\t\t'"$sse_payload"$'\t'
  print_record $'3\tMay 27, 2026 21:00:01.100000000 KST\t3\t1.2.3.4\t443\t127.0.0.1\t55555\tHTTP\tapi.openai.com\t\t/v1/chat/completions\t\t\t\t\tdata: [DONE]\t'

  local ws_payload
  ws_payload='{"prompt":"raw marker sk-demo1234567890 and crebro-local-placeholder"}'
  print_record $'4\tMay 27, 2026 21:00:02.000000000 KST\t9\t127.0.0.1\t55556\tchatgpt.com\t443\tWEBSOCKET\tchatgpt.com\tGET\t/backend-api/conversation\t\t\t'"$ws_payload"$'\t\t\t'
}

if [[ "$SELF_TEST" == "1" ]]; then
  run_self_test
  exit 0
fi

if [[ "${#CHILD_CMD[@]}" -eq 0 ]]; then
  echo "error: child command cannot be empty" >&2
  exit 2
fi

require_tool jq
require_tool perl
TSHARK_BIN="$(find_tshark || true)"
if [[ -z "$TSHARK_BIN" ]]; then
  echo "error: tshark is not installed or not in PATH" >&2
  exit 127
fi

HOST="${CREBRO_MONITOR_HOST:-chatgpt.com}"
CREBRO_BIN="${CREBRO_BIN:-$REPO_ROOT/target/debug/crebro}"
BPF_FILTER="${CREBRO_MONITOR_BPF_FILTER:-tcp port 443}"
DISPLAY_FILTER="${CREBRO_MONITOR_DISPLAY_FILTER:-websocket.payload.text || http.file_data || data-text-lines || http2.data.data}"

detect_iface() {
  route get "$HOST" 2>/dev/null | awk '/interface:/{print $2; exit}'
}

IFACE="${CREBRO_MONITOR_IFACE:-$(detect_iface)}"
if [[ -z "$IFACE" ]]; then
  echo "error: failed to detect network interface for $HOST; set CREBRO_MONITOR_IFACE" >&2
  exit 2
fi

if [[ "${CREBRO_MONITOR_SKIP_BUILD:-0}" != "1" ]]; then
  echo "Building debug Crebro..."
  (cd "$REPO_ROOT" && cargo build) || exit $?
fi

if [[ ! -x "$CREBRO_BIN" ]]; then
  echo "error: Crebro binary is not executable: $CREBRO_BIN" >&2
  exit 2
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/crebro-payload-monitor.XXXXXX")"
KEYLOG="$TMP_DIR/tls.keys"
TSHARK_LOG="$TMP_DIR/tshark.stderr"
FIFO="$TMP_DIR/payload.tsv"
: >"$KEYLOG"
mkfifo "$FIFO"

TSHARK_PID=""
FORMATTER_PID=""
CREBRO_STATUS=0

stop_capture() {
  if [[ -n "${TSHARK_PID:-}" ]] && kill -0 "$TSHARK_PID" 2>/dev/null; then
    echo "Stopping tshark monitor..." >&2
    kill -TERM "$TSHARK_PID" 2>/dev/null || true
    for _ in {1..30}; do
      if ! kill -0 "$TSHARK_PID" 2>/dev/null; then
        break
      fi
      sleep 0.2
    done
    if kill -0 "$TSHARK_PID" 2>/dev/null; then
      kill -KILL "$TSHARK_PID" 2>/dev/null || true
    fi
    wait "$TSHARK_PID" 2>/dev/null || true
  fi
  TSHARK_PID=""

  if [[ -n "${FORMATTER_PID:-}" ]] && kill -0 "$FORMATTER_PID" 2>/dev/null; then
    for _ in {1..10}; do
      if ! kill -0 "$FORMATTER_PID" 2>/dev/null; then
        break
      fi
      sleep 0.1
    done
    if kill -0 "$FORMATTER_PID" 2>/dev/null; then
      kill -TERM "$FORMATTER_PID" 2>/dev/null || true
    fi
    wait "$FORMATTER_PID" 2>/dev/null || true
  fi
  FORMATTER_PID=""
}

cleanup() {
  stop_capture
  if [[ -n "${TMP_DIR:-}" && -d "$TMP_DIR" ]]; then
    rm -rf "$TMP_DIR"
  fi
}

trap cleanup EXIT
trap 'CREBRO_STATUS=130; cleanup; exit 130' INT TERM

echo "Preparing sudo for tshark capture..." >&2
sudo -v || exit $?

echo "Starting live payload monitor..." >&2
echo "  interface: $IFACE" >&2
echo "  bpf:       $BPF_FILTER" >&2
echo "  display:   $DISPLAY_FILTER" >&2
echo "  keylog:    $KEYLOG (temporary)" >&2
echo "  child:     ${CHILD_CMD[*]}" >&2
echo >&2

format_stream <"$FIFO" &
FORMATTER_PID=$!

sudo "$TSHARK_BIN" -l -Q \
  -i "$IFACE" \
  -f "$BPF_FILTER" \
  -o tls.keylog_file:"$KEYLOG" \
  -Y "$DISPLAY_FILTER" \
  -T fields \
  -E separator=$'\t' \
  -E occurrence=f \
  -E quote=n \
  -e frame.number \
  -e frame.time \
  -e tcp.stream \
  -e ip.src \
  -e tcp.srcport \
  -e ip.dst \
  -e tcp.dstport \
  -e _ws.col.Protocol \
  -e http.host \
  -e http.request.method \
  -e http.request.uri \
  -e http2.headers.authority \
  -e http2.headers.path \
  -e websocket.payload.text \
  -e http.file_data \
  -e data-text-lines \
  -e http2.data.data \
  >"$FIFO" 2>"$TSHARK_LOG" &
TSHARK_PID=$!

sleep 1
if ! kill -0 "$TSHARK_PID" 2>/dev/null; then
  echo "error: tshark exited before Crebro started" >&2
  sed -n '1,120p' "$TSHARK_LOG" >&2 || true
  exit 1
fi

set +e
CREBRO_TLS_KEYLOG_FILE="$KEYLOG" "$CREBRO_BIN" -- "${CHILD_CMD[@]}"
CREBRO_STATUS=$?
set -u

stop_capture
trap - EXIT INT TERM
rm -rf "$TMP_DIR"

exit "$CREBRO_STATUS"
