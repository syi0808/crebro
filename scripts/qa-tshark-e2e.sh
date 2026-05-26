#!/usr/bin/env bash
set -u -o pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/qa-tshark-e2e.sh [-- child-command ...]

Default child command:
  codex

Environment overrides:
  CREBRO_QA_HOST=chatgpt.com
  CREBRO_QA_IFACE=en0
  CREBRO_QA_OUT_DIR=~/Workspace/pcapng
  CREBRO_QA_RUN_ID=crebro-chatgpt-upstream-YYYYMMDD-HHMMSS
  CREBRO_QA_SKIP_BUILD=1
  CREBRO_BIN=/absolute/path/to/crebro

The script starts sudo tshark, runs the debug Crebro binary in proxy mode with
TLS key logging enabled, then stops capture and writes a decrypted payload TSV.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ "${1:-}" == "--" ]]; then
  shift
fi

if [[ "$#" -gt 0 ]]; then
  CHILD_CMD=("$@")
else
  CHILD_CMD=("codex")
fi

if [[ "${#CHILD_CMD[@]}" -eq 0 ]]; then
  echo "error: child command cannot be empty" >&2
  exit 2
fi

if ! command -v tshark >/dev/null 2>&1; then
  echo "error: tshark is not installed or not in PATH" >&2
  exit 127
fi

HOST="${CREBRO_QA_HOST:-chatgpt.com}"
OUT_DIR="${CREBRO_QA_OUT_DIR:-$HOME/Workspace/pcapng}"
RUN_ID="${CREBRO_QA_RUN_ID:-crebro-chatgpt-upstream-$(date +%Y%m%d-%H%M%S)}"
CREBRO_BIN="${CREBRO_BIN:-$REPO_ROOT/target/debug/crebro}"
BPF_FILTER="${CREBRO_QA_BPF_FILTER:-tcp port 443}"
DISPLAY_FILTER="${CREBRO_QA_DISPLAY_FILTER:-websocket.payload.text || http.file_data || data-text-lines}"

mkdir -p "$OUT_DIR"

PCAP="$OUT_DIR/$RUN_ID.pcapng"
KEYLOG="$OUT_DIR/$RUN_ID.tls.keys"
TSV="$OUT_DIR/$RUN_ID.payloads.tsv"

detect_iface() {
  route get "$HOST" 2>/dev/null | awk '/interface:/{print $2; exit}'
}

IFACE="${CREBRO_QA_IFACE:-$(detect_iface)}"
if [[ -z "$IFACE" ]]; then
  echo "error: failed to detect network interface for $HOST; set CREBRO_QA_IFACE" >&2
  exit 2
fi

if [[ "${CREBRO_QA_SKIP_BUILD:-0}" != "1" ]]; then
  echo "Building debug Crebro..."
  (cd "$REPO_ROOT" && cargo build) || exit $?
fi

if [[ ! -x "$CREBRO_BIN" ]]; then
  echo "error: Crebro binary is not executable: $CREBRO_BIN" >&2
  exit 2
fi

echo "Preparing sudo for tshark capture..."
sudo -v || exit $?

rm -f "$PCAP" "$KEYLOG" "$TSV"

TSHARK_PID=""
CREBRO_STATUS=0

stop_capture() {
  if [[ -n "${TSHARK_PID:-}" ]] && kill -0 "$TSHARK_PID" 2>/dev/null; then
    echo "Stopping tshark capture..."
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
}

cleanup_on_exit() {
  stop_capture
}

trap cleanup_on_exit EXIT

echo "Starting tshark capture..."
echo "  interface: $IFACE"
echo "  bpf:       $BPF_FILTER"
echo "  pcap:      $PCAP"
sudo tshark -i "$IFACE" -f "$BPF_FILTER" -w "$PCAP" >/tmp/crebro-qa-tshark.log 2>&1 &
TSHARK_PID=$!
sleep 1

if ! kill -0 "$TSHARK_PID" 2>/dev/null; then
  echo "error: tshark exited before Crebro started" >&2
  sed -n '1,120p' /tmp/crebro-qa-tshark.log >&2 || true
  exit 1
fi

echo
echo "Starting debug Crebro. Exit the child session when QA is done."
echo "  crebro:    $CREBRO_BIN"
echo "  keylog:    $KEYLOG"
echo "  child:     ${CHILD_CMD[*]}"
echo

set +e
CREBRO_TLS_KEYLOG_FILE="$KEYLOG" "$CREBRO_BIN" --mode proxy -- "${CHILD_CMD[@]}"
CREBRO_STATUS=$?

stop_capture
trap - EXIT

if [[ -f "$PCAP" ]]; then
  sudo chown "$(id -u):$(id -g)" "$PCAP" 2>/dev/null || true
fi

echo
echo "Extracting decrypted payload TSV..."
if [[ ! -s "$KEYLOG" ]]; then
  echo "warning: keylog is empty; decrypted payload extraction may be empty" >&2
fi
if [[ ! -s "$PCAP" ]]; then
  echo "warning: pcap is empty or missing; payload TSV will be empty" >&2
fi

sudo tshark -r "$PCAP" \
  -o tls.keylog_file:"$KEYLOG" \
  -Y "$DISPLAY_FILTER" \
  -T fields \
  -E header=y \
  -E separator=$'\t' \
  -E quote=d \
  -e frame.number \
  -e frame.time \
  -e tcp.stream \
  -e ip.src \
  -e tcp.srcport \
  -e ip.dst \
  -e tcp.dstport \
  -e _ws.col.Protocol \
  -e _ws.col.Info \
  -e websocket.payload.text \
  -e http.file_data \
  -e data-text-lines \
  >"$TSV"
EXTRACT_STATUS=$?
if [[ "$EXTRACT_STATUS" -ne 0 ]]; then
  echo "warning: tshark payload extraction exited with status $EXTRACT_STATUS" >&2
fi

echo
echo "QA artifacts:"
echo "  pcap:   $PCAP"
echo "  keylog: $KEYLOG"
echo "  tsv:    $TSV"
echo
echo "Open payload TSV:"
echo "  less '$TSV'"
echo
echo "Search for raw credential and Crebro placeholders:"
echo "  rg -F -e 'YOUR_RAW_CREDENTIAL' -e 'CREBRO_SECRET' '$TSV'"
echo
if [[ ! -s "$TSV" ]]; then
  echo "warning: payload TSV is empty. Check that capture started before Crebro and that keylog is non-empty." >&2
fi

exit "$CREBRO_STATUS"
