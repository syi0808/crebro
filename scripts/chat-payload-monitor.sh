#!/usr/bin/env bash
set -u -o pipefail

usage() {
  cat <<'USAGE'
Usage:
  scripts/chat-payload-monitor.sh -- <child-agent-command ...>
  scripts/chat-payload-monitor.sh --self-test

Required child command examples:
  scripts/chat-payload-monitor.sh -- claude
  scripts/chat-payload-monitor.sh -- codex
  scripts/chat-payload-monitor.sh -- gemini
  scripts/chat-payload-monitor.sh -- opencode

Environment overrides:
  CREBRO_MONITOR_SKIP_BUILD=1
  CREBRO_MONITOR_SESSION=crebro-payload-...
  CREBRO_MONITOR_STARTUP_DELAY=1
  CREBRO_MONITOR_ATTACH=0
  CREBRO_BIN=/absolute/path/to/crebro

The script starts a tmux session with a child chat pane and a live request
payload monitor pane. The monitor pane tails Crebro's sanitized upstream request
tap and prints only chat-related payload fields. The tap file is temporary and
deleted on exit.
USAGE
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

RESET=$'\033[0m'
BOLD=$'\033[1m'
DIM=$'\033[2m'
CYAN=$'\033[36m'
CHAT_BODY_REGEX="${CREBRO_MONITOR_CHAT_BODY_REGEX:-(\"messages\"[[:space:]]*:|\"input\"[[:space:]]*:|\"contents\"[[:space:]]*:|\"prompt\"[[:space:]]*:|\"system\"[[:space:]]*:|\"instructions\"[[:space:]]*:|\"anthropic_version\"[[:space:]]*:|CREBRO_SECRET|Crebro replaced local secrets with safe placeholders|crebro-local-placeholder)}"

MODE="tmux"
if [[ "${1:-}" == "__monitor-pane" ]]; then
  MODE="monitor-pane"
  shift
elif [[ "${1:-}" == "__child-pane" ]]; then
  MODE="child-pane"
  shift
fi

SELF_TEST=0
if [[ "$MODE" == "tmux" && ( "${1:-}" == "-h" || "${1:-}" == "--help" ) ]]; then
  usage
  exit 0
elif [[ "$MODE" == "tmux" && "${1:-}" == "--self-test" ]]; then
  SELF_TEST=1
  shift
fi

if [[ "${1:-}" == "--" ]]; then
  shift
fi

if [[ "$MODE" == "child-pane" ]]; then
  CHILD_CMD=("$@")
elif [[ "$MODE" == "monitor-pane" ]]; then
  CHILD_CMD=()
elif [[ "$SELF_TEST" == "1" ]]; then
  CHILD_CMD=()
elif [[ "$#" -gt 0 ]]; then
  CHILD_CMD=("$@")
else
  echo "error: child agent command is required; pass it after --" >&2
  usage >&2
  exit 2
fi

require_tool() {
  local tool="$1"
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: $tool is not installed or not in PATH" >&2
    exit 127
  fi
}

highlight_crebro() {
  perl -pe '
    s/(\{\{CREBRO_SECRET:v1:[^}]+\}\})/\e[1;35m$1\e[0m/g;
    s/(<\/?cb>)/\e[1;31m$1\e[0m/g;
    s/(Crebro replaced local secrets with safe placeholders)/\e[1;36m$1\e[0m/g;
    s/\b(crebro-local-placeholder|sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16})\b/\e[1;31m$1\e[0m/g;
  '
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

project_chat_payload() {
  local payload="$1"
  if ! is_json "$payload"; then
    if [[ "$payload" =~ $CHAT_BODY_REGEX ]]; then
      printf '%s' "$payload"
    fi
    return 0
  fi

  printf '%s' "$payload" | jq -c '
    def maybe_json:
      if type == "string" then
        try fromjson catch .
      else
        .
      end;
    def selected_chat_object:
      . as $object
      | [
          "model",
          "model_slug",
          "messages",
          "input",
          "contents",
          "prompt",
          "system",
          "instructions",
          "anthropic_version"
        ] as $keys
      | reduce $keys[] as $key
          ({}; if $object[$key] != null then .[$key] = $object[$key] else . end)
      | select(length > 0);
    def project:
      maybe_json
      | if type == "object" then
          selected_chat_object
          // (if .turn != null then (.turn | project) else empty end)
          // (if .request != null then (.request | project) else empty end)
          // (if .body != null then (.body | project) else empty end)
          // (if .payload != null then (.payload | project) else empty end)
          // (if .message != null then (.message | project) else empty end)
        elif type == "array" then
          [ .[] | project ] | select(length > 0)
        else
          empty
        end;
    project
  ' 2>/dev/null || true
}

print_tap_record() {
  local line="$1"
  local kind method host path payload projected

  payload="$(printf '%s' "$line" | jq -r '.payload // empty' 2>/dev/null)" || return 0
  if [[ -z "$payload" ]]; then
    return 0
  fi

  projected="$(project_chat_payload "$payload")"
  if [[ -z "$projected" ]]; then
    return 0
  fi

  kind="$(printf '%s' "$line" | jq -r '.kind // "request"' 2>/dev/null)"
  method="$(printf '%s' "$line" | jq -r '.method // empty' 2>/dev/null)"
  host="$(printf '%s' "$line" | jq -r '.host // empty' 2>/dev/null)"
  path="$(printf '%s' "$line" | jq -r '.path // empty' 2>/dev/null)"

  printf '\n%s[%screbro-tap %s%s%s%s%s\n' \
    "$DIM" "$CYAN" "$kind" \
    "${method:+ $method}" "${host:+ $host}" "${path:+$path}" "$RESET"
  printf '%s%s%s\n' "$BOLD" "chat request payload" "$RESET"
  print_json_or_text "$projected"
}

format_tap_stream() {
  local line
  while IFS= read -r line || [[ -n "$line" ]]; do
    print_tap_record "$line"
  done
}

start_tap_formatter() {
  tail -n 0 -f "$PAYLOAD_TAP" | format_tap_stream
}

run_self_test() {
  require_tool jq
  require_tool perl

  local placeholder='{{CREBRO_SECRET:v1:OPENAI_API_KEY:s_demo}}'
  local tap_payload
  tap_payload='{"turn":{"messages":[{"role":"user","content":"only show chat '"$placeholder"'"}],"metadata":{"event":"turn"}}}'
  print_tap_record "$(jq -nc \
    --arg payload "$tap_payload" \
    '{kind:"http",method:"POST",host:"chatgpt.com",path:"/backend-api/turn",payload:$payload}')"

  local direct_payload
  direct_payload='{"model":"gpt-test","input":[{"role":"user","content":"direct '"$placeholder"'"}],"debug_event":"omitted"}'
  print_tap_record "$(jq -nc \
    --arg payload "$direct_payload" \
    '{kind:"http",method:"POST",host:"api.openai.com",path:"/v1/responses",payload:$payload}')"
}

if [[ "$SELF_TEST" == "1" ]]; then
  run_self_test
  exit 0
fi

shell_quote_args() {
  local out="" quoted
  for arg in "$@"; do
    printf -v quoted '%q' "$arg"
    out+="${quoted} "
  done
  printf '%s' "${out% }"
}

env_assignment() {
  local key="$1" value="$2" quoted
  printf -v quoted '%q' "$value"
  printf '%s=%s' "$key" "$quoted"
}

process_children() {
  local pid="$1"
  pgrep -P "$pid" 2>/dev/null || true
}

process_tree_pids() {
  local pid="$1"
  local child

  if [[ -z "$pid" ]] || ! kill -0 "$pid" 2>/dev/null; then
    return 0
  fi

  while IFS= read -r child; do
    if [[ -n "$child" ]]; then
      process_tree_pids "$child"
    fi
  done < <(process_children "$pid")

  printf '%s\n' "$pid"
}

terminate_process_list() {
  local signal="$1"
  local pids="$2"
  local pid

  while IFS= read -r pid; do
    if [[ -n "$pid" ]]; then
      kill "-$signal" "$pid" 2>/dev/null || true
    fi
  done <<<"$pids"
}

process_list_has_alive_pid() {
  local pids="$1"
  local pid

  while IFS= read -r pid; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      return 0
    fi
  done <<<"$pids"

  return 1
}

wait_for_process_exit() {
  local pid="$1"
  local attempts="$2"
  local delay="$3"

  for _ in $(seq 1 "$attempts"); do
    if ! kill -0 "$pid" 2>/dev/null; then
      return 0
    fi
    sleep "$delay"
  done

  return 1
}

stop_formatter() {
  if [[ -n "${FORMATTER_PID:-}" ]] && kill -0 "$FORMATTER_PID" 2>/dev/null; then
    local formatter_pids
    formatter_pids="$(process_tree_pids "$FORMATTER_PID")"
    terminate_process_list TERM "$formatter_pids"
    wait_for_process_exit "$FORMATTER_PID" 10 0.1 || true
    if process_list_has_alive_pid "$formatter_pids"; then
      terminate_process_list KILL "$formatter_pids"
    fi
    wait "$FORMATTER_PID" 2>/dev/null || true
  fi
  FORMATTER_PID=""
}

cleanup_monitor() {
  if [[ "$CLEANING_UP" == "1" ]]; then
    return 0
  fi
  CLEANING_UP=1
  trap '' INT TERM
  stop_formatter
}

run_monitor_pane() {
  require_tool jq
  require_tool perl

  PAYLOAD_TAP="${CREBRO_PAYLOAD_TAP_FILE:?missing CREBRO_PAYLOAD_TAP_FILE}"
  FORMATTER_PID=""
  CLEANING_UP=0

  trap cleanup_monitor EXIT
  trap 'cleanup_monitor; exit 130' INT TERM HUP

  echo "Payload monitor"
  echo "  source:    crebro request tap"
  echo "  scope:     chat payload projection"
  echo

  : >"$PAYLOAD_TAP"
  start_tap_formatter &
  FORMATTER_PID=$!
  wait "$FORMATTER_PID"
  exit $?
}

run_child_pane() {
  local status status_file session_name

  if [[ "${#CHILD_CMD[@]}" -eq 0 ]]; then
    echo "error: child command cannot be empty" >&2
    exit 2
  fi

  PAYLOAD_TAP="${CREBRO_PAYLOAD_TAP_FILE:?missing CREBRO_PAYLOAD_TAP_FILE}"
  CREBRO_BIN="${CREBRO_BIN:?missing CREBRO_BIN}"
  status_file="${CREBRO_MONITOR_STATUS_FILE:?missing CREBRO_MONITOR_STATUS_FILE}"
  session_name="${CREBRO_MONITOR_SESSION:?missing CREBRO_MONITOR_SESSION}"

  finish_child() {
    local status="$1"
    trap - INT TERM HUP
    printf '%s\n' "$status" >"$status_file"
    echo
    echo "Child exited with status $status; closing tmux monitor session..."
    sleep 1
    tmux kill-session -t "$session_name" 2>/dev/null || true
    exit "$status"
  }

  trap 'finish_child 130' INT
  trap 'finish_child 143' TERM
  trap 'finish_child 129' HUP

  echo "Child session"
  echo "  crebro: $CREBRO_BIN"
  echo "  child:  ${CHILD_CMD[*]}"
  echo

  set +e
  CREBRO_PAYLOAD_TAP_FILE="$PAYLOAD_TAP" "$CREBRO_BIN" -- "${CHILD_CMD[@]}"
  status=$?
  set -u

  finish_child "$status"
}

run_tmux_main() {
  local session_name tmp_dir payload_tap status_file
  local monitor_cmd child_cmd env_prefix attach_status child_status startup_delay

  if [[ "${#CHILD_CMD[@]}" -eq 0 ]]; then
    echo "error: child command cannot be empty" >&2
    exit 2
  fi

  require_tool tmux
  require_tool jq
  require_tool perl

  CREBRO_BIN="${CREBRO_BIN:-$REPO_ROOT/target/debug/crebro}"
  if [[ "${CREBRO_MONITOR_SKIP_BUILD:-0}" != "1" ]]; then
    echo "Building debug Crebro..."
    (cd "$REPO_ROOT" && cargo build) || exit $?
  fi

  if [[ ! -x "$CREBRO_BIN" ]]; then
    echo "error: Crebro binary is not executable: $CREBRO_BIN" >&2
    exit 2
  fi

  tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/crebro-payload-monitor.XXXXXX")"
  payload_tap="$tmp_dir/crebro-payload.tap.jsonl"
  status_file="$tmp_dir/child.status"
  : >"$payload_tap"

  session_name="${CREBRO_MONITOR_SESSION:-crebro-payload-$(date +%Y%m%d-%H%M%S)-$$}"
  startup_delay="${CREBRO_MONITOR_STARTUP_DELAY:-1}"

  cleanup_parent() {
    tmux kill-session -t "$session_name" 2>/dev/null || true
    if [[ -d "$tmp_dir" ]]; then
      rm -rf "$tmp_dir"
    fi
  }

  trap cleanup_parent EXIT
  trap 'cleanup_parent; exit 130' INT TERM HUP

  env_prefix="$(
    printf '%s ' \
      "$(env_assignment CREBRO_MONITOR_SESSION "$session_name")" \
      "$(env_assignment CREBRO_MONITOR_STATUS_FILE "$status_file")" \
      "$(env_assignment CREBRO_PAYLOAD_TAP_FILE "$payload_tap")" \
      "$(env_assignment CREBRO_MONITOR_CHAT_BODY_REGEX "$CHAT_BODY_REGEX")" \
      "$(env_assignment CREBRO_BIN "$CREBRO_BIN")" \
      "$(env_assignment PATH "$PATH")"
  )"
  monitor_cmd="${env_prefix}$(shell_quote_args "$SCRIPT_DIR/chat-payload-monitor.sh" "__monitor-pane")"
  child_cmd="${env_prefix}$(shell_quote_args "$SCRIPT_DIR/chat-payload-monitor.sh" "__child-pane" "${CHILD_CMD[@]}")"

  echo "Starting tmux payload monitor session: $session_name" >&2
  echo "  left:  child chat TUI" >&2
  echo "  right: live Crebro request tap" >&2
  echo "  temp:  $tmp_dir" >&2

  tmux new-session -d -s "$session_name" -n crebro -c "$REPO_ROOT" "$monitor_cmd" || exit $?
  sleep "$startup_delay"
  if ! tmux has-session -t "$session_name" 2>/dev/null; then
    echo "error: payload monitor tmux session exited before child started" >&2
    exit 1
  fi
  tmux split-window -h -p 30 -t "$session_name:0" -c "$REPO_ROOT" "$child_cmd" || exit $?
  tmux swap-pane -s "$session_name:0.1" -t "$session_name:0.0" || exit $?
  tmux select-pane -t "$session_name:0.0" || exit $?
  tmux set-option -t "$session_name" status-left "[crebro payload] " >/dev/null

  attach_status=0
  if [[ "${CREBRO_MONITOR_ATTACH:-1}" == "0" ]]; then
    while tmux has-session -t "$session_name" 2>/dev/null; do
      sleep 0.2
    done
  elif [[ -n "${TMUX:-}" ]]; then
    tmux switch-client -t "$session_name"
    while tmux has-session -t "$session_name" 2>/dev/null; do
      sleep 0.2
    done
  else
    tmux attach-session -t "$session_name" || attach_status=$?
  fi

  child_status="$attach_status"
  if [[ -s "$status_file" ]]; then
    child_status="$(sed -n '1p' "$status_file")"
  fi

  trap - EXIT INT TERM HUP
  cleanup_parent
  exit "$child_status"
}

case "$MODE" in
  monitor-pane)
    run_monitor_pane
    ;;
  child-pane)
    run_child_pane
    ;;
  tmux)
    run_tmux_main
    ;;
  *)
    echo "error: unknown mode: $MODE" >&2
    exit 2
    ;;
esac
