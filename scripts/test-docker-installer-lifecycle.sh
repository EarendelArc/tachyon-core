#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
INSTALLER="$SCRIPT_DIR/install-server-docker.sh"
CHILDREN=()
LAST_PID=""

fail() {
  echo "docker installer lifecycle test failed: $*" >&2
  exit 1
}

cleanup() {
  local pid
  trap - EXIT INT TERM HUP
  for pid in "${CHILDREN[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
    fi
  done
  sleep 0.1
  for pid in "${CHILDREN[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || true
  done
  [[ -z "${TEST_PARENT:-}" ]] || rm -rf -- "$TEST_PARENT"
}

trap cleanup EXIT INT TERM HUP

[[ "$(uname -s)" == "Linux" ]] || fail "this fixture must execute on Linux; skipping is forbidden"
for command in flock realpath setsid timeout; do
  command -v "$command" >/dev/null 2>&1 || fail "$command is required"
done

TEST_PARENT=$(mktemp -d /tmp/tachyon-docker-installer-policy.suite.XXXXXX)
chmod 0700 "$TEST_PARENT"

write_mock_commands() {
  local root="$1"
  mkdir -p "$root/bin"
  cat > "$root/bin/systemctl" <<'MOCK_SYSTEMCTL'
#!/usr/bin/env bash
set -euo pipefail
root=${TACHYON_INSTALLER_TEST_ROOT:?}
active_file="$root/state/service-active"
enabled_file="$root/state/service-enabled"
read_state() { [[ -f "$1" ]] && grep -Fxq true "$1"; }
write_state() { printf '%s\n' "$2" > "$1"; }
case "${1:-}" in
  is-active) read_state "$active_file" ;;
  is-enabled) read_state "$enabled_file" ;;
  start)
    [[ ! -e "$root/control/fail-start" ]] || exit 41
    write_state "$active_file" true
    ;;
  stop) write_state "$active_file" false ;;
  enable)
    write_state "$enabled_file" true
    [[ " $* " != *" --now "* ]] || write_state "$active_file" true
    ;;
  disable)
    write_state "$enabled_file" false
    [[ " $* " != *" --now "* ]] || write_state "$active_file" false
    ;;
  daemon-reload)
    [[ ! -e "$root/control/fail-daemon-reload" ]] || exit 42
    ;;
  *) exit 43 ;;
esac
MOCK_SYSTEMCTL
  cat > "$root/bin/docker" <<'MOCK_DOCKER'
#!/usr/bin/env bash
set -euo pipefail
root=${TACHYON_INSTALLER_TEST_ROOT:?}
container_id=$(printf 'a%.0s' {1..64})
image_id="sha256:$(printf 'b%.0s' {1..64})"
if [[ "${1:-}" == "compose" ]]; then
  if [[ " $* " == *" ps -q tachyon-core "* ]]; then
    printf '%s\n' "$container_id"
  fi
  exit 0
fi
if [[ "${1:-} ${2:-}" == "image inspect" ]]; then
  printf '%s\n' "$image_id"
  exit 0
fi
if [[ "${1:-}" == "inspect" ]]; then
  case "${3:-}" in
    '{{.Id}}') printf '%s\n' "$container_id" ;;
    '{{.State.Status}}') printf 'running\n' ;;
    '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}') printf 'healthy\n' ;;
    '{{.Config.Image}}') printf 'tachyon-core-local:0123456789ab\n' ;;
    '{{.Image}}') printf '%s\n' "$image_id" ;;
    '{{index .Config.Labels "com.docker.compose.service"}}') printf 'tachyon-core\n' ;;
    '{{.State.Pid}}') printf '4242\n' ;;
    *) exit 44 ;;
  esac
  exit 0
fi
exit 45
MOCK_DOCKER
  chmod 0555 "$root/bin/systemctl" "$root/bin/docker"
}

prepare_root() {
  local name="$1"
  local previous_state="$2"
  local root
  root=$(mktemp -d "$TEST_PARENT/${name}.XXXXXX")
  chmod 0700 "$root"
  mkdir -p "$root/state" "$root/control" "$root/systemd" "$root/staged/config" "$root/staged/logs" \
    "$root/proc/4242/fd" "$root/proc/4242/net"
  chmod 0700 "$root/state" "$root/control"
  write_mock_commands "$root"
  case "$previous_state" in
    absent)
      printf 'false\n' > "$root/state/service-active"
      printf 'false\n' > "$root/state/service-enabled"
      ;;
    inactive)
      mkdir -p "$root/live/config" "$root/live/logs"
      printf 'false\n' > "$root/state/service-active"
      printf 'true\n' > "$root/state/service-enabled"
      ;;
    active-disabled)
      mkdir -p "$root/live/config" "$root/live/logs"
      printf 'true\n' > "$root/state/service-active"
      printf 'false\n' > "$root/state/service-enabled"
      ;;
    *) fail "unknown previous state $previous_state" ;;
  esac
  if [[ "$previous_state" != "absent" ]]; then
    printf '{"tgp":{"auth":{"psk":"old-private-psk-0001"}}}\n' > "$root/live/config/server.json"
    printf 'old-compose\n' > "$root/live/docker-compose.yaml"
    printf 'old-log\n' > "$root/live/logs/tachyon-core.log"
    printf 'old-unit\n' > "$root/systemd/tachyon-docker.service"
  fi
  printf '{"tgp":{"auth":{"psk":"new-private-psk-0002"}}}\n' > "$root/staged/config/server.json"
  printf 'new-compose\n' > "$root/staged/docker-compose.yaml"
  printf 'new-unit\n' > "$root/staged-unit"
  cat > "$root/proc/4242/net/udp" <<'UDP'
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:01BB 00000000:0000 07 00000000:00000000 00:00000000 00000000 65532 0 987654 2 0000000000000000 0
UDP
  : > "$root/proc/4242/net/udp6"
  ln -s 'socket:[987654]' "$root/proc/4242/fd/7"
  printf '%s\n' "$previous_state" > "$root/expected-state"
  printf '%s\n' "$root"
}

start_installer() {
  local root="$1"
  local action="$2"
  local pause_at="${3:-}"
  shift 3 || true
  setsid env \
    CI=true \
    PATH="$root/bin:$PATH" \
    TACHYON_INSTALLER_POLICY_TEST=1 \
    TACHYON_INSTALLER_TEST_ROOT="$root" \
    TACHYON_INSTALLER_TEST_PAUSE_AT="$pause_at" \
    TACHYON_ROTATE_PSK="${TACHYON_ROTATE_PSK:-0}" \
    bash "$INSTALLER" --port 443 --policy-test-action "$action" "$@" \
      >"$root/process.$action.out" 2>&1 &
  LAST_PID=$!
  CHILDREN+=("$LAST_PID")
}

wait_for_checkpoint() {
  local root="$1"
  local checkpoint="$2"
  local pid="$3"
  local deadline=$((SECONDS + 8))
  while (( SECONDS < deadline )); do
    [[ -e "$root/events/$checkpoint.$pid" ]] && return 0
    kill -0 "$pid" 2>/dev/null || {
      sed -n '1,160p' "$root"/process.*.out >&2 || true
      fail "installer $pid exited before checkpoint $checkpoint"
    }
    sleep 0.05
  done
  fail "timed out waiting for checkpoint $checkpoint from $pid"
}

wait_for_status() {
  local pid="$1"
  local expected="$2"
  set +e
  wait "$pid"
  local actual=$?
  set -e
  [[ "$actual" -eq "$expected" ]] || fail "process $pid exited $actual, expected $expected"
  local retained=()
  local child
  for child in "${CHILDREN[@]}"; do
    [[ "$child" == "$pid" ]] || retained+=("$child")
  done
  CHILDREN=("${retained[@]}")
}

assert_restored() {
  local root="$1"
  local expected_state
  expected_state=$(<"$root/expected-state")
  [[ ! -e "$root/.tachyon-docker.transaction" ]] || fail "$expected_state rollback retained journal"
  case "$expected_state" in
    absent)
      [[ ! -e "$root/live" ]] || fail "absent rollback retained deployment"
      [[ ! -e "$root/systemd/tachyon-docker.service" ]] || fail "absent rollback retained unit"
      grep -Fxq false "$root/state/service-active" || fail "absent rollback left service active"
      grep -Fxq false "$root/state/service-enabled" || fail "absent rollback left service enabled"
      ;;
    inactive)
      grep -Fq old-private-psk-0001 "$root/live/config/server.json" || fail "inactive rollback lost old PSK"
      grep -Fxq old-compose "$root/live/docker-compose.yaml" || fail "inactive rollback lost compose"
      grep -Fxq old-log "$root/live/logs/tachyon-core.log" || fail "inactive rollback lost logs"
      grep -Fxq old-unit "$root/systemd/tachyon-docker.service" || fail "inactive rollback lost unit"
      grep -Fxq false "$root/state/service-active" || fail "inactive rollback started service"
      grep -Fxq true "$root/state/service-enabled" || fail "inactive rollback disabled service"
      ;;
    active-disabled)
      grep -Fq old-private-psk-0001 "$root/live/config/server.json" || fail "active-disabled rollback lost old PSK"
      grep -Fxq old-compose "$root/live/docker-compose.yaml" || fail "active-disabled rollback lost compose"
      grep -Fxq old-log "$root/live/logs/tachyon-core.log" || fail "active-disabled rollback lost logs"
      grep -Fxq old-unit "$root/systemd/tachyon-docker.service" || fail "active-disabled rollback lost unit"
      grep -Fxq true "$root/state/service-active" || fail "active-disabled rollback stopped service"
      grep -Fxq false "$root/state/service-enabled" || fail "active-disabled rollback enabled service"
      ;;
  esac
}

run_signal_case() {
  local signal_name="$1"
  local expected_status="$2"
  local checkpoint="$3"
  local previous_state="$4"
  local root
  root=$(prepare_root "signal-${signal_name,,}-${checkpoint}" "$previous_state")
  start_installer "$root" install "$checkpoint"
  local pid="$LAST_PID"
  wait_for_checkpoint "$root" "$checkpoint" "$pid"
  kill -s "$signal_name" -- "-$pid"
  wait_for_status "$pid" "$expected_status"
  assert_restored "$root"
  rm -rf -- "$root"
}

# Signals hit real installer subprocesses at every mutation boundary.
run_signal_case INT 130 transaction-prepared absent
run_signal_case TERM 143 old-backed-up inactive
run_signal_case HUP 129 deployment-active active-disabled
run_signal_case INT 130 unit-active active-disabled
run_signal_case TERM 143 health-verified inactive

# A start failure after an explicit staged PSK replacement restores the old PSK.
root=$(prepare_root start-failure active-disabled)
: > "$root/control/fail-start"
TACHYON_ROTATE_PSK=1 start_installer "$root" install '' --confirm-psk-rotation
pid="$LAST_PID"
set +e
wait "$pid"
status=$?
set -e
CHILDREN=()
[[ "$status" -ne 0 ]] || fail "start failure fixture unexpectedly succeeded"
assert_restored "$root"
rm -rf -- "$root"
unset TACHYON_ROTATE_PSK

# One process holds the same FD lock across install/recovery/uninstall dispatch.
root=$(prepare_root concurrency active-disabled)
start_installer "$root" install lock-acquired
owner_pid="$LAST_PID"
wait_for_checkpoint "$root" lock-acquired "$owner_pid"
grep -Fxq "owner_pid=$owner_pid" "$root/lock/docker-installer.lock" || fail "lock owner PID diagnostic is missing"
start_installer "$root" recover ''
contender_recover="$LAST_PID"
wait_for_status "$contender_recover" 1
grep -Fq 'another Docker installer owns the lifecycle lock' "$root/process.recover.out" \
  || fail "concurrent recovery did not fail on the lifecycle lock"
start_installer "$root" uninstall ''
contender_uninstall="$LAST_PID"
wait_for_status "$contender_uninstall" 1
grep -Fq 'another Docker installer owns the lifecycle lock' "$root/process.uninstall.out" \
  || fail "concurrent uninstall did not fail on the lifecycle lock"
[[ ! -e "$root/.tachyon-docker.transaction" ]] || fail "lock loser created a transaction journal"
kill -TERM -- "-$owner_pid"
wait_for_status "$owner_pid" 143
assert_restored "$root"
start_installer "$root" recover ''
wait_for_status "$LAST_PID" 0
rm -rf -- "$root"

# SIGKILL cannot run traps; a new real installer process must acquire the released
# kernel lock and recover the persistent journal before dispatching its action.
root=$(prepare_root sigkill active-disabled)
start_installer "$root" install deployment-active
killed_pid="$LAST_PID"
wait_for_checkpoint "$root" deployment-active "$killed_pid"
kill -KILL -- "-$killed_pid"
wait_for_status "$killed_pid" 137
[[ -d "$root/.tachyon-docker.transaction" ]] || fail "SIGKILL did not leave a recovery journal"
start_installer "$root" recover ''
wait_for_status "$LAST_PID" 0
assert_restored "$root"
rm -rf -- "$root"

# Lock and journal paths reject symlinks before any mutation.
root=$(prepare_root lock-symlink absent)
mkdir -p "$root/outside"
ln -s "$root/outside" "$root/lock"
start_installer "$root" recover ''
wait_for_status "$LAST_PID" 1
[[ -z "$(find "$root/outside" -mindepth 1 -print -quit)" ]] || fail "lock symlink target was modified"
rm -rf -- "$root"

root=$(prepare_root journal-symlink active-disabled)
mkdir -p "$root/journal-target"
ln -s "$root/journal-target" "$root/.tachyon-docker.transaction"
start_installer "$root" recover ''
wait_for_status "$LAST_PID" 1
grep -Fq 'not a private directory' "$root/process.recover.out" || fail "journal symlink was not rejected"
rm -rf -- "$root"

echo "docker installer lifecycle tests passed"
