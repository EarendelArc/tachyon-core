#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
INSTALLER="$SCRIPT_DIR/install-server-docker.sh"
LAUNCHER="$SCRIPT_DIR/fixture_process_launcher.py"
CHILDREN=()
LAST_PID=""
LAST_OUTPUT=""
LAST_AUDIT=""
PROCESS_COUNTER=0
TEST_PARENT=""

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
  [[ -z "${TEST_PARENT:-}" || ! -d "$TEST_PARENT" ]] || rm -rf -- "$TEST_PARENT"
}

initialize_case() {
  trap cleanup EXIT
  trap 'cleanup; exit 130' INT
  trap 'cleanup; exit 143' TERM
  trap 'cleanup; exit 129' HUP
  TEST_PARENT=$(mktemp -d /tmp/tachyon-docker-installer-policy.suite.XXXXXX)
  chmod 0700 "$TEST_PARENT"
}

[[ "$(uname -s)" == "Linux" ]] || fail "this fixture must execute on Linux; skipping is forbidden"
[[ -f "$LAUNCHER" && ! -L "$LAUNCHER" ]] || fail "audited fixture launcher is unavailable"
for command in flock realpath python3 timeout; do
  command -v "$command" >/dev/null 2>&1 || fail "$command is required"
done

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
    count_file="$root/state/start-call-count"
    call=0
    [[ ! -f "$count_file" ]] || IFS= read -r call < "$count_file"
    [[ "$call" =~ ^[0-9]+$ ]] || exit 46
    call=$((call + 1))
    printf '%s\n' "$call" > "$count_file"
    unit=unknown
    unit_file="$root/systemd/tachyon-docker.service"
    if [[ -f "$unit_file" ]] && grep -Fxq new-unit "$unit_file"; then
      unit=new
    elif [[ -f "$unit_file" ]] && grep -Fxq old-unit "$unit_file"; then
      unit=old
    fi
    phase=none
    phase_file="$root/.tachyon-docker.transaction/phase"
    [[ ! -f "$phase_file" ]] || IFS= read -r phase < "$phase_file"
    failure_spec="$root/control/fail-start.$call"
    if [[ -f "$failure_spec" ]]; then
      IFS='|' read -r expected_unit expected_phase extra < "$failure_spec"
      if [[ -n "${extra:-}" || "$unit" != "$expected_unit" || "$phase" != "$expected_phase" ]]; then
        printf 'call=%s unit=%s phase=%s result=spec-mismatch expected_unit=%s expected_phase=%s\n' \
          "$call" "$unit" "$phase" "$expected_unit" "$expected_phase" >> "$root/state/systemctl-start.log"
        exit 46
      fi
      printf 'call=%s unit=%s phase=%s result=injected\n' \
        "$call" "$unit" "$phase" >> "$root/state/systemctl-start.log"
      exit 41
    fi
    printf 'call=%s unit=%s phase=%s result=success\n' \
      "$call" "$unit" "$phase" >> "$root/state/systemctl-start.log"
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
  PROCESS_COUNTER=$((PROCESS_COUNTER + 1))
  local output="$root/process.$action.$PROCESS_COUNTER.out"
  local audit="$root/process.$action.$PROCESS_COUNTER.launch.json"
  python3 "$LAUNCHER" launch --audit-file "$audit" -- env \
    CI=true \
    PATH="$root/bin:$PATH" \
    TACHYON_INSTALLER_POLICY_TEST=1 \
    TACHYON_INSTALLER_TEST_ROOT="$root" \
    TACHYON_INSTALLER_TEST_PAUSE_AT="$pause_at" \
    TACHYON_ROTATE_PSK="${TACHYON_ROTATE_PSK:-0}" \
    bash "$INSTALLER" --port 443 --policy-test-action "$action" "$@" \
      >"$output" 2>&1 &
  LAST_PID=$!
  LAST_OUTPUT="$output"
  LAST_AUDIT="$audit"
  CHILDREN+=("$LAST_PID")
  wait_for_launcher_audit "$audit" "$LAST_PID" "$output" "$action"
}

wait_for_launcher_audit() {
  local audit="$1"
  local pid="$2"
  local output="$3"
  local action="$4"
  local deadline=$((SECONDS + 3))
  while (( SECONDS < deadline )); do
    if [[ -f "$audit" ]]; then
      python3 "$LAUNCHER" verify --audit-file "$audit" --expected-pid "$pid" \
        --expected-token bash \
        --expected-token "$INSTALLER" \
        --expected-token=--policy-test-action \
        --expected-token "$action" \
        || fail "launcher audit validation failed for process $pid"
      return 0
    fi
    kill -0 "$pid" 2>/dev/null || {
      sed -n '1,200p' "$output" >&2 || true
      fail "launcher process $pid exited before writing its audit"
    }
    sleep 0.02
  done
  fail "timed out waiting for launcher audit from process $pid"
}

wait_for_checkpoint() {
  local root="$1"
  local checkpoint="$2"
  local pid="$3"
  local deadline=$((SECONDS + 3))
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
  grep -Fq "Received $signal_name during Docker deployment" "$LAST_OUTPUT" \
    || fail "installer $pid did not audit receipt of $signal_name at $checkpoint"
  assert_restored "$root"
  rm -rf -- "$root"
}

case_signal_int_transaction() { run_signal_case INT 130 transaction-prepared absent; }
case_signal_term_backup() { run_signal_case TERM 143 old-backed-up inactive; }
case_signal_hup_deployment() { run_signal_case HUP 129 deployment-active active-disabled; }
case_signal_int_unit() { run_signal_case INT 130 unit-active active-disabled; }
case_signal_term_health() { run_signal_case TERM 143 health-verified inactive; }

case_start_failure() {
  local root pid status
  root=$(prepare_root start-failure active-disabled)
  printf 'new|unit-active\n' > "$root/control/fail-start.1"
  TACHYON_ROTATE_PSK=1 start_installer "$root" install '' --confirm-psk-rotation
  pid="$LAST_PID"
  set +e
  wait "$pid"
  status=$?
  set -e
  CHILDREN=()
  [[ "$status" -ne 0 ]] || fail "start failure fixture unexpectedly succeeded"
  grep -Fxq 'call=1 unit=new phase=unit-active result=injected' "$root/state/systemctl-start.log" \
    || fail "start failure did not target the new deployment precisely"
  grep -Fxq 'call=2 unit=old phase=unit-active result=success' "$root/state/systemctl-start.log" \
    || fail "rollback did not successfully restart the old deployment"
  assert_restored "$root"
  rm -rf -- "$root"
  unset TACHYON_ROTATE_PSK
}

case_old_service_restore_failure() {
  local root pid status first_output
  root=$(prepare_root old-service-restore-failure active-disabled)
  printf 'new|unit-active\n' > "$root/control/fail-start.1"
  printf 'old|unit-active\n' > "$root/control/fail-start.2"
  TACHYON_ROTATE_PSK=1 start_installer "$root" install '' --confirm-psk-rotation
  pid="$LAST_PID"
  first_output="$LAST_OUTPUT"
  set +e
  wait "$pid"
  status=$?
  set -e
  CHILDREN=()
  [[ "$status" -ne 0 ]] || fail "old-service restore failure fixture unexpectedly succeeded"
  grep -Fxq 'call=1 unit=new phase=unit-active result=injected' "$root/state/systemctl-start.log" \
    || fail "old-service fixture did not first fail the new deployment"
  grep -Fxq 'call=2 unit=old phase=unit-active result=injected' "$root/state/systemctl-start.log" \
    || fail "old-service fixture did not precisely fail rollback restart"
  grep -Fq 'Rollback was incomplete; the persistent journal remains' "$first_output" \
    || fail "failed old-service restart did not report retained journal"
  [[ -d "$root/.tachyon-docker.transaction" ]] \
    || fail "failed old-service restart did not retain the transaction journal"
  grep -Fxq unit-active "$root/.tachyon-docker.transaction/phase" \
    || fail "retained journal lost the failing transaction phase"
  grep -Fq old-private-psk-0001 "$root/live/config/server.json" \
    || fail "failed old-service restart did not restore old deployment files"
  grep -Fxq old-unit "$root/systemd/tachyon-docker.service" \
    || fail "failed old-service restart did not restore old unit"
  grep -Fxq false "$root/state/service-active" \
    || fail "failed old-service restart unexpectedly left service active"
  start_installer "$root" recover ''
  wait_for_status "$LAST_PID" 0
  grep -Fxq 'call=3 unit=old phase=unit-active result=success' "$root/state/systemctl-start.log" \
    || fail "next recovery process did not restart the restored old service"
  assert_restored "$root"
  rm -rf -- "$root"
  unset TACHYON_ROTATE_PSK
}

case_concurrency() {
  local root owner_pid contender_recover contender_uninstall recover_output uninstall_output
  root=$(prepare_root concurrency active-disabled)
  start_installer "$root" install lock-acquired
  owner_pid="$LAST_PID"
  wait_for_checkpoint "$root" lock-acquired "$owner_pid"
  grep -Fxq "owner_pid=$owner_pid" "$root/lock/docker-installer.lock" || fail "lock owner PID diagnostic is missing"
  start_installer "$root" recover ''
  contender_recover="$LAST_PID"
  recover_output="$LAST_OUTPUT"
  wait_for_status "$contender_recover" 1
  grep -Fq 'another Docker installer owns the lifecycle lock' "$recover_output" \
    || fail "concurrent recovery did not fail on the lifecycle lock"
  start_installer "$root" uninstall ''
  contender_uninstall="$LAST_PID"
  uninstall_output="$LAST_OUTPUT"
  wait_for_status "$contender_uninstall" 1
  grep -Fq 'another Docker installer owns the lifecycle lock' "$uninstall_output" \
    || fail "concurrent uninstall did not fail on the lifecycle lock"
  [[ ! -e "$root/.tachyon-docker.transaction" ]] || fail "lock loser created a transaction journal"
  kill -TERM -- "-$owner_pid"
  wait_for_status "$owner_pid" 143
  grep -Fq 'Received TERM during Docker deployment' "$root"/process.install.*.out \
    || fail "lock owner did not audit TERM receipt"
  assert_restored "$root"
  start_installer "$root" recover ''
  wait_for_status "$LAST_PID" 0
  rm -rf -- "$root"
}

case_sigkill_recovery() {
  local root killed_pid
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
}

case_lock_symlink() {
  local root
  root=$(prepare_root lock-symlink absent)
  mkdir -p "$root/outside"
  ln -s "$root/outside" "$root/lock"
  start_installer "$root" recover ''
  wait_for_status "$LAST_PID" 1
  [[ -z "$(find "$root/outside" -mindepth 1 -print -quit)" ]] || fail "lock symlink target was modified"
  rm -rf -- "$root"
}

case_journal_symlink() {
  local root output
  root=$(prepare_root journal-symlink active-disabled)
  mkdir -p "$root/journal-target"
  ln -s "$root/journal-target" "$root/.tachyon-docker.transaction"
  start_installer "$root" recover ''
  output="$LAST_OUTPUT"
  wait_for_status "$LAST_PID" 1
  grep -Fq 'not a private directory' "$output" || fail "journal symlink was not rejected"
  rm -rf -- "$root"
}

run_selected_case() {
  case "$1" in
    signal-int-transaction) case_signal_int_transaction ;;
    signal-term-backup) case_signal_term_backup ;;
    signal-hup-deployment) case_signal_hup_deployment ;;
    signal-int-unit) case_signal_int_unit ;;
    signal-term-health) case_signal_term_health ;;
    start-failure) case_start_failure ;;
    old-service-restore-failure) case_old_service_restore_failure ;;
    concurrency) case_concurrency ;;
    sigkill-recovery) case_sigkill_recovery ;;
    lock-symlink) case_lock_symlink ;;
    journal-symlink) case_journal_symlink ;;
    *) fail "unknown lifecycle fixture case: $1" ;;
  esac
}

run_suite() {
  local output_root output name status failures=0
  output_root=$(mktemp -d /tmp/tachyon-docker-installer-policy.results.XXXXXX)
  for name in \
    signal-int-transaction \
    signal-term-backup \
    signal-hup-deployment \
    signal-int-unit \
    signal-term-health \
    start-failure \
    old-service-restore-failure \
    concurrency \
    sigkill-recovery \
    lock-symlink \
    journal-symlink; do
    output="$output_root/$name.out"
    set +e
    timeout --signal=TERM --kill-after=2s 8s bash "$0" --case "$name" >"$output" 2>&1
    status=$?
    set -e
    if [[ "$status" -eq 0 ]]; then
      printf 'PASS lifecycle case %s\n' "$name"
    else
      failures=$((failures + 1))
      printf 'FAIL lifecycle case %s (status=%s)\n' "$name" "$status" >&2
      sed -n '1,240p' "$output" >&2 || true
    fi
  done
  rm -rf -- "$output_root"
  if (( failures > 0 )); then
    echo "docker installer lifecycle test failed: $failures scenario(s) failed" >&2
    return 1
  fi
  echo "docker installer lifecycle tests passed"
}

if [[ "${1:-}" == "--case" ]]; then
  [[ $# -eq 2 ]] || fail "--case requires exactly one scenario name"
  initialize_case
  run_selected_case "$2"
  echo "lifecycle case $2 passed"
elif [[ $# -eq 0 ]]; then
  run_suite
else
  fail "usage: $0 [--case NAME]"
fi
