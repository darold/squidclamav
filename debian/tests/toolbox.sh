# Ensure all errors are catched
set -e

# Helper functions
die() {
  echo "FATAL: $@" >&2
  exit 1
}

error() {
  echo "ERROR: $@" >&2
}

append_line() {
  local line="$1"
  local conf="$2"
  grep -qxF "${line}" "${conf}" \
    || echo "${line}" >> "${conf}"
}

# Steps
c_icap_enable() {
  echo 'Enabling c-icap'
  sed -i 's/^START=.*/START=yes/' /etc/default/c-icap
}

c_icap_start() {
  echo '(re-)Starting c-icap'
  service c-icap restart
}

c_icap_test_basic() {
  echo 'Testing c-icap'
  pidof /usr/bin/c-icap > /dev/null || die 'c-icap is not running'
  test -f /var/run/c-icap/c-icap.pid || error 'PidFile missing'
  test -p /var/run/c-icap/c-icap.ctl || error 'CommandsSocket missing'
}

c_icap_test_service() {
  local service_name="$1"
  local service_desc="$2"
  echo "Testing ${service_name} service (${service_desc})"
  c-icap-client -i 127.0.0.1 -s "${service_name}" 2>&1 \
    | grep -q "^[[:space:]]\+Service: C-ICAP/.* ${service_desc}\$" \
    || error "${service_name} service (${service_desc}) unavailable"
}
