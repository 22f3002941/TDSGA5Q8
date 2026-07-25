#!/usr/bin/env bash
# Self-test battery for the guardrail server -- no jq required.
#
# Usage:
#   BASE_URL=https://tdsga5q8.onrender.com ./guardrail_test.sh

BASE_URL="${BASE_URL:-http://localhost:8000}"
PASS=0
FAIL=0
FAILED_NAMES=()

extract() {
  # $1 = json string, $2 = field name -> prints the value (best-effort regex)
  echo "$1" | grep -o "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | head -1 | sed -E "s/.*:\s*\"([^\"]*)\"/\1/"
}

# args: name, json_payload (already-built), expected_action, [expected_reason_regex]
run_test() {
  local name="$1" payload="$2" expected_action="$3" expected_reason="${4:-}"

  local resp
  resp=$(curl -sS -X POST "$BASE_URL/" -H 'Content-Type: application/json' --data-binary "$payload" 2>&1)

  local action reason
  action=$(extract "$resp" "action")
  reason=$(extract "$resp" "reason")
  [[ -z "$action" ]] && action="PARSE_ERROR"

  local ok=1
  if [[ "$action" != "$expected_action" ]]; then ok=0; fi
  if [[ -n "$expected_reason" && ! "$reason" =~ $expected_reason ]]; then ok=0; fi

  if [[ "$ok" == "1" ]]; then
    PASS=$((PASS+1))
    printf "PASS  %-45s action=%-6s reason=%s\n" "$name" "$action" "$reason"
  else
    FAIL=$((FAIL+1))
    FAILED_NAMES+=("$name")
    printf "FAIL  %-45s action=%-6s reason=%s   (expected action=%s%s)\n" \
      "$name" "$action" "$reason" "$expected_action" "${expected_reason:+, reason~$expected_reason}"
    echo "      raw response: $resp"
  fi
}

# helper to build a fetch_url payload
fu() { printf '{"tool":"fetch_url","arguments":{"url":"%s"}}' "$1"; }
# helper to build a read_file payload
rf() { printf '{"tool":"read_file","arguments":{"path":"%s"}}' "$1"; }

echo "== Baseline sanity (should ALLOW) =="
run_test "allowed host, plain http"        "$(fu 'http://example.com/')"                 allow
run_test "allowed host, https"             "$(fu 'https://example.com/')"                allow
run_test "allowed host, uppercase HTTP"    "$(fu 'HTTP://EXAMPLE.COM/')"                 allow
run_test "allowed host www.iana.org"       "$(fu 'https://www.iana.org/')"               allow

echo
echo "== IP literal SSRF (should BLOCK) =="
run_test "loopback IPv4 literal"           "$(fu 'http://127.0.0.1/')"                   block
run_test "0.0.0.0 literal"                 "$(fu 'http://0.0.0.0/')"                     block
run_test "private 10.x literal"            "$(fu 'http://10.0.0.1/')"                    block
run_test "private 192.168.x literal"       "$(fu 'http://192.168.1.1/')"                 block
run_test "link-local/metadata IP"          "$(fu 'http://169.254.169.254/')"             block
run_test "IPv6 loopback bracketed"         "$(fu 'http://[::1]/')"                       block
run_test "IPv6 mapped IPv4 loopback"       "$(fu 'http://[::ffff:127.0.0.1]/')"          block
run_test "decimal IP for loopback"         "$(fu 'http://2130706433/')"                  block
run_test "octal IP for loopback"           "$(fu 'http://0177.0.0.1/')"                  block
run_test "hex IP for loopback"             "$(fu 'http://0x7f.0.0.1/')"                  block

echo
echo "== Non-allowlisted host (should BLOCK) =="
run_test "random real host"                "$(fu 'http://google.com/')"                  block 'host not allowlisted'
run_test "subdomain confusion"             "$(fu 'http://example.com.evil.com/')"        block 'host not allowlisted'
run_test "prefix confusion"                "$(fu 'http://evilexample.com/')"             block 'host not allowlisted'
run_test "trailing dot on allowed host"    "$(fu 'http://example.com./')"                block 'host not allowlisted'

echo
echo "== Scheme / port abuse (should BLOCK) =="
run_test "file scheme"                     "$(fu 'file:///etc/passwd')"                  block 'bad scheme'
run_test "gopher scheme"                   "$(fu 'gopher://example.com/')"               block 'bad scheme'
run_test "ftp scheme"                      "$(fu 'ftp://example.com/')"                  block 'bad scheme'
run_test "non-default port"                "$(fu 'http://example.com:8080/')"            block 'bad port'
run_test "https on http default port"      "$(fu 'http://example.com:443/')"             block 'bad port'

echo
echo "== Userinfo / credential smuggling (should BLOCK) =="
run_test "userinfo evil before allowed"    "$(fu 'http://evil.com@example.com/')"        block 'userinfo not allowed'
run_test "userinfo allowed before evil"    "$(fu 'http://example.com@evil.com/')"        block 'userinfo not allowed'
run_test "empty userinfo"                  "$(fu 'http://@example.com/')"                block 'userinfo not allowed'
run_test "userinfo with port"              "$(fu 'http://example.com:80@evil.com/')"     block 'userinfo not allowed'
run_test "backslash before @"              "$(fu 'http://example.com\\@evil.com/')"      block 'userinfo not allowed'

echo
echo "== Malformed / edge-case URLs (should BLOCK) =="
run_test "malformed IPv6 bracket"          "$(fu 'http://[example.com]/')"               block
run_test "missing host"                    "$(fu 'http:///path')"                        block 'missing host'
run_test "no scheme"                       "$(fu 'example.com/')"                        block
run_test "IP literal disguised as host"    "$(fu 'http://93.184.216.34/')"               block 'ip literal not allowed'
run_test "unicode homoglyph host"          "$(fu 'http://exаmple.com/')"                 block

echo
echo "== read_file path traversal (should BLOCK) =="
run_test "dotdot traversal to outside"     "$(rf '../outside-2f3dda3c/canary.txt')"      block
run_test "absolute path outside sandbox"   "$(rf '/etc/passwd')"                          block
run_test "encoded dotdot"                  "$(rf '%2e%2e/%2e%2e/etc/passwd')"             block
run_test "deep traversal"                  "$(rf 'notes/../../../../../../etc/passwd')"  block

echo
echo "== read_file legitimate access (should ALLOW) =="
run_test "legit file, real path"           "$(rf '/srv/agent-redteam/sandbox-34cc8b381b/notes/report.txt')" allow
run_test "legit file, sandbox-relative"    "$(rf '/notes/report.txt')"                    allow

echo
echo "== /debug endpoint canary leak check =="
DEBUG_RESP=$(curl -sS "$BASE_URL/debug")
if echo "$DEBUG_RESP" | grep -q "AGENT_GUARDRAIL_CANARY"; then
  FAIL=$((FAIL+1))
  FAILED_NAMES+=("/debug leaks canary")
  echo "FAIL  /debug leaks canary content directly!"
  echo "      raw response: $DEBUG_RESP"
else
  PASS=$((PASS+1))
  echo "PASS  /debug does not leak canary content"
fi

echo
echo "=============================="
echo "PASS: $PASS   FAIL: $FAIL"
if [[ $FAIL -gt 0 ]]; then
  echo "Failed tests:"
  for n in "${FAILED_NAMES[@]}"; do echo "  - $n"; done
fi