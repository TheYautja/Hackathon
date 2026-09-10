#!/usr/bin/env bash
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build"
ADMIN="$BUILD/admin/labadmin"
AGENT="$BUILD/agent/labagent"
POLICY="$ROOT/policies/default.json"

PASS=0
FAIL=0

ok() {
echo "[PASS] $1"
PASS=$((PASS + 1))
}

fail() {
echo "[FAIL] $1"
FAIL=$((FAIL + 1))
}

echo "========================================"
echo " LabOrchestrator Linux Integration Test"
echo "========================================"
echo

# ------------------------------------------------------------------

# 1. Build

# ------------------------------------------------------------------

echo "[1/7] Building..."

if cmake --build "$BUILD" -j"$(nproc)" >/dev/null 2>&1; then
ok "Build"
else
fail "Build"
exit 1
fi

# ------------------------------------------------------------------

# 2. Check required files

# ------------------------------------------------------------------

echo "[2/7] Checking files..."

[[ -x "$ADMIN" ]] && ok "labadmin exists" || fail "labadmin missing"
[[ -x "$AGENT" ]] && ok "labagent exists" || fail "labagent missing"
[[ -f "$POLICY" ]] && ok "default policy exists" || fail "default policy missing"

# ------------------------------------------------------------------

# 3. Check agent process

# ------------------------------------------------------------------

echo "[3/7] Checking agent..."

if pgrep -x labagent >/dev/null 2>&1; then
ok "labagent is running"
else
fail "labagent is not running"
echo
echo "Start it with:"
echo "  $AGENT"
exit 1
fi

# ------------------------------------------------------------------

# 4. Discovery

# ------------------------------------------------------------------

echo "[4/7] Testing discovery..."

DISCOVER_OUTPUT="$("$ADMIN" discover --timeout 3 2>&1)"
echo "$DISCOVER_OUTPUT"

if echo "$DISCOVER_OUTPUT" | grep -q "TheYautja"; then
ok "UDP discovery"
else
fail "UDP discovery"
fi

# ------------------------------------------------------------------

# 5. Push policy

# ------------------------------------------------------------------

echo "[5/7] Testing policy push..."

PUSH_OUTPUT="$("$ADMIN" push TheYautja "$POLICY" 2>&1)"
echo "$PUSH_OUTPUT"

if ! echo "$PUSH_OUTPUT" | grep -qiE "erro|falha|nao encontrada|nao encontrado"; then
ok "Policy push"
else
fail "Policy push"
fi

# ------------------------------------------------------------------

# 6. Direct IP connection

# ------------------------------------------------------------------

echo "[6/7] Testing direct IP..."

IP="$(echo "$DISCOVER_OUTPUT" |
grep -oE '@ [0-9]+.[0-9]+.[0-9]+.[0-9]+:[0-9]+' |
head -n1 |
sed -E 's/@ ([0-9.]+):[0-9]+/\1/')"

if [[ -n "$IP" ]]; then
IP_OUTPUT="$("$ADMIN" status "$IP" 2>&1)"
echo "$IP_OUTPUT"

```
if ! echo "$IP_OUTPUT" | grep -qiE "erro|falha|nao encontrado"; then
    ok "Direct IP connection"
else
    fail "Direct IP connection"
fi
```

else
fail "Could not extract agent IP"
fi

# ------------------------------------------------------------------

# 7. Check generated state/logs

# ------------------------------------------------------------------

echo "[7/7] Checking agent data..."

if [[ -d "$ROOT/data" ]]; then
ok "data directory exists"

```
echo
echo "Files under data/:"
find "$ROOT/data" -maxdepth 3 -type f -print 2>/dev/null | head -50
```

else
echo "[WARN] data/ directory not found"
fi

echo
echo "========================================"
echo " Results"
echo "========================================"
echo "PASS: $PASS"
echo "FAIL: $FAIL"
echo

if (( FAIL == 0 )); then
echo "ALL TESTS PASSED"
exit 0
else
echo "SOME TESTS FAILED"
exit 1
fi

