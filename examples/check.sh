#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TAGS="${TAGS:-with_gvisor,with_wireguard,with_awg,with_masque}"
BIN="$ROOT/.cache/sing-box-examples-check"

mkdir -p "$ROOT/.cache"
go build -tags "$TAGS" -o "$BIN" ./cmd/sing-box

passed=0
failed=0
skipped=0

skip_mkcp() {
  [[ "$1" == *"/mkcp/"* ]]
}

while IFS= read -r f; do
  rel="${f#./}"
  if skip_mkcp "$rel"; then
    echo "SKIP  $rel (mkcp transport not in this fork yet)"
    skipped=$((skipped + 1))
    continue
  fi
  if "$BIN" check -c "$f" >/dev/null 2>&1; then
    echo "PASS  $rel"
    passed=$((passed + 1))
  else
    echo "FAIL  $rel"
    "$BIN" check -c "$f" 2>&1 | sed 's/^/      /'
    failed=$((failed + 1))
  fi
done < <(find examples -name '*.json' | sort)

echo "---"
echo "Passed: $passed  Failed: $failed  Skipped: $skipped"
exit "$failed"
