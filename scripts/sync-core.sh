#!/usr/bin/env bash
# Keeps the core files identical between the Transferd repo and TransferDaemon.
#
#   scripts/sync-core.sh <Transferd checkout>           copy the core files into this repo
#   scripts/sync-core.sh <Transferd checkout> --check   change nothing; fail if anything differs
#
# The core files are the ones named in core.manifest of the Transferd checkout. Without
# --check, every such file here is made equal to the checkout's copy, and any file under
# a core entry that the checkout does not have is removed. Generated output (target/,
# node_modules/, dist/, __pycache__/, .pytest_cache/, *.egg-info/) is never a core file.
# Run against this same repo it does nothing, so this script is identical in both repos.
set -euo pipefail
export LC_ALL=C

usage() {
  echo "usage: $0 <Transferd checkout> [--check]" >&2
  exit 2
}

[[ $# -ge 1 && $# -le 2 ]] || usage
[[ -d "$1" ]] || { echo "not a directory: $1" >&2; exit 2; }
SRC="$(cd "$1" && pwd)"
MODE="${2:-sync}"
case "$MODE" in sync|--check) ;; *) usage ;; esac
DST="$(cd "$(dirname "$0")/.." && pwd)"
MANIFEST="$SRC/core.manifest"
[[ -f "$MANIFEST" ]] || { echo "no core.manifest in $SRC" >&2; exit 2; }

# Each manifest entry, without comments and blank lines.
entries() { grep -vE '^[[:space:]]*(#|$)' "$MANIFEST" || true; }

# Generated output, pruned wherever it appears under a manifest entry.
GENERATED=(-name target -o -name node_modules -o -name dist -o -name __pycache__ -o -name .pytest_cache -o -name '*.egg-info')

# Every file the manifest names, found under the repo root given as $1 (sorted, relative).
files_in() {
  local root="$1" e
  while IFS= read -r e; do
    if [[ -d "$root/$e" ]]; then
      (cd "$root" && find "$e" \( "${GENERATED[@]}" \) -prune -o -type f -print)
    elif [[ -f "$root/$e" ]]; then
      printf '%s\n' "$e"
    fi
  done < <(entries) | sort -u
}

# Every manifest entry must exist in the checkout, or the manifest is wrong.
while IFS= read -r e; do
  [[ -e "$SRC/$e" ]] || { echo "manifest entry missing from $SRC: $e" >&2; exit 2; }
done < <(entries)

SRC_LIST="$(files_in "$SRC")"
DST_LIST="$(files_in "$DST")"

changed=()
while IFS= read -r f; do
  [[ -n "$f" ]] || continue
  if [[ ! -f "$DST/$f" ]] || ! cmp -s "$SRC/$f" "$DST/$f"; then
    changed+=("$f")
  fi
done <<< "$SRC_LIST"

extra=()
while IFS= read -r f; do
  [[ -n "$f" ]] || continue
  if ! grep -qxF -- "$f" <<< "$SRC_LIST"; then
    extra+=("$f")
  fi
done <<< "$DST_LIST"

if [[ "$MODE" == "--check" ]]; then
  if (( ${#changed[@]} == 0 && ${#extra[@]} == 0 )); then
    echo "core files are identical to $SRC"
    exit 0
  fi
  for f in ${changed[@]+"${changed[@]}"}; do echo "differs or missing: $f"; done
  for f in ${extra[@]+"${extra[@]}"}; do echo "not in the checkout: $f"; done
  echo "core files are NOT in sync with $SRC; run scripts/sync-core.sh $SRC" >&2
  exit 1
fi

for f in ${changed[@]+"${changed[@]}"}; do
  mkdir -p "$(dirname "$DST/$f")"
  cp "$SRC/$f" "$DST/$f"
  echo "copied  $f"
done
for f in ${extra[@]+"${extra[@]}"}; do
  rm -f "$DST/$f"
  echo "removed $f"
done
# Prune directories that the removals left empty, inside the manifest entries.
while IFS= read -r e; do
  [[ -d "$DST/$e" ]] && find "$DST/$e" -depth -type d -empty -delete
done < <(entries)
echo "core files now match $SRC (${#changed[@]} copied, ${#extra[@]} removed)"
