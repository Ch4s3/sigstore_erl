#!/bin/bash
# Vendor sigstore_erl into another project the way hex vendors hex_core:
#   scripts/vendor.sh <prefix> <target_src_dir>
# Copies the files in scripts/vendor_list.txt flat into the target with a
# module-name prefix, rewriting the listed tokens with sed.
set -euo pipefail
prefix=${1:?prefix (e.g. mix_ or r3_)}
target=${2:?target src dir}
here=$(cd "$(dirname "$0")/.." && pwd)
list="$here/scripts/vendor_list.txt"
ref=$(cd "$here" && git rev-parse --short HEAD 2>/dev/null || echo unknown)
files=$(sed -n '/^\[files\]/,/^\[tokens\]/p' "$list" | grep -v '^\[' | grep -v '^#' | grep .)
tokens=$(sed -n '/^\[tokens\]/,$p' "$list" | grep -v '^\[' | grep -v '^#' | grep .)
mkdir -p "$target"
for f in $files; do
  out="$target/$prefix$f"
  { echo "%% Vendored from sigstore_erl ($ref), do not edit manually"; echo; cat "$here/src/$f"; } > "$out"
  for tok in $tokens; do
    sed -i.bak "s/$tok/$prefix$tok/g" "$out" && rm -f "$out.bak"
  done
done
