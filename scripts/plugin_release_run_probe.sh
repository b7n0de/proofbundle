#!/usr/bin/env bash
# Acceptance driver for plugin_release_artifacts.py at one commit.
#
# Usage:
#   plugin_release_run_probe.sh --repo DIR --commit REV --out EMPTY_DIR --version X.Y.Z --expect-pin X.Y.Z
#                               --wrong-pin X.Y.Z [--layout split|combined] [--scan-commit REV ...]
#
# Every step has an expected status. A step whose status differs is logged as UNEXPECTED and makes the driver end
# with exit 1; the driver ends with exit 0 only when every step ended as expected, and with exit 2 on a usage error.
# Steps: three positive builds (two in fresh folders, one from a second clone with working directory /), each with
# exactly the three expected artifacts; byte comparison of the three reports and of every artifact; sha256sum -c of
# A3; the archive against git's own objects (every selected path, its bytes and its executable bit, and nothing
# else); T1 accepted by git mktag with the reported object id; one negative build with --wrong-pin, which must end
# with exit 1 and leave no output folder; optionally scan, twice, byte for byte. In the split layout the archive holds
# the Guard's root with its house marketplace, so the comparison with git covers that root as well.
# Nothing is written into the given clone. Exit codes are read directly, never through a pipe.
#
# Assisted by little helpers.
set -u
here=$(cd "$(dirname "$0")" && pwd)
gen="$here/plugin_release_artifacts.py"
repo=""; commit=""; out=""; version=""; pin=""; wrong=""; layout="split"; scans=()
while [ $# -gt 0 ]; do
  case "$1" in
    --repo) repo=$2; shift 2 ;;
    --commit) commit=$2; shift 2 ;;
    --out) out=$2; shift 2 ;;
    --version) version=$2; shift 2 ;;
    --expect-pin) pin=$2; shift 2 ;;
    --wrong-pin) wrong=$2; shift 2 ;;
    --layout) layout=$2; shift 2 ;;
    --scan-commit) scans+=("$2"); shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
for v in repo commit out version pin wrong; do
  [ -n "${!v}" ] || { echo "missing --${v/pin/expect-pin}" >&2; exit 2; }
done
[ "$pin" != "$wrong" ] || { echo "--wrong-pin must differ from --expect-pin" >&2; exit 2; }
# Nothing is written into the clone read (line 3 of the reading of 7684a47c: an output folder inside it was accepted):
# the output folder lies outside the path given, its git folder, the common git folder of a worktree and the top of its
# working tree, checked before anything is written.
o=$(realpath -m -- "$out")
for d in "$repo" "$(git -C "$repo" rev-parse --path-format=absolute --absolute-git-dir 2>/dev/null)" \
         "$(git -C "$repo" rev-parse --path-format=absolute --git-common-dir 2>/dev/null)" \
         "$(git -C "$repo" rev-parse --show-toplevel 2>/dev/null)"; do
  [ -n "$d" ] || continue
  d=$(realpath -m -- "$d")
  case "$o/" in "$d"/*) echo "the output folder lies outside the repository read; $out does not" >&2; exit 2 ;; esac
done
mkdir -p "$out"
[ -z "$(ls -A "$out")" ] || { echo "output folder not empty" >&2; exit 2; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
log="$out/determinism.txt"
: > "$log"
fail=0

expect() {  # expect NAME EXPECTED GOT
  if [ "$2" = "$3" ]; then
    echo "$1 $3 (expected $2) ok" >> "$log"
  else
    echo "$1 $3 (expected $2) UNEXPECTED" >> "$log"
    fail=1
  fi
}

{
  echo "python $(python3 -c 'import sys; print(sys.version.split()[0])')"
  echo "git $(git --version | awk '{print $3}')"
  echo "platform $(uname -srm)"
  echo "generator sha256 $(sha256sum "$gen" | awk '{print $1}')"
  echo "driver sha256 $(sha256sum "$0" | awk '{print $1}')"
  echo "layout $layout version $version expect-pin $pin wrong-pin $wrong"
} > "$out/environment.txt"

stem="proofbundle-plugin-$version"
expected_list=$(printf '%s\n' "$stem.release.json" "$stem.tar" SHA256SUMS | sort)
common=(build --repo "$repo" --commit "$commit" --version "$version" --expect-pin "$pin" --layout "$layout")

python3 -I "$gen" "${common[@]}" --out "$out/run1" --tag-out "$out/t1.tag" --inventory-out "$out/archive_inventory.txt" \
  > "$out/run1_report.txt"
expect "run1 build exit" 0 $?
python3 -I "$gen" "${common[@]}" --out "$work/run2" > "$out/run2_report.txt"
expect "run2 build exit" 0 $?
git clone -q --shared --no-checkout "$repo" "$work/clone2"
expect "second clone exit" 0 $?
( cd / && python3 -I "$gen" build --repo "$work/clone2" --commit "$commit" --version "$version" --expect-pin "$pin" \
    --layout "$layout" --out "$work/run3" > "$out/run3_report.txt" )
expect "run3 build exit (second clone, working directory /)" 0 $?

for d in "$out/run1" "$work/run2" "$work/run3"; do
  got=$( (cd "$d" 2>/dev/null && ls -A) | sort)
  if [ "$got" = "$expected_list" ]; then same=yes; else same=no; fi
  expect "artifact list of $(basename "$d") is exactly A1 A2 A3" yes "$same"
done

cmp -s "$out/run1_report.txt" "$out/run2_report.txt"; expect "cmp report run1 run2" 0 $?
cmp -s "$out/run1_report.txt" "$out/run3_report.txt"; expect "cmp report run1 run3" 0 $?
while read -r f; do
  cmp -s "$out/run1/$f" "$work/run2/$f"; expect "cmp $f run1 run2" 0 $?
  cmp -s "$out/run1/$f" "$work/run3/$f"; expect "cmp $f run1 run3" 0 $?
done <<< "$expected_list"
( cd "$out/run1" 2>/dev/null && sha256sum -- * ) > "$out/run1_sha256.txt"
( cd "$out/run1" 2>/dev/null && sha256sum -c --quiet SHA256SUMS ); expect "sha256sum -c SHA256SUMS in run1" 0 $?

# The archive against git's objects, independent of the generator's code.
paths=(LICENSE .claude-plugin/marketplace.json plugins/proofbundle)
[ "$layout" = split ] && paths+=(plugins/proofbundle-guard)
mkdir -p "$work/x"
tar -xf "$out/run1/$stem.tar" -C "$work/x" 2>/dev/null; expect "tar -x A1" 0 $?
mismatch=0; count=0
while IFS=$'\t' read -r meta path; do
  set -- $meta
  mode=$1; oid=$3; count=$((count + 1))
  f="$work/x/$stem/$path"
  git -C "$repo" cat-file blob "$oid" > "$work/blob"; got_blob=$?
  if [ "$got_blob" != 0 ] || ! cmp -s "$work/blob" "$f"; then mismatch=$((mismatch + 1)); continue; fi
  if [ "$mode" = 100755 ] && [ ! -x "$f" ]; then mismatch=$((mismatch + 1)); fi
  if [ "$mode" = 100644 ] && [ -x "$f" ]; then mismatch=$((mismatch + 1)); fi
done < <(git -C "$repo" ls-tree -r --full-tree "$commit" -- "${paths[@]}")
files_in_tar=$(find "$work/x" -type f | wc -l)
expect "archive files against git ls-tree, bytes and mode, mismatches" 0 "$mismatch"
expect "archive file count against git ls-tree ($count)" "$count" "$files_in_tar"
tar -tvf "$out/run1/$stem.tar" > "$out/archive_listing.txt" 2>&1

# T1 as git reads it.
reported=$(awk '$1 == "t1_expected_object_id" {print $2}' "$out/run1_report.txt")
if [ -f "$out/t1.tag" ]; then
  made=$(git -C "$work/clone2" mktag < "$out/t1.tag" 2>/dev/null); rc=$?
else
  made=""; rc=missing
fi
expect "git mktag accepts T1" 0 "$rc"
[ -n "$reported" ] && [ "$made" = "$reported" ]; expect "T1 object id equals the reported one" 0 $?

python3 -I "$gen" build --repo "$repo" --commit "$commit" --version "$version" --expect-pin "$wrong" --layout "$layout" \
  --out "$work/neg" > "$out/negative_wrong_pin.txt"
expect "negative build with --expect-pin $wrong exit" 1 $?
if [ -e "$work/neg" ]; then neg=yes; else neg=no; fi
expect "negative build left an output folder" no "$neg"

if [ ${#scans[@]} -gt 0 ]; then
  args=(--commit "$commit"); for c in "${scans[@]}"; do args+=(--commit "$c"); done
  python3 -I "$gen" scan --repo "$repo" "${args[@]}" > "$out/scan.txt"; expect "scan exit" 0 $?
  python3 -I "$gen" scan --repo "$repo" "${args[@]}" > "$work/scan2.txt"; expect "scan second run exit" 0 $?
  cmp -s "$out/scan.txt" "$work/scan2.txt"; expect "cmp scan run1 run2" 0 $?
fi

if [ "$fail" = 0 ]; then echo "result OK, every step as expected" >> "$log"; else echo "result FAILED, see UNEXPECTED" >> "$log"; fi
cat "$log"
exit "$fail"
