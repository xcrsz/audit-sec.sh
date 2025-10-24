#!/bin/sh
# ============================================================
# audit-sec.sh — GhostBSD/FreeBSD vulnerability review helper
# ============================================================
#
# This script checks installed packages for known vulnerabilities,
# refreshes the VuXML database, and shows practical advice on what to do.
#
# It provides two output modes:
#   --brief      : Compact, easy-to-read one-line summaries (default recommended)
#   full (no flag): Detailed technical output with advisory links
#
# Options:
#   --unmaintained-only   Show only packages that are marked as "unmaintained" or "end of life"
#   --brief               One-line mode with simple suggestions
#   --top-reqs N          Show up to N reverse dependencies in detailed mode (default 20)
#
# Examples:
#   ./audit-sec.sh
#   ./audit-sec.sh --brief
#   ./audit-sec.sh --unmaintained-only
#   ./audit-sec.sh --top-reqs 50
#
# ============================================================

set -eu

UNMAINTAINED_ONLY=0
BRIEF=0
TOP_REQS=20

while [ $# -gt 0 ]; do
  case "$1" in
    --unmaintained-only) UNMAINTAINED_ONLY=1 ;;
    --brief) BRIEF=1 ;;
    --top-reqs) shift; TOP_REQS="${1:-20}" ;;
    -h|--help)
      sed -n '2,30p' "$0"
      exit 0
      ;;
  esac
  shift
done

TMP_AUDIT="$(mktemp)"
trap 'rm -f "$TMP_AUDIT"' EXIT

echo "Checking for known vulnerabilities..."
pkg audit -F >"$TMP_AUDIT" || true

if ! grep -q ' is vulnerable:' "$TMP_AUDIT"; then
  echo "✅ No vulnerable packages found."
  exit 0
fi

# Colors only if stdout is a tty
if [ -t 1 ]; then
  C_WARN="$(printf '\033[33m')"   # yellow
  C_BAD="$(printf '\033[31m')"    # red
  C_OK="$(printf '\033[32m')"     # green
  C_DIM="$(printf '\033[2m')"     # dim
  C_CLR="$(printf '\033[0m')"     # clear
else
  C_WARN= C_BAD= C_OK= C_DIM= C_CLR=
fi

# Parse pkg audit output into blocks
awk 'BEGIN{RS=""; FS="\n"}
/ is vulnerable:/ {
  pkg=""; reason=""; url=""; cves="";
  for(i=1;i<=NF;i++){
    line=$i
    if (line ~ / is vulnerable:/) { split(line,a," "); pkg=a[1] }
    low=tolower(line)
    if (reason=="" && low ~ /unmaintained|end of life|no longer maintained/) { reason=line }
    if (low ~ /^ *cve:/) { gsub(/^ *cve: */,"",line); cves=(cves? cves ", " line : line) }
    if (low ~ /^ *www:/) { gsub(/^ *www: */,"",line); url=line }
    if (reason=="" && i>1 && line !~ /^ *cve:|^ *www:|^$/ && line !~ / is vulnerable:/) { reason=line }
  }
  if (pkg!="") { print pkg "||" reason "||" cves "||" url }
}' "$TMP_AUDIT" | while IFS='||' read -r PKG REASON CVES URL; do

  # Filter for unmaintained only if requested
  if [ "$UNMAINTAINED_ONLY" -eq 1 ]; then
    echo "$REASON" | awk 'BEGIN{IGNORECASE=1} /unmaintained|end of life|no longer maintained/ {f=1} END{exit(f?0:1)}' || continue
  fi

  NAME="$(pkg query '%n' "$PKG" 2>/dev/null || true)"
  INST_VER="$(pkg query '%v' "$PKG" 2>/dev/null || true)"
  ORIGIN="$(pkg query '%o' "$PKG" 2>/dev/null || true)"
  AUTO_FLAG="$(pkg query '%a' "$PKG" 2>/dev/null || echo '?')"
  [ "$AUTO_FLAG" = "1" ] && AUTO="automatic" || AUTO="manual"
  [ "$AUTO_FLAG" = "?" ] && AUTO="unknown"

  # Get latest repo version if available
  REPO_VER="$( [ -n "$NAME" ] && pkg rquery -e "%n = '$NAME'" '%v' 2>/dev/null || true )"

  # Determine version status
  ACTION="review"
  if [ -n "$INST_VER" ] && [ -n "$REPO_VER" ]; then
    COMP="$(pkg version -t "$INST_VER" "$REPO_VER" || true)"
    case "$COMP" in
      "<") ACTION="upgrade available" ;;
      "=") ACTION="no newer version in repo" ;;
      ">") ACTION="installed newer than repo" ;;
      *)   ACTION="version compare unknown" ;;
    esac
  else
    ACTION="version info unavailable"
  fi

  # Reverse dependency count
  REQS="$(pkg info -qr "$PKG" 2>/dev/null || true)"
  REQ_COUNT="$(printf '%s' "$REQS" | sed '/^$/d' | wc -l | tr -d ' ')"
  [ -z "$REQ_COUNT" ] && REQ_COUNT=0
  [ "$REQ_COUNT" -eq 0 ] && LEAF="yes" || LEAF="no"
  REQ_HEAD="$(printf '%s' "$REQS" | head -n "$TOP_REQS" | tr '\n' ' ')"
  [ -z "$REQ_HEAD" ] && REQ_HEAD="none"

  # Build friendly text
  if [ "$REQ_COUNT" -eq 0 ]; then
    USES="not used by other packages"
  elif [ "$REQ_COUNT" -eq 1 ]; then
    USES="used by 1 other package"
  else
    USES="shared by $REQ_COUNT packages"
  fi

  case "$ACTION" in
    "upgrade available")    ACTION_TXT="Update available" ;;
    "no newer version in repo") ACTION_TXT="No updates available" ;;
    "installed newer than repo") ACTION_TXT="Newer than repo" ;;
    *) ACTION_TXT="Check manually" ;;
  esac

  # Decide what to suggest
  if printf '%s' "$REASON" | grep -qi "unmaintained"; then
    if [ "$REQ_COUNT" -eq 0 ]; then
      SUGGEST="Safe to remove (sudo pkg delete $PKG && sudo pkg autoremove)"
    else
      SUGGEST="Keep if required; otherwise remove unused apps that depend on it."
    fi
  elif [ "$ACTION" = "upgrade available" ]; then
    SUGGEST="Run: sudo pkg upgrade $NAME"
  else
    SUGGEST="Monitor for updates or isolate in a jail if used with untrusted data."
  fi

  # -------------------------
  # Brief output mode
  # -------------------------
  if [ "$BRIEF" -eq 1 ]; then
    printf '%s%s%s | %s | %s install | %s\n' \
      "$C_BAD" "$PKG" "$C_CLR" "$ACTION_TXT" "$AUTO" "$USES"
    echo "   → Suggestion: $SUGGEST"
    continue
  fi

  # -------------------------
  # Detailed output mode
  # -------------------------
  printf '\n%s\n' "=================================================="
  printf '%sPackage%s   %s\n' "$C_BAD" "$C_CLR" "$PKG"
  [ -n "$NAME" ] && printf '%sName%s      %s\n' "$C_DIM" "$C_CLR" "$NAME"
  [ -n "$ORIGIN" ] && printf '%sOrigin%s    %s\n' "$C_DIM" "$C_CLR" "$ORIGIN"
  [ -n "$INST_VER" ] && printf '%sInstalled%s %s\n' "$C_DIM" "$C_CLR" "$INST_VER"
  [ -n "$REPO_VER" ] && printf '%sRepo%s       %s\n' "$C_DIM" "$C_CLR" "$REPO_VER"
  printf '%sStatus%s     %s install | %s\n' "$C_DIM" "$C_CLR" "$AUTO" "$USES"
  printf '%sReason%s     %s\n' "$C_WARN" "$C_CLR" "$(printf '%s' "$REASON" | sed 's/^[[:space:]]*//')"
  [ -n "$CVES" ] && printf 'CVEs        %s\n' "$CVES"
  [ -n "$URL" ] && printf 'Advisory    %s\n' "$URL"
  printf 'Action      %s\n' "$ACTION_TXT"
  printf 'Suggestion  %s\n' "$SUGGEST"
  printf 'Dependents  %s\n' "$REQ_HEAD"
done

echo
echo "Tip: run 'sudo pkg update && sudo pkg upgrade' then rerun this script."

