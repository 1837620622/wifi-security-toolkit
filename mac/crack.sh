#!/bin/bash
# ============================================================================
# macOS / Apple Silicon 专用入口
# 自动使用仓库 shared/dicts 与 shared/captures
# ============================================================================
# 用法:
#   bash mac/crack.sh
#   bash mac/crack.sh --hash ../shared/captures/x.hc22000
#   bash mac/crack.sh --dict-dir /Volumes/xxx/dicts --cap ./a.cap
# ============================================================================
set -e
MAC_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${MAC_DIR}/.." && pwd)"
ENGINE="${REPO_ROOT}/wifi-crack-notebook/crack_local.sh"

if [ ! -f "$ENGINE" ]; then
    echo "[!] 找不到引擎: $ENGINE"
    exit 1
fi

export WIFI_WORK_DIR="${WIFI_WORK_DIR:-${MAC_DIR}/work}"
mkdir -p "${WIFI_WORK_DIR}"

echo "┌─────────────────────────────────────────┐"
echo "│  WiFi Security Toolkit · macOS Metal    │"
echo "│  字典: shared/dicts                     │"
echo "└─────────────────────────────────────────┘"
echo ""

exec bash "$ENGINE" \
    --work-dir "${WIFI_WORK_DIR}" \
    --dict-dir "${REPO_ROOT}/shared/dicts" \
    "$@"
