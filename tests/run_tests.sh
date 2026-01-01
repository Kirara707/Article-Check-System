#!/bin/bash
#
# run_tests.sh - 运行所有测试
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║         Paper Review FS - Test Suite                 ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# 编译测试
echo "[1/3] Compiling tests..."

gcc -Wall -Wextra -std=c11 -g -pthread \
    -I"$PROJECT_DIR/include" \
    "$SCRIPT_DIR/test_vfs.c" \
    "$PROJECT_DIR/src/vfs.c" \
    "$PROJECT_DIR/src/protocol.c" \
    "$PROJECT_DIR/src/cache.c" \
    -o "$SCRIPT_DIR/test_vfs"

echo "[2/3] Running VFS tests..."
"$SCRIPT_DIR/test_vfs"

echo "[3/3] Cleaning up..."
rm -f "$SCRIPT_DIR/test_vfs"
rm -f "$SCRIPT_DIR/test_disk.img"

echo ""
echo "All tests completed!"
echo ""
