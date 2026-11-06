#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"

mkdir -p "$DIST_DIR"
rm -rf "$DIST_DIR/zubquant" "$DIST_DIR/zubquant-pro" "$DIST_DIR/zubquant-1.0.0.zip" "$DIST_DIR/zubquant-pro-1.0.0.zip"

cp -R "$ROOT_DIR/wordpress/zubquant" "$DIST_DIR/zubquant"
cp -R "$ROOT_DIR/wordpress/zubquant-pro" "$DIST_DIR/zubquant-pro"
cp -R "$ROOT_DIR/packages/pro-ui-vault" "$DIST_DIR/zubquant-pro/pro-ui-vault-sdk"

find "$DIST_DIR" -name ".DS_Store" -delete

cd "$DIST_DIR"
zip -rq "zubquant-1.0.0.zip" "zubquant"
zip -rq "zubquant-pro-1.0.0.zip" "zubquant-pro"
rm -rf "$DIST_DIR/zubquant" "$DIST_DIR/zubquant-pro"

echo "Built release archives:"
ls -lh "$DIST_DIR/zubquant-1.0.0.zip" "$DIST_DIR/zubquant-pro-1.0.0.zip"
