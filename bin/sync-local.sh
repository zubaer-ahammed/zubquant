#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WP_PLUGINS_DIR="/Users/zubaer/Code/ZubaerWebsites/wp.zubaer/wp-content/plugins"

# 1. Build JS Core Browser & Node bundles
/opt/homebrew/bin/node "${ROOT_DIR}/packages/js-core/scripts/build.mjs"

# 2. Sync PHP Core & Browser JS into WordPress Free plugin
cp "${ROOT_DIR}/packages/php-core/src/"*.php "${ROOT_DIR}/wordpress/zubquant/includes/Crypto/"
cp "${ROOT_DIR}/packages/js-core/dist/zubquant.browser.js" "${ROOT_DIR}/wordpress/zubquant/assets/js/zubquant.browser.js"

# 3. Sync Free & Pro plugins into wp.zubaer
rm -rf "${WP_PLUGINS_DIR}/zubquant" "${WP_PLUGINS_DIR}/zubquant-pro"
cp -R "${ROOT_DIR}/wordpress/zubquant" "${WP_PLUGINS_DIR}/zubquant"
cp -R "${ROOT_DIR}/wordpress/zubquant-pro" "${WP_PLUGINS_DIR}/zubquant-pro"

echo "Synced ZubQuant Free & Pro into ${WP_PLUGINS_DIR}"

