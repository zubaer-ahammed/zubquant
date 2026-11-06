#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ -x "/opt/homebrew/bin/node" ]; then
  NODE_BIN="/opt/homebrew/bin/node"
else
  NODE_BIN="$(command -v node)"
fi

if [ -x "/opt/homebrew/bin/php" ]; then
  PHP_BIN="/opt/homebrew/bin/php"
else
  PHP_BIN="$(command -v php)"
fi

echo "=== 1. Building & Testing JS Core SDK (packages/js-core) ==="
cd "$ROOT_DIR/packages/js-core"
"$NODE_BIN" scripts/build.mjs
"$NODE_BIN" --test test/zubquant.test.mjs

echo ""
echo "=== 2. Running PHP Cross-Language Cryptographic Tests (packages/php-core) ==="
cd "$ROOT_DIR/packages/php-core"
"$PHP_BIN" tests/CrossLanguageTest.php

echo ""
echo "=== 3. Preparing Standalone Git Subtree Branches for Packagist ==="
cd "$ROOT_DIR"
git branch -D dist-php-core 2>/dev/null || true
git branch -D dist-laravel 2>/dev/null || true
git subtree split --prefix=packages/php-core -b dist-php-core
git subtree split --prefix=packages/laravel -b dist-laravel
git tag -f v1.0.0 HEAD

echo ""
echo "✅ All SDK builds, cross-language tests, and subtree splits succeeded!"
echo ""
echo "Next steps to publish:"
echo "  1. NPM (zubquant):          cd packages/js-core && npm publish --access public"
echo "  2. GitHub PHP Core repo:    git push <php-core-remote-url> dist-php-core:main --tags"
echo "  3. GitHub Laravel repo:     git push <laravel-remote-url> dist-laravel:main --tags"
