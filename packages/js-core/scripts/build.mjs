import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');
const srcDir = path.join(rootDir, 'src');
const distDir = path.join(rootDir, 'dist');

fs.mkdirSync(distDir, { recursive: true });

const moduleOrder = [
  'keccak.js',
  'x25519.js',
  'mlkem768.js',
  'xwing.js',
  'mldsa65.js',
  'envelope.js'
];

let combinedBody = `/**
 * ZubQuant v1.0.0 — Post-Quantum Cryptography SDK (ML-KEM-768, X-Wing, ML-DSA-65, AES-256-GCM)
 * Author: Md. Zubaer Ahammed (https://zubaer.com)
 * License: MIT
 */\n\n`;

for (const file of moduleOrder) {
  const raw = fs.readFileSync(path.join(srcDir, file), 'utf8');
  const modExports = [];
  const exportRegex = /^export\s+(?:async\s+function|function|class|const)\s+([A-Za-z0-9_]+)/gm;
  let match;
  while ((match = exportRegex.exec(raw)) !== null) {
    modExports.push(match[1]);
  }

  const stripped = raw
    .replace(/^import\s+[\s\S]*?from\s+['"][^'"]+['"];?\s*$/gm, '')
    .replace(/^export\s+(async\s+function|function|class|const)/gm, '$1');

  combinedBody += `// --- ${file} ---\nconst { ${modExports.join(', ')} } = (() => {\n${stripped.trim()}\n  return { ${modExports.join(', ')} };\n})();\n\n`;
}

const exportedSymbols = [
  'generateKeyPair',
  'seal',
  'open',
  'protectPrivateKey',
  'unlockPrivateKey',
  'generateSigningKeyPair',
  'sign',
  'verify',
  'toBase64Url',
  'fromBase64Url',
  'randomBytes',
  'xwingKeyGenFromSeed',
  'xwingEncapsDeterministic',
  'xwingDecaps',
  'mlkem768KeygenInternal',
  'mlkem768EncapsInternal',
  'mlkem768DecapsInternal',
  'mldsaKeyGen',
  'mldsaSign',
  'mldsaVerify',
  'sha3_256',
  'sha3_512',
  'shake128',
  'shake256',
  'x25519',
  'x25519Base'
];

// 1. ESM Bundle (dist/index.js)
const esmContent = `${combinedBody}export {\n  ${exportedSymbols.join(',\n  ')}\n};\n`;
fs.writeFileSync(path.join(distDir, 'index.js'), esmContent, 'utf8');

// 2. CommonJS Bundle (dist/index.cjs)
const cjsContent = `'use strict';\n${combinedBody}module.exports = {\n  ${exportedSymbols.join(',\n  ')}\n};\n`;
fs.writeFileSync(path.join(distDir, 'index.cjs'), cjsContent, 'utf8');

// 3. Browser Global IIFE Bundle (dist/zubquant.browser.js)
const browserContent = `(function (globalScope) {\n'use strict';\n${combinedBody}globalScope.ZubQuant = {\n  ${exportedSymbols.join(',\n  ')}\n};\n})(typeof window !== 'undefined' ? window : globalThis);\n`;
fs.writeFileSync(path.join(distDir, 'zubquant.browser.js'), browserContent, 'utf8');

// 4. Copy TypeScript declarations (dist/index.d.ts)
fs.copyFileSync(path.join(srcDir, 'index.d.ts'), path.join(distDir, 'index.d.ts'));

console.log('Built dist/index.js, dist/index.cjs, dist/zubquant.browser.js, and dist/index.d.ts');
