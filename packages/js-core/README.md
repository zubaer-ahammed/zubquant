# zubquant

**Zero-dependency Post-Quantum Cryptography (PQC) SDK for JavaScript & TypeScript (Browser, Node.js, Edge, React, Vue).**

Built on **NIST FIPS 203 (`ML-KEM-768`)**, **IETF `X-Wing` Hybrid KEM (`ML-KEM-768` + `X25519`)**, **NIST FIPS 204 (`ML-DSA-65`)**, and **Authenticated Encryption (`AES-256-GCM`)**.

100% wire-compatible (`ZPQ1` envelope format) with **`zubaer/zubquant` (PHP / Laravel)** and the **ZubQuant WordPress Plugin**.

[![Get ZubQuant Pro on Patreon](https://img.shields.io/badge/Patreon_Shop-ZubQuant_Pro-F96854)](https://www.patreon.com/Zubaer/posts/zubquant-pro-e-0-174534260)

---

## Installation

```bash
npm install zubquant
```

## Quick Start

### 1. Hybrid Post-Quantum Encryption (`seal` & `open`)

Combines **ML-KEM-768** (lattice post-quantum KEM) + **X25519** (classical elliptic-curve DH) + **HKDF-SHA256** + **AES-256-GCM**.

```ts
import { generateKeyPair, seal, open } from 'zubquant';

// 1. Generate Hybrid X-Wing KeyPair
const { publicKey, privateKey } = generateKeyPair();
// publicKey  -> "zpq1_pub_..." (Safe to store on public servers / wp_options / frontend)
// privateKey -> "zpq1_sec_..." (Keep offline or locked in user's browser vault)

// 2. Seal any String, JSON Object, or Uint8Array using ONLY the Public Key
const envelope = await seal(
  { ssn: '123-45-6789', patient: 'Jane Doe' },
  publicKey
);
// -> "zpq1.xwing-aes256gcm.<kem_ct>.<nonce>.<ciphertext_and_tag>"

// 3. Open the envelope using the Private Key (in Browser, Node.js, or PHP/Laravel!)
const data = await open(envelope, privateKey, { parseJson: true });
console.log(data.ssn); // "123-45-6789"
```

### 2. Passphrase-Protected Private Key Vault (`protectPrivateKey` & `unlockPrivateKey`)

Safely encrypt a `zpq1_sec_...` key using **PBKDF2-SHA256 (600,000 iterations) + AES-256-GCM** so it can be stored in `localStorage`, IndexedDB, or a `.json` backup file:

```ts
import { protectPrivateKey, unlockPrivateKey } from 'zubquant';

const lockedKey = await protectPrivateKey(privateKey, 'MyStrongVaultPassphrase!');
// Store `lockedKey` in localStorage or database

const unlockedPrivateKey = await unlockPrivateKey(lockedKey, 'MyStrongVaultPassphrase!');
```

### 3. Post-Quantum Digital Signatures & License Tokens (`sign` & `verify`)

Uses **ML-DSA-65 (NIST FIPS 204)** lattice signatures for tamper-proof webhooks, audit logs, and offline software license verification:

```ts
import { generateSigningKeyPair, sign, verify } from 'zubquant';

const { verifyKey, signingKey } = generateSigningKeyPair();

const token = sign(
  { license: 'pro', domain: 'zubaer.com', expires: '2028-12-31' },
  signingKey
);
// -> "zpq1.mldsa65.<payload>.<signature>"

const result = verify(token, verifyKey, { parseJson: true });
if (result.valid) {
  console.log('Verified payload:', result.payload);
}
```

---

## Pro Add-on (`@zubaer/zubquant-pro`)

Need **WebAuthn Passkey (TouchID / FaceID / YubiKey) Private Key Unlock**, **Multi-Recipient Key Splitting (Admin + Compliance + Recovery Key)**, or **Automated Zero-Downtime Key Rotation**?

Get the Pro add-on at **[Patreon Shop (ZubQuant Pro)](https://www.patreon.com/Zubaer/posts/zubquant-pro-e-0-174534260)**.

## License

MIT © [Md. Zubaer Ahammed](https://zubaer.com)

