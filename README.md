# ZubQuant — Post-Quantum Cryptography Suite (JS/TS, PHP/Laravel, WordPress)

**ZubQuant** is a cross-language, zero-dependency Post-Quantum Cryptography (PQC) suite built on **NIST FIPS 203 (`ML-KEM-768`)**, **IETF `X-Wing` Hybrid KEM (`ML-KEM-768` + `X25519`)**, **NIST FIPS 204 (`ML-DSA-65`)**, and **Authenticated Encryption (`AES-256-GCM`)**.

Payloads sealed or signed in **JavaScript/TypeScript (Browser & Node.js)** can be opened or verified natively in **PHP (Laravel & WordPress)**, and vice versa, using the unified **`ZPQ1` wire envelope format**.

---

## Monorepo Architecture

| Package / Directory | Platform | Description |
| :--- | :--- | :--- |
| [`packages/js-core`](./packages/js-core) | **NPM (`zubquant`)** | Zero-dependency TypeScript/JavaScript SDK for Browser, Node.js, Edge, React, & Vue. |
| [`packages/php-core`](./packages/php-core) | **Composer (`zubaer/zubquant`)** | Pure PHP 8.1+ SDK with native OpenSSL/Libsodium acceleration and 100% `ZPQ1` wire compatibility. |
| [`packages/laravel`](./packages/laravel) | **Composer (`zubaer/laravel-zubquant`)** | Laravel ServiceProvider, `ZubQuant` Facade, `AsQuantumSealed` Eloquent Cast, & Quantum Webhook Middleware. |
| [`packages/pro-ui-vault`](./packages/pro-ui-vault) | **Polar.sh Pro Add-on** | WebAuthn Passkey (TouchID/FaceID) Private Key Vault, Multi-Recipient Splitting (M-of-N / Admin+Recovery), & Key Rotation CLI. |
| [`wordpress/zubquant`](./wordpress/zubquant) | **WordPress.org (Free)** | Zero-Knowledge Quantum Vault for WordPress forms, comments, browser-side admin decryption, & quantum-signed audit logs. |
| [`wordpress/zubquant-pro`](./wordpress/zubquant-pro) | **Freemius (Pro)** | Automatic Post-Quantum encryption for Elementor Forms, Ninja Forms, Contact Form 7, WooCommerce PII, Passkey Unlock, & Encrypted Backups. |
| [`spec/test-vectors.json`](./spec/test-vectors.json) | **Spec & Vectors** | Deterministic cross-language test vectors verifying bit-for-bit interoperability between JS and PHP. |

---

## The `ZPQ1` Unified Wire Envelope

### 1. Hybrid Post-Quantum Sealed Payload (`seal` / `open`)
Combines **IETF X-Wing** (`ML-KEM-768` lattice KEM + `X25519` elliptic curve DH) with **`HKDF-SHA256`** and **`AES-256-GCM`** authenticated encryption:

```text
zpq1.xwing-aes256gcm.<base64url(kem_ciphertext_1120B)>.<base64url(nonce_12B)>.<base64url(ciphertext_and_tag)>
```

### 2. Multi-Recipient Sealed Envelope (`sealMulti` / `openMulti` — Pro)
Encrypts the payload once with a random Content Encryption Key (CEK) and encapsulates the CEK independently for multiple recipients (e.g., Primary Admin + Offline Recovery Key + Compliance Officer).

### 3. Post-Quantum Digital Signatures & License Tokens (`sign` / `verify`)
Uses lattice-based **ML-DSA-65 (NIST FIPS 204)** digital signatures:

```text
zpq1.mldsa65.<base64url(payload)>.<base64url(signature)>
```

---

## Author & Commercial Licensing

Created by **Md. Zubaer Ahammed** ([zubaer.com](https://zubaer.com)).
- **Open-Source Core (`js-core`, `php-core`, `laravel`):** MIT License.
- **Pro Developer Add-ons (`pro-ui-vault` & `zubquant-pro`):** Available via [Polar.sh (`ZubQuant Pro`)](https://buy.polar.sh/polar_cl_brmuJexJSmUsWDysyGsTNjFpVhmAJAqRoSPvi0G4qie).
- **WordPress Pro Plugin (`zubquant-pro`):** Available via Freemius.

