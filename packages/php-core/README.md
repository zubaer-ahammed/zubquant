# zubaer/zubquant (PHP Core SDK)

**Zero-dependency Post-Quantum Cryptography (PQC) SDK for PHP 8.1+.**

Implements **NIST FIPS 203 (`ML-KEM-768`)**, **IETF `X-Wing` Hybrid KEM (`ML-KEM-768` + `X25519`)**, **NIST FIPS 204 (`ML-DSA-65`)**, and **Authenticated Encryption (`AES-256-GCM`)**.

100% bit-for-bit wire-compatible (`ZPQ1` format) with the **[`zubquant` NPM package](https://www.npmjs.com/package/zubquant)**—encrypt in Browser/React/Vue and decrypt in PHP, or encrypt in PHP and decrypt in the Browser.

---

## Installation

```bash
composer require zubaer/zubquant
```

## Usage

```php
use Zubaer\ZubQuant\ZubQuant;

// 1. Generate Hybrid X-Wing KeyPair (ML-KEM-768 + X25519)
$keys = ZubQuant::generateKeyPair();
// $keys['publicKey']  => "zpq1_pub_..." (Safe to store in .env / database)
// $keys['privateKey'] => "zpq1_sec_..." (Keep offline or in admin browser vault)

// 2. Seal data using ONLY the Public Key
$envelope = ZubQuant::seal([
    'ssn' => '123-45-6789',
    'patient' => 'Md. Zubaer Ahammed',
], $keys['publicKey']);

// 3. Open data using the Private Key (works in PHP or in Browser via `zubquant` NPM!)
$data = ZubQuant::open($envelope, $keys['privateKey'], ['parseJson' => true]);

// 4. Post-Quantum Digital Signatures (ML-DSA-65 / NIST FIPS 204)
$sigKeys = ZubQuant::generateSigningKeyPair();
$token = ZubQuant::sign(['license' => 'pro', 'domain' => 'zubaer.com'], $sigKeys['signingKey']);
$verified = ZubQuant::verify($token, $sigKeys['verifyKey'], ['parseJson' => true]);
```

## License

MIT © [Md. Zubaer Ahammed](https://zubaer.com) — Get ZubQuant Pro at [buy.polar.sh](https://buy.polar.sh/polar_cl_brmuJexJSmUsWDysyGsTNjFpVhmAJAqRoSPvi0G4qie).

