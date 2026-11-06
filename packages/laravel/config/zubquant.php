<?php

return [
    /*
    |--------------------------------------------------------------------------
    | X-Wing Hybrid Post-Quantum Encapsulation Keys (ML-KEM-768 + X25519)
    |--------------------------------------------------------------------------
    |
    | For Zero-Knowledge security on production web servers, only set
    | ZUBQUANT_PUBLIC_KEY on the web server so compromised servers cannot
    | decrypt stored database records. Set ZUBQUANT_PRIVATE_KEY only on
    | isolated worker nodes or decrypt client-side using the `zubquant` NPM SDK.
    |
    */
    'public_key' => env('ZUBQUANT_PUBLIC_KEY'),
    'private_key' => env('ZUBQUANT_PRIVATE_KEY'),

    /*
    |--------------------------------------------------------------------------
    | ML-DSA-65 Post-Quantum Digital Signature Keys (NIST FIPS 204)
    |--------------------------------------------------------------------------
    |
    | Used for signing and verifying quantum-safe webhooks, audit logs,
    | and software license tokens.
    |
    */
    'verify_key' => env('ZUBQUANT_VERIFY_KEY'),
    'signing_key' => env('ZUBQUANT_SIGNING_KEY'),
];

