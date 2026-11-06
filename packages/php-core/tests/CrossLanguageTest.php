<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/Keccak.php';
require_once __DIR__ . '/../src/MLKem768.php';
require_once __DIR__ . '/../src/XWing.php';
require_once __DIR__ . '/../src/MLDsa65.php';
require_once __DIR__ . '/../src/ZubQuant.php';

use Zubaer\ZubQuant\ZubQuant;

$vectorsPath = __DIR__ . '/../../../spec/test-vectors.json';
if (!file_exists($vectorsPath)) {
    fwrite(STDERR, "Missing spec/test-vectors.json\n");
    exit(1);
}

$vectors = json_decode((string) file_get_contents($vectorsPath), true);

function assertSameValue(mixed $actual, mixed $expected, string $message): void
{
    if ($actual !== $expected) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
    echo "✔ {$message}\n";
}

// 1. Verify KeyGen from deterministic seed matches JS publicKey & privateKey bit-for-bit
$kemSeed = hex2bin($vectors['kemSeedHex']);
$phpKp = ZubQuant::generateKeyPair($kemSeed);
assertSameValue($phpKp['publicKey'], $vectors['publicKey'], 'PHP X-Wing KeyGen matches JS PublicKey bit-for-bit');
assertSameValue($phpKp['privateKey'], $vectors['privateKey'], 'PHP X-Wing KeyGen matches JS PrivateKey bit-for-bit');

// 2. Verify PHP Seal with deterministic seeds matches JS ZPQ1 Envelope bit-for-bit
$ephemSeed = hex2bin($vectors['ephemeralSeedHex']);
$nonce = hex2bin($vectors['nonceHex']);
$phpEnvelope = ZubQuant::seal($vectors['plaintextJson'], $vectors['publicKey'], [
    'ephemeralSeed' => $ephemSeed,
    'nonce' => $nonce,
]);
assertSameValue($phpEnvelope, $vectors['envelope'], 'PHP seal() produces identical ZPQ1 envelope to JS seal()');

// 3. Verify PHP Open decrypts the JS-generated ZPQ1 Envelope
$opened = ZubQuant::open($vectors['envelope'], $vectors['privateKey']);
assertSameValue($opened, $vectors['plaintextJson'], 'PHP open() decrypts JS-sealed ZPQ1 envelope');

// 4. Verify PHP unlocks the JS-locked passphrase private key
$unlockedKey = ZubQuant::unlockPrivateKey($vectors['lockedKey'], $vectors['lockedKeyPassphrase']);
assertSameValue($unlockedKey, $vectors['privateKey'], 'PHP unlockPrivateKey() decrypts JS PBKDF2-AES256GCM locked key');

// 5. Verify PHP ML-DSA-65 KeyGen, Sign, and Verify match JS bit-for-bit
$sigSeed = hex2bin($vectors['sigSeedHex']);
$phpSigKp = ZubQuant::generateSigningKeyPair($sigSeed);
assertSameValue($phpSigKp['verifyKey'], $vectors['verifyKey'], 'PHP ML-DSA-65 KeyGen matches JS verifyKey bit-for-bit');
assertSameValue($phpSigKp['signingKey'], $vectors['signingKey'], 'PHP ML-DSA-65 KeyGen matches JS signingKey bit-for-bit');

$phpSignedToken = ZubQuant::sign($vectors['licensePayloadJson'], $vectors['signingKey']);
assertSameValue($phpSignedToken, $vectors['signedToken'], 'PHP ML-DSA-65 sign() matches JS signedToken bit-for-bit');

$verified = ZubQuant::verify($vectors['signedToken'], $vectors['verifyKey']);
assertSameValue($verified['valid'], true, 'PHP ML-DSA-65 verify() validates JS signedToken');
assertSameValue($verified['payload'], $vectors['licensePayloadJson'], 'PHP ML-DSA-65 verify() extracts exact payload');

echo "\nAll 9 PHP <-> JS cross-language Post-Quantum test vectors passed!\n";

