<?php

declare(strict_types=1);

namespace Zubaer\ZubQuant;

use InvalidArgumentException;

/**
 * IETF X-Wing Hybrid Post-Quantum KEM (ML-KEM-768 + X25519 + SHA3-256 Combiner)
 * Bit-for-bit identical to packages/js-core/src/xwing.js.
 */
final class XWing
{
    private const XWING_LABEL = "\x5c\x2e\x2f\x5e\x5c\x5c";

    /**
     * @return array{skM: string, skX: string, pkX: string, pk: string}
     */
    public static function expandDecapsulationKey(string $skSeed32): array
    {
        if (strlen($skSeed32) !== 32) {
            throw new InvalidArgumentException('X-Wing secret seed must be 32 bytes');
        }
        $expanded = Keccak::shake256($skSeed32, 96);
        $d = substr($expanded, 0, 32);
        $z = substr($expanded, 32, 32);
        $skX = substr($expanded, 64, 32);

        $mlkem = MLKem768::keygenInternal($d, $z);
        $pkM = $mlkem['ek'];
        $skM = $mlkem['dk'];
        $pkX = sodium_crypto_scalarmult_base($skX);

        return [
            'skM' => $skM,
            'skX' => $skX,
            'pkX' => $pkX,
            'pk' => $pkM . $pkX
        ];
    }

    /**
     * @return array{publicKey: string, privateKey: string}
     */
    public static function keyGenFromSeed(string $skSeed32): array
    {
        $expanded = self::expandDecapsulationKey($skSeed32);
        return [
            'publicKey' => $expanded['pk'],
            'privateKey' => $skSeed32
        ];
    }

    private static function combineSharedSecrets(string $ssM, string $ssX, string $ctX, string $pkX): string
    {
        return Keccak::sha3_256($ssM . $ssX . $ctX . $pkX . self::XWING_LABEL);
    }

    /**
     * @return array{ciphertext: string, sharedSecret: string}
     */
    public static function encapsDeterministic(string $pk1216, string $ephemSeed64): array
    {
        if (strlen($pk1216) !== 1216) {
            throw new InvalidArgumentException('X-Wing public key must be 1216 bytes');
        }
        if (strlen($ephemSeed64) !== 64) {
            throw new InvalidArgumentException('X-Wing encapsulation seed must be 64 bytes');
        }

        $pkM = substr($pk1216, 0, 1184);
        $pkX = substr($pk1216, 1184, 32);

        $m = substr($ephemSeed64, 0, 32);
        $ekX = substr($ephemSeed64, 32, 32);

        $ctX = sodium_crypto_scalarmult_base($ekX);
        $ssX = sodium_crypto_scalarmult($ekX, $pkX);
        $encM = MLKem768::encapsInternal($pkM, $m);

        $sharedSecret = self::combineSharedSecrets($encM['sharedSecret'], $ssX, $ctX, $pkX);
        return [
            'ciphertext' => $encM['ciphertext'] . $ctX,
            'sharedSecret' => $sharedSecret
        ];
    }

    public static function decaps(string $skSeed32, string $ct1120): string
    {
        if (strlen($ct1120) !== 1120) {
            throw new InvalidArgumentException('X-Wing ciphertext must be 1120 bytes');
        }
        $expanded = self::expandDecapsulationKey($skSeed32);
        $ctM = substr($ct1120, 0, 1088);
        $ctX = substr($ct1120, 1088, 32);

        $ssM = MLKem768::decapsInternal($expanded['skM'], $ctM);
        $ssX = sodium_crypto_scalarmult($expanded['skX'], $ctX);

        return self::combineSharedSecrets($ssM, $ssX, $ctX, $expanded['pkX']);
    }
}

