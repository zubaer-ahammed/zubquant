<?php

declare(strict_types=1);

namespace Zubaer\ZubQuant;

use InvalidArgumentException;
use RuntimeException;

/**
 * ZubQuant ZPQ1 Unified Wire Envelope API for PHP 8.1+
 * 100% wire-compatible with the `zubquant` NPM package.
 */
final class ZubQuant
{
    public const PUB_PREFIX = 'zpq1_pub_';
    public const SEC_PREFIX = 'zpq1_sec_';
    public const VFY_PREFIX = 'zpq1_vfy_';
    public const SIG_PREFIX = 'zpq1_sig_';
    private const HKDF_INFO = 'zubquant-zpq1-xwing-aes256gcm';
    private const DEFAULT_AAD = 'zpq1.xwing-aes256gcm';

    public static function toBase64Url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    public static function fromBase64Url(string $str): string
    {
        $pad = (4 - (strlen($str) % 4)) % 4;
        $decoded = base64_decode(strtr($str, '-_', '+/') . str_repeat('=', $pad), true);
        if ($decoded === false) {
            throw new InvalidArgumentException('Invalid base64url string');
        }
        return $decoded;
    }

    /**
     * Generates an X-Wing Hybrid Post-Quantum KeyPair (ML-KEM-768 + X25519).
     *
     * @return array{publicKey: string, privateKey: string}
     */
    public static function generateKeyPair(?string $seed32 = null): array
    {
        $seed = $seed32 ?? random_bytes(32);
        $kp = XWing::keyGenFromSeed($seed);
        return [
            'publicKey' => self::PUB_PREFIX . self::toBase64Url($kp['publicKey']),
            'privateKey' => self::SEC_PREFIX . self::toBase64Url($kp['privateKey']),
        ];
    }

    /**
     * Seals (encrypts) a string or array using the recipient's X-Wing Public Key.
     *
     * @param string|array<mixed> $data
     * @param array{aad?: string, ephemeralSeed?: string, nonce?: string} $options
     */
    public static function seal(string|array $data, string $publicKeyStr, array $options = []): string
    {
        if (!str_starts_with($publicKeyStr, self::PUB_PREFIX)) {
            throw new InvalidArgumentException('Invalid ZubQuant public key (expected prefix zpq1_pub_)');
        }

        $pkBytes = self::fromBase64Url(substr($publicKeyStr, strlen(self::PUB_PREFIX)));
        $ephemSeed = $options['ephemeralSeed'] ?? random_bytes(64);
        $nonce = $options['nonce'] ?? random_bytes(12);
        $aad = $options['aad'] ?? self::DEFAULT_AAD;

        $enc = XWing::encapsDeterministic($pkBytes, $ephemSeed);
        $kemCt = $enc['ciphertext'];
        $sharedSecret = $enc['sharedSecret'];

        $aesKey = hash_hkdf('sha256', $sharedSecret, 32, self::HKDF_INFO, $nonce);
        $plaintext = is_array($data) ? (string) json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) : $data;

        $tag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            'aes-256-gcm',
            $aesKey,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $aad,
            16
        );

        if ($ciphertext === false) {
            throw new RuntimeException('AES-256-GCM encryption failed');
        }

        return implode('.', [
            'zpq1',
            'xwing-aes256gcm',
            self::toBase64Url($kemCt),
            self::toBase64Url($nonce),
            self::toBase64Url($ciphertext . $tag),
        ]);
    }

    /**
     * Opens (decrypts) a ZPQ1 sealed envelope using the recipient's X-Wing Private Key.
     *
     * @param array{aad?: string, parseJson?: bool} $options
     * @return string|array<mixed>
     */
    public static function open(string $envelope, string $privateKeyStr, array $options = []): string|array
    {
        if (!str_starts_with($privateKeyStr, self::SEC_PREFIX)) {
            throw new InvalidArgumentException('Invalid ZubQuant private key (expected prefix zpq1_sec_)');
        }

        $parts = explode('.', $envelope);
        if (count($parts) !== 5 || $parts[0] !== 'zpq1' || $parts[1] !== 'xwing-aes256gcm') {
            throw new InvalidArgumentException('Unsupported or malformed ZPQ1 envelope header');
        }

        $skSeed = self::fromBase64Url(substr($privateKeyStr, strlen(self::SEC_PREFIX)));
        $kemCt = self::fromBase64Url($parts[2]);
        $nonce = self::fromBase64Url($parts[3]);
        $ctAndTag = self::fromBase64Url($parts[4]);

        if (strlen($ctAndTag) < 16) {
            throw new InvalidArgumentException('Ciphertext too short to contain GCM authentication tag');
        }

        $ciphertext = substr($ctAndTag, 0, -16);
        $tag = substr($ctAndTag, -16);
        $aad = $options['aad'] ?? self::DEFAULT_AAD;

        $sharedSecret = XWing::decaps($skSeed, $kemCt);
        $aesKey = hash_hkdf('sha256', $sharedSecret, 32, self::HKDF_INFO, $nonce);

        $decrypted = openssl_decrypt(
            $ciphertext,
            'aes-256-gcm',
            $aesKey,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $aad
        );

        if ($decrypted === false) {
            throw new RuntimeException('ZPQ1 envelope decryption failed (invalid key or tampered ciphertext)');
        }

        if (!empty($options['parseJson'])) {
            $decoded = json_decode($decrypted, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new RuntimeException('Failed to decode JSON payload: ' . json_last_error_msg());
            }
            return $decoded;
        }

        return $decrypted;
    }

    /**
     * Wraps a ZubQuant private key with a passphrase using PBKDF2-SHA256 + AES-256-GCM.
     */
    public static function protectPrivateKey(string $privateKeyStr, string $passphrase, int $iterations = 600000): string
    {
        if (!str_starts_with($privateKeyStr, self::SEC_PREFIX) && !str_starts_with($privateKeyStr, self::SIG_PREFIX)) {
            throw new InvalidArgumentException('Invalid ZubQuant secret key');
        }

        $salt = random_bytes(16);
        $nonce = random_bytes(12);
        $aesKey = hash_pbkdf2('sha256', $passphrase, $salt, $iterations, 32, true);

        $tag = '';
        $ct = openssl_encrypt(
            $privateKeyStr,
            'aes-256-gcm',
            $aesKey,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            '',
            16
        );

        if ($ct === false) {
            throw new RuntimeException('Failed to encrypt private key');
        }

        return implode('.', [
            'zpq1',
            'locked-key',
            (string) $iterations,
            self::toBase64Url($salt),
            self::toBase64Url($nonce),
            self::toBase64Url($ct . $tag),
        ]);
    }

    /**
     * Unlocks a passphrase-protected ZubQuant private key.
     */
    public static function unlockPrivateKey(string $lockedEnvelope, string $passphrase): string
    {
        $parts = explode('.', $lockedEnvelope);
        if (count($parts) !== 6 || $parts[0] !== 'zpq1' || $parts[1] !== 'locked-key') {
            throw new InvalidArgumentException('Invalid locked key format');
        }

        $iterations = (int) $parts[2];
        $salt = self::fromBase64Url($parts[3]);
        $nonce = self::fromBase64Url($parts[4]);
        $ctAndTag = self::fromBase64Url($parts[5]);

        $ct = substr($ctAndTag, 0, -16);
        $tag = substr($ctAndTag, -16);
        $aesKey = hash_pbkdf2('sha256', $passphrase, $salt, $iterations, 32, true);

        $plain = openssl_decrypt(
            $ct,
            'aes-256-gcm',
            $aesKey,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            ''
        );

        if ($plain === false) {
            throw new RuntimeException('Failed to unlock private key (incorrect passphrase or corrupted vault)');
        }

        return $plain;
    }

    /**
     * Generates an ML-DSA-65 (NIST FIPS 204) Post-Quantum Digital Signature KeyPair.
     *
     * @return array{verifyKey: string, signingKey: string}
     */
    public static function generateSigningKeyPair(?string $seed32 = null): array
    {
        $seed = $seed32 ?? random_bytes(32);
        $kp = MLDsa65::keyGen($seed);
        return [
            'verifyKey' => self::VFY_PREFIX . self::toBase64Url($kp['verifyKey']),
            'signingKey' => self::SIG_PREFIX . self::toBase64Url($kp['signingKey']),
        ];
    }

    /**
     * Signs a string or array using ML-DSA-65.
     *
     * @param string|array<mixed> $payload
     */
    public static function sign(string|array $payload, string $signingKeyStr): string
    {
        if (!str_starts_with($signingKeyStr, self::SIG_PREFIX)) {
            throw new InvalidArgumentException('Invalid ZubQuant signing key (expected prefix zpq1_sig_)');
        }

        $seed = self::fromBase64Url(substr($signingKeyStr, strlen(self::SIG_PREFIX)));
        $payloadBytes = is_array($payload)
            ? (string) json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
            : $payload;

        $sigBytes = MLDsa65::sign($seed, $payloadBytes);
        return implode('.', [
            'zpq1',
            'mldsa65',
            self::toBase64Url($payloadBytes),
            self::toBase64Url($sigBytes),
        ]);
    }

    /**
     * Verifies an ML-DSA-65 signed token using the public verification key.
     *
     * @param array{parseJson?: bool} $options
     * @return array{valid: bool, payload: mixed}
     */
    public static function verify(string $signedToken, string $verifyKeyStr, array $options = []): array
    {
        if (!str_starts_with($verifyKeyStr, self::VFY_PREFIX)) {
            throw new InvalidArgumentException('Invalid ZubQuant verify key (expected prefix zpq1_vfy_)');
        }

        $parts = explode('.', $signedToken);
        if (count($parts) !== 4 || $parts[0] !== 'zpq1' || $parts[1] !== 'mldsa65') {
            return ['valid' => false, 'payload' => null];
        }

        $verifyKeyBytes = self::fromBase64Url(substr($verifyKeyStr, strlen(self::VFY_PREFIX)));
        $payloadBytes = self::fromBase64Url($parts[2]);
        $sigBytes = self::fromBase64Url($parts[3]);

        $valid = MLDsa65::verify($verifyKeyBytes, $payloadBytes, $sigBytes);
        if (!$valid) {
            return ['valid' => false, 'payload' => null];
        }

        return [
            'valid' => true,
            'payload' => !empty($options['parseJson']) ? json_decode($payloadBytes, true) : $payloadBytes,
        ];
    }
}

