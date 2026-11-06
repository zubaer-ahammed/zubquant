<?php

declare(strict_types=1);

namespace Zubaer\LaravelZubQuant;

use RuntimeException;
use Zubaer\ZubQuant\ZubQuant;

class ZubQuantManager
{
    public function __construct(
        private readonly ?string $publicKey = null,
        private readonly ?string $privateKey = null,
        private readonly ?string $verifyKey = null,
        private readonly ?string $signingKey = null,
    ) {
    }

    /**
     * @param string|array<mixed> $data
     * @param array<string, mixed> $options
     */
    public function seal(string|array $data, ?string $publicKey = null, array $options = []): string
    {
        $key = $publicKey ?? $this->publicKey;
        if (empty($key)) {
            throw new RuntimeException('No ZUBQUANT_PUBLIC_KEY configured.');
        }
        return ZubQuant::seal($data, $key, $options);
    }

    /**
     * @param array<string, mixed> $options
     * @return string|array<mixed>
     */
    public function open(string $envelope, ?string $privateKey = null, array $options = []): string|array
    {
        $key = $privateKey ?? $this->privateKey;
        if (empty($key)) {
            throw new RuntimeException('No ZUBQUANT_PRIVATE_KEY configured on this instance.');
        }
        return ZubQuant::open($envelope, $key, $options);
    }

    /**
     * @param string|array<mixed> $payload
     */
    public function sign(string|array $payload, ?string $signingKey = null): string
    {
        $key = $signingKey ?? $this->signingKey;
        if (empty($key)) {
            throw new RuntimeException('No ZUBQUANT_SIGNING_KEY configured.');
        }
        return ZubQuant::sign($payload, $key);
    }

    /**
     * @param array<string, mixed> $options
     * @return array{valid: bool, payload: mixed}
     */
    public function verify(string $token, ?string $verifyKey = null, array $options = []): array
    {
        $key = $verifyKey ?? $this->verifyKey;
        if (empty($key)) {
            throw new RuntimeException('No ZUBQUANT_VERIFY_KEY configured.');
        }
        return ZubQuant::verify($token, $key, $options);
    }

    /**
     * @return array{publicKey: string, privateKey: string}
     */
    public function generateKeyPair(?string $seed32 = null): array
    {
        return ZubQuant::generateKeyPair($seed32);
    }

    /**
     * @return array{verifyKey: string, signingKey: string}
     */
    public function generateSigningKeyPair(?string $seed32 = null): array
    {
        return ZubQuant::generateSigningKeyPair($seed32);
    }
}

