<?php

declare(strict_types=1);

namespace Zubaer\LaravelZubQuant\Facades;

use Illuminate\Support\Facades\Facade;
use Zubaer\LaravelZubQuant\ZubQuantManager;

/**
 * @method static string seal(string|array $data, ?string $publicKey = null, array $options = [])
 * @method static string|array open(string $envelope, ?string $privateKey = null, array $options = [])
 * @method static string sign(string|array $payload, ?string $signingKey = null)
 * @method static array verify(string $token, ?string $verifyKey = null, array $options = [])
 * @method static array generateKeyPair(?string $seed32 = null)
 * @method static array generateSigningKeyPair(?string $seed32 = null)
 *
 * @see \Zubaer\LaravelZubQuant\ZubQuantManager
 */
class ZubQuant extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return ZubQuantManager::class;
    }
}

