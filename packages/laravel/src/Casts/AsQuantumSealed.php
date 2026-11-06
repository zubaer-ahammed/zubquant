<?php

declare(strict_types=1);

namespace Zubaer\LaravelZubQuant\Casts;

use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Database\Eloquent\Model;
use Zubaer\ZubQuant\ZubQuant;

/**
 * Eloquent Cast that seals attributes using the X-Wing Post-Quantum Public Key on write.
 *
 * Zero-Knowledge Mode:
 * - If ZUBQUANT_PRIVATE_KEY is present in config, reading the attribute automatically decrypts it.
 * - If ZUBQUANT_PRIVATE_KEY is omitted on the web server (Zero-Knowledge mode), reading the attribute
 *   returns the raw `zpq1.xwing-aes256gcm...` envelope so it can be sent to the Admin's browser and
 *   decrypted client-side via the `zubquant` NPM package!
 */
class AsQuantumSealed implements CastsAttributes
{
    public function __construct(
        private readonly bool $asJson = false
    ) {
    }

    public function get(Model $model, string $key, mixed $value, array $attributes): mixed
    {
        if ($value === null || $value === '') {
            return null;
        }

        $privateKey = function_exists('config') ? config('zubquant.private_key') : null;
        if (empty($privateKey) || !str_starts_with((string) $value, 'zpq1.xwing-aes256gcm.')) {
            return $value;
        }

        return ZubQuant::open((string) $value, (string) $privateKey, [
            'parseJson' => $this->asJson,
            'aad' => $model->getTable() . '.' . $key,
        ]);
    }

    public function set(Model $model, string $key, mixed $value, array $attributes): mixed
    {
        if ($value === null) {
            return null;
        }

        if (is_string($value) && str_starts_with($value, 'zpq1.xwing-aes256gcm.')) {
            return $value;
        }

        $publicKey = function_exists('config') ? config('zubquant.public_key') : null;
        return ZubQuant::seal($value, (string) $publicKey, [
            'aad' => $model->getTable() . '.' . $key,
        ]);
    }
}

