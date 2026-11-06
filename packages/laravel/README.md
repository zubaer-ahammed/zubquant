# zubaer/laravel-zubquant

**Post-Quantum Cryptography (NIST FIPS 203 `ML-KEM-768` + `X25519` Hybrid `X-Wing` & FIPS 204 `ML-DSA-65`) for Laravel.**

100% wire-compatible with the [`zubquant` NPM package](https://www.npmjs.com/package/zubquant) for client-side React/Vue/Livewire decryption!

---

## Installation

```bash
composer require zubaer/laravel-zubquant
php artisan zubquant:keygen
```

## Features

### 1. Zero-Knowledge Eloquent Attribute Encryption (`AsQuantumSealed`)
Unlike Laravel's standard `encrypted` cast (where an attacker who steals your database AND `.env` `APP_KEY` can decrypt every customer record), `AsQuantumSealed` only needs `ZUBQUANT_PUBLIC_KEY` on your web server!

```php
use Illuminate\Database\Eloquent\Model;
use Zubaer\LaravelZubQuant\Casts\AsQuantumSealed;

class PatientRecord extends Model
{
    protected function casts(): array
    {
        return [
            'ssn' => AsQuantumSealed::class,
            'medical_notes' => AsQuantumSealed::class . ':true', // JSON mode
        ];
    }
}
```
* **On Write:** Automatically seals the column with `X-Wing` (`ML-KEM-768` + `X25519`) + `AES-256-GCM` bound to `table.column` as Additional Authenticated Data (AAD) to prevent column-swapping attacks!
* **On Read (Zero-Knowledge Mode):** If `ZUBQUANT_PRIVATE_KEY` is omitted from the web server `.env`, reading `$record->ssn` returns the `zpq1.xwing-aes256gcm...` envelope so your admin React/Vue dashboard can decrypt it in the browser using `import { open } from 'zubquant'`.

### 2. Facade Usage (`ZubQuant`)
```php
use Zubaer\LaravelZubQuant\Facades\ZubQuant;

$envelope = ZubQuant::seal(['secret' => 'value']);
$decrypted = ZubQuant::open($envelope, parseJson: true);

$signedToken = ZubQuant::sign(['webhook_event' => 'order.paid']);
$verified = ZubQuant::verify($signedToken);
```

## License

MIT © [Md. Zubaer Ahammed](https://zubaer.com) — Pro UI Vault & Key Rotation tools available at [Patreon Shop (ZubQuant Pro)](https://www.patreon.com/Zubaer/posts/zubquant-pro-e-0-174534260).

