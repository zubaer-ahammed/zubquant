<?php

declare(strict_types=1);

namespace Zubaer\LaravelZubQuant\Console;

use Illuminate\Console\Command;
use Zubaer\ZubQuant\ZubQuant;

class KeyGenCommand extends Command
{
    protected $signature = 'zubquant:keygen {--passphrase= : Optional passphrase to lock the private key}';
    protected $description = 'Generate X-Wing (ML-KEM-768 + X25519) and ML-DSA-65 Post-Quantum keypairs for .env';

    public function handle(): int
    {
        $kem = ZubQuant::generateKeyPair();
        $dsa = ZubQuant::generateSigningKeyPair();

        $this->info('ZubQuant Post-Quantum Keypairs Generated Successfully!');
        $this->line('');
        $this->comment('# Add to your .env file (Keep PRIVATE_KEY & SIGNING_KEY offline for Zero-Knowledge mode):');
        $this->line('ZUBQUANT_PUBLIC_KEY=' . $kem['publicKey']);
        $this->line('ZUBQUANT_PRIVATE_KEY=' . $kem['privateKey']);
        $this->line('ZUBQUANT_VERIFY_KEY=' . $dsa['verifyKey']);
        $this->line('ZUBQUANT_SIGNING_KEY=' . $dsa['signingKey']);

        $passphrase = $this->option('passphrase');
        if (is_string($passphrase) && $passphrase !== '') {
            $locked = ZubQuant::protectPrivateKey($kem['privateKey'], $passphrase);
            $this->line('');
            $this->comment('# Passphrase-Locked Private Key Vault:');
            $this->line('ZUBQUANT_LOCKED_PRIVATE_KEY=' . $locked);
        }

        return self::SUCCESS;
    }
}

