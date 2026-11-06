<?php

declare(strict_types=1);

namespace Zubaer\ZubQuant;

/**
 * FIPS 202 Keccak-f[1600] sponge for SHA3-256, SHA3-512, SHAKE128, and SHAKE256.
 * Bit-for-bit identical to packages/js-core/src/keccak.js.
 */
final class Keccak
{
    private const ROTC = [
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
    ];

    private const PILN = [
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
    ];

    private const RC_HI = [
        0x00000000, 0x00000000, 0x80000000, 0x80000000, 0x00000000, 0x00000000,
        0x80000000, 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
        0x00000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000,
        0x00000000, 0x80000000, 0x80000000, 0x80000000, 0x00000000, 0x80000000
    ];

    private const RC_LO = [
        0x00000001, 0x00008082, 0x0000808a, 0x80008000, 0x0000808b, 0x80000001,
        0x80008081, 0x00008009, 0x0000008a, 0x00000088, 0x80008009, 0x8000000a,
        0x8000808b, 0x0000008b, 0x00008089, 0x00008003, 0x00008002, 0x00000080,
        0x0000800a, 0x8000000a, 0x80008081, 0x00008080, 0x80000001, 0x80008008
    ];

    private int $rateBytes;
    private int $suffix;
    /** @var int[] */
    private array $stateBytes;
    /** @var int[] */
    private array $sLo;
    /** @var int[] */
    private array $sHi;
    private int $pos = 0;
    private bool $squeezing = false;

    public function __construct(int $rateBytes, int $suffix)
    {
        $this->rateBytes = $rateBytes;
        $this->suffix = $suffix;
        $this->stateBytes = array_fill(0, 200, 0);
        $this->sLo = array_fill(0, 25, 0);
        $this->sHi = array_fill(0, 25, 0);
    }

    private function permute(): void
    {
        for ($i = 0; $i < 25; $i++) {
            $o = $i * 8;
            $this->sLo[$i] = ($this->stateBytes[$o]
                | ($this->stateBytes[$o + 1] << 8)
                | ($this->stateBytes[$o + 2] << 16)
                | ($this->stateBytes[$o + 3] << 24)) & 0xffffffff;
            $this->sHi[$i] = ($this->stateBytes[$o + 4]
                | ($this->stateBytes[$o + 5] << 8)
                | ($this->stateBytes[$o + 6] << 16)
                | ($this->stateBytes[$o + 7] << 24)) & 0xffffffff;
        }

        $bLo = [0, 0, 0, 0, 0];
        $bHi = [0, 0, 0, 0, 0];

        for ($round = 0; $round < 24; $round++) {
            for ($x = 0; $x < 5; $x++) {
                $bLo[$x] = $this->sLo[$x] ^ $this->sLo[$x + 5] ^ $this->sLo[$x + 10] ^ $this->sLo[$x + 15] ^ $this->sLo[$x + 20];
                $bHi[$x] = $this->sHi[$x] ^ $this->sHi[$x + 5] ^ $this->sHi[$x + 10] ^ $this->sHi[$x + 15] ^ $this->sHi[$x + 20];
            }

            for ($x = 0; $x < 5; $x++) {
                $x4 = ($x + 4) % 5;
                $x1 = ($x + 1) % 5;
                $c1Lo = $bLo[$x1];
                $c1Hi = $bHi[$x1];
                $rotLo = (($c1Lo << 1) | ($c1Hi >> 31)) & 0xffffffff;
                $rotHi = (($c1Hi << 1) | ($c1Lo >> 31)) & 0xffffffff;
                $tLo = $bLo[$x4] ^ $rotLo;
                $tHi = $bHi[$x4] ^ $rotHi;
                for ($y = 0; $y < 25; $y += 5) {
                    $this->sLo[$x + $y] ^= $tLo;
                    $this->sHi[$x + $y] ^= $tHi;
                }
            }

            $tLo = $this->sLo[1];
            $tHi = $this->sHi[1];
            for ($i = 0; $i < 24; $i++) {
                $j = self::PILN[$i];
                $r = self::ROTC[$i];
                $nLo = $this->sLo[$j];
                $nHi = $this->sHi[$j];
                if ($r < 32) {
                    $this->sLo[$j] = (($tLo << $r) | ($tHi >> (32 - $r))) & 0xffffffff;
                    $this->sHi[$j] = (($tHi << $r) | ($tLo >> (32 - $r))) & 0xffffffff;
                } else {
                    $s = $r - 32;
                    $this->sLo[$j] = (($tHi << $s) | ($tLo >> (32 - $s))) & 0xffffffff;
                    $this->sHi[$j] = (($tLo << $s) | ($tHi >> (32 - $s))) & 0xffffffff;
                }
                $tLo = $nLo;
                $tHi = $nHi;
            }

            for ($y = 0; $y < 25; $y += 5) {
                for ($x = 0; $x < 5; $x++) {
                    $bLo[$x] = $this->sLo[$y + $x];
                    $bHi[$x] = $this->sHi[$y + $x];
                }
                for ($x = 0; $x < 5; $x++) {
                    $this->sLo[$y + $x] = ($bLo[$x] ^ ((~$bLo[($x + 1) % 5]) & $bLo[($x + 2) % 5])) & 0xffffffff;
                    $this->sHi[$y + $x] = ($bHi[$x] ^ ((~$bHi[($x + 1) % 5]) & $bHi[($x + 2) % 5])) & 0xffffffff;
                }
            }

            $this->sLo[0] ^= self::RC_LO[$round];
            $this->sHi[0] ^= self::RC_HI[$round];
        }

        for ($i = 0; $i < 25; $i++) {
            $o = $i * 8;
            $lo = $this->sLo[$i];
            $hi = $this->sHi[$i];
            $this->stateBytes[$o] = $lo & 0xff;
            $this->stateBytes[$o + 1] = ($lo >> 8) & 0xff;
            $this->stateBytes[$o + 2] = ($lo >> 16) & 0xff;
            $this->stateBytes[$o + 3] = ($lo >> 24) & 0xff;
            $this->stateBytes[$o + 4] = $hi & 0xff;
            $this->stateBytes[$o + 5] = ($hi >> 8) & 0xff;
            $this->stateBytes[$o + 6] = ($hi >> 16) & 0xff;
            $this->stateBytes[$o + 7] = ($hi >> 24) & 0xff;
        }
    }

    public function absorb(string $data): self
    {
        $len = strlen($data);
        for ($i = 0; $i < $len; $i++) {
            $this->stateBytes[$this->pos++] ^= ord($data[$i]);
            if ($this->pos === $this->rateBytes) {
                $this->permute();
                $this->pos = 0;
            }
        }
        return $this;
    }

    public function finalize(): self
    {
        if (!$this->squeezing) {
            $this->stateBytes[$this->pos] ^= $this->suffix;
            $this->stateBytes[$this->rateBytes - 1] ^= 0x80;
            $this->permute();
            $this->pos = 0;
            $this->squeezing = true;
        }
        return $this;
    }

    public function squeeze(int $outLen): string
    {
        if (!$this->squeezing) {
            $this->finalize();
        }
        $out = '';
        $remaining = $outLen;
        while ($remaining > 0) {
            if ($this->pos === $this->rateBytes) {
                $this->permute();
                $this->pos = 0;
            }
            $take = min($this->rateBytes - $this->pos, $remaining);
            for ($i = 0; $i < $take; $i++) {
                $out .= chr($this->stateBytes[$this->pos + $i]);
            }
            $this->pos += $take;
            $remaining -= $take;
        }
        return $out;
    }

    public static function sha3_256(string $data): string
    {
        return hash('sha3-256', $data, true);
    }

    public static function sha3_512(string $data): string
    {
        return hash('sha3-512', $data, true);
    }

    public static function shake128(string $data, int $outLen): string
    {
        return (new self(168, 0x1f))->absorb($data)->squeeze($outLen);
    }

    public static function shake256(string $data, int $outLen): string
    {
        return (new self(136, 0x1f))->absorb($data)->squeeze($outLen);
    }
}

