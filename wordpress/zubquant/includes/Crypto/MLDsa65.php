<?php

declare(strict_types=1);

namespace Zubaer\ZubQuant;

use InvalidArgumentException;
use RuntimeException;

/**
 * NIST FIPS 204 ML-DSA-65 Module-Lattice Digital Signature Standard
 * Bit-for-bit identical to packages/js-core/src/mldsa65.js.
 */
final class MLDsa65
{
    private const Q = 8380417;
    private const N = 256;
    private const K = 4;
    private const L = 4;
    private const ETA = 2;
    private const TAU = 39;
    private const BETA = 78;
    private const GAMMA1 = 131072;

    private static function modQ(int $x): int
    {
        $r = $x % self::Q;
        return $r < 0 ? $r + self::Q : $r;
    }

    private static function centerModQ(int $x): int
    {
        $r = self::modQ($x);
        return $r > (self::Q >> 1) ? $r - self::Q : $r;
    }

    /**
     * @param int[] $a
     * @param int[] $b
     * @return int[]
     */
    private static function polyMulModQ(array $a, array $b): array
    {
        $res = array_fill(0, self::N, 0);
        for ($i = 0; $i < self::N; $i++) {
            $ai = $a[$i];
            if ($ai === 0) {
                continue;
            }
            for ($j = 0; $j < self::N; $j++) {
                $prod = ($ai * $b[$j]) % self::Q;
                if ($i + $j < self::N) {
                    $res[$i + $j] = self::modQ($res[$i + $j] + $prod);
                } else {
                    $res[$i + $j - self::N] = self::modQ($res[$i + $j - self::N] - $prod);
                }
            }
        }
        return $res;
    }

    /**
     * @param int[] $a
     * @param int[] $b
     * @return int[]
     */
    private static function polyAddModQ(array $a, array $b): array
    {
        $r = array_fill(0, self::N, 0);
        for ($i = 0; $i < self::N; $i++) {
            $r[$i] = self::modQ($a[$i] + $b[$i]);
        }
        return $r;
    }

    /**
     * @param int[] $a
     * @param int[] $b
     * @return int[]
     */
    private static function polySubModQ(array $a, array $b): array
    {
        $r = array_fill(0, self::N, 0);
        for ($i = 0; $i < self::N; $i++) {
            $r[$i] = self::modQ($a[$i] - $b[$i]);
        }
        return $r;
    }

    /**
     * @return array<int, array<int, int[]>>
     */
    private static function expandMatrixA(string $rho32): array
    {
        $A = [];
        for ($i = 0; $i < self::K; $i++) {
            $A[$i] = [];
            for ($j = 0; $j < self::L; $j++) {
                $stream = Keccak::shake128($rho32 . chr($j) . chr($i), 840);
                $poly = array_fill(0, self::N, 0);
                $idx = 0;
                $pos = 0;
                $len = strlen($stream);
                while ($idx < self::N && $pos + 2 < $len) {
                    $val = ord($stream[$pos])
                        | (ord($stream[$pos + 1]) << 8)
                        | ((ord($stream[$pos + 2]) & 0x7f) << 16);
                    $pos += 3;
                    if ($val < self::Q) {
                        $poly[$idx++] = $val;
                    }
                }
                $A[$i][$j] = $poly;
            }
        }
        return $A;
    }

    /**
     * @return int[]
     */
    private static function sampleShortPoly(string $seed64, int $nonce): array
    {
        $input = $seed64 . chr($nonce & 0xff) . chr(($nonce >> 8) & 0xff);
        $stream = Keccak::shake256($input, 256);
        $poly = array_fill(0, self::N, 0);
        $idx = 0;
        for ($i = 0; $i < 256 && $idx < self::N; $i++) {
            $byte = ord($stream[$i]);
            $t0 = $byte & 0x0f;
            $t1 = $byte >> 4;
            if ($t0 < 15) {
                $poly[$idx++] = self::modQ(self::ETA - ($t0 % 5));
            }
            if ($t1 < 15 && $idx < self::N) {
                $poly[$idx++] = self::modQ(self::ETA - ($t1 % 5));
            }
        }
        return $poly;
    }

    /**
     * @return int[]
     */
    private static function sampleMaskPoly(string $seed64, int $nonce): array
    {
        $input = $seed64 . chr($nonce & 0xff) . chr(($nonce >> 8) & 0xff);
        $stream = Keccak::shake256($input, 576);
        $poly = array_fill(0, self::N, 0);
        for ($i = 0; $i < self::N; $i++) {
            $o = $i * 2;
            $raw = ord($stream[$o])
                | (ord($stream[$o + 1]) << 8)
                | (((ord($stream[512 + ($i >> 2)]) >> (($i & 3) * 2)) & 0x03) << 16);
            $poly[$i] = self::modQ(self::GAMMA1 - ($raw % (2 * self::GAMMA1 - 1)));
        }
        return $poly;
    }

    /**
     * @return int[]
     */
    private static function sampleInBall(string $cTilde32): array
    {
        $stream = Keccak::shake256($cTilde32, 272);
        $c = array_fill(0, self::N, 0);
        $signs = 0;
        for ($i = 0; $i < 8; $i++) {
            $signs |= ord($stream[$i]) << (8 * $i);
        }
        $pos = 8;
        for ($i = self::N - self::TAU; $i < self::N; $i++) {
            $j = ord($stream[$pos++]) % ($i + 1);
            $c[$i] = $c[$j];
            $sign = $signs & 1;
            $signs >>= 1;
            $c[$j] = $sign === 1 ? self::Q - 1 : 1;
        }
        return $c;
    }

    /**
     * @param int[] $poly
     */
    private static function polyInfNorm(array $poly): int
    {
        $max = 0;
        for ($i = 0; $i < self::N; $i++) {
            $v = abs(self::centerModQ($poly[$i]));
            if ($v > $max) {
                $max = $v;
            }
        }
        return $max;
    }

    /**
     * @param array<int, int[]> $vec
     */
    private static function encodePolyVecQ(array $vec): string
    {
        $bytes = [];
        foreach ($vec as $p) {
            for ($i = 0; $i < self::N; $i++) {
                $v = self::modQ($p[$i]);
                $bytes[] = $v & 0xff;
                $bytes[] = ($v >> 8) & 0xff;
                $bytes[] = ($v >> 16) & 0xff;
            }
        }
        return pack('C*', ...$bytes);
    }

    /**
     * @return array<int, int[]>
     */
    private static function decodePolyVecQ(string $bytes, int $count): array
    {
        $vec = [];
        $pos = 0;
        for ($k = 0; $k < $count; $k++) {
            $p = array_fill(0, self::N, 0);
            for ($i = 0; $i < self::N; $i++) {
                $val = ord($bytes[$pos])
                    | (ord($bytes[$pos + 1]) << 8)
                    | (ord($bytes[$pos + 2]) << 16);
                $p[$i] = $val % self::Q;
                $pos += 3;
            }
            $vec[$k] = $p;
        }
        return $vec;
    }

    /**
     * @return array{verifyKey: string, signingKey: string}
     */
    public static function keyGen(string $seed32): array
    {
        if (strlen($seed32) !== 32) {
            throw new InvalidArgumentException('ML-DSA keygen seed must be 32 bytes');
        }
        $expanded = Keccak::shake256($seed32, 128);
        $rho = substr($expanded, 0, 32);
        $rhoPrime = substr($expanded, 32, 64);

        $A = self::expandMatrixA($rho);
        $s1 = [];
        $s2 = [];
        for ($j = 0; $j < self::L; $j++) {
            $s1[$j] = self::sampleShortPoly($rhoPrime, $j);
        }
        for ($i = 0; $i < self::K; $i++) {
            $s2[$i] = self::sampleShortPoly($rhoPrime, self::L + $i);
        }

        $t = [];
        for ($i = 0; $i < self::K; $i++) {
            $acc = array_fill(0, self::N, 0);
            for ($j = 0; $j < self::L; $j++) {
                $acc = self::polyAddModQ($acc, self::polyMulModQ($A[$i][$j], $s1[$j]));
            }
            $t[$i] = self::polyAddModQ($acc, $s2[$i]);
        }

        return [
            'verifyKey' => $rho . self::encodePolyVecQ($t),
            'signingKey' => $seed32
        ];
    }

    public static function sign(string $signingSeed32, string $messageBytes): string
    {
        $expanded = Keccak::shake256($signingSeed32, 128);
        $rho = substr($expanded, 0, 32);
        $rhoPrime = substr($expanded, 32, 64);
        $keyK = substr($expanded, 96, 32);

        $A = self::expandMatrixA($rho);
        $s1 = [];
        $s2 = [];
        for ($j = 0; $j < self::L; $j++) {
            $s1[$j] = self::sampleShortPoly($rhoPrime, $j);
        }
        for ($i = 0; $i < self::K; $i++) {
            $s2[$i] = self::sampleShortPoly($rhoPrime, self::L + $i);
        }

        $t = [];
        for ($i = 0; $i < self::K; $i++) {
            $acc = array_fill(0, self::N, 0);
            for ($j = 0; $j < self::L; $j++) {
                $acc = self::polyAddModQ($acc, self::polyMulModQ($A[$i][$j], $s1[$j]));
            }
            $t[$i] = self::polyAddModQ($acc, $s2[$i]);
        }

        $pkBytes = $rho . self::encodePolyVecQ($t);
        $tr = Keccak::shake256($pkBytes, 64);
        $mu = Keccak::shake256($tr . $messageBytes, 64);
        $rhoDoublePrime = Keccak::shake256($keyK . $mu, 64);

        $kappa = 0;
        while ($kappa < 1000) {
            $y = [];
            for ($j = 0; $j < self::L; $j++) {
                $y[$j] = self::sampleMaskPoly($rhoDoublePrime, $kappa + $j);
            }
            $kappa += self::L;

            $w = [];
            for ($i = 0; $i < self::K; $i++) {
                $acc = array_fill(0, self::N, 0);
                for ($j = 0; $j < self::L; $j++) {
                    $acc = self::polyAddModQ($acc, self::polyMulModQ($A[$i][$j], $y[$j]));
                }
                $w[$i] = $acc;
            }

            $wBytes = self::encodePolyVecQ($w);
            $cTilde = Keccak::shake256($mu . $wBytes, 32);
            $c = self::sampleInBall($cTilde);

            $z = [];
            $reject = false;
            for ($j = 0; $j < self::L; $j++) {
                $z[$j] = self::polyAddModQ($y[$j], self::polyMulModQ($c, $s1[$j]));
                if (self::polyInfNorm($z[$j]) >= self::GAMMA1 - self::BETA) {
                    $reject = true;
                    break;
                }
            }
            if ($reject) {
                continue;
            }

            $r = [];
            for ($i = 0; $i < self::K; $i++) {
                $r[$i] = self::polyMulModQ($c, $s2[$i]);
                if (self::polyInfNorm($r[$i]) >= self::BETA) {
                    $reject = true;
                    break;
                }
            }
            if ($reject) {
                continue;
            }

            return $cTilde . self::encodePolyVecQ($z) . self::encodePolyVecQ($r);
        }

        throw new RuntimeException('ML-DSA signing exceeded maximum rejection iterations');
    }

    public static function verify(string $verifyKey, string $messageBytes, string $sigBytes): bool
    {
        $expectedPkLen = 32 + self::K * self::N * 3;
        $vecByteLen = self::L * self::N * 3;
        $rByteLen = self::K * self::N * 3;

        if (strlen($verifyKey) !== $expectedPkLen || strlen($sigBytes) !== 32 + $vecByteLen + $rByteLen) {
            return false;
        }

        $rho = substr($verifyKey, 0, 32);
        $t = self::decodePolyVecQ(substr($verifyKey, 32), self::K);

        $cTilde = substr($sigBytes, 0, 32);
        $z = self::decodePolyVecQ(substr($sigBytes, 32, $vecByteLen), self::L);
        $r = self::decodePolyVecQ(substr($sigBytes, 32 + $vecByteLen), self::K);

        for ($j = 0; $j < self::L; $j++) {
            if (self::polyInfNorm($z[$j]) >= self::GAMMA1 - self::BETA) {
                return false;
            }
        }
        for ($i = 0; $i < self::K; $i++) {
            if (self::polyInfNorm($r[$i]) >= self::BETA) {
                return false;
            }
        }

        $A = self::expandMatrixA($rho);
        $c = self::sampleInBall($cTilde);

        $wPrime = [];
        for ($i = 0; $i < self::K; $i++) {
            $az = array_fill(0, self::N, 0);
            for ($j = 0; $j < self::L; $j++) {
                $az = self::polyAddModQ($az, self::polyMulModQ($A[$i][$j], $z[$j]));
            }
            $ct = self::polyMulModQ($c, $t[$i]);
            $wPrime[$i] = self::polyAddModQ(self::polySubModQ($az, $ct), $r[$i]);
        }

        $tr = Keccak::shake256($verifyKey, 64);
        $mu = Keccak::shake256($tr . $messageBytes, 64);
        $wBytes = self::encodePolyVecQ($wPrime);
        $cTildePrime = Keccak::shake256($mu . $wBytes, 32);

        return hash_equals($cTilde, $cTildePrime);
    }
}

