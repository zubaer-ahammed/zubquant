<?php

declare(strict_types=1);

namespace Zubaer\ZubQuant;

/**
 * NIST FIPS 203 ML-KEM-768 (k = 3, eta1 = 2, eta2 = 2, du = 10, dv = 4, q = 3329, n = 256)
 * Bit-for-bit identical to packages/js-core/src/mlkem768.js.
 */
final class MLKem768
{
    private const Q = 3329;
    private const K = 3;

    private const ZETAS = [
        1, 1729, 2580, 3289, 2642, 630, 1897, 848,
        1062, 1919, 193, 797, 2786, 3260, 569, 1746,
        296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
        1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
        289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
        650, 1977, 2513, 632, 2865, 33, 1320, 1915,
        2319, 1435, 807, 452, 1438, 2868, 1534, 2402,
        2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
        17, 2761, 583, 2649, 1637, 723, 2288, 1100,
        1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
        1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
        939, 2308, 2437, 2388, 733, 2337, 268, 641,
        1584, 2298, 2037, 3220, 375, 2549, 2090, 1645,
        1063, 319, 2773, 757, 2099, 561, 2466, 2594,
        2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
        1722, 1212, 1874, 1029, 2110, 2935, 885, 2154
    ];

    private static function modQ(int $x): int
    {
        $r = $x % self::Q;
        return $r < 0 ? $r + self::Q : $r;
    }

    /**
     * @param int[] $f
     * @return int[]
     */
    public static function ntt(array $f): array
    {
        $i = 1;
        for ($len = 128; $len >= 2; $len >>= 1) {
            for ($start = 0; $start < 256; $start += 2 * $len) {
                $zeta = self::ZETAS[$i++];
                for ($j = $start; $j < $start + $len; $j++) {
                    $t = self::modQ($zeta * $f[$j + $len]);
                    $f[$j + $len] = self::modQ($f[$j] - $t);
                    $f[$j] = self::modQ($f[$j] + $t);
                }
            }
        }
        return $f;
    }

    /**
     * @param int[] $f
     * @return int[]
     */
    public static function invNtt(array $f): array
    {
        $i = 127;
        for ($len = 2; $len <= 128; $len <<= 1) {
            for ($start = 0; $start < 256; $start += 2 * $len) {
                $zeta = self::ZETAS[$i--];
                for ($j = $start; $j < $start + $len; $j++) {
                    $t = $f[$j];
                    $f[$j] = self::modQ($t + $f[$j + $len]);
                    $f[$j + $len] = self::modQ($zeta * ($f[$j + $len] - $t));
                }
            }
        }
        for ($j = 0; $j < 256; $j++) {
            $f[$j] = self::modQ($f[$j] * 3303);
        }
        return $f;
    }

    /**
     * @param int[] $f
     * @param int[] $g
     * @return int[]
     */
    public static function multiplyNTTs(array $f, array $g): array
    {
        $h = array_fill(0, 256, 0);
        for ($i = 0; $i < 128; $i++) {
            $i2 = 2 * $i;
            $a0 = $f[$i2];
            $a1 = $f[$i2 + 1];
            $b0 = $g[$i2];
            $b1 = $g[$i2 + 1];
            $gamma = ($i & 1) === 0 ? self::ZETAS[64 + ($i >> 1)] : -self::ZETAS[64 + ($i >> 1)];
            $h[$i2] = self::modQ($a0 * $b0 + self::modQ($a1 * $b1) * $gamma);
            $h[$i2 + 1] = self::modQ($a0 * $b1 + $a1 * $b0);
        }
        return $h;
    }

    /**
     * @param int[] $a
     * @param int[] $b
     * @return int[]
     */
    private static function polyAdd(array $a, array $b): array
    {
        $r = array_fill(0, 256, 0);
        for ($i = 0; $i < 256; $i++) {
            $r[$i] = self::modQ($a[$i] + $b[$i]);
        }
        return $r;
    }

    /**
     * @param int[] $a
     * @param int[] $b
     * @return int[]
     */
    private static function polySub(array $a, array $b): array
    {
        $r = array_fill(0, 256, 0);
        for ($i = 0; $i < 256; $i++) {
            $r[$i] = self::modQ($a[$i] - $b[$i]);
        }
        return $r;
    }

    /**
     * @return int[]
     */
    public static function sampleNTT(string $seed34): array
    {
        $xof = (new Keccak(168, 0x1f))->absorb($seed34)->finalize();
        $a = array_fill(0, 256, 0);
        $j = 0;
        while ($j < 256) {
            $c = $xof->squeeze(3);
            $c0 = ord($c[0]);
            $c1 = ord($c[1]);
            $c2 = ord($c[2]);
            $d1 = $c0 + 256 * ($c1 & 0x0f);
            $d2 = ($c1 >> 4) + 16 * $c2;
            if ($d1 < self::Q) {
                $a[$j++] = $d1;
            }
            if ($d2 < self::Q && $j < 256) {
                $a[$j++] = $d2;
            }
        }
        return $a;
    }

    /**
     * @return int[]
     */
    public static function samplePolyCBD2(string $bytes128): array
    {
        $f = array_fill(0, 256, 0);
        for ($i = 0; $i < 128; $i++) {
            $byte = ord($bytes128[$i]);
            $a0 = ($byte & 1) + (($byte >> 1) & 1);
            $b0 = (($byte >> 2) & 1) + (($byte >> 3) & 1);
            $a1 = (($byte >> 4) & 1) + (($byte >> 5) & 1);
            $b1 = (($byte >> 6) & 1) + (($byte >> 7) & 1);
            $f[2 * $i] = self::modQ($a0 - $b0);
            $f[2 * $i + 1] = self::modQ($a1 - $b1);
        }
        return $f;
    }

    private static function prfEta2(string $sigma32, int $nByte): string
    {
        return Keccak::shake256($sigma32 . chr($nByte & 0xff), 128);
    }

    private static function compressElem(int $x, int $d): int
    {
        return intdiv(($x << $d) + 1664, self::Q) & ((1 << $d) - 1);
    }

    private static function decompressElem(int $y, int $d): int
    {
        return (self::Q * $y + (1 << ($d - 1))) >> $d;
    }

    /**
     * @param int[] $f
     */
    public static function byteEncode(array $f, int $d): string
    {
        $out = array_fill(0, 32 * $d, 0);
        $bitPos = 0;
        for ($i = 0; $i < 256; $i++) {
            $val = $f[$i];
            for ($b = 0; $b < $d; $b++) {
                if (($val & 1) !== 0) {
                    $out[$bitPos >> 3] |= 1 << ($bitPos & 7);
                }
                $val >>= 1;
                $bitPos++;
            }
        }
        return pack('C*', ...$out);
    }

    /**
     * @return int[]
     */
    public static function byteDecode(string $bytes, int $d): array
    {
        $f = array_fill(0, 256, 0);
        $mask = $d === 12 ? self::Q : (1 << $d);
        $bitPos = 0;
        for ($i = 0; $i < 256; $i++) {
            $val = 0;
            for ($b = 0; $b < $d; $b++) {
                $byte = ord($bytes[$bitPos >> 3]);
                $bit = ($byte >> ($bitPos & 7)) & 1;
                $val |= $bit << $b;
                $bitPos++;
            }
            $f[$i] = $d === 12 ? ($val % self::Q) : ($val & ($mask - 1));
        }
        return $f;
    }

    /**
     * @param int[] $f
     * @return int[]
     */
    private static function compressPoly(array $f, int $d): array
    {
        $out = array_fill(0, 256, 0);
        for ($i = 0; $i < 256; $i++) {
            $out[$i] = self::compressElem($f[$i], $d);
        }
        return $out;
    }

    /**
     * @param int[] $f
     * @return int[]
     */
    private static function decompressPoly(array $f, int $d): array
    {
        $out = array_fill(0, 256, 0);
        for ($i = 0; $i < 256; $i++) {
            $out[$i] = self::decompressElem($f[$i], $d);
        }
        return $out;
    }

    /**
     * @return array{ekPke: string, dkPke: string}
     */
    public static function kpkeKeyGen(string $d32): array
    {
        $rhoSigma = Keccak::sha3_512($d32 . chr(self::K));
        $rho = substr($rhoSigma, 0, 32);
        $sigma = substr($rhoSigma, 32, 32);

        $A = [];
        for ($i = 0; $i < self::K; $i++) {
            $A[$i] = [];
            for ($j = 0; $j < self::K; $j++) {
                $A[$i][$j] = self::sampleNTT($rho . chr($j) . chr($i));
            }
        }

        $n = 0;
        $s = [];
        for ($i = 0; $i < self::K; $i++) {
            $s[$i] = self::ntt(self::samplePolyCBD2(self::prfEta2($sigma, $n++)));
        }
        $e = [];
        for ($i = 0; $i < self::K; $i++) {
            $e[$i] = self::ntt(self::samplePolyCBD2(self::prfEta2($sigma, $n++)));
        }

        $tHat = [];
        for ($i = 0; $i < self::K; $i++) {
            $acc = array_fill(0, 256, 0);
            for ($j = 0; $j < self::K; $j++) {
                $acc = self::polyAdd($acc, self::multiplyNTTs($A[$i][$j], $s[$j]));
            }
            $tHat[$i] = self::polyAdd($acc, $e[$i]);
        }

        $ekPke = '';
        $dkPke = '';
        for ($i = 0; $i < self::K; $i++) {
            $ekPke .= self::byteEncode($tHat[$i], 12);
            $dkPke .= self::byteEncode($s[$i], 12);
        }
        $ekPke .= $rho;

        return ['ekPke' => $ekPke, 'dkPke' => $dkPke];
    }

    public static function kpkeEncrypt(string $ekPke, string $m32, string $r32): string
    {
        $tHat = [];
        for ($i = 0; $i < self::K; $i++) {
            $tHat[$i] = self::byteDecode(substr($ekPke, $i * 384, 384), 12);
        }
        $rho = substr($ekPke, 384 * self::K, 32);

        $A = [];
        for ($i = 0; $i < self::K; $i++) {
            $A[$i] = [];
            for ($j = 0; $j < self::K; $j++) {
                $A[$i][$j] = self::sampleNTT($rho . chr($j) . chr($i));
            }
        }

        $n = 0;
        $y = [];
        for ($i = 0; $i < self::K; $i++) {
            $y[$i] = self::ntt(self::samplePolyCBD2(self::prfEta2($r32, $n++)));
        }
        $e1 = [];
        for ($i = 0; $i < self::K; $i++) {
            $e1[$i] = self::samplePolyCBD2(self::prfEta2($r32, $n++));
        }
        $e2 = self::samplePolyCBD2(self::prfEta2($r32, $n++));

        $u = [];
        for ($i = 0; $i < self::K; $i++) {
            $acc = array_fill(0, 256, 0);
            for ($j = 0; $j < self::K; $j++) {
                $acc = self::polyAdd($acc, self::multiplyNTTs($A[$j][$i], $y[$j]));
            }
            $u[$i] = self::polyAdd(self::invNtt($acc), $e1[$i]);
        }

        $mu = self::decompressPoly(self::byteDecode($m32, 1), 1);

        $vAcc = array_fill(0, 256, 0);
        for ($i = 0; $i < self::K; $i++) {
            $vAcc = self::polyAdd($vAcc, self::multiplyNTTs($tHat[$i], $y[$i]));
        }
        $v = self::polyAdd(self::polyAdd(self::invNtt($vAcc), $e2), $mu);

        $c = '';
        for ($i = 0; $i < self::K; $i++) {
            $c .= self::byteEncode(self::compressPoly($u[$i], 10), 10);
        }
        $c .= self::byteEncode(self::compressPoly($v, 4), 4);
        return $c;
    }

    public static function kpkeDecrypt(string $dkPke, string $c1088): string
    {
        $uPrime = [];
        for ($i = 0; $i < self::K; $i++) {
            $uPrime[$i] = self::decompressPoly(self::byteDecode(substr($c1088, $i * 320, 320), 10), 10);
        }
        $vPrime = self::decompressPoly(self::byteDecode(substr($c1088, 960, 128), 4), 4);

        $sHat = [];
        for ($i = 0; $i < self::K; $i++) {
            $sHat[$i] = self::byteDecode(substr($dkPke, $i * 384, 384), 12);
        }

        $acc = array_fill(0, 256, 0);
        for ($i = 0; $i < self::K; $i++) {
            $acc = self::polyAdd($acc, self::multiplyNTTs($sHat[$i], self::ntt($uPrime[$i])));
        }
        $w = self::polySub($vPrime, self::invNtt($acc));
        return self::byteEncode(self::compressPoly($w, 1), 1);
    }

    /**
     * @return array{ek: string, dk: string}
     */
    public static function keygenInternal(string $d32, string $z32): array
    {
        $keys = self::kpkeKeyGen($d32);
        $ekPke = $keys['ekPke'];
        $dkPke = $keys['dkPke'];
        $hEk = Keccak::sha3_256($ekPke);
        return [
            'ek' => $ekPke,
            'dk' => $dkPke . $ekPke . $hEk . $z32
        ];
    }

    /**
     * @return array{ciphertext: string, sharedSecret: string}
     */
    public static function encapsInternal(string $ek1184, string $m32): array
    {
        $hEk = Keccak::sha3_256($ek1184);
        $kr = Keccak::sha3_512($m32 . $hEk);
        $sharedSecret = substr($kr, 0, 32);
        $r = substr($kr, 32, 32);
        $ciphertext = self::kpkeEncrypt($ek1184, $m32, $r);
        return [
            'ciphertext' => $ciphertext,
            'sharedSecret' => $sharedSecret
        ];
    }

    public static function decapsInternal(string $dk2400, string $c1088): string
    {
        $dkPke = substr($dk2400, 0, 1152);
        $ekPke = substr($dk2400, 1152, 1184);
        $h = substr($dk2400, 2336, 32);
        $z = substr($dk2400, 2368, 32);

        $mPrime = self::kpkeDecrypt($dkPke, $c1088);
        $krPrime = Keccak::sha3_512($mPrime . $h);
        $kPrime = substr($krPrime, 0, 32);
        $rPrime = substr($krPrime, 32, 32);

        $kBar = Keccak::shake256($z . $c1088, 32);
        $cPrime = self::kpkeEncrypt($ekPke, $mPrime, $rPrime);

        return hash_equals($c1088, $cPrime) ? $kPrime : $kBar;
    }
}

