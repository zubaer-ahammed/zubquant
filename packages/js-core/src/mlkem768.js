/**
 * NIST FIPS 203 ML-KEM-768 (Module-Lattice-Based Key-Encapsulation Mechanism)
 * Parameter Set: ML-KEM-768 (k = 3, eta1 = 2, eta2 = 2, du = 10, dv = 4, q = 3329, n = 256)
 *
 * Key & Ciphertext Sizes (bytes):
 * - Encapsulation Key (ek / Public Key): 1184
 * - Decapsulation Key (dk / Secret Key): 2400
 * - Ciphertext (ct): 1088
 * - Shared Secret (ss): 32
 */

import { sha3_256, sha3_512, shake256, createShake128 } from './keccak.js';

const Q = 3329;
const K = 3;

// FIPS 203 Appendix A - Precomputed NTT Zetas (BitRev7(i) powers of 17 mod 3329)
const ZETAS = new Int16Array([
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
]);

function modQ(x) {
  const r = x % Q;
  return r < 0 ? r + Q : r;
}

/**
 * FIPS 203 Algorithm 9: NTT(f)
 */
export function ntt(fIn) {
  const f = new Int16Array(fIn);
  let i = 1;
  for (let len = 128; len >= 2; len >>= 1) {
    for (let start = 0; start < 256; start += 2 * len) {
      const zeta = ZETAS[i++];
      for (let j = start; j < start + len; j++) {
        const t = modQ(zeta * f[j + len]);
        f[j + len] = modQ(f[j] - t);
        f[j] = modQ(f[j] + t);
      }
    }
  }
  return f;
}

/**
 * FIPS 203 Algorithm 10: NTT^-1(f)
 */
export function invNtt(fIn) {
  const f = new Int16Array(fIn);
  let i = 127;
  for (let len = 2; len <= 128; len <<= 1) {
    for (let start = 0; start < 256; start += 2 * len) {
      const zeta = ZETAS[i--];
      for (let j = start; j < start + len; j++) {
        const t = f[j];
        f[j] = modQ(t + f[j + len]);
        f[j + len] = modQ(zeta * (f[j + len] - t));
      }
    }
  }
  // 3303 = 128^-1 mod 3329
  for (let j = 0; j < 256; j++) {
    f[j] = modQ(f[j] * 3303);
  }
  return f;
}

/**
 * FIPS 203 Algorithm 11 & 12: MultiplyNTTs(f, g)
 */
export function multiplyNTTs(f, g) {
  const h = new Int16Array(256);
  for (let i = 0; i < 128; i++) {
    const i2 = 2 * i;
    const a0 = f[i2];
    const a1 = f[i2 + 1];
    const b0 = g[i2];
    const b1 = g[i2 + 1];
    const gamma = (i & 1) === 0 ? ZETAS[64 + (i >> 1)] : -ZETAS[64 + (i >> 1)];
    h[i2] = modQ(a0 * b0 + modQ(a1 * b1) * gamma);
    h[i2 + 1] = modQ(a0 * b1 + a1 * b0);
  }
  return h;
}

function polyAdd(a, b) {
  const r = new Int16Array(256);
  for (let i = 0; i < 256; i++) r[i] = modQ(a[i] + b[i]);
  return r;
}

function polySub(a, b) {
  const r = new Int16Array(256);
  for (let i = 0; i < 256; i++) r[i] = modQ(a[i] - b[i]);
  return r;
}

/**
 * FIPS 203 Algorithm 7: SampleNTT(B)
 */
export function sampleNTT(seed34) {
  const xof = createShake128().absorb(seed34).finalize();
  const a = new Int16Array(256);
  let j = 0;
  while (j < 256) {
    const c = xof.squeeze(3);
    const d1 = c[0] + 256 * (c[1] & 0x0f);
    const d2 = (c[1] >> 4) + 16 * c[2];
    if (d1 < Q) a[j++] = d1;
    if (d2 < Q && j < 256) a[j++] = d2;
  }
  return a;
}

/**
 * FIPS 203 Algorithm 8: SamplePolyCBD_eta(B) for eta = 2
 */
export function samplePolyCBD2(bytes128) {
  const f = new Int16Array(256);
  for (let i = 0; i < 128; i++) {
    const byte = bytes128[i];
    const a0 = (byte & 1) + ((byte >> 1) & 1);
    const b0 = ((byte >> 2) & 1) + ((byte >> 3) & 1);
    const a1 = ((byte >> 4) & 1) + ((byte >> 5) & 1);
    const b1 = ((byte >> 6) & 1) + ((byte >> 7) & 1);
    f[2 * i] = modQ(a0 - b0);
    f[2 * i + 1] = modQ(a1 - b1);
  }
  return f;
}

function prfEta2(sigma32, nByte) {
  const input = new Uint8Array(33);
  input.set(sigma32, 0);
  input[32] = nByte;
  return shake256(input, 128);
}

/**
 * FIPS 203 Section 4.2.1: Compress_d and Decompress_d
 */
function compressElem(x, d) {
  // Round((2^d / q) * x) mod 2^d = (((x << d) + q/2) / q) & ((1 << d) - 1)
  return Math.floor(((x << d) + 1664) / Q) & ((1 << d) - 1);
}

function decompressElem(y, d) {
  // Round((q / 2^d) * y) = (q * y + 2^(d-1)) >> d
  return (Q * y + (1 << (d - 1))) >> d;
}

/**
 * FIPS 203 Algorithm 5 & 6: ByteEncode_d and ByteDecode_d
 */
export function byteEncode(f, d) {
  const out = new Uint8Array(32 * d);
  let bitPos = 0;
  for (let i = 0; i < 256; i++) {
    let val = f[i];
    for (let b = 0; b < d; b++) {
      if ((val & 1) !== 0) {
        out[bitPos >> 3] |= 1 << (bitPos & 7);
      }
      val >>= 1;
      bitPos++;
    }
  }
  return out;
}

export function byteDecode(bytes, d) {
  const f = new Int16Array(256);
  const mask = d === 12 ? Q : (1 << d);
  let bitPos = 0;
  for (let i = 0; i < 256; i++) {
    let val = 0;
    for (let b = 0; b < d; b++) {
      const bit = (bytes[bitPos >> 3] >> (bitPos & 7)) & 1;
      val |= bit << b;
      bitPos++;
    }
    f[i] = d === 12 ? val % Q : val & (mask - 1);
  }
  return f;
}

function compressPoly(f, d) {
  const out = new Int16Array(256);
  for (let i = 0; i < 256; i++) out[i] = compressElem(f[i], d);
  return out;
}

function decompressPoly(f, d) {
  const out = new Int16Array(256);
  for (let i = 0; i < 256; i++) out[i] = decompressElem(f[i], d);
  return out;
}

/**
 * FIPS 203 Algorithm 13: K-PKE.KeyGen(d)
 */
export function kpkeKeyGen(d32) {
  const dWithK = new Uint8Array(33);
  dWithK.set(d32, 0);
  dWithK[32] = K;
  const rhoSigma = sha3_512(dWithK);
  const rho = rhoSigma.subarray(0, 32);
  const sigma = rhoSigma.subarray(32, 64);

  const A = Array.from({ length: K }, () => new Array(K));
  const seed34 = new Uint8Array(34);
  seed34.set(rho, 0);
  for (let i = 0; i < K; i++) {
    for (let j = 0; j < K; j++) {
      seed34[32] = j;
      seed34[33] = i;
      A[i][j] = sampleNTT(seed34);
    }
  }

  let n = 0;
  const s = new Array(K);
  for (let i = 0; i < K; i++) {
    s[i] = ntt(samplePolyCBD2(prfEta2(sigma, n++)));
  }
  const e = new Array(K);
  for (let i = 0; i < K; i++) {
    e[i] = ntt(samplePolyCBD2(prfEta2(sigma, n++)));
  }

  const tHat = new Array(K);
  for (let i = 0; i < K; i++) {
    let acc = new Int16Array(256);
    for (let j = 0; j < K; j++) {
      acc = polyAdd(acc, multiplyNTTs(A[i][j], s[j]));
    }
    tHat[i] = polyAdd(acc, e[i]);
  }

  const ekPke = new Uint8Array(384 * K + 32);
  for (let i = 0; i < K; i++) {
    ekPke.set(byteEncode(tHat[i], 12), i * 384);
  }
  ekPke.set(rho, 384 * K);

  const dkPke = new Uint8Array(384 * K);
  for (let i = 0; i < K; i++) {
    dkPke.set(byteEncode(s[i], 12), i * 384);
  }

  return { ekPke, dkPke };
}

/**
 * FIPS 203 Algorithm 14: K-PKE.Encrypt(ek_PKE, m, r)
 */
export function kpkeEncrypt(ekPke, m32, r32) {
  const tHat = new Array(K);
  for (let i = 0; i < K; i++) {
    tHat[i] = byteDecode(ekPke.subarray(i * 384, (i + 1) * 384), 12);
  }
  const rho = ekPke.subarray(384 * K, 384 * K + 32);

  const A = Array.from({ length: K }, () => new Array(K));
  const seed34 = new Uint8Array(34);
  seed34.set(rho, 0);
  for (let i = 0; i < K; i++) {
    for (let j = 0; j < K; j++) {
      seed34[32] = j;
      seed34[33] = i;
      A[i][j] = sampleNTT(seed34);
    }
  }

  let n = 0;
  const y = new Array(K);
  for (let i = 0; i < K; i++) {
    y[i] = ntt(samplePolyCBD2(prfEta2(r32, n++)));
  }
  const e1 = new Array(K);
  for (let i = 0; i < K; i++) {
    e1[i] = samplePolyCBD2(prfEta2(r32, n++));
  }
  const e2 = samplePolyCBD2(prfEta2(r32, n++));

  // u = NTT^-1(A^T o y) + e1
  const u = new Array(K);
  for (let i = 0; i < K; i++) {
    let acc = new Int16Array(256);
    for (let j = 0; j < K; j++) {
      acc = polyAdd(acc, multiplyNTTs(A[j][i], y[j]));
    }
    u[i] = polyAdd(invNtt(acc), e1[i]);
  }

  // mu = Decompress_1(ByteDecode_1(m))
  const mu = decompressPoly(byteDecode(m32, 1), 1);

  // v = NTT^-1(tHat^T o y) + e2 + mu
  let vAcc = new Int16Array(256);
  for (let i = 0; i < K; i++) {
    vAcc = polyAdd(vAcc, multiplyNTTs(tHat[i], y[i]));
  }
  const v = polyAdd(polyAdd(invNtt(vAcc), e2), mu);

  // c1 (3 * 320 = 960 bytes), c2 (128 bytes) -> total 1088 bytes
  const c = new Uint8Array(1088);
  for (let i = 0; i < K; i++) {
    c.set(byteEncode(compressPoly(u[i], 10), 10), i * 320);
  }
  c.set(byteEncode(compressPoly(v, 4), 4), 960);
  return c;
}

/**
 * FIPS 203 Algorithm 15: K-PKE.Decrypt(dk_PKE, c)
 */
export function kpkeDecrypt(dkPke, c1088) {
  const uPrime = new Array(K);
  for (let i = 0; i < K; i++) {
    uPrime[i] = decompressPoly(byteDecode(c1088.subarray(i * 320, (i + 1) * 320), 10), 10);
  }
  const vPrime = decompressPoly(byteDecode(c1088.subarray(960, 1088), 4), 4);

  const sHat = new Array(K);
  for (let i = 0; i < K; i++) {
    sHat[i] = byteDecode(dkPke.subarray(i * 384, (i + 1) * 384), 12);
  }

  let acc = new Int16Array(256);
  for (let i = 0; i < K; i++) {
    acc = polyAdd(acc, multiplyNTTs(sHat[i], ntt(uPrime[i])));
  }
  const w = polySub(vPrime, invNtt(acc));
  return byteEncode(compressPoly(w, 1), 1);
}

/**
 * FIPS 203 Algorithm 16: ML-KEM.KeyGen_internal(d, z)
 */
export function mlkem768KeygenInternal(d32, z32) {
  const { ekPke, dkPke } = kpkeKeyGen(d32);
  const hEk = sha3_256(ekPke);
  const dk = new Uint8Array(2400);
  dk.set(dkPke, 0);          // 0..1152
  dk.set(ekPke, 1152);       // 1152..2336
  dk.set(hEk, 2336);         // 2336..2368
  dk.set(z32, 2368);         // 2368..2400
  return { ek: ekPke, dk };
}

/**
 * FIPS 203 Algorithm 17: ML-KEM.Encaps_internal(ek, m)
 */
export function mlkem768EncapsInternal(ek1184, m32) {
  const hEk = sha3_256(ek1184);
  const gInput = new Uint8Array(64);
  gInput.set(m32, 0);
  gInput.set(hEk, 32);
  const kr = sha3_512(gInput);
  const sharedSecret = kr.subarray(0, 32);
  const r = kr.subarray(32, 64);
  const ciphertext = kpkeEncrypt(ek1184, m32, r);
  return { ciphertext, sharedSecret: new Uint8Array(sharedSecret) };
}

/**
 * FIPS 203 Algorithm 18: ML-KEM.Decaps_internal(dk, c)
 */
export function mlkem768DecapsInternal(dk2400, c1088) {
  const dkPke = dk2400.subarray(0, 1152);
  const ekPke = dk2400.subarray(1152, 2336);
  const h = dk2400.subarray(2336, 2368);
  const z = dk2400.subarray(2368, 2400);

  const mPrime = kpkeDecrypt(dkPke, c1088);

  const gInput = new Uint8Array(64);
  gInput.set(mPrime, 0);
  gInput.set(h, 32);
  const krPrime = sha3_512(gInput);
  const kPrime = krPrime.subarray(0, 32);
  const rPrime = krPrime.subarray(32, 64);

  const zConcatC = new Uint8Array(32 + 1088);
  zConcatC.set(z, 0);
  zConcatC.set(c1088, 32);
  const kBar = shake256(zConcatC, 32);

  const cPrime = kpkeEncrypt(ekPke, mPrime, rPrime);

  // Constant-time comparison of c1088 and cPrime
  let diff = 0;
  for (let i = 0; i < 1088; i++) {
    diff |= c1088[i] ^ cPrime[i];
  }
  const mask = ((diff - 1) >> 8) & 0xff; // 0xff if equal, 0x00 if different

  const sharedSecret = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    sharedSecret[i] = (kPrime[i] & mask) | (kBar[i] & ~mask);
  }
  return sharedSecret;
}

