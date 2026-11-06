/**
 * FIPS 202 Keccak-f[1600] sponge implementation for SHA3-256, SHA3-512, SHAKE128, and SHAKE256.
 * Required by NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) and works identically in Browser & Node.js.
 */

const ROTC = [
  1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
];

const PILN = [
  10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
];

const RC_HI = new Uint32Array([
  0x00000000, 0x00000000, 0x80000000, 0x80000000, 0x00000000, 0x00000000,
  0x80000000, 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
  0x00000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000,
  0x00000000, 0x80000000, 0x80000000, 0x80000000, 0x00000000, 0x80000000
]);

const RC_LO = new Uint32Array([
  0x00000001, 0x00008082, 0x0000808a, 0x80008000, 0x0000808b, 0x80000001,
  0x80008081, 0x00008009, 0x0000008a, 0x00000088, 0x80008009, 0x8000000a,
  0x8000808b, 0x0000008b, 0x00008089, 0x00008003, 0x00008002, 0x00000080,
  0x0000800a, 0x8000000a, 0x80008081, 0x00008080, 0x80000001, 0x80008008
]);

export function keccakP1600(sLo, sHi) {
  const bLo = new Uint32Array(5);
  const bHi = new Uint32Array(5);

  for (let round = 0; round < 24; round++) {
    for (let x = 0; x < 5; x++) {
      bLo[x] = sLo[x] ^ sLo[x + 5] ^ sLo[x + 10] ^ sLo[x + 15] ^ sLo[x + 20];
      bHi[x] = sHi[x] ^ sHi[x + 5] ^ sHi[x + 10] ^ sHi[x + 15] ^ sHi[x + 20];
    }

    for (let x = 0; x < 5; x++) {
      const x4 = (x + 4) % 5;
      const x1 = (x + 1) % 5;
      const c1Lo = bLo[x1];
      const c1Hi = bHi[x1];
      const rotLo = (c1Lo << 1) | (c1Hi >>> 31);
      const rotHi = (c1Hi << 1) | (c1Lo >>> 31);
      const tLo = bLo[x4] ^ rotLo;
      const tHi = bHi[x4] ^ rotHi;
      for (let y = 0; y < 25; y += 5) {
        sLo[x + y] ^= tLo;
        sHi[x + y] ^= tHi;
      }
    }

    let tLo = sLo[1];
    let tHi = sHi[1];
    for (let i = 0; i < 24; i++) {
      const j = PILN[i];
      const r = ROTC[i];
      const nLo = sLo[j];
      const nHi = sHi[j];
      if (r < 32) {
        sLo[j] = (tLo << r) | (tHi >>> (32 - r));
        sHi[j] = (tHi << r) | (tLo >>> (32 - r));
      } else {
        const s = r - 32;
        sLo[j] = (tHi << s) | (tLo >>> (32 - s));
        sHi[j] = (tLo << s) | (tHi >>> (32 - s));
      }
      tLo = nLo;
      tHi = nHi;
    }

    for (let y = 0; y < 25; y += 5) {
      for (let x = 0; x < 5; x++) {
        bLo[x] = sLo[y + x];
        bHi[x] = sHi[y + x];
      }
      for (let x = 0; x < 5; x++) {
        sLo[y + x] = bLo[x] ^ (~bLo[(x + 1) % 5] & bLo[(x + 2) % 5]);
        sHi[y + x] = bHi[x] ^ (~bHi[(x + 1) % 5] & bHi[(x + 2) % 5]);
      }
    }

    sLo[0] ^= RC_LO[round];
    sHi[0] ^= RC_HI[round];
  }
}

export class KeccakSponge {
  constructor(rateBytes, suffix) {
    this.rateBytes = rateBytes;
    this.suffix = suffix;
    this.stateBytes = new Uint8Array(200);
    this.sLo = new Uint32Array(25);
    this.sHi = new Uint32Array(25);
    this.pos = 0;
    this.squeezing = false;
  }

  _bytesToLanes() {
    const b = this.stateBytes;
    for (let i = 0; i < 25; i++) {
      const o = i * 8;
      this.sLo[i] = (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
      this.sHi[i] = (b[o + 4] | (b[o + 5] << 8) | (b[o + 6] << 16) | (b[o + 7] << 24)) >>> 0;
    }
  }

  _lanesToBytes() {
    const b = this.stateBytes;
    for (let i = 0; i < 25; i++) {
      const o = i * 8;
      const lo = this.sLo[i];
      const hi = this.sHi[i];
      b[o] = lo & 0xff;
      b[o + 1] = (lo >>> 8) & 0xff;
      b[o + 2] = (lo >>> 16) & 0xff;
      b[o + 3] = (lo >>> 24) & 0xff;
      b[o + 4] = hi & 0xff;
      b[o + 5] = (hi >>> 8) & 0xff;
      b[o + 6] = (hi >>> 16) & 0xff;
      b[o + 7] = (hi >>> 24) & 0xff;
    }
  }

  _permute() {
    this._bytesToLanes();
    keccakP1600(this.sLo, this.sHi);
    this._lanesToBytes();
  }

  absorb(data) {
    if (this.squeezing) {
      throw new Error('Cannot absorb after squeezing has started');
    }
    for (let i = 0; i < data.length; i++) {
      this.stateBytes[this.pos++] ^= data[i];
      if (this.pos === this.rateBytes) {
        this._permute();
        this.pos = 0;
      }
    }
    return this;
  }

  finalize() {
    if (!this.squeezing) {
      this.stateBytes[this.pos] ^= this.suffix;
      this.stateBytes[this.rateBytes - 1] ^= 0x80;
      this._permute();
      this.pos = 0;
      this.squeezing = true;
    }
    return this;
  }

  squeeze(outLen) {
    if (!this.squeezing) {
      this.finalize();
    }
    const out = new Uint8Array(outLen);
    let offset = 0;
    while (offset < outLen) {
      if (this.pos === this.rateBytes) {
        this._permute();
        this.pos = 0;
      }
      const take = Math.min(this.rateBytes - this.pos, outLen - offset);
      out.set(this.stateBytes.subarray(this.pos, this.pos + take), offset);
      this.pos += take;
      offset += take;
    }
    return out;
  }
}

export function sha3_256(data) {
  return new KeccakSponge(136, 0x06).absorb(data).squeeze(32);
}

export function sha3_512(data) {
  return new KeccakSponge(72, 0x06).absorb(data).squeeze(64);
}

export function shake128(data, outLen) {
  return new KeccakSponge(168, 0x1f).absorb(data).squeeze(outLen);
}

export function shake256(data, outLen) {
  return new KeccakSponge(136, 0x1f).absorb(data).squeeze(outLen);
}

export function createShake128() {
  return new KeccakSponge(168, 0x1f);
}

export function createShake256() {
  return new KeccakSponge(136, 0x1f);
}

