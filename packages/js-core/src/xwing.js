/**
 * IETF X-Wing Hybrid Post-Quantum KEM (draft-connolly-cfrg-xwing-kem)
 * Combines NIST FIPS 203 ML-KEM-768 + RFC 7748 X25519 with SHA3-256 combiner.
 *
 * Key & Ciphertext Sizes (bytes):
 * - Seed (Secret Key): 32 bytes (expands deterministically to ML-KEM-768 dk + X25519 scalar)
 * - Public Key (pk): 1216 bytes (1184B ML-KEM-768 ek + 32B X25519 pk)
 * - Ciphertext (ct): 1120 bytes (1088B ML-KEM-768 ct + 32B X25519 ct)
 * - Shared Secret (ss): 32 bytes
 */

import { sha3_256, shake256 } from './keccak.js';
import { x25519, x25519Base } from './x25519.js';
import {
  mlkem768KeygenInternal,
  mlkem768EncapsInternal,
  mlkem768DecapsInternal
} from './mlkem768.js';

// ASCII label "\./^\" (0x5c, 0x2e, 0x2f, 0x5e, 0x5c, 0x5c) from IETF X-Wing specification
const XWING_LABEL = new Uint8Array([0x5c, 0x2e, 0x2f, 0x5e, 0x5c, 0x5c]);

export function expandDecapsulationKey(skSeed32) {
  if (skSeed32.length !== 32) {
    throw new Error('X-Wing secret seed must be 32 bytes');
  }
  const expanded = shake256(skSeed32, 96);
  const d = expanded.subarray(0, 32);
  const z = expanded.subarray(32, 64);
  const skX = expanded.subarray(64, 96);

  const { ek: pkM, dk: skM } = mlkem768KeygenInternal(d, z);
  const pkX = x25519Base(skX);

  const pk = new Uint8Array(1216);
  pk.set(pkM, 0);
  pk.set(pkX, 1184);

  return { skM, skX: new Uint8Array(skX), pkX, pk };
}

export function xwingKeyGenFromSeed(skSeed32) {
  const { pk } = expandDecapsulationKey(skSeed32);
  return {
    publicKey: pk,
    privateKey: new Uint8Array(skSeed32)
  };
}

function combineSharedSecrets(ssM, ssX, ctX, pkX) {
  // SHA3-256(ss_M || ss_X || ct_X || pk_X || XWING_LABEL) = 32 + 32 + 32 + 32 + 6 = 134 bytes
  const buf = new Uint8Array(134);
  buf.set(ssM, 0);
  buf.set(ssX, 32);
  buf.set(ctX, 64);
  buf.set(pkX, 96);
  buf.set(XWING_LABEL, 128);
  return sha3_256(buf);
}

export function xwingEncapsDeterministic(pk1216, ephemSeed64) {
  if (pk1216.length !== 1216) {
    throw new Error('X-Wing public key must be 1216 bytes');
  }
  if (ephemSeed64.length !== 64) {
    throw new Error('X-Wing encapsulation seed must be 64 bytes');
  }
  const pkM = pk1216.subarray(0, 1184);
  const pkX = pk1216.subarray(1184, 1216);

  const m = ephemSeed64.subarray(0, 32);
  const ekX = ephemSeed64.subarray(32, 64);

  const ctX = x25519Base(ekX);
  const ssX = x25519(ekX, pkX);
  const { ciphertext: ctM, sharedSecret: ssM } = mlkem768EncapsInternal(pkM, m);

  const sharedSecret = combineSharedSecrets(ssM, ssX, ctX, pkX);
  const ciphertext = new Uint8Array(1120);
  ciphertext.set(ctM, 0);
  ciphertext.set(ctX, 1088);

  return { ciphertext, sharedSecret };
}

export function xwingDecaps(skSeed32, ct1120) {
  if (ct1120.length !== 1120) {
    throw new Error('X-Wing ciphertext must be 1120 bytes');
  }
  const { skM, skX, pkX } = expandDecapsulationKey(skSeed32);
  const ctM = ct1120.subarray(0, 1088);
  const ctX = ct1120.subarray(1088, 1120);

  const ssM = mlkem768DecapsInternal(skM, ctM);
  const ssX = x25519(skX, ctX);

  return combineSharedSecrets(ssM, ssX, ctX, pkX);
}

