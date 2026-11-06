/**
 * ZubQuant ZPQ1 Unified Wire Envelope (X-Wing Hybrid KEM + HKDF-SHA256 + AES-256-GCM + ML-DSA-65)
 * Works identically across Browser WebCrypto, Node.js, Cloudflare Workers, PHP, Laravel, and WordPress.
 */

import { xwingKeyGenFromSeed, xwingEncapsDeterministic, xwingDecaps } from './xwing.js';
import { mldsaKeyGen, mldsaSign, mldsaVerify } from './mldsa65.js';

const PUB_PREFIX = 'zpq1_pub_';
const SEC_PREFIX = 'zpq1_sec_';
const VFY_PREFIX = 'zpq1_vfy_';
const SIG_PREFIX = 'zpq1_sig_';
const HKDF_INFO = new TextEncoder().encode('zubquant-zpq1-xwing-aes256gcm');

function getWebCrypto() {
  if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle) {
    return globalThis.crypto;
  }
  throw new Error('WebCrypto API (globalThis.crypto.subtle) is required');
}

export function randomBytes(len) {
  const out = new Uint8Array(len);
  getWebCrypto().getRandomValues(out);
  return out;
}

export function toBase64Url(bytes) {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64url');
  }
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(str) {
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(str, 'base64url'));
  }
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

async function deriveAesKeyFromSharedSecret(sharedSecret32, salt12) {
  const crypto = getWebCrypto();
  const baseKey = await crypto.subtle.importKey(
    'raw',
    sharedSecret32,
    'HKDF',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt12,
      info: HKDF_INFO
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Generates an X-Wing Hybrid Post-Quantum KeyPair (ML-KEM-768 + X25519).
 * @param {Uint8Array} [seed32] Optional 32-byte deterministic seed.
 */
export function generateKeyPair(seed32) {
  const seed = seed32 ? new Uint8Array(seed32) : randomBytes(32);
  const { publicKey, privateKey } = xwingKeyGenFromSeed(seed);
  return {
    publicKey: PUB_PREFIX + toBase64Url(publicKey),
    privateKey: SEC_PREFIX + toBase64Url(privateKey)
  };
}

/**
 * Seals (encrypts) a string, JSON object, or Uint8Array using the recipient's X-Wing Public Key.
 * Output format: zpq1.xwing-aes256gcm.<kem_ct>.<nonce>.<ciphertext_and_tag>
 */
export async function seal(data, publicKeyStr, options = {}) {
  if (typeof publicKeyStr !== 'string' || !publicKeyStr.startsWith(PUB_PREFIX)) {
    throw new Error('Invalid ZubQuant public key (expected prefix zpq1_pub_)');
  }
  const pkBytes = fromBase64Url(publicKeyStr.slice(PUB_PREFIX.length));
  const ephemSeed = options.ephemeralSeed || randomBytes(64);
  const nonce = options.nonce || randomBytes(12);

  const { ciphertext: kemCt, sharedSecret } = xwingEncapsDeterministic(pkBytes, ephemSeed);
  const aesKey = await deriveAesKeyFromSharedSecret(sharedSecret, nonce);

  let plaintextBytes;
  if (data instanceof Uint8Array) {
    plaintextBytes = data;
  } else if (typeof data === 'string') {
    plaintextBytes = new TextEncoder().encode(data);
  } else {
    plaintextBytes = new TextEncoder().encode(JSON.stringify(data));
  }

  const aadBytes = options.aad
    ? (typeof options.aad === 'string' ? new TextEncoder().encode(options.aad) : options.aad)
    : new TextEncoder().encode('zpq1.xwing-aes256gcm');

  const encryptedBuf = await getWebCrypto().subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
      additionalData: aadBytes,
      tagLength: 128
    },
    aesKey,
    plaintextBytes
  );

  const ctAndTag = new Uint8Array(encryptedBuf);
  return [
    'zpq1',
    'xwing-aes256gcm',
    toBase64Url(kemCt),
    toBase64Url(nonce),
    toBase64Url(ctAndTag)
  ].join('.');
}

/**
 * Opens (decrypts) a ZPQ1 sealed envelope using the recipient's X-Wing Private Key.
 */
export async function open(envelope, privateKeyStr, options = {}) {
  if (typeof privateKeyStr !== 'string' || !privateKeyStr.startsWith(SEC_PREFIX)) {
    throw new Error('Invalid ZubQuant private key (expected prefix zpq1_sec_)');
  }
  if (typeof envelope !== 'string') {
    throw new Error('Invalid ZPQ1 envelope');
  }
  const parts = envelope.split('.');
  if (parts.length !== 5 || parts[0] !== 'zpq1' || parts[1] !== 'xwing-aes256gcm') {
    throw new Error('Unsupported or malformed ZPQ1 envelope header');
  }

  const skSeed = fromBase64Url(privateKeyStr.slice(SEC_PREFIX.length));
  const kemCt = fromBase64Url(parts[2]);
  const nonce = fromBase64Url(parts[3]);
  const ctAndTag = fromBase64Url(parts[4]);

  const sharedSecret = xwingDecaps(skSeed, kemCt);
  const aesKey = await deriveAesKeyFromSharedSecret(sharedSecret, nonce);

  const aadBytes = options.aad
    ? (typeof options.aad === 'string' ? new TextEncoder().encode(options.aad) : options.aad)
    : new TextEncoder().encode('zpq1.xwing-aes256gcm');

  const decryptedBuf = await getWebCrypto().subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
      additionalData: aadBytes,
      tagLength: 128
    },
    aesKey,
    ctAndTag
  );

  const bytes = new Uint8Array(decryptedBuf);
  if (options.returnBytes) {
    return bytes;
  }
  const text = new TextDecoder().decode(bytes);
  if (options.parseJson) {
    return JSON.parse(text);
  }
  return text;
}

/**
 * Wraps a ZubQuant private key with a passphrase using PBKDF2-SHA256 (600,000 iterations) + AES-256-GCM.
 */
export async function protectPrivateKey(privateKeyStr, passphrase, iterations = 600000) {
  if (!privateKeyStr.startsWith(SEC_PREFIX) && !privateKeyStr.startsWith(SIG_PREFIX)) {
    throw new Error('Invalid ZubQuant secret key');
  }
  const crypto = getWebCrypto();
  const salt = randomBytes(16);
  const nonce = randomBytes(12);
  const passBytes = new TextEncoder().encode(passphrase);

  const baseKey = await crypto.subtle.importKey('raw', passBytes, 'PBKDF2', false, ['deriveKey']);
  const aesKey = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: 'SHA-256'
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  const ctBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 },
    aesKey,
    new TextEncoder().encode(privateKeyStr)
  );

  return [
    'zpq1',
    'locked-key',
    String(iterations),
    toBase64Url(salt),
    toBase64Url(nonce),
    toBase64Url(new Uint8Array(ctBuf))
  ].join('.');
}

/**
 * Unlocks a passphrase-protected ZubQuant private key.
 */
export async function unlockPrivateKey(lockedEnvelope, passphrase) {
  const parts = lockedEnvelope.split('.');
  if (parts.length !== 6 || parts[0] !== 'zpq1' || parts[1] !== 'locked-key') {
    throw new Error('Invalid locked key format');
  }
  const iterations = parseInt(parts[2], 10);
  const salt = fromBase64Url(parts[3]);
  const nonce = fromBase64Url(parts[4]);
  const ct = fromBase64Url(parts[5]);

  const crypto = getWebCrypto();
  const baseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  const aesKey = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: 'SHA-256'
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  const plainBuf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 },
    aesKey,
    ct
  );
  return new TextDecoder().decode(new Uint8Array(plainBuf));
}

/**
 * Generates an ML-DSA-65 (NIST FIPS 204) Post-Quantum Digital Signature KeyPair.
 */
export function generateSigningKeyPair(seed32) {
  const seed = seed32 ? new Uint8Array(seed32) : randomBytes(32);
  const { verifyKey, signingKey } = mldsaKeyGen(seed);
  return {
    verifyKey: VFY_PREFIX + toBase64Url(verifyKey),
    signingKey: SIG_PREFIX + toBase64Url(signingKey)
  };
}

/**
 * Signs a string, JSON object, or Uint8Array using ML-DSA-65.
 * Output format: zpq1.mldsa65.<base64url(payload)>.<base64url(signature)>
 */
export function sign(payload, signingKeyStr) {
  if (typeof signingKeyStr !== 'string' || !signingKeyStr.startsWith(SIG_PREFIX)) {
    throw new Error('Invalid ZubQuant signing key (expected prefix zpq1_sig_)');
  }
  const seed = fromBase64Url(signingKeyStr.slice(SIG_PREFIX.length));
  let payloadBytes;
  if (payload instanceof Uint8Array) {
    payloadBytes = payload;
  } else if (typeof payload === 'string') {
    payloadBytes = new TextEncoder().encode(payload);
  } else {
    payloadBytes = new TextEncoder().encode(JSON.stringify(payload));
  }

  const sigBytes = mldsaSign(seed, payloadBytes);
  return ['zpq1', 'mldsa65', toBase64Url(payloadBytes), toBase64Url(sigBytes)].join('.');
}

/**
 * Verifies an ML-DSA-65 signed token using the public verification key.
 */
export function verify(signedToken, verifyKeyStr, options = {}) {
  if (typeof verifyKeyStr !== 'string' || !verifyKeyStr.startsWith(VFY_PREFIX)) {
    throw new Error('Invalid ZubQuant verify key (expected prefix zpq1_vfy_)');
  }
  if (typeof signedToken !== 'string') {
    return { valid: false, payload: null };
  }
  const parts = signedToken.split('.');
  if (parts.length !== 4 || parts[0] !== 'zpq1' || parts[1] !== 'mldsa65') {
    return { valid: false, payload: null };
  }
  const verifyKeyBytes = fromBase64Url(verifyKeyStr.slice(VFY_PREFIX.length));
  const payloadBytes = fromBase64Url(parts[2]);
  const sigBytes = fromBase64Url(parts[3]);

  const valid = mldsaVerify(verifyKeyBytes, payloadBytes, sigBytes);
  if (!valid) {
    return { valid: false, payload: null };
  }
  if (options.returnBytes) {
    return { valid: true, payload: payloadBytes };
  }
  const text = new TextDecoder().decode(payloadBytes);
  return {
    valid: true,
    payload: options.parseJson ? JSON.parse(text) : text
  };
}

