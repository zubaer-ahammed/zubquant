import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  sha3_256,
  sha3_512,
  shake128,
  shake256,
  x25519,
  x25519Base,
  mlkem768KeygenInternal,
  mlkem768EncapsInternal,
  mlkem768DecapsInternal,
  xwingKeyGenFromSeed,
  xwingEncapsDeterministic,
  xwingDecaps,
  generateKeyPair,
  seal,
  open,
  protectPrivateKey,
  unlockPrivateKey,
  generateSigningKeyPair,
  sign,
  verify,
  toBase64Url
} from '../src/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

test('FIPS 202 Keccak (SHA3-256, SHA3-512, SHAKE128, SHAKE256) matches Node OpenSSL crypto', () => {
  const msg = new TextEncoder().encode('ZubQuant Post-Quantum Test Vector 2026');

  const expectedSha3_256 = new Uint8Array(crypto.createHash('sha3-256').update(msg).digest());
  const expectedSha3_512 = new Uint8Array(crypto.createHash('sha3-512').update(msg).digest());
  const expectedShake128 = new Uint8Array(crypto.createHash('shake128', { outputLength: 64 }).update(msg).digest());
  const expectedShake256 = new Uint8Array(crypto.createHash('shake256', { outputLength: 96 }).update(msg).digest());

  assert.deepEqual(sha3_256(msg), expectedSha3_256);
  assert.deepEqual(sha3_512(msg), expectedSha3_512);
  assert.deepEqual(shake128(msg, 64), expectedShake128);
  assert.deepEqual(shake256(msg, 96), expectedShake256);
});

test('RFC 7748 X25519 scalar multiplication matches RFC 7748 Section 6.1 test vector', () => {
  const alicePrivate = Buffer.from(
    '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
    'hex'
  );
  const expectedAlicePublic = Buffer.from(
    '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
    'hex'
  );
  const bobPrivate = Buffer.from(
    '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb',
    'hex'
  );
  const expectedBobPublic = Buffer.from(
    'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f',
    'hex'
  );
  const expectedShared = Buffer.from(
    '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742',
    'hex'
  );

  const alicePub = x25519Base(alicePrivate);
  const bobPub = x25519Base(bobPrivate);
  assert.deepEqual(Buffer.from(alicePub), expectedAlicePublic);
  assert.deepEqual(Buffer.from(bobPub), expectedBobPublic);

  const sharedAB = x25519(alicePrivate, bobPub);
  const sharedBA = x25519(bobPrivate, alicePub);
  assert.deepEqual(Buffer.from(sharedAB), expectedShared);
  assert.deepEqual(Buffer.from(sharedBA), expectedShared);
});

test('NIST FIPS 203 ML-KEM-768 encapsulation, decapsulation, and implicit rejection', () => {
  const d = new Uint8Array(32).fill(0x11);
  const z = new Uint8Array(32).fill(0x22);
  const m = new Uint8Array(32).fill(0x33);

  const { ek, dk } = mlkem768KeygenInternal(d, z);
  assert.equal(ek.length, 1184);
  assert.equal(dk.length, 2400);

  const { ciphertext, sharedSecret } = mlkem768EncapsInternal(ek, m);
  assert.equal(ciphertext.length, 1088);
  assert.equal(sharedSecret.length, 32);

  const decapsulated = mlkem768DecapsInternal(dk, ciphertext);
  assert.deepEqual(decapsulated, sharedSecret);

  // Tampered ciphertext triggers FIPS 203 implicit rejection (returns pseudo-random key != sharedSecret)
  const tamperedCt = new Uint8Array(ciphertext);
  tamperedCt[100] ^= 0xff;
  const rejectedSecret = mlkem768DecapsInternal(dk, tamperedCt);
  assert.notDeepEqual(rejectedSecret, sharedSecret);
});

test('IETF X-Wing Hybrid KEM (ML-KEM-768 + X25519) roundtrip', () => {
  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i++) seed[i] = i + 1;
  const ephem = new Uint8Array(64);
  for (let i = 0; i < 64; i++) ephem[i] = 100 + i;

  const { publicKey, privateKey } = xwingKeyGenFromSeed(seed);
  assert.equal(publicKey.length, 1216);
  assert.equal(privateKey.length, 32);

  const { ciphertext, sharedSecret } = xwingEncapsDeterministic(publicKey, ephem);
  assert.equal(ciphertext.length, 1120);
  assert.equal(sharedSecret.length, 32);

  const recovered = xwingDecaps(privateKey, ciphertext);
  assert.deepEqual(recovered, sharedSecret);
});

test('ZPQ1 High-Level Envelope seal(), open(), protectPrivateKey(), and ML-DSA-65 sign()/verify()', async () => {
  const seed = new Uint8Array(32);
  for (let i = 0; i < 32; i++) seed[i] = i + 1;
  const ephemSeed = new Uint8Array(64);
  for (let i = 0; i < 64; i++) ephemSeed[i] = 0x40 + i;
  const nonce = new Uint8Array(12);
  for (let i = 0; i < 12; i++) nonce[i] = 0x80 + i;

  const kp = generateKeyPair(seed);
  assert.ok(kp.publicKey.startsWith('zpq1_pub_'));
  assert.ok(kp.privateKey.startsWith('zpq1_sec_'));

  const payloadObj = {
    form: 'Ninja Forms Medical Intake',
    patient: 'Md. Zubaer Ahammed',
    diagnosis: 'Quantum-Safe Verified',
    year: 2026
  };

  const envelope = await seal(payloadObj, kp.publicKey, {
    ephemeralSeed: ephemSeed,
    nonce
  });
  assert.ok(envelope.startsWith('zpq1.xwing-aes256gcm.'));

  const openedObj = await open(envelope, kp.privateKey, { parseJson: true });
  assert.deepEqual(openedObj, payloadObj);

  // Passphrase protection roundtrip
  const lockedKey = await protectPrivateKey(kp.privateKey, 'CorrectHorseBatteryStaple!', 10000);
  assert.ok(lockedKey.startsWith('zpq1.locked-key.10000.'));
  const unlockedKey = await unlockPrivateKey(lockedKey, 'CorrectHorseBatteryStaple!');
  assert.equal(unlockedKey, kp.privateKey);

  // ML-DSA-65 Digital Signature roundtrip
  const sigSeed = new Uint8Array(32);
  for (let i = 0; i < 32; i++) sigSeed[i] = 200 - i;
  const sigKp = generateSigningKeyPair(sigSeed);
  const licensePayload = {
    product: 'zubquant-pro',
    domain: 'zubaer.com',
    tier: 'agency',
    expires: '2028-12-31'
  };

  const signedToken = sign(licensePayload, sigKp.signingKey);
  assert.ok(signedToken.startsWith('zpq1.mldsa65.'));

  const verified = verify(signedToken, sigKp.verifyKey, { parseJson: true });
  assert.equal(verified.valid, true);
  assert.deepEqual(verified.payload, licensePayload);

  // Tamper test on signature
  const parts = signedToken.split('.');
  const tamperedToken = [parts[0], parts[1], toBase64Url(new TextEncoder().encode('{"tampered":true}')), parts[3]].join('.');
  const tamperedResult = verify(tamperedToken, sigKp.verifyKey);
  assert.equal(tamperedResult.valid, false);

  // Save deterministic cross-language test vectors to spec/test-vectors.json for PHP verification
  const specDir = path.resolve(__dirname, '../../../spec');
  fs.mkdirSync(specDir, { recursive: true });
  const vectors = {
    version: 'zpq1',
    kemSeedHex: Buffer.from(seed).toString('hex'),
    ephemeralSeedHex: Buffer.from(ephemSeed).toString('hex'),
    nonceHex: Buffer.from(nonce).toString('hex'),
    publicKey: kp.publicKey,
    privateKey: kp.privateKey,
    plaintextJson: JSON.stringify(payloadObj),
    envelope,
    lockedKeyPassphrase: 'CorrectHorseBatteryStaple!',
    lockedKey,
    sigSeedHex: Buffer.from(sigSeed).toString('hex'),
    verifyKey: sigKp.verifyKey,
    signingKey: sigKp.signingKey,
    licensePayloadJson: JSON.stringify(licensePayload),
    signedToken
  };
  fs.writeFileSync(path.join(specDir, 'test-vectors.json'), JSON.stringify(vectors, null, 2), 'utf8');
});

