import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { copyDocumentKeyEnvelope, unwrapDocumentKey, wrapDocumentKey } from '../dist/esm/index.js';

test('AES-KW wraps and unwraps a 256-bit AES-GCM key without returning key bytes', async () => {
  const wrapping = await webcrypto.subtle.generateKey({ name: 'AES-KW', length: 256 }, false, [
    'wrapKey',
    'unwrapKey',
  ]);
  const documentKey = await webcrypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ]);
  const envelope = await wrapDocumentKey(documentKey, wrapping, webcrypto.subtle);
  assert.equal(envelope.algorithm, 'AES-KW');
  const clone = copyDocumentKeyEnvelope(envelope);
  envelope.wrappedKey.fill(0);
  const unwrapped = await unwrapDocumentKey(clone, wrapping, webcrypto.subtle);
  assert.equal(unwrapped.extractable, false);
  const iv = new Uint8Array(12);
  const ciphertext = await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    documentKey,
    new Uint8Array([5, 6]),
  );
  assert.deepEqual(
    new Uint8Array(await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv }, unwrapped, ciphertext)),
    new Uint8Array([5, 6]),
  );
  const tampered = copyDocumentKeyEnvelope(clone);
  tampered.wrappedKey[0] ^= 1;
  await assert.rejects(unwrapDocumentKey(tampered, wrapping, webcrypto.subtle));
});

test('RSA-OAEP wraps and unwraps and wrong wrapping key fails', async () => {
  const pair = await webcrypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    false,
    ['wrapKey', 'unwrapKey'],
  );
  const key = await webcrypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ]);
  const envelope = await wrapDocumentKey(key, pair.publicKey, webcrypto.subtle);
  assert.equal(envelope.algorithm, 'RSA-OAEP');
  const unwrapped = await unwrapDocumentKey(envelope, pair.privateKey, webcrypto.subtle);
  const iv = new Uint8Array(12);
  const ciphertext = await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new Uint8Array([9]),
  );
  assert.deepEqual(
    new Uint8Array(await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv }, unwrapped, ciphertext)),
    new Uint8Array([9]),
  );
  const wrongPair = await webcrypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    false,
    ['wrapKey', 'unwrapKey'],
  );
  await assert.rejects(unwrapDocumentKey(envelope, wrongPair.privateKey, webcrypto.subtle));
  await assert.rejects(
    unwrapDocumentKey({ ...envelope, version: 2 }, pair.privateKey, webcrypto.subtle),
    /Unsupported/,
  );
});

test('rejects wrong key types, non-extractable content keys and malformed envelopes', async () => {
  const wrap = await webcrypto.subtle.generateKey({ name: 'AES-KW', length: 256 }, false, [
    'wrapKey',
    'unwrapKey',
  ]);
  const key = await webcrypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);
  await assert.rejects(wrapDocumentKey(key, wrap, webcrypto.subtle), /extractable/);
  await assert.rejects(
    unwrapDocumentKey(
      { version: 1, algorithm: 'AES-KW', keyAlgorithm: 'AES-GCM', wrappedKey: new Uint8Array([1]) },
      wrap,
      webcrypto.subtle,
    ),
    /Wrapped key/,
  );
});
