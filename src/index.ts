export interface DocumentKeyEnvelope {
  version: 1;
  algorithm: 'AES-KW' | 'RSA-OAEP';
  keyAlgorithm: 'AES-GCM';
  wrappedKey: Uint8Array;
}

function subtleProvider(value?: SubtleCrypto): SubtleCrypto {
  const subtle = value ?? globalThis.crypto?.subtle;
  if (!subtle) throw new Error('WebCrypto SubtleCrypto is unavailable.');
  return subtle;
}

function source(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function envelope(value: DocumentKeyEnvelope): DocumentKeyEnvelope {
  if (
    !value ||
    typeof value !== 'object' ||
    value.version !== 1 ||
    value.keyAlgorithm !== 'AES-GCM'
  )
    throw new TypeError('Unsupported document key envelope version or key algorithm.');
  if (value.algorithm !== 'AES-KW' && value.algorithm !== 'RSA-OAEP')
    throw new TypeError('Unsupported key wrapping algorithm.');
  if (
    !(value.wrappedKey instanceof Uint8Array) ||
    value.wrappedKey.length < 16 ||
    value.wrappedKey.length > 8192
  )
    throw new TypeError('Wrapped key bytes are invalid.');
  return {
    version: 1,
    algorithm: value.algorithm,
    keyAlgorithm: 'AES-GCM',
    wrappedKey: new Uint8Array(value.wrappedKey),
  };
}

export async function wrapDocumentKey(
  documentKey: CryptoKey,
  wrappingKey: CryptoKey,
  subtleInput?: SubtleCrypto,
): Promise<DocumentKeyEnvelope> {
  if (
    !documentKey ||
    documentKey.algorithm?.name !== 'AES-GCM' ||
    !('length' in documentKey.algorithm) ||
    documentKey.algorithm.length !== 256
  )
    throw new TypeError('Document key must be a 256-bit AES-GCM key.');
  const subtle = subtleProvider(subtleInput);
  const name = wrappingKey?.algorithm?.name;
  if (name !== 'AES-KW' && name !== 'RSA-OAEP')
    throw new TypeError('Wrapping key must use AES-KW or RSA-OAEP.');
  if (!documentKey.extractable)
    throw new TypeError(
      'Document key must be extractable for WebCrypto wrapKey; key bytes are never returned.',
    );
  if (!wrappingKey.usages.includes('wrapKey'))
    throw new TypeError('Wrapping key lacks wrapKey usage.');
  const wrappedKey = new Uint8Array(
    await subtle.wrapKey('raw', documentKey, wrappingKey, { name }),
  );
  return Object.freeze({ version: 1, algorithm: name, keyAlgorithm: 'AES-GCM', wrappedKey });
}

export async function unwrapDocumentKey(
  input: DocumentKeyEnvelope,
  wrappingKey: CryptoKey,
  subtleInput?: SubtleCrypto,
): Promise<CryptoKey> {
  const value = envelope(input);
  if (!wrappingKey || wrappingKey.algorithm?.name !== value.algorithm)
    throw new TypeError('Wrapping key algorithm does not match the envelope.');
  if (!wrappingKey.usages.includes('unwrapKey'))
    throw new TypeError('Unwrapping key lacks unwrapKey usage.');
  const subtle = subtleProvider(subtleInput);
  return subtle.unwrapKey(
    'raw',
    source(value.wrappedKey),
    wrappingKey,
    { name: value.algorithm },
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export function copyDocumentKeyEnvelope(input: DocumentKeyEnvelope): DocumentKeyEnvelope {
  return Object.freeze(envelope(input));
}
