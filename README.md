# @lp-labs/document-key-envelope

Wrap an AES-256-GCM document `CryptoKey` with WebCrypto AES-KW or RSA-OAEP and unwrap it as a
non-extractable encryption key. The envelope is versioned and records the wrapping algorithm; raw
document key bytes are never returned by this API.

## Install

```bash
npm install @lp-labs/document-key-envelope
```

No runtime or peer dependencies; ESM, CommonJS, and declarations are included.

## Quickstart

```js
import { webcrypto } from 'node:crypto';
import { unwrapDocumentKey, wrapDocumentKey } from '@lp-labs/document-key-envelope';

const wrappingKey = await webcrypto.subtle.generateKey({ name: 'AES-KW', length: 256 }, false, [
  'wrapKey',
  'unwrapKey',
]);
const documentKey = await webcrypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
  'encrypt',
  'decrypt',
]);
const envelope = await wrapDocumentKey(documentKey, wrappingKey);
const restored = await unwrapDocumentKey(envelope, wrappingKey);
if (restored.extractable) throw new Error('Unwrapped key must be non-extractable');
```

## API and customization

`wrapDocumentKey(documentKey, wrappingKey, subtle?)` returns a version 1
`DocumentKeyEnvelope` (`AES-KW` or `RSA-OAEP`, `AES-GCM`, wrapped bytes).
`unwrapDocumentKey(envelope, unwrappingKey, subtle?)` returns a non-extractable 256-bit AES-GCM
`CryptoKey` with encrypt/decrypt usages. `copyDocumentKeyEnvelope` validates and clones an
envelope. `DocumentKeyEnvelope` is the TypeScript export. Omit `subtle` to use global WebCrypto or
inject `SubtleCrypto`.

Wrapping requires an extractable input `CryptoKey` because the WebCrypto `wrapKey` operation
requires export internally; this library never exposes those key bytes. AES-KW requires a compatible
key with wrap/unwrap usage; RSA-OAEP requires a compatible public/private pair. Unsupported
versions, mismatched key algorithms, invalid envelope sizes, or cryptographic failures reject.

## Runtime and scope

Requires WebCrypto `wrapKey`/`unwrapKey` support for AES-KW and/or RSA-OAEP. The caller provisions,
stores, rotates, and authorizes wrapping keys and should protect envelopes as sensitive data. This
does not provide a key-management service, password derivation, native PDF encryption, or trust
validation.

## Exports

Runtime: `wrapDocumentKey`, `unwrapDocumentKey`, `copyDocumentKeyEnvelope`.
Type: `DocumentKeyEnvelope`.

## Support

If this library is useful to you, consider supporting its maintenance with a [donation via PayPal](https://www.paypal.me/LibinPrasanth).

## Author

Created by [Libin Prasanth](https://www.linkedin.com/in/libinprasanth/). Connect on LinkedIn for updates and discussion.
