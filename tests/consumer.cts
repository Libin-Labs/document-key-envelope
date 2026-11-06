import packageExports = require('@lp-labs/document-key-envelope');
import type { DocumentKeyEnvelope } from '@lp-labs/document-key-envelope';
const runtimeExports: unknown[] = [
  packageExports.wrapDocumentKey,
  packageExports.unwrapDocumentKey,
  packageExports.copyDocumentKeyEnvelope,
];
type PublicTypes = DocumentKeyEnvelope;
void runtimeExports;
let publicType!: PublicTypes;
void publicType;
