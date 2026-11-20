import type { SourceReference } from '@/lib/api';

type DigestAndLines = Pick<SourceReference, 'content_sha256' | 'original_sha256' | 'csv_first_line' | 'csv_last_line'>;

function isPhysicalLine(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

export function SourceProvenance({ source, showLegacyDigest = false }: { source: DigestAndLines; showLegacyDigest?: boolean }) {
  const { original_sha256: original, content_sha256: content, csv_first_line: first, csv_last_line: last } = source;
  const hasOriginal = typeof original === 'string' && /^[0-9a-f]{64}$/i.test(original);
  const lines = isPhysicalLine(first) && isPhysicalLine(last) && first <= last
    ? (first === last ? String(first) : `${first}–${last}`) : null;
  const hasCsvProvenance = hasOriginal || lines !== null;
  if (!hasCsvProvenance && !showLegacyDigest) return null;

  return <dl className="provenance-grid">
    {lines !== null && <div><dt>Physical CSV lines (inclusive)</dt><dd>{lines}</dd></div>}
    {hasOriginal && <div className="hash-field"><dt>Original CSV bytes SHA-256</dt><dd className="mono breakable">{original}</dd></div>}
    <div className="hash-field"><dt>{hasCsvProvenance ? 'Extracted content SHA-256' : 'Content SHA-256'}</dt><dd className="mono breakable">{content}</dd></div>
  </dl>;
}
