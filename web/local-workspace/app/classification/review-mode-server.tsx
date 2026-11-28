import 'server-only';
import { headers } from 'next/headers';
import type { ReactNode } from 'react';
import { reviewModeHeader } from '../../review-mode.mjs';
import { ReviewMetadataMode } from './initial-review';

export async function ReviewRouteLayout({ children }: { children: ReactNode }) {
  // The private bridge overwrites this value on every request it dispatches to Next.
  // Without the bridge's explicit off marker, retain the protected discovery gate.
  const required = (await headers()).get(reviewModeHeader) !== 'disabled';
  return <ReviewMetadataMode required={required}>{children}</ReviewMetadataMode>;
}