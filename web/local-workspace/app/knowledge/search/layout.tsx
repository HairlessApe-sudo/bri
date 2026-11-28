import { headers } from 'next/headers';
import type { ReactNode } from 'react';
import { reviewModeHeader } from '../../../review-mode.mjs';
import { EvidenceCorrectionMode } from './evidence-correction';

export default async function SearchLayout({ children }: { children: ReactNode }) {
  const enabled = (await headers()).get(reviewModeHeader) === 'enabled';
  return <EvidenceCorrectionMode enabled={enabled}>{children}</EvidenceCorrectionMode>;
}
