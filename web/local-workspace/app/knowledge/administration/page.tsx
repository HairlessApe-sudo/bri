import { headers } from 'next/headers';
import { reviewModeHeader } from '../../../review-mode.mjs';
import { AdministrationWorkspace } from './workspace';

export default async function AdministrationPage() {
  const enabled = (await headers()).get(reviewModeHeader) === 'enabled';
  return <section aria-labelledby="administration-title">
    <h1 id="administration-title">Knowledge Administration</h1>
    <p>Submit classified files and check exact submission jobs. Review and evidence remain in their existing workspaces.</p>
    <nav aria-label="Knowledge administration navigation">
      <ul>
        <li><a href="/knowledge/search">Knowledge Interface</a></li>
        <li><a href="/review">CSV review queue</a></li>
        <li><a href="/xlsx/review">XLSX review queue</a></li>
      </ul>
    </nav>
    <p>To request a metadata correction, open exact version evidence in the Knowledge Interface.</p>
    {enabled ? <AdministrationWorkspace /> : <p>Classified submission and My Submissions are disabled in this local mode.</p>}
  </section>;
}
