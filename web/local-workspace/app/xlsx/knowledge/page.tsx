'use client';

import { useState } from 'react';
import { xlsxUuid } from '../../../xlsx-intake.mjs';

export default function XlsxRecordLookupPage() {
  const [invalid, setInvalid] = useState(false);
  return <>
    <h1>Published XLSX records</h1>
    <p><a href="/xlsx">← XLSX intake</a></p>
    <p>Open a known record ID. A current authorized session is required for the record and for its exact worksheet evidence.</p>
    <form className="content-panel" onSubmit={(event) => {
      event.preventDefault();
      const id = new FormData(event.currentTarget).get('record');
      if (typeof id === 'string' && xlsxUuid.test(id)) window.location.assign(`/xlsx/knowledge/${id}`);
      else setInvalid(true);
    }}>
      <label>Record ID <input name="record" required maxLength={36} autoComplete="off" onChange={() => setInvalid(false)} /></label>{' '}
      <button type="submit">Open record</button>
    </form>
    {invalid && <p role="alert">Enter a valid XLSX record ID.</p>}
  </>;
}
