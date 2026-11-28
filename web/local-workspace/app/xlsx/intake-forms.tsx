'use client';

import type { FormEvent } from 'react';

export function IntakeForms({ onUpload, onStatus, disabled }: {
  onUpload: (file: File, node: string) => void;
  onStatus: (id: string) => void;
  disabled?: boolean;
}) {
  function upload(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const file = form.get('workbook');
    if (file instanceof File) onUpload(file, String(form.get('node')));
  }
  function status(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    onStatus(String(new FormData(event.currentTarget).get('job')));
  }
  return <>
    <form className="content-panel" onSubmit={upload}>
      <fieldset disabled={disabled}>
        <legend>Submit a legacy unclassified workbook</legend>
        <p><label>Node ID <input name="node" required maxLength={128} autoComplete="off" /></label></p>
        <p><label>Workbook <input name="workbook" type="file" accept=".xlsx" required /></label></p>
        <button type="submit">Upload workbook</button>
      </fieldset>
    </form>
    <form className="content-panel" onSubmit={status}>
      <fieldset disabled={disabled}>
        <legend>Check an existing submission</legend>
        <label>Job ID <input name="job" required maxLength={36} autoComplete="off" /></label>{' '}
        <button type="submit">Check job status</button>
      </fieldset>
    </form>
  </>;
}
