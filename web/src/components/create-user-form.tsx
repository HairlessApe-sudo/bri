'use client';

import { useState, type FormEvent } from 'react';
import { CreateUserFields } from '@/components/create-user-fields';
import { isDirectoryUserId } from '@/lib/user-directory.mjs';

const provisioningPath = '/v1/users/provisioning';
const maxDisplayNameLength = 128;
const emailPattern = /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+$/i;
export const provisioningStatusCopy = {
  pending_setup: 'Pending setup — the account is not active.',
  inviting: 'Invitation in progress — sending has not been confirmed.',
  invitation_sent: 'Invitation sent — setup is still required; the account is not active.',
  invitation_retryable: 'Invitation marked retryable — sending is not confirmed. This screen does not resend invitations.',
  invitation_unresolved: 'Invitation outcome unknown — do not assume it was sent or resend it.',
  active: 'Active — account setup is complete.',
} as const;

type Transport = (path: string, options: RequestInit) => Promise<Response>;
type Receipt = { id: string; status: keyof typeof provisioningStatusCopy };
type View = { attempted: boolean; busy: boolean; error?: string; receipt?: Receipt };
const initialView: View = { attempted: false, busy: false };

async function readReceipt(response: Response): Promise<Receipt> {
  if (!response.ok) throw new Error('Provisioning response unavailable');
  const result: unknown = await response.json();
  if (!result || typeof result !== 'object' || Object.keys(result).length !== 2 ||
      !('id' in result) || typeof result.id !== 'string' || !isDirectoryUserId(result.id) ||
      !('status' in result) || typeof result.status !== 'string' || !Object.hasOwn(provisioningStatusCopy, result.status)) {
    throw new Error('Invalid provisioning response');
  }
  return { id: result.id, status: result.status as Receipt['status'] };
}

// Only the local test harness imports this form. No default transport or release wiring.
export function createProvisioningFlow(transport: Transport, show: (view: View) => void) {
  let view = initialView;
  let body: string | undefined;
  let requestKey: string | undefined;
  function update(next: Partial<View>) {
    view = { ...view, ...next };
    show(view);
  }

  async function submit(name: string, address: string) {
    if (view.busy || view.receipt) return;
    if (!body) {
      const display_name = name.trim();
      const email = address.trim();
      if (!display_name || [...display_name].length > maxDisplayNameLength || /\p{Cc}/u.test(display_name)) {
        update({ error: `Enter a display name between 1 and ${maxDisplayNameLength} characters without control characters.` });
        return;
      }
      if (email.length > 254 || !emailPattern.test(email)) {
        update({ error: 'Enter a valid email address.' });
        return;
      }
      requestKey = crypto.randomUUID();
      body = JSON.stringify({ request_id: requestKey, display_name, email });
    }
    update({ attempted: true, busy: true, error: undefined });
    try {
      const receipt = await readReceipt(await transport(provisioningPath, {
        method: 'POST', body, headers: { 'Content-Type': 'application/json' },
      }));
      body = undefined;
      update({ receipt, busy: false });
    } catch {
      update({ error: 'Could not confirm the request. Retrying uses the same request and does not start a new one.', busy: false });
    }
  }

  async function checkStatus() {
    if (view.busy || !view.receipt || !requestKey) return;
    const { id } = view.receipt;
    update({ busy: true, error: undefined });
    try {
      const receipt = await readReceipt(await transport(`${provisioningPath}/${requestKey}`, { method: 'GET' }));
      if (receipt.id.toLowerCase() !== id.toLowerCase()) throw new Error('Unexpected provisioning ID');
      update({ receipt, busy: false });
    } catch {
      update({ error: 'Could not check the current status. The last confirmed status is shown below.', busy: false });
    }
  }

  return { submit, checkStatus };
}

export function CreateUserForm({ transport }: { transport: Transport }) {
  const [view, show] = useState(initialView);
  const [flow] = useState(() => createProvisioningFlow(transport, show));
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    void flow.submit(String(data.get('display_name') ?? ''), String(data.get('email') ?? ''));
  }
  return <form className="auth-form directory-create" aria-label="Create user" method="post" onSubmit={submit} noValidate>
    <fieldset className="auth-form directory-create-fields" disabled={view.attempted}>
      <CreateUserFields />
    </fieldset>
    {!view.receipt && <button type="submit" className="auth-submit" disabled={view.busy}>
      {view.busy ? 'Submitting…' : view.attempted ? 'Retry same request' : 'Create user'}
    </button>}
    {view.error && <p className="auth-error" role="alert">{view.error}</p>}
    {view.receipt && <>
      <p className="auth-notice" role="status">Last confirmed status: {provisioningStatusCopy[view.receipt.status]}</p>
      <button type="button" className="auth-submit" disabled={view.busy} onClick={() => void flow.checkStatus()}>
        {view.busy ? 'Checking status…' : 'Check status'}
      </button>
    </>}
  </form>;
}
