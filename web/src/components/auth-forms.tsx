'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { type FormEvent, useEffect, useState } from 'react';
import { completeBriAuth } from '@/lib/auth-flow.mjs';
import { createSupabaseBrowserClient } from '@/lib/supabase/browser';

function messageFromApi(status: number) {
  if (status === 403) return 'This account is not linked to active BRI access. Contact authorized BRI support.';
  if (status === 401) return 'Your sign-in session expired. Sign in again to continue.';
  return 'BRI could not start a session. Try again later.';
}

async function startBriSession() {
  const response = await fetch('/api/bri/v1/auth/session', {
    method: 'POST',
    credentials: 'same-origin',
    cache: 'no-store',
  });
  if (!response.ok) throw new Error(messageFromApi(response.status));
}

async function routeAfterAuth(router: ReturnType<typeof useRouter>) {
  const supabase = createSupabaseBrowserClient();
  const { data: assurance, error: assuranceError } = await supabase.auth.mfa.getAuthenticatorAssuranceLevel();
  if (assuranceError) throw new Error('Authentication status could not be verified. Try again.');
  const { data: factorData, error: factorError } = await supabase.auth.mfa.listFactors();
  if (factorError) throw new Error('Authentication status could not be verified. Try again.');
  const hasVerifiedTotp = Boolean(factorData?.totp?.some((factor) => factor.status === 'verified'));
  const destination = await completeBriAuth({
    currentLevel: assurance?.currentLevel ?? null,
    nextLevel: assurance?.nextLevel ?? null,
    hasVerifiedTotp,
    startSession: startBriSession,
  });
  router.replace(destination);
  router.refresh();
}

function FormFeedback({ error, notice }: { error: string; notice: string }) {
  return <>
    {error && <p className="auth-error" role="alert">{error}</p>}
    {notice && <p className="auth-notice" role="status">{notice}</p>}
  </>;
}

export function LoginForm({ notice = '' }: { notice?: string }) {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const { error: signInError } = await createSupabaseBrowserClient().auth.signInWithPassword({ email: email.trim(), password });
      if (signInError) throw new Error('Email or password could not be verified.');
      await routeAfterAuth(router);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Sign-in could not be completed.');
      setBusy(false);
    }
  }

  return <>
    <form className="auth-form" onSubmit={submit}>
      <label>Email<input type="email" name="email" autoComplete="username" required value={email} onChange={(event) => setEmail(event.target.value)} /></label>
      <label>Password<input type="password" name="password" autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)} /></label>
      <FormFeedback error={error} notice={notice} />
      <button className="auth-submit" type="submit" disabled={busy}>{busy ? 'Verifying…' : 'Continue securely'}</button>
    </form>
    <div className="auth-links"><Link href="/auth/recover">Forgot your password?</Link><span>Account access is provisioned by BRI; public sign-up is disabled.</span></div>
  </>;
}

export function TotpChallengeForm() {
  const router = useRouter();
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    async function checkFactors() {
      try {
        const { data, error: factorError } = await createSupabaseBrowserClient().auth.mfa.listFactors();
        if (factorError) throw factorError;
        if (!data?.totp?.some((factor) => factor.status === 'verified') && !cancelled) {
          router.replace('/auth/mfa/enroll');
        }
      } catch {
        if (!cancelled) setError('A verified authenticator could not be found. Sign in again or contact BRI support.');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    void checkFactors();
    return () => { cancelled = true; };
  }, [router]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const supabase = createSupabaseBrowserClient();
      const { data: factors, error: factorError } = await supabase.auth.mfa.listFactors();
      if (factorError) throw factorError;
      const factor = factors?.totp?.find((item) => item.status === 'verified');
      if (!factor) {
        router.replace('/auth/mfa/enroll');
        return;
      }
      const { data: challenge, error: challengeError } = await supabase.auth.mfa.challenge({ factorId: factor.id });
      if (challengeError || !challenge) throw new Error('Authenticator challenge could not be started.');
      const { error: verifyError } = await supabase.auth.mfa.verify({ factorId: factor.id, challengeId: challenge.id, code: code.trim() });
      if (verifyError) throw new Error('That code was not accepted. Check the code and try again.');
      await routeAfterAuth(router);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Multi-factor verification could not be completed.');
      setBusy(false);
    }
  }

  return <>
    <form className="auth-form" onSubmit={submit}>
      <label>Authenticator code<input type="text" name="totp" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} required value={code} onChange={(event) => setCode(event.target.value.replace(/\D/g, '').slice(0, 6))} /></label>
      <FormFeedback error={error} notice="" />
      <button className="auth-submit" type="submit" disabled={busy || loading}>{busy ? 'Checking code…' : loading ? 'Checking authenticator…' : 'Verify and continue'}</button>
    </form>
    <p className="auth-help">If you have lost access to your authenticator, contact authorized BRI support. Self-service factor removal is disabled.</p>
  </>;
}

export function TotpEnrollmentForm() {
  const router = useRouter();
  const [factor, setFactor] = useState<{ id: string; qrCode: string; secret: string } | null>(null);
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  async function beginEnrollment() {
    setBusy(true);
    setError('');
    try {
      const supabase = createSupabaseBrowserClient();
      const { data: existing, error: listError } = await supabase.auth.mfa.listFactors();
      if (listError) throw listError;
      const verified = existing?.totp?.find((item) => item.status === 'verified');
      if (verified) {
        router.replace('/auth/mfa/challenge');
        return;
      }
      for (const pending of existing?.all?.filter((item) => item.factor_type === 'totp' && item.status === 'unverified') ?? []) {
        const { error: removeError } = await supabase.auth.mfa.unenroll({ factorId: pending.id });
        if (removeError) throw removeError;
      }
      const { data, error: enrollError } = await supabase.auth.mfa.enroll({ factorType: 'totp', friendlyName: 'BRI authenticator' });
      if (enrollError || !data?.totp) throw new Error('Authenticator setup could not be started.');
      setFactor({ id: data.id, qrCode: data.totp.qr_code, secret: data.totp.secret });
    } catch {
      setError('Sign in before setting up an authenticator. If this continues, contact BRI support.');
    } finally {
      setBusy(false);
    }
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!factor) return;
    setBusy(true);
    setError('');
    try {
      const supabase = createSupabaseBrowserClient();
      const { data: challenge, error: challengeError } = await supabase.auth.mfa.challenge({ factorId: factor.id });
      if (challengeError || !challenge) throw new Error('Authenticator challenge could not be started.');
      const { error: verifyError } = await supabase.auth.mfa.verify({ factorId: factor.id, challengeId: challenge.id, code: code.trim() });
      if (verifyError) throw new Error('That code was not accepted. Check the code and try again.');
      await routeAfterAuth(router);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Authenticator setup could not be completed.');
      setBusy(false);
    }
  }

  return <>
    {factor ? <div className="totp-setup">
      <p>Scan this QR code with an authenticator app. The setup key is shown for manual entry if needed.</p>
      <img className="totp-qr" src={factor.qrCode} alt="TOTP enrollment QR code" referrerPolicy="no-referrer" />
      <p className="totp-secret-label">Manual setup key</p><code className="totp-secret">{factor.secret}</code>
      <form className="auth-form" onSubmit={submit}>
        <label>Enter the six-digit code from your app<input type="text" name="totp" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} required value={code} onChange={(event) => setCode(event.target.value.replace(/\D/g, '').slice(0, 6))} /></label>
        <FormFeedback error={error} notice="" />
        <button className="auth-submit" type="submit" disabled={busy}>{busy ? 'Verifying setup…' : 'Verify authenticator'}</button>
      </form>
    </div> : <>
      <FormFeedback error={error} notice={error ? '' : 'An authenticator must be registered and verified before workspace access.'} />
      <button className="auth-submit" type="button" onClick={beginEnrollment} disabled={busy}>{busy ? 'Preparing setup…' : 'Set up TOTP authenticator'}</button>
    </>}
    <p className="auth-help">BRI will not allow protected access until this TOTP factor is verified. For lost-device recovery, contact authorized BRI support.</p>
  </>;
}

export function RecoveryRequestForm({ callbackUrl }: { callbackUrl: string }) {
  const [email, setEmail] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const { error: requestError } = await createSupabaseBrowserClient().auth.resetPasswordForEmail(email.trim(), { redirectTo: callbackUrl });
      if (requestError) throw requestError;
      setNotice('If an account is eligible, password-reset instructions will be sent to its email address.');
      setEmail('');
    } catch {
      setNotice('If an account is eligible, password-reset instructions will be sent to its email address.');
    } finally {
      setBusy(false);
    }
  }

  return <>
    <form className="auth-form" onSubmit={submit}>
      <label>Account email<input type="email" name="email" autoComplete="username" required value={email} onChange={(event) => setEmail(event.target.value)} /></label>
      <FormFeedback error={error} notice={notice} />
      <button className="auth-submit" type="submit" disabled={busy}>{busy ? 'Requesting…' : 'Send recovery instructions'}</button>
    </form>
    <p className="auth-help">Password recovery does not bypass required TOTP verification. Lost-authenticator recovery remains with authorized BRI support.</p>
  </>;
}

export function UpdatePasswordForm() {
  const router = useRouter();
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (password !== confirmation) {
      setError('The passwords do not match.');
      return;
    }
    setBusy(true);
    setError('');
    try {
      const { error: updateError } = await createSupabaseBrowserClient().auth.updateUser({ password });
      if (updateError) throw new Error('Password update could not be completed. Use a valid recovery link or request a new one.');
      await routeAfterAuth(router);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Password update could not be completed.');
      setBusy(false);
    }
  }

  return <form className="auth-form" onSubmit={submit}>
    <label>New password<input type="password" name="new-password" autoComplete="new-password" minLength={12} required value={password} onChange={(event) => setPassword(event.target.value)} /></label>
    <label>Confirm new password<input type="password" name="confirm-password" autoComplete="new-password" minLength={12} required value={confirmation} onChange={(event) => setConfirmation(event.target.value)} /></label>
    <FormFeedback error={error} notice="" />
    <button className="auth-submit" type="submit" disabled={busy}>{busy ? 'Updating…' : 'Update password'}</button>
  </form>;
}
