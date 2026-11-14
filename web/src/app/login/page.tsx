import Link from 'next/link';
import { AuthFrame, AuthUnavailable } from '@/components/auth-frame';
import { LoginForm } from '@/components/auth-forms';
import { supabaseEnvironmentReady } from '@/lib/supabase/server';

export default async function LoginPage({ searchParams }: { searchParams: Promise<{ reason?: string }> }) {
  const { reason } = await searchParams;
  const enabled = process.env.BRI_UI_AUTH_MODE === 'supabase' && supabaseEnvironmentReady();
  const notice = reason === 'session-cleanup-pending'
    ? 'You are signed out. The BRI session revocation could not be confirmed; it will expire automatically.'
    : reason === 'recovery-link-invalid'
      ? 'That recovery link is invalid or expired. Request a new one.'
      : '';

  return <AuthFrame eyebrow="SECURE ACCESS" title="Sign in to BRI" description="Use your provisioned account. A verified TOTP authenticator is required before workspace access.">
    {enabled ? <LoginForm notice={notice} /> : <AuthUnavailable message={process.env.BRI_UI_AUTH_MODE === 'synthetic' ? 'Hosted sign-in is disabled in the isolated synthetic development mode.' : 'Required Supabase authentication configuration is unavailable.'}>{process.env.BRI_UI_AUTH_MODE === 'synthetic' && <Link href="/">Open the local synthetic workspace</Link>}</AuthUnavailable>}
  </AuthFrame>;
}
