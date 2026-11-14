import Link from 'next/link';
import { AuthFrame, AuthUnavailable } from '@/components/auth-frame';
import { RecoveryRequestForm } from '@/components/auth-forms';
import { buildRecoveryCallbackUrl } from '@/lib/auth-flow.mjs';
import { supabaseEnvironmentReady } from '@/lib/supabase/server';

export default function PasswordRecoveryPage() {
  let callbackUrl = '';
  try {
    callbackUrl = buildRecoveryCallbackUrl(process.env);
  } catch {
    callbackUrl = '';
  }
  const enabled = process.env.BRI_UI_AUTH_MODE === 'supabase' && supabaseEnvironmentReady() && Boolean(callbackUrl);

  return <AuthFrame eyebrow="ACCOUNT RECOVERY" title="Reset your password" description="Request a one-time recovery link for your provisioned account.">
    {enabled ? <RecoveryRequestForm callbackUrl={callbackUrl} /> : <AuthUnavailable message="Supabase authentication or the fixed BRI_WEB_ORIGIN is not configured for password recovery."><Link href="/login">Return to sign in</Link></AuthUnavailable>}
  </AuthFrame>;
}
