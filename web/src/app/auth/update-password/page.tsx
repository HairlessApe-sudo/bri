import { redirect } from 'next/navigation';
import { AuthFrame } from '@/components/auth-frame';
import { UpdatePasswordForm } from '@/components/auth-forms';
import { createSupabaseServerClient, supabaseEnvironmentReady } from '@/lib/supabase/server';

export default async function UpdatePasswordPage() {
  if (process.env.BRI_UI_AUTH_MODE !== 'supabase' || !supabaseEnvironmentReady()) redirect('/login?reason=recovery-link-invalid');
  let hasRecoverySession = false;
  try {
    const supabase = await createSupabaseServerClient();
    const { data, error } = await supabase.auth.getClaims();
    hasRecoverySession = !error && typeof data?.claims?.sub === 'string' && data.claims.role === 'authenticated';
  } catch {
    hasRecoverySession = false;
  }
  if (!hasRecoverySession) redirect('/login?reason=recovery-link-invalid');

  return <AuthFrame eyebrow="ACCOUNT RECOVERY" title="Choose a new password" description="After changing your password, complete TOTP verification before returning to BRI.">
    <UpdatePasswordForm />
  </AuthFrame>;
}
