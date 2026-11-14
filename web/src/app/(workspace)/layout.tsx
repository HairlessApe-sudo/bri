import { redirect } from 'next/navigation';
import { AppShell } from '@/components/app-shell';
import { resolveUiAuthMode } from '@/lib/backend-proxy.mjs';
import { resolveMfaRoute } from '@/lib/auth-flow.mjs';
import { createSupabaseServerClient, supabaseEnvironmentReady } from '@/lib/supabase/server';

export default async function WorkspaceLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  let mode: string;
  try {
    mode = resolveUiAuthMode(process.env);
  } catch {
    redirect('/login?reason=auth-not-configured');
  }
  if (mode === 'synthetic') return <AppShell authMode="synthetic">{children}</AppShell>;
  if (mode !== 'supabase' || !supabaseEnvironmentReady()) redirect('/login?reason=auth-not-configured');

  let authState: {
    claims: Record<string, unknown> | null;
    currentLevel: string | null;
    nextLevel: string | null;
    hasVerifiedTotp: boolean;
  };
  try {
    const supabase = await createSupabaseServerClient();
    const { data: claimsData, error: claimsError } = await supabase.auth.getClaims();
    if (claimsError) throw claimsError;
    const { data: factorsData, error: factorsError } = await supabase.auth.mfa.listFactors();
    if (factorsError) throw factorsError;
    const hasVerifiedTotp = Boolean(factorsData?.totp?.some((factor) => factor.status === 'verified'));
    authState = {
      claims: claimsData?.claims ?? null,
      currentLevel: typeof claimsData?.claims?.aal === 'string' ? claimsData.claims.aal : null,
      nextLevel: hasVerifiedTotp ? 'aal2' : 'aal1',
      hasVerifiedTotp,
    };
  } catch {
    redirect('/login?reason=auth-unavailable');
  }

  if (!authState.claims) redirect('/login');
  const destination = resolveMfaRoute(authState);
  if (destination !== '/') redirect(destination);
  return <AppShell authMode="supabase">{children}</AppShell>;
}
