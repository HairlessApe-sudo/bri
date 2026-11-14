import { redirect } from 'next/navigation';
import { createSupabaseServerClient, supabaseEnvironmentReady } from '@/lib/supabase/server';

export default async function MfaLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  if (process.env.BRI_UI_AUTH_MODE !== 'supabase' || !supabaseEnvironmentReady()) redirect('/login?reason=auth-not-configured');

  let authenticated = false;
  try {
    const supabase = await createSupabaseServerClient();
    const { data, error } = await supabase.auth.getClaims();
    authenticated = !error && typeof data?.claims?.sub === 'string' && data.claims.role === 'authenticated' && data.claims.is_anonymous !== true;
  } catch {
    authenticated = false;
  }
  if (!authenticated) redirect('/login');
  return children;
}
