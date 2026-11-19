import { UserDirectory } from '@/components/user-directory';
import { resolveUiAuthMode } from '@/lib/backend-proxy.mjs';

export const dynamic = 'force-dynamic';

export default function UsersPage() {
  let enabled = false;
  try { enabled = resolveUiAuthMode() === 'supabase'; }
  catch { /* The workspace layout handles unconfigured authentication. */ }
  return <UserDirectory enabled={enabled} />;
}
