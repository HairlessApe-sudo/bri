'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useState } from 'react';
import { createSupabaseBrowserClient } from '@/lib/supabase/browser';

const links = [
  { href: '/', label: 'Overview', short: '01' },
  { href: '/organization', label: 'Organisation', short: '02' },
  { href: '/knowledge', label: 'Knowledge', short: '03' },
];

type AuthMode = 'synthetic' | 'supabase';

export function AppShell({ children, authMode }: { children: React.ReactNode; authMode: AuthMode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [loggingOut, setLoggingOut] = useState(false);
  const [logoutError, setLogoutError] = useState('');

  async function logout() {
    if (authMode !== 'supabase' || loggingOut) return;
    setLoggingOut(true);
    setLogoutError('');
    let sessionRevoked = false;
    try {
      const response = await fetch('/api/bri/v1/auth/session', {
        method: 'DELETE',
        credentials: 'same-origin',
        cache: 'no-store',
      });
      sessionRevoked = response.ok;
    } catch {
      sessionRevoked = false;
    }
    try {
      const { error } = await createSupabaseBrowserClient().auth.signOut({ scope: 'local' });
      if (error) throw error;
      router.replace(sessionRevoked ? '/login' : '/login?reason=session-cleanup-pending');
      router.refresh();
    } catch {
      setLogoutError('Sign-out could not be confirmed. Retry after checking your connection.');
      setLoggingOut(false);
    }
  }

  const hosted = authMode === 'supabase';
  return <div className="app-frame">
    <aside className="sidebar">
      <Link href="/" className="brand" aria-label="BRI home"><span className="brand-mark">b</span><span><strong>BRI</strong><small>Knowledge infrastructure</small></span></Link>
      <div className="environment"><span className="environment-dot" />{hosted ? 'Authenticated workspace' : 'Synthetic development'}</div>
      <p className="nav-label">WORKSPACE</p>
      <nav aria-label="Main navigation" className="main-nav">
        {links.map((item) => <Link key={item.href} href={item.href} aria-current={pathname === item.href ? 'page' : undefined} className={pathname === item.href || (item.href !== '/' && pathname.startsWith(item.href)) ? 'nav-link active' : 'nav-link'}>
          <span className="nav-index">{item.short}</span>{item.label}<span className="nav-arrow">↗</span>
        </Link>)}
      </nav>
      <div className="sidebar-bottom"><span className="small-label">{hosted ? 'ACCESS MODEL' : 'LOCAL INSTANCE'}</span><span className="instance-address">{hosted ? 'Server-resolved' : '127.0.0.1'}</span><span className="sidebar-footnote">{hosted ? 'Tenant membership and permissions are resolved by the BRI API.' : 'Development identity and permissions are selected by the local server configuration.'}</span></div>
    </aside>
    <main className="main-area">
      <header className="topbar"><span className="breadcrumb">BRI <span>/</span> Workspace</span><span className="topbar-status"><i /> {hosted ? 'Authenticated' : 'Local environment'}</span>{hosted && <button className="logout-button" type="button" onClick={logout} disabled={loggingOut}>{loggingOut ? 'Signing out…' : 'Sign out'}</button>}</header>
      {logoutError && <p className="logout-error" role="alert">{logoutError}</p>}
      <div className="page-content">{children}</div>
      <footer className="page-footer"><span>BRI · {hosted ? 'Authenticated workspace' : 'Synthetic development environment'}</span><span>{hosted ? 'Authorization is enforced by FastAPI and PostgreSQL' : 'All records served by the local FastAPI backend'}</span></footer>
    </main>
  </div>;
}
