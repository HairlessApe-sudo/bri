'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

const links = [
  { href: '/', label: 'Overview', short: '01' },
  { href: '/organization', label: 'Organisation', short: '02' },
  { href: '/knowledge', label: 'Knowledge', short: '03' },
];

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  return <div className="app-frame">
    <aside className="sidebar">
      <Link href="/" className="brand" aria-label="BRI home"><span className="brand-mark">b</span><span><strong>BRI</strong><small>Knowledge infrastructure</small></span></Link>
      <div className="environment"><span className="environment-dot" />Synthetic development</div>
      <p className="nav-label">WORKSPACE</p>
      <nav aria-label="Main navigation" className="main-nav">
        {links.map((item) => <Link key={item.href} href={item.href} aria-current={pathname === item.href ? 'page' : undefined} className={pathname === item.href || (item.href !== '/' && pathname.startsWith(item.href)) ? 'nav-link active' : 'nav-link'}>
          <span className="nav-index">{item.short}</span>{item.label}<span className="nav-arrow">↗</span>
        </Link>)}
      </nav>
      <div className="sidebar-bottom"><span className="small-label">LOCAL INSTANCE</span><span className="instance-address">127.0.0.1</span><span className="sidebar-footnote">Development identity and permissions are selected by the local server configuration.</span></div>
    </aside>
    <main className="main-area">
      <header className="topbar"><span className="breadcrumb">BRI <span>/</span> Workspace</span><span className="topbar-status"><i /> Local environment</span></header>
      <div className="page-content">{children}</div>
      <footer className="page-footer"><span>BRI · Synthetic development environment</span><span>All records served by the local FastAPI backend</span></footer>
    </main>
  </div>;
}
