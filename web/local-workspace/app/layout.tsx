import '../../src/app/globals.css';

export const metadata = { title: 'BRI — Local fixture workspace' };

export default function Layout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body><div className="app-frame">
    <aside className="sidebar">
      <a href="/knowledge" className="brand"><span className="brand-mark">b</span><span><strong>BRI</strong><small>Knowledge infrastructure</small></span></a>
      <div className="environment"><span className="environment-dot" />Local fixture workspace</div>
      <nav aria-label="Main navigation" className="main-nav">
        <a href="/knowledge" className="nav-link"><span className="nav-index">03</span>Knowledge</a>
        <a href="/review" className="nav-link"><span className="nav-index">04</span>Review</a>
        <a href="/reports" className="nav-link"><span className="nav-index">05</span>Reports</a>
      </nav>
    </aside>
    <main className="main-area"><div className="page-content">{children}</div></main>
  </div></body></html>;
}
