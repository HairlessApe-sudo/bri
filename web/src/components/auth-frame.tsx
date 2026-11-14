import Link from 'next/link';

export function AuthFrame({ eyebrow, title, description, children }: {
  eyebrow: string;
  title: string;
  description: string;
  children: React.ReactNode;
}) {
  return <main className="auth-page">
    <Link className="auth-brand" href="/login" aria-label="BRI sign in"><span className="brand-mark">b</span><span><strong>BRI</strong><small>Knowledge infrastructure</small></span></Link>
    <section className="auth-card" aria-labelledby="auth-title">
      <p className="section-kicker">{eyebrow}</p>
      <h1 id="auth-title">{title}</h1>
      <p className="auth-description">{description}</p>
      {children}
    </section>
    <p className="auth-footer">BRI access is assigned by explicit server-side identity and tenant membership.</p>
  </main>;
}

export function AuthUnavailable({ children, message = 'This workspace is running with its isolated synthetic development identity.' }: { children?: React.ReactNode; message?: string }) {
  return <div className="auth-unavailable" role="status">
    <strong>Secure sign-in is not enabled here.</strong>
    <p>{message}</p>
    {children}
  </div>;
}
