import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'BRI — Organisational knowledge',
  description: 'Governed organisational knowledge with explicit tenant access.',
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
