import { AuthFrame } from '@/components/auth-frame';
import { TotpEnrollmentForm } from '@/components/auth-forms';

export default function MfaEnrollmentPage() {
  return <AuthFrame eyebrow="MULTI-FACTOR SETUP" title="Secure your account" description="Register a TOTP authenticator before any BRI tenant data can be accessed.">
    <TotpEnrollmentForm />
  </AuthFrame>;
}
