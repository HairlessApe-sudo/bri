import { AuthFrame } from '@/components/auth-frame';
import { TotpChallengeForm } from '@/components/auth-forms';

export default function MfaChallengePage() {
  return <AuthFrame eyebrow="MULTI-FACTOR CHECK" title="Verify your authenticator" description="Enter the current six-digit code from your registered TOTP authenticator.">
    <TotpChallengeForm />
  </AuthFrame>;
}
