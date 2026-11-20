export default function config(phase) {
  if (phase !== 'phase-development-server') throw new Error('Local workspace has no release build');
  return {
    devIndicators: false,
    poweredByHeader: false,
    skipTrailingSlashRedirect: true,
    images: { unoptimized: true },
    logging: { incomingRequests: false, browserToTerminal: false },
  };
}
