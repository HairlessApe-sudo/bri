import type { NextConfig } from 'next';
import { backendProxyPrefix } from './src/lib/backend-proxy.mjs';

const nextConfig: NextConfig = {
  poweredByHeader: false,
  reactStrictMode: true,
  // Let exact proxy routes reject a trailing slash rather than redirecting to an allowed path.
  skipTrailingSlashRedirect: true,
  // Do not print proxy URLs (including directory search terms and user IDs).
  logging: { incomingRequests: { ignore: [backendProxyPrefix, /^\/users(?:[/?]|$)/] } },
};

export default nextConfig;
