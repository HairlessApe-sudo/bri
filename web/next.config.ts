import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  poweredByHeader: false,
  reactStrictMode: true,
  // Do not print proxy URLs (including directory search terms and user IDs).
  logging: { incomingRequests: { ignore: [/^\/api\/bri(?:[/?]|$)/, /^\/users(?:[/?]|$)/] } },
};

export default nextConfig;
