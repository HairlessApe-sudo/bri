import { NextResponse } from 'next/server';
import { recoveryBinding } from '@/lib/password-recovery.mjs';
import { BackendRequestError, prepareProxyRequest, readProxySessionToken } from '@/lib/backend-proxy.mjs';
import { createSupabaseServerClient } from '@/lib/supabase/server';
import { parseGrants } from '@/lib/user-grants';

type RouteContext = { params: Promise<{ path: string[] }> };

async function proxyRequest(request: Request, context: RouteContext) {
  try {
    const { path } = await context.params;
    const method = request.method.toUpperCase();
    const { url, headers, accessToken, directory, grants } = await prepareProxyRequest(request, `/${path.join('/')}`, process.env, async (directory: boolean) => {
      const supabase = await createSupabaseServerClient();
      // BRI independently verifies the application session, client Admin role and grant.
      return readProxySessionToken(supabase.auth, directory);
    });
    const upstream = await fetch(url, {
      method,
      headers: Object.fromEntries(headers),
      cache: 'no-store',
      redirect: 'manual',
      signal: AbortSignal.timeout(8000),
    });
    if (directory && !upstream.ok) {
      await upstream.body?.cancel();
      const status = upstream.status >= 400 ? upstream.status : 502;
      return NextResponse.json({ detail: 'The directory request could not be completed.' }, { status, headers: { 'cache-control': 'no-store' } });
    }
    if (grants) {
      const headers = { 'cache-control': 'no-store, max-age=0', 'x-content-type-options': 'nosniff' };
      try {
        return NextResponse.json(parseGrants(await upstream.json()), { headers });
      } catch {
        return NextResponse.json({ detail: 'The grants response could not be read.' }, { status: 502, headers });
      }
    }
    const binding = accessToken && method === 'POST' && path.join('/') === 'v1/auth/recovery/invalidate' && upstream.status === 204
      ? await recoveryBinding(accessToken) : null;
    const body = upstream.status === 204 || upstream.status === 304 ? null : await upstream.text();
    return new Response(body, {
      status: upstream.status,
      headers: {
        'content-type': upstream.headers.get('content-type') || 'application/json',
        'cache-control': 'no-store, max-age=0',
        'x-content-type-options': 'nosniff',
        ...(binding ? { 'x-bri-recovery-binding': binding } : {}),
      },
    });
  } catch (error) {
    if (error instanceof BackendRequestError) {
      return NextResponse.json({ detail: error.message }, { status: error.status, headers: { 'cache-control': 'no-store' } });
    }
    const message = error instanceof Error && error.name === 'TimeoutError'
      ? 'The BRI API did not respond in time.'
      : 'The BRI API is unavailable or authentication is not configured.';
    return NextResponse.json({ detail: message }, { status: 503, headers: { 'cache-control': 'no-store' } });
  }
}

export async function GET(request: Request, context: RouteContext) {
  return proxyRequest(request, context);
}

export async function POST(request: Request, context: RouteContext) {
  return proxyRequest(request, context);
}

export async function DELETE(request: Request, context: RouteContext) {
  return proxyRequest(request, context);
}
