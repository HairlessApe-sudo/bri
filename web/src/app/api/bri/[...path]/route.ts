import { NextResponse } from 'next/server';
import { BackendRequestError, assertNoSpoofedIdentityHeaders, assertSameOriginMutation, buildBackendRequest, resolveUiAuthMode } from '@/lib/backend-proxy.mjs';
import { createSupabaseServerClient } from '@/lib/supabase/server';

type RouteContext = { params: Promise<{ path: string[] }> };

async function proxyRequest(request: Request, context: RouteContext) {
  try {
    const { path } = await context.params;
    const method = request.method.toUpperCase();
    const mode = resolveUiAuthMode(process.env);
    const isMutation = method === 'POST' || method === 'DELETE';
    let accessToken: string | undefined;

    if (mode === 'supabase') {
      assertNoSpoofedIdentityHeaders(request.headers);
      if (isMutation) {
        assertSameOriginMutation(request.url, request.headers.get('origin'));
        if (request.body !== null) throw new BackendRequestError('Session routes do not accept a body', 400);
      }
      const supabase = await createSupabaseServerClient();
      // The API verifies this bearer independently; getSession is used only to retrieve it from SSR cookies.
      const { data: { session }, error } = await supabase.auth.getSession();
      if (error || !session?.access_token) {
        throw new BackendRequestError('Authentication required', 401);
      }
      accessToken = session.access_token;
    }

    const { url, headers } = buildBackendRequest(
      `/${path.join('/')}`,
      new URL(request.url).searchParams,
      process.env,
      { method, accessToken },
    );
    const upstream = await fetch(url, {
      method,
      headers: Object.fromEntries(headers),
      cache: 'no-store',
      redirect: 'manual',
      signal: AbortSignal.timeout(8000),
    });
    const body = upstream.status === 204 || upstream.status === 304 ? null : await upstream.text();
    return new Response(body, {
      status: upstream.status,
      headers: {
        'content-type': upstream.headers.get('content-type') || 'application/json',
        'cache-control': 'no-store, max-age=0',
        'x-content-type-options': 'nosniff',
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
