import { NextResponse } from 'next/server';
import { BackendRequestError, buildBackendRequest } from '@/lib/backend-proxy.mjs';

type RouteContext = { params: Promise<{ path: string[] }> };

export async function GET(request: Request, context: RouteContext) {
  try {
    const { path } = await context.params;
    const { url, headers } = buildBackendRequest(
      `/${path.join('/')}`,
      new URL(request.url).searchParams,
    );
    const upstream = await fetch(url, {
      method: 'GET',
      headers: Object.fromEntries(headers),
      cache: 'no-store',
      signal: AbortSignal.timeout(8000),
    });
    const body = await upstream.text();
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
      : 'The BRI API is unavailable or the local development identity is not configured.';
    return NextResponse.json({ detail: message }, { status: 503, headers: { 'cache-control': 'no-store' } });
  }
}
