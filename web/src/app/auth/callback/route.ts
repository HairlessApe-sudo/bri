import { createServerClient } from '@supabase/ssr';
import { NextResponse, type NextRequest } from 'next/server';

function redirectWithoutCache(request: NextRequest, destination: string) {
  const response = NextResponse.redirect(new URL(destination, request.nextUrl.origin));
  response.headers.set('cache-control', 'no-store, max-age=0');
  response.headers.set('referrer-policy', 'no-referrer');
  return response;
}

export async function GET(request: NextRequest) {
  const destination = request.nextUrl.searchParams.get('next');
  const code = request.nextUrl.searchParams.get('code');
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const publishableKey = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
  if (
    process.env.BRI_UI_AUTH_MODE !== 'supabase'
    || !url
    || !publishableKey
    || destination !== '/auth/update-password'
    || !code
    || code.length > 4096
  ) {
    return redirectWithoutCache(request, '/login?reason=recovery-link-invalid');
  }

  const response = redirectWithoutCache(request, '/auth/update-password');
  const supabase = createServerClient(url, publishableKey, {
    cookieOptions: {
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
    },
    cookies: {
      getAll() {
        return request.cookies.getAll();
      },
      setAll(cookiesToSet) {
        for (const { name, value } of cookiesToSet) {
          request.cookies.set(name, value);
        }
        for (const { name, value, options } of cookiesToSet) {
          response.cookies.set(name, value, options);
        }
      },
    },
  });

  const { error } = await supabase.auth.exchangeCodeForSession(code);
  if (error) return redirectWithoutCache(request, '/login?reason=recovery-link-invalid');
  return response;
}
