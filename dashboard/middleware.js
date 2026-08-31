import { jwtVerify } from 'jose';

export const config = {
  matcher: ['/((?!login\\.html|api/auth).*)'],
};

function parseCookieToken(cookieHeader, name) {
  if (!cookieHeader) return null;
  const match = cookieHeader.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]*)'));
  return match ? decodeURIComponent(match[1]) : null;
}

export default async function middleware(request) {
  const { pathname } = new URL(request.url);

  if (pathname === '/login.html' || pathname.startsWith('/api/auth')) {
    return;
  }

  const token = parseCookieToken(request.headers.get('cookie'), 'cti_session');
  if (!token) {
    return Response.redirect(new URL('/login.html', request.url));
  }

  try {
    const secret = new TextEncoder().encode(process.env.SESSION_SECRET || 'changeme-32-char-secret-key!!!!!');
    await jwtVerify(token, secret);
  } catch {
    const res = Response.redirect(new URL('/login.html', request.url));
    res.headers.set('Set-Cookie', 'cti_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Strict');
    return res;
  }
}
