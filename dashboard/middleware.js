import { jwtVerify } from 'jose';

export const config = {
  matcher: ['/((?!login\\.html|api/auth).*)'],
};

export default async function middleware(request) {
  const { pathname } = new URL(request.url);

  // Static assets and the login page are always allowed
  if (
    pathname === '/login.html' ||
    pathname.startsWith('/api/auth')
  ) {
    return;
  }

  const cookie = request.cookies.get('cti_session');
  if (!cookie?.value) {
    return Response.redirect(new URL('/login.html', request.url));
  }

  try {
    const secret = new TextEncoder().encode(process.env.SESSION_SECRET || 'changeme-32-char-secret-key!!!!!');
    await jwtVerify(cookie.value, secret);
  } catch {
    const res = Response.redirect(new URL('/login.html', request.url));
    res.headers.set('Set-Cookie', 'cti_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Strict');
    return res;
  }
}
