import { NextResponse } from 'next/server'

// Typical "auth in middleware" pattern: protect everything under /admin.
export function middleware(request) {
  const ok = request.headers.get('x-auth') === 'letmein'
  if (!ok) {
    return new NextResponse('BLOCKED-BY-MIDDLEWARE', { status: 401 })
  }
  return NextResponse.next()
}

export const config = { matcher: ['/admin/:path*'] }
