import { NextResponse, type NextRequest } from "next/server";

/**
 * Host allowlisting + same-origin enforcement for local API requests.
 */

const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const ALLOWED_HOSTNAMES = new Set(["127.0.0.1", "localhost", "spent.local"]);

function parseHostHeader(value: string | null): { hostname: string; port: string } | null {
  if (!value) return null;

  const trimmed = value.trim().toLowerCase();
  const url = new URL(`http://${trimmed}`);
  if (!ALLOWED_HOSTNAMES.has(url.hostname)) return null;

  return {
    hostname: url.hostname,
    port: url.port,
  };
}

function urlMatchesAllowedOrigin(value: string | null): boolean {
  if (!value) return false;

  try {
    const url = new URL(value);
    return ALLOWED_HOSTNAMES.has(url.hostname.toLowerCase());
  } catch {
    return false;
  }
}

export function middleware(request: NextRequest) {
  if (!request.nextUrl.pathname.startsWith("/api/")) {
    return NextResponse.next();
  }

  const host = parseHostHeader(request.headers.get("host"));
  if (!host) {
    return new NextResponse("Forbidden: untrusted host", { status: 403 });
  }

  // Non-mutating API requests still require a trusted Host header to
  // prevent DNS rebinding reads.
  if (!MUTATING_METHODS.has(request.method)) {
    return NextResponse.next();
  }

  const origin = request.headers.get("origin");
  const referer = request.headers.get("referer");

  if (!origin && !referer) {
    return new NextResponse("Forbidden: missing origin/referer", {
      status: 403,
    });
  }

  if (origin && !urlMatchesAllowedOrigin(origin)) {
    return new NextResponse("Forbidden: cross-origin request blocked", {
      status: 403,
    });
  }
  if (!origin && referer && !urlMatchesAllowedOrigin(referer)) {
    return new NextResponse("Forbidden: cross-origin referer", {
      status: 403,
    });
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/api/:path*"],
};
