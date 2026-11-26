import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { cookies } from "next/headers";
import { NextResponse } from "next/server";

export const runtime = "nodejs";
const COOKIE = "ag_dashboard_session";
const MAX_AGE = 8 * 60 * 60;

function sessionKey() {
  const encoded = process.env.AG_DASHBOARD_SESSION_KEY || "";
  const key = Buffer.from(encoded, "base64");
  if (key.length !== 32) throw new Error("AG_DASHBOARD_SESSION_KEY must be base64 for exactly 32 random bytes");
  return key;
}

function sameOrigin(request) {
  const origin = request.headers.get("origin");
  return !origin || origin === new URL(request.url).origin;
}

function encrypt(value) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", sessionKey(), iv);
  const ciphertext = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString("base64url");
}

function decrypt(value) {
  const packed = Buffer.from(value, "base64url");
  if (packed.length < 29 || packed.length > 1024) throw new Error("Invalid session");
  const decipher = createDecipheriv("aes-256-gcm", sessionKey(), packed.subarray(0, 12));
  decipher.setAuthTag(packed.subarray(12, 28));
  return Buffer.concat([decipher.update(packed.subarray(28)), decipher.final()]).toString("utf8");
}

export async function GET() {
  const jar = await cookies();
  const value = jar.get(COOKIE)?.value;
  if (!value) return NextResponse.json({ authenticated: false });
  try {
    const token = decrypt(value);
    return NextResponse.json({ authenticated: token.startsWith("ag_live_") });
  } catch {
    const response = NextResponse.json({ authenticated: false });
    response.cookies.delete(COOKIE);
    return response;
  }
}

export async function POST(request) {
  if (!sameOrigin(request)) return NextResponse.json({ error: "Cross-origin session requests are not allowed." }, { status: 403 });
  const length = Number(request.headers.get("content-length") || 0);
  if (length > 1024) return NextResponse.json({ error: "Request is too large." }, { status: 413 });
  let body;
  try { body = await request.json(); } catch { return NextResponse.json({ error: "Invalid JSON" }, { status: 400 }); }
  const token = typeof body?.apiKey === "string" ? body.apiKey.trim() : "";
  if (!/^ag_live_[a-f0-9]{16}\.[A-Za-z0-9_-]{40,64}$/.test(token)) {
    return NextResponse.json({ error: "Enter a valid AgentGuard API key." }, { status: 400 });
  }
  const controlPlane = process.env.AG_CONTROL_PLANE_URL;
  if (!controlPlane) return NextResponse.json({ error: "Control plane URL is not configured." }, { status: 503 });
  try {
    const origin = new URL(controlPlane);
    if (process.env.NODE_ENV === "production" && origin.protocol !== "https:") throw new Error("HTTPS required");
    const validationURL = new URL("/v1/dashboard/summary", origin);
    const validation = await fetch(validationURL, {
      headers: { Authorization: "Bearer " + token, Accept: "application/json" },
      cache: "no-store",
      signal: AbortSignal.timeout(5000),
      redirect: "error"
    });
    if (validation.status === 401 || validation.status === 403) {
      return NextResponse.json({ error: "The API key is invalid or does not have dashboard access." }, { status: validation.status });
    }
    if (!validation.ok) return NextResponse.json({ error: "Control plane validation failed." }, { status: 502 });
    const response = NextResponse.json({ authenticated: true });
    response.cookies.set(COOKIE, encrypt(token), {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      path: "/api",
      maxAge: MAX_AGE
    });
    return response;
  } catch {
    return NextResponse.json({ error: "Dashboard session encryption is not configured correctly." }, { status: 503 });
  }
}

export async function DELETE(request) {
  if (!sameOrigin(request)) return NextResponse.json({ error: "Cross-origin session requests are not allowed." }, { status: 403 });
  const response = NextResponse.json({ authenticated: false });
  response.cookies.set(COOKIE, "", { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "strict", path: "/api", maxAge: 0 });
  return response;
}
