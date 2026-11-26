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
  return Boolean(origin) && origin === new URL(request.url).origin;
}

async function readJSONLimited(request, maxBytes) {
  if (!request.body) throw new Error("Missing request body");
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new RangeError("Request is too large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)), total);
  const source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  return JSON.parse(source);
}

function noStore(response) {
  response.headers.set("Cache-Control", "no-store, max-age=0");
  response.headers.set("Pragma", "no-cache");
  return response;
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
  if (!value) return noStore(NextResponse.json({ authenticated: false }));
  try {
    const token = decrypt(value);
    return noStore(NextResponse.json({ authenticated: token.startsWith("ag_live_") }));
  } catch {
    const response = noStore(NextResponse.json({ authenticated: false }));
    response.cookies.delete(COOKIE);
    return response;
  }
}

export async function POST(request) {
  if (!sameOrigin(request)) return NextResponse.json({ error: "Cross-origin session requests are not allowed." }, { status: 403 });
  if (!sameOrigin(request)) return noStore(NextResponse.json({ error: "A same-origin request is required." }, { status: 403 }));
  if (!/^application\\/json(?:\\s*;|$)/i.test(request.headers.get("content-type") || "")) {
    return noStore(NextResponse.json({ error: "Content-Type must be application/json." }, { status: 415 }));
  }
  let body;
  try {
    body = await readJSONLimited(request, 1024);
  } catch (error) {
    const tooLarge = error instanceof RangeError;
    return noStore(NextResponse.json(
      { error: tooLarge ? "Request is too large." : "Invalid JSON" },
      { status: tooLarge ? 413 : 400 }
    ));
  }
  const token = typeof body?.apiKey === "string" ? body.apiKey.trim() : "";
  if (!/^ag_live_[a-f0-9]{16}\.[A-Za-z0-9_-]{40,64}$/.test(token)) {
    return noStore(NextResponse.json({ error: "Enter a valid AgentGuard API key." }, { status: 400 }));
  }
  const controlPlane = process.env.AG_CONTROL_PLANE_URL;
  if (!controlPlane) return noStore(NextResponse.json({ error: "Control plane URL is not configured." }, { status: 503 }));
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
    await validation.body?.cancel();
    if (validation.status === 401 || validation.status === 403) {
      return noStore(NextResponse.json({ error: "The API key is invalid or does not have dashboard access." }, { status: validation.status }));
    }
    if (!validation.ok) return noStore(NextResponse.json({ error: "Control plane validation failed." }, { status: 502 }));
    const response = noStore(NextResponse.json({ authenticated: true }));
    response.cookies.set(COOKIE, encrypt(token), {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      path: "/api",
      maxAge: MAX_AGE
    });
    return response;
  } catch {
    return noStore(NextResponse.json({ error: "Unable to establish a secure dashboard session. Check the control-plane connection and session-key configuration." }, { status: 503 }));
  }
}

export async function DELETE(request) {
  if (!sameOrigin(request)) return NextResponse.json({ error: "Cross-origin session requests are not allowed." }, { status: 403 });
  const response = noStore(NextResponse.json({ authenticated: false }));
  response.cookies.set(COOKIE, "", { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "strict", path: "/api", maxAge: 0 });
  return response;
}
