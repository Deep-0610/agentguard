import { createDecipheriv } from "node:crypto";
import { cookies } from "next/headers";
import { NextResponse } from "next/server";

export const runtime = "nodejs";
const COOKIE = "ag_dashboard_session";
const METHODS = new Set(["GET"]);
const ROUTES = new Set(["v1/dashboard/summary", "v1/identities", "v1/findings", "v1/audit-events"]);

function decrypt(value) {
  const key = Buffer.from(process.env.AG_DASHBOARD_SESSION_KEY || "", "base64");
  if (key.length !== 32) throw new Error("Invalid session key");
  const packed = Buffer.from(value, "base64url");
  if (packed.length < 29 || packed.length > 1024) throw new Error("Invalid session");
  const decipher = createDecipheriv("aes-256-gcm", key, packed.subarray(0, 12));
  decipher.setAuthTag(packed.subarray(12, 28));
  return Buffer.concat([decipher.update(packed.subarray(28)), decipher.final()]).toString("utf8");
}

async function proxy(request, context) {
  if (!METHODS.has(request.method)) return NextResponse.json({ error: "Method not allowed" }, { status: 405 });
  const { path = [] } = await context.params;
  const endpoint = path.join("/");
  if (!ROUTES.has(endpoint)) return NextResponse.json({ error: "Route not allowed" }, { status: 404 });
  const base = process.env.AG_CONTROL_PLANE_URL;
  if (!base) return NextResponse.json({ error: "Control plane URL is not configured." }, { status: 503 });
  let token;
  try {
    const jar = await cookies();
    const value = jar.get(COOKIE)?.value;
    if (!value) throw new Error("Missing session");
    token = decrypt(value);
    if (!token.startsWith("ag_live_")) throw new Error("Invalid session");
  } catch {
    return NextResponse.json({ error: "Authentication required." }, { status: 401 });
  }
  let target;
  try {
    const origin = new URL(base);
    if (origin.protocol !== "https:" && process.env.NODE_ENV === "production") throw new Error("HTTPS required");
    target = new URL("/" + endpoint, origin);
    target.search = new URL(request.url).search;
  } catch {
    return NextResponse.json({ error: "Control plane URL is invalid." }, { status: 503 });
  }
  try {
    const upstream = await fetch(target, {
      method: "GET",
      headers: { Authorization: "Bearer " + token, Accept: "application/json" },
      cache: "no-store",
      signal: AbortSignal.timeout(10000),
      redirect: "error"
    });
    const contentType = upstream.headers.get("content-type") || "application/json";
    const body = await upstream.arrayBuffer();
    return new Response(body, { status: upstream.status, headers: { "Content-Type": contentType, "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" } });
  } catch {
    return NextResponse.json({ error: "Control plane request failed." }, { status: 502 });
  }
}

export const GET = proxy;
