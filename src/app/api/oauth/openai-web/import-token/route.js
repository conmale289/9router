import { randomUUID } from "node:crypto";
import { NextResponse } from "next/server";
import { createProviderConnection } from "@/models";

function decodeJwtPayload(token) {
  try {
    const parts = String(token || "").split(".");
    if (parts.length !== 3) return null;
    const base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
    return { payload: JSON.parse(Buffer.from(padded, "base64").toString("utf8")), repaired: false };
  } catch {
    return null;
  }
}

// Tolerant decode for chat-mangled pastes (e.g. stray commas inside numbers
// from thousands-separator formatting). Returns { payload, repaired } or
// null. The stored token bytes are NEVER modified — only claim extraction
// is best-effort. Callers should warn when repaired is true.
export function decodeJwtPayloadTolerant(token) {
  const strict = decodeJwtPayload(token);
  if (strict) return strict;
  try {
    const parts = String(token || "").split(".");
    if (parts.length !== 3) return null;
    const base64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
    const raw = Buffer.from(padded, "base64").toString("utf8");
    // Repair digit-grouping commas: 1788432503,296 -> 1788432503296
    const repaired = raw.replace(/(\d),(\d)/g, "$1$2");
    if (repaired === raw) return null;
    return { payload: JSON.parse(repaired), repaired: true };
  } catch {
    return null;
  }
}

// Normalize the many shapes a pasted ChatGPT credential can take:
// plain access token, {access_token, refresh_token, ...}, camelCase aliases,
// or nesting under credentials/credential/tokens/auth.
export function normalizePastedCredential(input) {
  if (typeof input === "string") {
    const trimmed = input.trim();
    if (trimmed.startsWith("{")) {
      try {
        return normalizePastedCredential(JSON.parse(trimmed));
      } catch {
        return { accessToken: trimmed };
      }
    }
    return { accessToken: trimmed };
  }
  if (input && typeof input === "object" && !Array.isArray(input)) {
    const nested = input.credentials || input.credential || input.tokens || input.auth;
    const src = nested && typeof nested === "object" ? { ...input, ...nested } : input;
    const pick = (...keys) => {
      for (const k of keys) {
        const v = src[k];
        if (typeof v === "string" && v.trim()) return v.trim();
      }
      return null;
    };
    return {
      accessToken: pick("access_token", "accessToken", "token", "at"),
      refreshToken: pick("refresh_token", "refreshToken", "rt"),
      idToken: pick("id_token", "idToken"),
      deviceId: pick("oai-device-id", "oaiDeviceId", "device_id", "deviceId"),
      sessionId: pick("oai-session-id", "oaiSessionId", "session_id", "sessionId"),
      // Raw browser Cookie header value (e.g. oai-did=...) — optional trust
      // material the executor forwards with web calls.
      cookies: pick("cookies", "cookie", "cookie_header", "cookieHeader"),
    };
  }
  return {};
}

/**
 * POST /api/oauth/openai-web/import-token
 * Import a ChatGPT credential as an openai-web connection without the
 * browser OAuth round-trip.
 *
 * Body: { accessToken?: string, refreshToken?: string, sessionJson?: string|object, name?: string }
 * - accessToken + optional refreshToken: direct paste.
 * - sessionJson: pasted session export (object or JSON string) holding the token triple.
 */
export async function POST(request) {
  try {
    const { accessToken, refreshToken, sessionJson, name } = await request.json();

    const fromSession = sessionJson !== undefined ? normalizePastedCredential(sessionJson) : {};
    const access = (typeof accessToken === "string" && accessToken.trim())
      || fromSession.accessToken
      || null;
    if (!access) {
      return NextResponse.json(
        { error: "Access token is required (accessToken or sessionJson)" },
        { status: 400 }
      );
    }
    const refresh = (typeof refreshToken === "string" && refreshToken.trim())
      || fromSession.refreshToken
      || null;

    const decoded = decodeJwtPayloadTolerant(access);
    const payload = decoded?.payload || {};
    const auth = payload["https://api.openai.com/auth"] || {};
    const profile = payload["https://api.openai.com/profile"] || {};
    const email = profile.email || payload.email || payload.preferred_username || null;
    const accountId = auth.chatgpt_account_id || payload.account_id || null;
    const planType = auth.chatgpt_plan_type || payload.plan_type || null;

    const providerSpecificData = { authMethod: refresh ? "oauth_tokens" : "access_token" };
    if (accountId) providerSpecificData.chatgptAccountId = accountId;
    if (planType) providerSpecificData.chatgptPlanType = planType;
    if (payload.exp) providerSpecificData.jwtExp = payload.exp;
    // Stable device identity per connection: reuse pasted ids when present,
    // otherwise mint once here so every request from this account carries the
    // same device (rotating ids per request is a bot tell).
    providerSpecificData.oaiDeviceId = fromSession.deviceId || randomUUID();
    providerSpecificData.oaiSessionId = fromSession.sessionId || randomUUID();
    if (fromSession.cookies) providerSpecificData.cookies = fromSession.cookies;

    const connection = await createProviderConnection({
      provider: "openai-web",
      authType: refresh ? "oauth" : "access_token",
      accessToken: access,
      refreshToken: refresh,
      name: name || email || "ChatGPT Web Token",
      email: email,
      providerSpecificData,
      testStatus: "active",
    });

    return NextResponse.json({
      success: true,
      hasRefreshToken: !!refresh,
      claimsRepaired: decoded?.repaired === true,
      claimsWarning: decoded
        ? (decoded.repaired ? "Token claims needed repair (paste may be corrupted) — verify the token works before relying on it." : null)
        : "Token claims unreadable (possible paste corruption) — saved as-is; validation will fail if the bytes are damaged.",
      connection: {
        id: connection.id,
        provider: connection.provider,
        email: connection.email,
        name: connection.name,
        workspace: providerSpecificData.chatgptAccountId || null,
        plan: providerSpecificData.chatgptPlanType || null,
      },
    });
  } catch (error) {
    console.log("OpenAI Web token import error:", error);
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
