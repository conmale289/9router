import crypto from "crypto";
import { OPENAI_WEB_CONFIG } from "../constants/oauth.js";
import { extractCodexAccountInfo, extractEmailFromAccessToken } from "../providerHelpers.js";

// ChatGPT platform OAuth bridge (manual PKCE + callback paste).
// The platform authorize endpoint requires its own fixed callback
// (platform.openai.com/auth/callback) — a localhost redirect_uri is rejected
// with unknown_error. The user pastes the callback URL back; the code is
// extracted and exchanged server-side with the stored verifier.

function randomHex(bytes) {
  return crypto.randomBytes(bytes).toString("hex");
}

export function extractOpenAIWebCode(input) {
  const raw = String(input || "").trim();
  if (!raw) return "";
  if (/^https?:\/\//i.test(raw)) {
    try {
      const url = new URL(raw);
      return url.searchParams.get("code") || "";
    } catch {
      return "";
    }
  }
  return raw;
}

const openaiWeb = {
  config: OPENAI_WEB_CONFIG,
  flowType: "authorization_code_pkce",
  buildAuthUrl: (config, _redirectUri, state, codeChallenge) => {
    const params = {
      issuer: config.issuer,
      client_id: config.clientId,
      audience: config.audience,
      redirect_uri: config.platformCallback,
      device_id: crypto.randomUUID(),
      screen_hint: "login_or_signup",
      max_age: "0",
      scope: config.scope,
      response_type: "code",
      response_mode: "query",
      state: state,
      nonce: randomHex(16),
      code_challenge: codeChallenge,
      code_challenge_method: config.codeChallengeMethod,
      auth0Client: config.auth0Client,
    };
    const queryString = Object.entries(params)
      .map(([key, value]) => `${key}=${encodeURIComponent(value)}`)
      .join("&");
    return `${config.authorizeUrl}?${queryString}`;
  },
  exchangeToken: async (config, code, _redirectUri, codeVerifier) => {
    const authCode = extractOpenAIWebCode(code);
    if (!authCode) {
      throw new Error("Missing code — paste the full platform.openai.com/auth/callback URL or the code itself");
    }
    const response = await fetch(config.tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        "auth0-client": config.auth0Client,
        Origin: "https://auth.openai.com",
        Referer: "https://platform.openai.com/",
      },
      body: JSON.stringify({
        client_id: config.clientId,
        code_verifier: codeVerifier,
        grant_type: "authorization_code",
        code: authCode,
        redirect_uri: config.platformCallback,
      }),
    });

    if (!response.ok) {
      let detail = await response.text().catch(() => "");
      try {
        const parsed = JSON.parse(detail);
        detail = parsed.error_description || parsed.error || parsed.message || detail;
      } catch {
        // keep raw text
      }
      throw new Error(`Token exchange failed (HTTP ${response.status}): ${String(detail).slice(0, 300)}`);
    }

    const tokens = await response.json();
    if (!tokens.access_token) {
      throw new Error("Token exchange failed: no access_token returned");
    }
    if (!tokens.refresh_token) {
      throw new Error("Token exchange returned no refresh_token (code may have been used already)");
    }
    return tokens;
  },
  mapTokens: (tokens) => {
    const info = extractCodexAccountInfo(tokens.id_token);
    const mapped = {
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      idToken: tokens.id_token,
      expiresIn: tokens.expires_in,
      lastRefreshAt: new Date().toISOString(),
    };
    const email = info.email || extractEmailFromAccessToken(tokens.access_token);
    if (email) mapped.email = email;
    if (info.chatgptAccountId || info.chatgptPlanType) {
      mapped.providerSpecificData = {
        chatgptAccountId: info.chatgptAccountId,
        chatgptPlanType: info.chatgptPlanType,
      };
    } else {
      mapped.providerSpecificData = {};
    }
    // Stable device identity per connection (see import-token route).
    mapped.providerSpecificData.oaiDeviceId = crypto.randomUUID();
    mapped.providerSpecificData.oaiSessionId = crypto.randomUUID();
    return mapped;
  },
};

export default openaiWeb;
