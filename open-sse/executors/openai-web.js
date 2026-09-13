import { BaseExecutor } from "./base.js";
import { PROVIDERS } from "../config/providers.js";
import { proxyAwareFetch } from "../utils/proxyFetch.js";
import { sseChunk, chatChunkSse } from "../utils/sse.js";
import { SSE_DONE, SSE_HEADERS_NO_BUFFER } from "../utils/sseConstants.js";
import {
  refreshProviderCredentials,
  shouldRefreshCredentials,
} from "../services/oauthCredentialManager.js";
import {
  OPENAI_WEB_HOST,
  OPENAI_WEB_CONVERSATION_PATH,
  OPENAI_WEB_REQUIREMENTS_PATH,
  OPENAI_WEB_PREPARE_PATH,
  OPENAI_WEB_FILES_PATH,
  OPENAI_WEB_ORIGIN,
  OPENAI_WEB_USER_AGENT,
  OPENAI_WEB_SEC_CH_UA,
  OPENAI_WEB_ACCEPT_LANGUAGE,
  OPENAI_WEB_LANGUAGE,
  OPENAI_WEB_CLIENT_VERSION,
  OPENAI_WEB_CLIENT_BUILD,
  OPENAI_WEB_TIMEZONE,
  OPENAI_WEB_TIMEZONE_OFFSET_MIN,
  OPENAI_WEB_ARKOSE_MARKERS,
  OPENAI_WEB_AUTH_MARKERS,
  OPENAI_WEB_RATE_MARKERS,
  OPENAI_WEB_IMAGE_MODEL_MAP,
  OPENAI_WEB_IMAGE_STREAM_TIMEOUT_MS,
  OPENAI_WEB_IMAGE_MAX_N,
  OPENAI_WEB_FILE_POINTER_RE,
  OPENAI_WEB_SEDIMENT_POINTER_RE,
  OPENAI_WEB_FILE_ID_RE,
  OPENAI_WEB_CLEARANCE_TIMEOUT_MS,
} from "../config/openaiWeb.js";
import {
  buildLegacyRequirementsToken,
  buildProofToken,
  parsePowResources,
} from "../sentinel/pow.js";
import { solveTurnstileToken } from "../sentinel/turnstile.js";

const CONVERSATION_URL = PROVIDERS["openai-web"]?.baseUrl
  || `${OPENAI_WEB_HOST}${OPENAI_WEB_CONVERSATION_PATH}`;
const REQUIREMENTS_URL = `${OPENAI_WEB_HOST}${OPENAI_WEB_REQUIREMENTS_PATH}`;
const PREPARE_URL = `${OPENAI_WEB_HOST}${OPENAI_WEB_PREPARE_PATH}`;
const FILES_URL = `${OPENAI_WEB_HOST}${OPENAI_WEB_FILES_PATH}`;

function randomUuid() {
  if (typeof crypto?.randomUUID === "function") return crypto.randomUUID();
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function messageToText(msg) {
  const content = msg?.content;
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .filter((p) => p && (p.type === "text" || typeof p.text === "string"))
      .map((p) => (typeof p.text === "string" ? p.text : String(p.text?.value ?? "")))
      .join("\n");
  }
  return "";
}

// Fold OpenAI roles onto web-conversation roles. The web endpoint only
// understands user/assistant turns: system prompts prefix the first user turn,
// tool results arrive as plain user text (documented limitation, fail-open).
export function toWebMessages(messages) {
  const turns = [];
  const systemParts = [];
  for (const msg of messages || []) {
    const role = String(msg?.role || "user");
    const text = messageToText(msg).trim();
    if (!text) continue;
    if (role === "system" || role === "developer") {
      systemParts.push(text);
      continue;
    }
    if (role === "tool") {
      turns.push({ role: "user", text: `[tool result] ${text}` });
      continue;
    }
    turns.push({ role: role === "assistant" ? "assistant" : "user", text });
  }
  if (systemParts.length) {
    const prefix = systemParts.join("\n\n");
    const firstUser = turns.find((t) => t.role === "user");
    if (firstUser) firstUser.text = `${prefix}\n\n${firstUser.text}`;
    else turns.unshift({ role: "user", text: prefix });
  }
  return turns;
}

export function isChallengeWall(bodyText, contentType) {
  const text = String(bodyText || "");
  if (/text\/html/i.test(String(contentType || ""))) return true;
  const head = text.slice(0, 200).toLowerCase();
  return head.includes("<html") || head.includes("<!doctype html");
}

// Pull a short human-readable detail out of an upstream error body
// (JSON {"detail"/"error"/"message"} or raw text), tolerating HTML walls.
export function extractUpstreamDetail(bodyText) {
  const text = String(bodyText || "").trim();
  if (!text || isChallengeWall(text, "")) return null;
  try {
    const parsed = JSON.parse(text);
    const detail = parsed?.detail || parsed?.error?.message || parsed?.error || parsed?.message;
    if (typeof detail === "string" && detail.trim()) return detail.trim().slice(0, 200);
    if (detail) return JSON.stringify(detail).slice(0, 200);
  } catch {
    return text.slice(0, 200);
  }
  return null;
}

// Minimal cookie jar: harvest Set-Cookie from one upstream response so the
// next call in the same turn carries session cookies (mirrors a browser
// session: bootstrap → requirements → conversation). Fail-open throughout.
export function harvestSetCookies(response, jar) {
  try {
    const setCookies = typeof response?.headers?.getSetCookie === "function"
      ? response.headers.getSetCookie()
      : null;
    const list = Array.isArray(setCookies) && setCookies.length
      ? setCookies
      : (response?.headers?.get?.("set-cookie") ? [response.headers.get("set-cookie")] : []);
    for (const entry of list) {
      const pair = String(entry || "").split(";")[0].trim();
      const eq = pair.indexOf("=");
      if (eq > 0) jar[pair.slice(0, eq).trim()] = pair.slice(eq + 1).trim();
    }
  } catch {
    // ignore — cookieless requests still work
  }
  return jar;
}

export function jarCookieHeader(jar, extra) {
  const parts = [];
  if (extra && String(extra).trim()) parts.push(String(extra).trim().replace(/;+$/, ""));
  for (const [k, v] of Object.entries(jar || {})) parts.push(`${k}=${v}`);
  return parts.length ? parts.join("; ") : null;
}

// Parse a FlareSolverr-compatible clearance solution
// ({solution: {cookies: [{name, value}], userAgent}}) into a cookie jar +
// UA override. Pure function — unit-tested.
export function parseClearanceSolution(data) {
  const solution = data?.solution || data || {};
  const jar = {};
  const cookies = Array.isArray(solution.cookies) ? solution.cookies : [];
  for (const c of cookies) {
    if (c && typeof c.name === "string" && c.name && typeof c.value === "string") {
      jar[c.name] = c.value;
    }
  }
  const userAgent = typeof solution.userAgent === "string" && solution.userAgent.trim()
    ? solution.userAgent.trim()
    : null;
  return { jar, userAgent };
}

export function errorKind(message, status) {
  const text = String(message || "").toLowerCase();
  // NOTE: 403 is deliberately NOT blanket-mapped to auth — the web endpoint
  // uses 403 for rate/unusual-activity walls too. Auth class requires 401 or
  // explicit token markers. Callers map 403 output status separately.
  if (status === 401 || OPENAI_WEB_AUTH_MARKERS.some((m) => text.includes(m))) return "auth";
  if (status === 429 || OPENAI_WEB_ARKOSE_MARKERS.some((m) => text.includes(m))) return "rate";
  if (OPENAI_WEB_RATE_MARKERS.some((m) => text.includes(m))) return "rate";
  return "upstream";
}

// Extract incremental assistant text from one parsed web-SSE event.
// Handles full message snapshots (message.content.parts/text) and JSON-patch
// deltas (p/o/v with text appended at /message/content/parts/0).
export function extractDeltaText(event, state) {
  if (!event || typeof event !== "object") return "";
  if (event.message && typeof event.message === "object") {
    const msg = event.message;
    if (msg.author?.role && msg.author.role !== "assistant") return "";
    if (typeof msg.content?.text === "string") {
      const full = msg.content.text;
      const prev = state.fullText || "";
      if (full.length > prev.length && full.startsWith(prev)) {
        state.fullText = full;
        return full.slice(prev.length);
      }
      return "";
    }
    if (Array.isArray(msg.content?.parts)) {
      const full = msg.content.parts.filter((p) => typeof p === "string").join("");
      const prev = state.fullText || "";
      if (full.length > prev.length) {
        state.fullText = full;
        return full.slice(prev.length);
      }
      return "";
    }
  }
  const ops = Array.isArray(event.v) ? event.v : null;
  const patchOps = ops || (event.p && event.o ? [event] : null);
  if (patchOps) {
    let out = "";
    for (const op of patchOps) {
      if (typeof op.p === "string" && op.p.startsWith("/message/content/parts") && typeof op.v === "string") {
        if (op.o === "append") out += op.v;
        else if (op.o === "replace") {
          state.fullText = op.v;
          out += op.v;
        }
      }
    }
    return out;
  }
  return "";
}

export function isTerminalEvent(event) {
  if (!event || typeof event !== "object") return false;
  if (event.message && typeof event.message === "object") {
    return event.message.end_turn === true || event.message.status === "finished_successfully";
  }
  return false;
}

function eventErrorMessage(event) {
  if (!event || typeof event !== "object") return null;
  const err = event.error || event.detail;
  if (!err) return null;
  if (typeof err === "string") return err;
  return err.message || err.code || null;
}

async function* readSseDataEvents(body, signal) {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  try {
    while (true) {
      if (signal?.aborted) return;
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let idx;
      while ((idx = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, idx).trim();
        buffer = buffer.slice(idx + 1);
        if (!line.startsWith("data:")) continue;
        const payload = line.slice(5).trim();
        if (!payload || payload === "[DONE]") {
          if (payload === "[DONE]") return;
          continue;
        }
        try {
          yield JSON.parse(payload);
        } catch {
          // version markers / raw fragments carry no usable text
        }
      }
    }
  } finally {
    reader.releaseLock();
  }
}

function errorResponse(status, message, url, headers, transformedBody) {
  return {
    response: new Response(JSON.stringify({ error: { message, type: "upstream_error", code: `HTTP_${status}` } }), {
      status,
      headers: { "Content-Type": "application/json" },
    }),
    url,
    headers,
    transformedBody,
    responseFormat: "openai",
  };
}

export class OpenAIWebExecutor extends BaseExecutor {
  constructor() {
    super("openai-web", PROVIDERS["openai-web"] || { id: "openai-web", baseUrl: CONVERSATION_URL });
  }

  async refreshCredentials(credentials, log) {
    if (!credentials?.refreshToken) return null;
    return refreshProviderCredentials("openai-web", credentials, log);
  }

  needsRefresh(credentials) {
    return shouldRefreshCredentials("openai-web", credentials);
  }

  buildWebHeaders(accessToken, deviceId, sessionId, requirements, cookieHeader, userAgentOverride) {
    const ua = userAgentOverride || OPENAI_WEB_USER_AGENT;
    const headers = {
      Accept: "text/event-stream",
      "Content-Type": "application/json",
      Authorization: `Bearer ${accessToken}`,
      Origin: OPENAI_WEB_ORIGIN,
      Referer: `${OPENAI_WEB_ORIGIN}/`,
      "User-Agent": ua,
      "Accept-Language": OPENAI_WEB_ACCEPT_LANGUAGE,
      "Cache-Control": "no-cache",
      Pragma: "no-cache",
      Priority: "u=1, i",
      "Sec-Ch-Ua": OPENAI_WEB_SEC_CH_UA,
      "Sec-Ch-Ua-Arch": '"x86"',
      "Sec-Ch-Ua-Bitness": '"64"',
      "Sec-Ch-Ua-Full-Version": '"143.0.3650.96"',
      "Sec-Ch-Ua-Full-Version-List": '"Microsoft Edge";v="143.0.3650.96", "Chromium";v="143.0.7499.147", "Not A(Brand";v="24.0.0.0"',
      "Sec-Ch-Ua-Mobile": "?0",
      "Sec-Ch-Ua-Model": '""',
      "Sec-Ch-Ua-Platform": '"Windows"',
      "Sec-Ch-Ua-Platform-Version": '"19.0.0"',
      "Sec-Fetch-Dest": "empty",
      "Sec-Fetch-Mode": "cors",
      "Sec-Fetch-Site": "same-origin",
      "OAI-Device-Id": deviceId,
      "OAI-Session-Id": sessionId,
      "OAI-Language": OPENAI_WEB_LANGUAGE,
      "OAI-Client-Version": this.clientVersion,
      "OAI-Client-Build-Number": this.clientBuildNumber,
      "X-OpenAI-Target-Path": OPENAI_WEB_CONVERSATION_PATH,
      "X-OpenAI-Target-Route": OPENAI_WEB_CONVERSATION_PATH,
    };
    if (requirements?.token) {
      headers["OpenAI-Sentinel-Chat-Requirements-Token"] = requirements.token;
    }
    if (requirements?.proofToken) {
      headers["OpenAI-Sentinel-Proof-Token"] = requirements.proofToken;
    }
    if (requirements?.turnstileToken) {
      headers["OpenAI-Sentinel-Turnstile-Token"] = requirements.turnstileToken;
    }
    if (requirements?.soToken) {
      headers["OpenAI-Sentinel-SO-Token"] = requirements.soToken;
    }
    if (cookieHeader) {
      headers["Cookie"] = cookieHeader;
    }
    return headers;
  }

  get clientVersion() {
    return PROVIDERS["openai-web"]?.clientVersion || OPENAI_WEB_CLIENT_VERSION;
  }

  get clientBuildNumber() {
    return PROVIDERS["openai-web"]?.clientBuildNumber || OPENAI_WEB_CLIENT_BUILD;
  }

  // Homepage bootstrap: warms the session and extracts PoW script sources +
  // data-build from the HTML. Fail-open (defaults keep the flow going).
  async bootstrapPowResources(log, proxyOptions, jar = {}) {
    const out = { scriptSources: null, dataBuild: "" };
    try {
      const res = await proxyAwareFetch(`${OPENAI_WEB_HOST}/`, {
        headers: {
          "User-Agent": OPENAI_WEB_USER_AGENT,
          Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
          "Accept-Language": OPENAI_WEB_ACCEPT_LANGUAGE,
          "Sec-Ch-Ua": OPENAI_WEB_SEC_CH_UA,
          "Sec-Ch-Ua-Mobile": "?0",
          "Sec-Ch-Ua-Platform": '"Windows"',
          "Sec-Fetch-Dest": "document",
          "Sec-Fetch-Mode": "navigate",
          "Sec-Fetch-Site": "none",
          "Sec-Fetch-User": "?1",
          "Upgrade-Insecure-Requests": "1",
        },
        signal: AbortSignal.timeout(15000),
      }, proxyOptions);
      harvestSetCookies(res, jar);
      if (!res.ok) {
        log?.debug?.("OPENAI-WEB", `bootstrap HTTP ${res.status} — using default PoW resources`);
        return out;
      }
      const html = await res.text().catch(() => "");
      if (!html) return out;
      const parsed = parsePowResources(html);
      out.scriptSources = parsed.scriptSources;
      out.dataBuild = parsed.dataBuild;
      return out;
    } catch (err) {
      log?.debug?.("OPENAI-WEB", `bootstrap failed (${err?.message || err}) — using default PoW resources`);
      return out;
    }
  }

  // Full sentinel handshake: bootstrap → legacy token → requirements/prepare →
  // PoW/Turnstile → requirements/finalize. Returns { token, proofToken,
  // turnstileToken, soToken, jar }. Arkose and required-but-unsolvable
  // Turnstile raise wall-class errors (failover, not silent skip).
  async fetchRequirements(accessToken, log, proxyOptions, jar = {}) {
    const empty = { token: null, proofToken: null, turnstileToken: null, soToken: null, jar };
    const pow = await this.bootstrapPowResources(log, proxyOptions, jar);
    let legacyToken;
    try {
      legacyToken = buildLegacyRequirementsToken(
        OPENAI_WEB_USER_AGENT, pow.scriptSources, pow.dataBuild,
      );
    } catch (err) {
      log?.debug?.("OPENAI-WEB", `legacy token build failed (${err?.message || err}) — continuing without requirements`);
      return empty;
    }
    const base = `${OPENAI_WEB_HOST}/backend-api/sentinel/chat-requirements`;
    let prepare;
    try {
      const res = await proxyAwareFetch(`${base}/prepare`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${accessToken}`,
          Origin: OPENAI_WEB_ORIGIN,
          Referer: `${OPENAI_WEB_ORIGIN}/`,
          "User-Agent": OPENAI_WEB_USER_AGENT,
        },
        body: JSON.stringify({ p: legacyToken }),
        signal: AbortSignal.timeout(15000),
      }, proxyOptions);
      harvestSetCookies(res, jar);
      if (!res.ok) {
        log?.debug?.("OPENAI-WEB", `requirements prepare HTTP ${res.status} — continuing without requirements`);
        return empty;
      }
      prepare = await res.json().catch(() => null);
      if (!prepare) return empty;
    } catch (err) {
      log?.debug?.("OPENAI-WEB", `requirements prepare failed (${err?.message || err}) — continuing without requirements`);
      return empty;
    }

    if (prepare?.arkose?.required) {
      throw new Error("OpenAI Web requires Arkose verification for this account/network (not solvable server-side). Cooling down — try again or rotate accounts.");
    }

    let proofToken = "";
    const proofInfo = prepare?.proofofwork || {};
    if (proofInfo.required) {
      try {
        proofToken = buildProofToken(
          proofInfo.seed || "", proofInfo.difficulty || "",
          OPENAI_WEB_USER_AGENT, pow.scriptSources, pow.dataBuild,
        );
      } catch (err) {
        throw new Error(`OpenAI Web proof-of-work failed (${err?.message || err}). Cooling down — try again or rotate accounts.`);
      }
    }

    const turnstileInfo = prepare?.turnstile || {};
    if (process.env.OPENAI_WEB_DEBUG_DX) {
      try {
        const fs = await import("node:fs");
        fs.writeFileSync("/tmp/openai-web-dx.json", JSON.stringify({ dx: turnstileInfo.dx || "", p: legacyToken }));
      } catch { /* ignore */ }
      log?.info?.("OPENAI-WEB", "TURNSTILE-DX captured to /tmp/openai-web-dx.json");
    }
    let turnstileToken = "";
    if (turnstileInfo.required && turnstileInfo.dx) {
      try {
        turnstileToken = solveTurnstileToken(turnstileInfo.dx, legacyToken) || "";
      } catch (err) {
        log?.debug?.("OPENAI-WEB", `turnstile solve failed (${err?.message || err}) — continuing without it`);
        turnstileToken = "";
      }
      if (!turnstileToken) {
        throw new Error("OpenAI Web requires Turnstile verification for this account/network (solver returned empty). Cooling down — try again or rotate accounts.");
      }
    }

    try {
      const res = await proxyAwareFetch(`${base}/finalize`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${accessToken}`,
          Origin: OPENAI_WEB_ORIGIN,
          Referer: `${OPENAI_WEB_ORIGIN}/`,
          "User-Agent": OPENAI_WEB_USER_AGENT,
        },
        body: JSON.stringify({
          prepare_token: prepare.prepare_token || "",
          proof_token: proofToken,
          turnstile_token: turnstileToken,
        }),
        signal: AbortSignal.timeout(15000),
      }, proxyOptions);
      harvestSetCookies(res, jar);
      if (!res.ok) {
        log?.debug?.("OPENAI-WEB", `requirements finalize HTTP ${res.status} — continuing without requirements`);
        return empty;
      }
      const data = await res.json().catch(() => null);
      if (!data?.token) {
        log?.debug?.("OPENAI-WEB", "requirements finalize returned no token — continuing without requirements");
        return empty;
      }
      return {
        token: data.token,
        proofToken: proofToken || null,
        turnstileToken: turnstileToken || null,
        soToken: data.so_token || null,
        jar,
      };
    } catch (err) {
      log?.debug?.("OPENAI-WEB", `requirements finalize failed (${err?.message || err}) — continuing without requirements`);
      return empty;
    }
  }

  // Legacy single-shot requirements (kept for the validate probe path).
  // Prefer fetchRequirements() for chat/image turns.
  async fetchSentinelToken(accessToken, log, proxyOptions, jar = {}) {
    try {
      const res = await proxyAwareFetch(REQUIREMENTS_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${accessToken}`,
          Origin: OPENAI_WEB_ORIGIN,
          Referer: `${OPENAI_WEB_ORIGIN}/`,
          "User-Agent": OPENAI_WEB_USER_AGENT,
        },
        body: "{}",
        signal: AbortSignal.timeout(10000),
      }, proxyOptions);
      harvestSetCookies(res, jar);
      if (!res.ok) {
        log?.debug?.("OPENAI-WEB", `sentinel requirements HTTP ${res.status} — continuing without token`);
        return { token: null, jar };
      }
      const data = await res.json().catch(() => null);
      return { token: typeof data?.token === "string" ? data.token : null, jar };
    } catch (err) {
      log?.debug?.("OPENAI-WEB", `sentinel requirements failed (${err?.message || err}) — continuing without token`);
      return { token: null, jar };
    }
  }

  // Optional FlareSolverr-compatible clearance: solve the Cloudflare challenge
  // in a real browser and reuse its cookies + UA from server egress.
  // Returns { jar, userAgent } (both possibly empty) — never throws.
  async fetchClearance(clearanceUrl, log, proxyOptions) {
    const out = { jar: {}, userAgent: null };
    const base = String(clearanceUrl || "").trim().replace(/\/+$/, "");
    if (!base) return out;
    try {
      const res = await proxyAwareFetch(`${base}/v1`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          cmd: "request.get",
          url: `${OPENAI_WEB_HOST}/`,
          maxTimeout: OPENAI_WEB_CLEARANCE_TIMEOUT_MS,
          returnOnlyCookies: true,
        }),
        signal: AbortSignal.timeout(OPENAI_WEB_CLEARANCE_TIMEOUT_MS + 15000),
      }, proxyOptions);
      if (!res.ok) {
        log?.debug?.("OPENAI-WEB", `clearance solver HTTP ${res.status} — continuing without clearance`);
        return out;
      }
      const data = await res.json().catch(() => null);
      const parsed = parseClearanceSolution(data);
      log?.info?.("OPENAI-WEB", `clearance solved: ${Object.keys(parsed.jar).length} cookie(s)${parsed.userAgent ? ", custom UA" : ""}`);
      return parsed;
    } catch (err) {
      log?.debug?.("OPENAI-WEB", `clearance solver failed (${err?.message || err}) — continuing without clearance`);
      return out;
    }
  }

  async execute({ model, body, stream, credentials, signal, log, proxyOptions = null }) {
    const turns = toWebMessages(body?.messages);
    if (!turns.length) {
      return errorResponse(400, "Missing or empty messages array", CONVERSATION_URL, {}, body);
    }

    const accessToken = credentials?.accessToken || credentials?.apiKey;
    if (!accessToken) {
      return errorResponse(401, "No ChatGPT access token for provider: openai-web", CONVERSATION_URL, {}, body);
    }

    const psd = credentials?.providerSpecificData || {};
    const deviceId = psd.oaiDeviceId || randomUuid();
    const sessionId = psd.oaiSessionId || randomUuid();
    const upstreamModel = model && model !== "auto" ? model : "auto";

    const jar = {};
    let clearanceUa = null;
    if (psd.clearanceUrl) {
      const clearance = await this.fetchClearance(psd.clearanceUrl, log, proxyOptions);
      Object.assign(jar, clearance.jar);
      clearanceUa = clearance.userAgent;
    }
    // Consistency: when clearance carries an oai-did cookie, it IS the device
    // identity — the OAI-Device-Id header must match it, not our minted id.
    // (Mismatched cookie/header device ids are a bot tell.)
    const effectiveDeviceId = jar["oai-did"] || deviceId;
    const requirements = await this.fetchRequirements(accessToken, log, proxyOptions, jar);
    const headers = this.buildWebHeaders(
      accessToken, effectiveDeviceId, sessionId, requirements,
      jarCookieHeader(jar, psd.cookies),
      clearanceUa,
    );

    const payload = {
      action: "next",
      messages: turns.map((t) => ({
        id: randomUuid(),
        author: { role: t.role },
        content: { content_type: "text", parts: [t.text] },
      })),
      model: upstreamModel,
      parent_message_id: randomUuid(),
      conversation_mode: { kind: "primary_assistant" },
      conversation_origin: null,
      force_paragen: false,
      force_paragen_model_slug: "",
      force_rate_limit: false,
      force_use_sse: true,
      history_and_training_disabled: true,
      reset_rate_limits: false,
      suggestions: [],
      supported_encodings: [],
      system_hints: [],
      timezone: OPENAI_WEB_TIMEZONE,
      timezone_offset_min: OPENAI_WEB_TIMEZONE_OFFSET_MIN,
      variant_purpose: "comparison_implicit",
      websocket_request_id: randomUuid(),
      client_contextual_info: {
        is_dark_mode: false,
        time_since_loaded: 120,
        page_height: 900,
        page_width: 1400,
        pixel_ratio: 2,
        screen_height: 1440,
        screen_width: 2560,
      },
    };

    log?.info?.("OPENAI-WEB", `Query to ${upstreamModel}, ${turns.length} turn(s), len=${turns[turns.length - 1]?.text?.length || 0}`);

    let response;
    try {
      response = await proxyAwareFetch(CONVERSATION_URL, {
        method: "POST",
        headers,
        body: JSON.stringify(payload),
        signal,
      }, proxyOptions);
    } catch (err) {
      log?.error?.("OPENAI-WEB", `Fetch failed: ${err?.message || String(err)}`);
      return errorResponse(502, `OpenAI Web connection failed: ${err?.message || String(err)}`, CONVERSATION_URL, headers, payload);
    }

    if (!response.ok) {
      const status = response.status;
      const contentType = response.headers?.get?.("content-type") || "";
      const raw = await response.text().catch(() => "");
      const kind = errorKind(raw, status);
      let message = `OpenAI Web returned HTTP ${status}`;
      if (isChallengeWall(raw, contentType)) {
        message = "OpenAI Web verification wall (this server's network is fingerprinted — not a token problem). Route this connection through a residential proxy or run 9Router on unwalled egress, then retry.";
      } else if (kind === "auth") {
        const detail = extractUpstreamDetail(raw);
        message = detail
          ? `OpenAI Web auth failed (${detail}). Re-import a fresh token or wait for refresh.`
          : "OpenAI Web auth failed — access token may be expired. Re-import the token or wait for refresh.";
      } else if (kind === "rate") {
        const detail = extractUpstreamDetail(raw);
        message = detail
          ? `OpenAI Web limited this account (${detail}). Cooling down — try again or rotate accounts.`
          : "OpenAI Web rate limited or challenged this account. Cooling down — try again or rotate accounts.";
      } else if (raw) {
        message = `OpenAI Web error: ${raw.slice(0, 240)}`;
      }
      log?.warn?.("OPENAI-WEB", message);
      // 403 from the web endpoint behaves like auth/rate class for fallback purposes.
      const outStatus = status === 403 ? 429 : status;
      return errorResponse(outStatus, message, CONVERSATION_URL, headers, payload);
    }

    if (!response.body) {
      return errorResponse(502, "OpenAI Web returned empty response body", CONVERSATION_URL, headers, payload);
    }

    const cid = `chatcmpl-web-${randomUuid().slice(0, 12)}`;
    const created = Math.floor(Date.now() / 1000);
    const responseModel = model || upstreamModel;

    if (stream) {
      const upstream = response.body;
      const encoder = new TextEncoder();
      const sseStream = new ReadableStream({
        async start(controller) {
          const push = (frame) => controller.enqueue(encoder.encode(frame));
          push(sseChunk({
            id: cid,
            object: "chat.completion.chunk",
            created,
            model: responseModel,
            choices: [{ index: 0, delta: { role: "assistant", content: "" }, finish_reason: null }],
          }));
          const state = {};
          try {
            for await (const event of readSseDataEvents(upstream, signal)) {
              const errMsg = eventErrorMessage(event);
              if (errMsg) {
                const kind = errorKind(errMsg, 0);
                push(chatChunkSse({
                  id: cid,
                  created,
                  model: responseModel,
                  delta: {},
                  finishReason: kind === "rate" ? "length" : "stop",
                }));
                break;
              }
              const delta = extractDeltaText(event, state);
              if (delta) {
                push(chatChunkSse({
                  id: cid,
                  created,
                  model: responseModel,
                  delta: { content: delta },
                }));
              }
              if (isTerminalEvent(event)) break;
            }
          } catch (err) {
            log?.error?.("OPENAI-WEB", `Stream error: ${err?.message || String(err)}`);
          }
          push(chatChunkSse({ id: cid, created, model: responseModel, delta: {}, finishReason: "stop" }));
          push(SSE_DONE);
          controller.close();
        },
      });
      return {
        response: new Response(sseStream, { status: 200, headers: { ...SSE_HEADERS_NO_BUFFER } }),
        url: CONVERSATION_URL,
        headers,
        transformedBody: payload,
        responseFormat: "openai",
      };
    }

    let text = "";
    const state = {};
    try {
      for await (const event of readSseDataEvents(response.body, signal)) {
        const errMsg = eventErrorMessage(event);
        if (errMsg) {
          const kind = errorKind(errMsg, 0);
          const outStatus = kind === "auth" ? 401 : 429;
          return errorResponse(outStatus, `OpenAI Web error: ${errMsg.slice(0, 240)}`, CONVERSATION_URL, headers, payload);
        }
        text += extractDeltaText(event, state);
        if (isTerminalEvent(event)) break;
      }
    } catch (err) {
      return errorResponse(502, `OpenAI Web stream failed: ${err?.message || String(err)}`, CONVERSATION_URL, headers, payload);
    }

    return {
      response: new Response(JSON.stringify({
        id: cid,
        object: "chat.completion",
        created,
        model: responseModel,
        choices: [{ index: 0, message: { role: "assistant", content: text }, finish_reason: "stop" }],
        usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
      }), { status: 200, headers: { "Content-Type": "application/json" } }),
      url: CONVERSATION_URL,
      headers,
      transformedBody: payload,
      responseFormat: "openai",
    };
  }

  async downloadPointer(url, accessToken, log, proxyOptions, signal, cookieHeader) {
    const headers = {
      Authorization: `Bearer ${accessToken}`,
      Origin: OPENAI_WEB_ORIGIN,
      Referer: `${OPENAI_WEB_ORIGIN}/`,
      "User-Agent": OPENAI_WEB_USER_AGENT,
      ...(cookieHeader ? { Cookie: cookieHeader } : {}),
    };
    // Up to 2 hops: service resolve endpoints return JSON
    // {download_url|url}, which is then fetched as bytes.
    let current = url;
    for (let hop = 0; hop < 2; hop++) {
      let res;
      try {
        res = await proxyAwareFetch(current, { headers, signal }, proxyOptions);
      } catch (err) {
        log?.debug?.("OPENAI-WEB", `pointer download failed (${current}): ${err?.message || err}`);
        return null;
      }
      if (!res.ok) return null;
      const contentType = res.headers?.get?.("content-type") || "";
      if (/application\/json/i.test(contentType)) {
        const data = await res.json().catch(() => null);
        const next = extractDownloadUrl(data);
        if (!next || next === current) return null;
        current = next;
        continue;
      }
      const buf = Buffer.from(await res.arrayBuffer());
      if (!buf.length) return null;
      return { bytes: buf, contentType: contentType || "image/png", url: current };
    }
    return null;
  }

  async prepareImage(prompt, slug, accessToken, deviceId, sessionId, log, proxyOptions, signal, jar = {}) {
    // Image prepare handshake. Returns { conduitToken, conversationId }.
    // The conduit token is REQUIRED by the generation call (sent as
    // X-Conduit-Token); a missing one throws instead of silently producing a
    // doomed request.
    const payload = {
      action: "next",
      fork_from_shared_post: false,
      parent_message_id: "client-created-root",
      model: slug,
      client_prepare_state: "success",
      timezone_offset_min: OPENAI_WEB_TIMEZONE_OFFSET_MIN,
      timezone: OPENAI_WEB_TIMEZONE,
      conversation_mode: { kind: "primary_assistant" },
      system_hints: [],
      partial_query: {
        id: randomUuid(),
        author: { role: "user" },
        content: { content_type: "text", parts: [prompt] },
      },
      supports_buffering: true,
      supported_encodings: ["v1"],
      client_contextual_info: { app_name: "chatgpt.com" },
    };
    const res = await proxyAwareFetch(PREPARE_URL, {
      method: "POST",
      headers: {
        Accept: "*/*",
        "Content-Type": "application/json",
        Authorization: `Bearer ${accessToken}`,
        Origin: OPENAI_WEB_ORIGIN,
        Referer: `${OPENAI_WEB_ORIGIN}/`,
        "User-Agent": OPENAI_WEB_USER_AGENT,
        "OAI-Device-Id": deviceId,
        "OAI-Session-Id": sessionId,
        "X-Conduit-Token": "no-token",
      },
      body: JSON.stringify(payload),
      signal,
    }, proxyOptions);
    harvestSetCookies(res, jar);
    if (!res.ok) {
      const raw = await res.text().catch(() => "");
      throw new Error(`OpenAI Web prepare HTTP ${res.status}: ${extractUpstreamDetail(raw) || "no conduit token"}`.slice(0, 200));
    }
    const data = await res.json().catch(() => null);
    const conduitToken = data && typeof data.conduit_token === "string" ? data.conduit_token : "";
    if (!conduitToken) {
      throw new Error("OpenAI Web prepare returned no conduit_token");
    }
    const out = { conduitToken };
    if (data && typeof data.conversation_id === "string") out.conversationId = data.conversation_id;
    return out;
  }

  // Image generation via the Web conversation path. Returns OpenAI-shaped
  // {created, data:[{b64_json}]}. Throws on auth/rate/upstream failures so the
  // image core can cool the account down and fall back.
  async executeImage({ model, body, credentials, log, proxyOptions = null, signal = null }) {
    const prompt = String(body?.prompt || "").trim();
    if (!prompt) throw new Error("Missing required field: prompt");
    const accessToken = credentials?.accessToken || credentials?.apiKey;
    if (!accessToken) throw new Error("No ChatGPT access token for provider: openai-web");

    const slug = resolveWebImageSlug(model);
    const count = Math.min(Math.max(Number(body.n) || 1, 1), OPENAI_WEB_IMAGE_MAX_N);

    const psd = credentials?.providerSpecificData || {};
    const deviceId = psd.oaiDeviceId || randomUuid();
    const sessionId = psd.oaiSessionId || randomUuid();
    const jar = {};
    let clearanceUa = null;
    if (psd.clearanceUrl) {
      const clearance = await this.fetchClearance(psd.clearanceUrl, log, proxyOptions);
      Object.assign(jar, clearance.jar);
      clearanceUa = clearance.userAgent;
    }
    const requirements = await this.fetchRequirements(accessToken, log, proxyOptions, jar);
    const cookieHeader = () => jarCookieHeader(jar, psd.cookies);
    // Same oai-did consistency rule as the chat path (see above).
    const effectiveDeviceId = jar["oai-did"] || deviceId;
    const headers = this.buildWebHeaders(accessToken, effectiveDeviceId, sessionId, requirements, cookieHeader(), clearanceUa);

    const prepared = await this.prepareImage(prompt, slug, accessToken, effectiveDeviceId, sessionId, log, proxyOptions, signal, jar);

    const images = [];
    for (let attempt = 0; attempt < count; attempt++) {
      const payload = {
        action: "next",
        messages: [{
          id: randomUuid(),
          author: { role: "user" },
          create_time: Date.now() / 1000,
          content: { content_type: "text", parts: [prompt] },
          metadata: {
            developer_mode_connector_ids: [],
            selected_github_repos: [],
            selected_all_github_repos: false,
            system_hints: ["picture_v2"],
            serialization_metadata: { custom_symbol_offsets: [] },
          },
        }],
        parent_message_id: randomUuid(),
        model: slug,
        client_prepare_state: "sent",
        timezone_offset_min: OPENAI_WEB_TIMEZONE_OFFSET_MIN,
        timezone: OPENAI_WEB_TIMEZONE,
        conversation_mode: { kind: "primary_assistant" },
        enable_message_followups: true,
        system_hints: ["picture_v2"],
        supports_buffering: true,
        supported_encodings: ["v1"],
        client_contextual_info: {
          is_dark_mode: false,
          time_since_loaded: 1200,
          page_height: 1072,
          page_width: 1724,
          pixel_ratio: 1.2,
          screen_height: 1440,
          screen_width: 2560,
          app_name: "chatgpt.com",
        },
        paragen_cot_summary_display_override: "allow",
        force_parallel_switch: "auto",
        ...(prepared?.conversationId ? { conversation_id: prepared.conversationId } : {}),
      };

      let response;
      try {
        const timeoutSignal = AbortSignal.timeout(OPENAI_WEB_IMAGE_STREAM_TIMEOUT_MS);
        const combined = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal;
        // Refresh cookies per attempt — the jar grows as prepare/conversation
        // calls set them.
        const attemptCookies = cookieHeader();
        // Image SSE calls carry the conduit token + a turn trace id.
        const attemptHeaders = {
          ...headers,
          "X-Conduit-Token": prepared.conduitToken,
          "X-Oai-Turn-Trace-Id": randomUuid(),
        };
        if (attemptCookies) attemptHeaders.Cookie = attemptCookies;
        response = await proxyAwareFetch(CONVERSATION_URL, {
          method: "POST",
          headers: attemptHeaders,
          body: JSON.stringify(payload),
          signal: combined,
        }, proxyOptions);
      } catch (err) {
        const timedOut = err?.name === "TimeoutError" || err?.name === "AbortError";
        throw new Error(timedOut
          ? `OpenAI Web image render timed out after ${OPENAI_WEB_IMAGE_STREAM_TIMEOUT_MS / 1000}s`
          : `OpenAI Web connection failed: ${err?.message || String(err)}`);
      }

      if (!response.ok) {
        const raw = await response.text().catch(() => "");
        if (isChallengeWall(raw, response.headers?.get?.("content-type") || "")) {
          throw new Error("OpenAI Web verification wall (this server's network is fingerprinted — not a token problem)");
        }
        const detail = extractUpstreamDetail(raw) || `HTTP ${response.status}`;
        const kind = errorKind(raw, response.status);
        if (kind === "auth") throw new Error(`OpenAI Web auth failed (${detail.slice(0, 200)}). Re-import a fresh token.`);
        throw new Error(`OpenAI Web image error: ${detail.slice(0, 200)}`);
      }
      if (!response.body) throw new Error("OpenAI Web returned empty response body");

      const pointers = [];
      let terminalText = "";
      let conversationId = prepared?.conversationId || "";
      const state = {};
      for await (const event of readSseDataEvents(response.body, signal)) {
        const errMsg = eventErrorMessage(event);
        if (errMsg) throw new Error(`OpenAI Web image error: ${errMsg.slice(0, 200)}`);
        if (!conversationId && typeof event.conversation_id === "string" && event.conversation_id) {
          conversationId = event.conversation_id;
        }
        for (const p of collectImagePointers(event)) {
          if (!pointers.includes(p)) pointers.push(p);
        }
        terminalText += extractDeltaText(event, state);
        if (isTerminalEvent(event)) break;
      }

      let downloaded = null;
      for (const pointer of pointers) {
        for (const url of pointerDownloadCandidates(pointer, conversationId)) {
          downloaded = await this.downloadPointer(url, accessToken, log, proxyOptions, signal, cookieHeader());
          if (downloaded) break;
        }
        if (downloaded) break;
      }
      if (downloaded) {
        images.push({ b64_json: downloaded.bytes.toString("base64") });
      } else if (pointers.length) {
        log?.warn?.("OPENAI-WEB", `${pointers.length} pointer(s) unresolvable — keeping turn without asset`);
      } else if (terminalText.trim()) {
        throw new Error(`Upstream text reply (no image asset): ${terminalText.trim().slice(0, 200)}`);
      } else {
        throw new Error("OpenAI Web returned no image asset for this turn");
      }
    }

    return { created: Math.floor(Date.now() / 1000), data: images };
  }
}

export default OpenAIWebExecutor;

// ── image pipeline (Web path) ─────────────────────────────────────────────
// Sequence: prepare handshake → image conversation SSE → collect output-asset
// pointers from trusted tool context → resolve + download bytes → OpenAI shape.
// Strict gating: input attachments and bare tool signals never count as output.

export function resolveWebImageSlug(model) {
  if (model && OPENAI_WEB_IMAGE_MODEL_MAP[model]) return OPENAI_WEB_IMAGE_MODEL_MAP[model];
  return "auto";
}

function eventImageTrust(event) {
  if (!event || typeof event !== "object") return false;
  for (const msg of candidateMessages(event)) {
    if (!msg || typeof msg !== "object") continue;
    const role = String(msg?.author?.role || "").toLowerCase();
    if (role === "tool") return true;
    const metadata = msg?.metadata && typeof msg.metadata === "object" ? msg.metadata : {};
    const content = msg?.content && typeof msg.content === "object" ? msg.content : {};
    const isImageGen = metadata.async_task_type === "image_gen";
    const hasPointer = hasAssetPointer(content) || hasAssetPointer(metadata);
    if (role === "assistant" && (isImageGen || hasPointer)) return true;
  }
  return false;
}

// Message objects possibly nested in SSE patch envelopes:
// {"message": {...}} (snapshot) or {"p","o","v": {...message...}} (patch).
function candidateMessages(event) {
  const out = [];
  const pushMsg = (m) => {
    if (m && typeof m === "object" && (m.author || m.content || m.metadata)) out.push(m);
  };
  pushMsg(event.message);
  const v = event.v;
  if (v && typeof v === "object") {
    if (Array.isArray(v)) {
      for (const item of v) pushMsg(item?.message || item);
    } else {
      pushMsg(v.message || v);
    }
  }
  return out;
}

function hasAssetPointer(node) {
  if (!node || typeof node !== "object") return false;
  if (node.content_type === "image_asset_pointer") return true;
  const ap = node.asset_pointer;
  if (typeof ap === "string" && (ap.startsWith("file-service://") || ap.startsWith("sediment://"))) return true;
  return Object.values(node).some((child) => {
    if (Array.isArray(child)) return child.some(hasAssetPointer);
    if (child && typeof child === "object") return hasAssetPointer(child);
    return false;
  });
}

// Collect output pointers from ONE event. Returns [] unless the event carries
// trusted tool/assistant-image context (message may sit inside an SSE patch
// envelope under event.v). Scans trusted message JSON for file-service://,
// sediment:// and strict file_ ids, plus explicit file_ids/sediment_ids arrays.
export function collectImagePointers(event) {
  if (!eventImageTrust(event)) return [];
  const found = [];
  const scanText = (text) => {
    const scan = (re) => {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text)) !== null) {
        if (!found.includes(m[0])) found.push(m[0]);
      }
    };
    scan(new RegExp(OPENAI_WEB_FILE_POINTER_RE.source, "g"));
    scan(new RegExp(OPENAI_WEB_SEDIMENT_POINTER_RE.source, "g"));
    scan(new RegExp(OPENAI_WEB_FILE_ID_RE.source, "g"));
  };
  for (const msg of candidateMessages(event)) {
    try {
      scanText(JSON.stringify(msg));
    } catch {
      // ignore unserializable message
    }
    for (const key of ["file_ids", "sediment_ids"]) {
      const arr = msg[key] || event[key];
      if (Array.isArray(arr)) {
        for (const id of arr) {
          if (typeof id === "string" && id && !found.includes(id)) found.push(id);
        }
      }
    }
    // Direct https asset links when present (e.g. asset_pointer_link).
    for (const key of ["asset_pointer_link", "watermarked_asset_pointer", "download_url", "url"]) {
      const val = msg[key];
      if (typeof val === "string" && /^https?:\/\//i.test(val) && !found.includes(val)) found.push(val);
    }
  }
  return found;
}

// Ordered download candidates for one pointer. file-service/file_ ids resolve
// via /backend-api/files/{id}/download; sediment ids resolve via the
// conversation-scoped attachment endpoint (needs conversationId), with the
// files endpoint as fallback. https pointers download as-is.
export function pointerDownloadCandidates(pointer, conversationId = "") {
  const p = String(pointer || "").trim();
  if (!p) return [];
  if (/^https?:\/\//i.test(p)) return [p];
  const id = p
    .replace(/^file-service:\/\//, "")
    .replace(/^sediment:\/\//, "")
    .replace(/^\/+/, "");
  if (!id) return [];
  const cands = [];
  const isSediment = /^sediment:\/\//i.test(p);
  if (isSediment && conversationId) {
    cands.push(`${OPENAI_WEB_HOST}/backend-api/conversation/${conversationId}/attachment/${id}/download`);
  }
  cands.push(`${FILES_URL}/${id}/download`);
  return cands;
}

// Resolve a files/attachment resolve-response to the downloadable URL.
export function extractDownloadUrl(body) {
  if (!body || typeof body !== "object") return "";
  const url = body.download_url || body.url || "";
  return typeof url === "string" ? url : "";
}
