// OpenAI-compatible adapter (used by openai, minimax, openrouter, recraft,
// vercel-ai-gateway, xai). Default endpoint comes from the provider registry
// (openai → https://api.openai.com/v1/images/generations); a per-connection
// baseUrl override (credentials.providerSpecificData.baseUrl, also bare
// credentials.baseUrl) wins when set — same opt-in pattern as STT/TTS/embeddings.
import { PROVIDER_MEDIA } from "../../providers/index.js";

const imageCfg = (id) => PROVIDER_MEDIA[id]?.imageConfig || {};
const defaultImageUrl = (id) => imageCfg(id).baseUrl;

export function resolveOpenAIImageUrl(providerId, credentials) {
  const fallback = defaultImageUrl(providerId);
  const raw = credentials?.providerSpecificData?.baseUrl || credentials?.baseUrl;
  if (!raw) return fallback;
  const normalized = String(raw).trim().replace(/\/+$/, "");
  if (!normalized) return fallback;
  if (normalized.endsWith("/images/generations")) return normalized;
  if (normalized.endsWith("/v1")) return `${normalized}/images/generations`;
  if (/\/v1\/.+/.test(normalized)) return `${normalized}/images/generations`;
  return `${normalized}/v1/images/generations`;
}

export default function createOpenAIAdapter(providerId) {
  const cfg = imageCfg(providerId);
  return {
    buildUrl: (model, credentials) => resolveOpenAIImageUrl(providerId, credentials),
    buildHeaders: (creds) => {
      const headers = { "Content-Type": "application/json", ...(cfg.headers || {}) };
      const key = creds?.apiKey || creds?.accessToken;
      if (key) headers["Authorization"] = `Bearer ${key}`;
      return headers;
    },
    buildBody: (model, body) => {
      const { prompt, n = 1, size = "1024x1024", quality, style, response_format } = body;
      const full = { model, prompt, n, size };
      if (quality) full.quality = quality;
      if (style) full.style = style;
      if (response_format) full.response_format = response_format;
      // bodyFields whitelist (e.g. xAI accepts only model/prompt/n/response_format)
      if (Array.isArray(cfg.bodyFields)) {
        const req = {};
        for (const f of cfg.bodyFields) if (full[f] !== undefined) req[f] = full[f];
        return req;
      }
      return full;
    },
    normalize: (responseBody) => responseBody,
  };
}
