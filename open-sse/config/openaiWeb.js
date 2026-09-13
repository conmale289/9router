// OpenAI Web (chatgpt.com conversation API) wire constants.
// Independently derived wire contract: endpoint paths, header names, and the
// action:"next" conversation envelope shape. No upstream code is reused here.
export const OPENAI_WEB_HOST = "https://chatgpt.com";
export const OPENAI_WEB_CONVERSATION_PATH = "/backend-api/conversation";
export const OPENAI_WEB_REQUIREMENTS_PATH = "/backend-api/sentinel/chat-requirements";
export const OPENAI_WEB_PREPARE_PATH = "/backend-api/f/conversation/prepare";
export const OPENAI_WEB_FILES_PATH = "/backend-api/files";
export const OPENAI_WEB_ME_PATH = "/backend-api/me";
export const OPENAI_WEB_ORIGIN = "https://chatgpt.com";

export const OPENAI_WEB_USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0";
export const OPENAI_WEB_SEC_CH_UA =
  '"Microsoft Edge";v="143", "Chromium";v="143", "Not A(Brand";v="24"';
export const OPENAI_WEB_ACCEPT_LANGUAGE = "zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7";
export const OPENAI_WEB_LANGUAGE = "zh-CN";
// Web client build identity echoed back by the working reference client.
export const OPENAI_WEB_CLIENT_VERSION = "prod-a194cd50d4416d3c0b47c740f206b12ce60f5887";
export const OPENAI_WEB_CLIENT_BUILD = "6708908";
// Conversation locale pinned by the reference client.
export const OPENAI_WEB_TIMEZONE = "Asia/Shanghai";
export const OPENAI_WEB_TIMEZONE_OFFSET_MIN = -480;

// ChatGPT web client identity headers sent with every conversation call.
// NOTE: OAI-Client-Version / OAI-Client-Build-Number are intentionally NOT sent —
// genuine build hashes rotate with web releases and a stale hardcoded value is
// worse than absence (fail-open: upstream still answers text turns).

// Sentinel gate: arkose has no solvable client-side path — surface as rate-limit
// class so the account cools down and the next account is tried.
export const OPENAI_WEB_ARKOSE_MARKERS = ["arkose", "arkose_token", "require_arkose"];
export const OPENAI_WEB_AUTH_MARKERS = [
  "invalid access token",
  "invalid_access_token",
  "token_invalidated",
  "token expired",
  "unauthorized",
  "authentication",
];
export const OPENAI_WEB_RATE_MARKERS = [
  "rate_limit",
  "rate limit",
  "too many requests",
  "unusual activity",
  "capacity",
  "overloaded",
  "turnstile",
  "proofofwork",
  "proof_of_work",
  "challenge",
];

// Public image model names → upstream conversation model slugs.
export const OPENAI_WEB_IMAGE_MODEL_MAP = {
  "gpt-image-2": "gpt-5-3",
  "gpt-image-2.5": "auto",
  "gpt-image-2.5-flare": "auto",
  "gpt-image-2.5-sunburst": "auto",
};

// Image pipeline knobs (mirrors upstream-side stream/poll budgets).
export const OPENAI_WEB_IMAGE_STREAM_TIMEOUT_MS = 80000;
export const OPENAI_WEB_IMAGE_MAX_N = 4;

// FlareSolverr-compatible clearance solver (optional, per-connection
// `providerSpecificData.clearanceUrl`). Solves the Cloudflare challenge in a
// real browser and returns cookies + UA to reuse from server egress.
export const OPENAI_WEB_CLEARANCE_TIMEOUT_MS = 60000;

// Output-asset pointer patterns. Only pointers seen inside trusted tool-role
// message/patch context count as image output — input attachments and bare
// tool signals never do.
export const OPENAI_WEB_FILE_POINTER_RE = /file-service:\/\/[^\s"'<>]+/g;
export const OPENAI_WEB_SEDIMENT_POINTER_RE = /sediment:\/\/[^\s"'<>]+/g;
export const OPENAI_WEB_FILE_ID_RE = /\bfile_[0-9a-fA-F]{24}\b/g;
