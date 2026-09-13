/**
 * Sentinel proof-of-work solver for the ChatGPT web handshake.
 *
 * Algorithm ported from utils/pow.py of chatgpt2api (MIT License,
 * Copyright (c) 2026 kunkun — https://github.com/conmale289/chatgpt2api-v2):
 * build a browser-plausible config array, then search a nonce `i` such that
 * sha3-512(seed + base64(config with i at slots 3 and 9>>1)) meets the
 * difficulty target. Pure computation plus header-string constants — no
 * upstream code is reused.
 *
 * Serialization must match CPython exactly: JSON.stringify's compact output
 * equals json.dumps(..., separators=(",", ":")) for the number/string-only
 * values used here, and Buffer base64 equals pybase64 standard encoding.
 */
import { createHash, randomUUID } from "node:crypto";

export const POW_ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D";
export const POW_DEFAULT_SCRIPT = "https://chatgpt.com/backend-api/sentinel/sdk.js";
export const POW_MAX_ATTEMPTS = 500000;

const CORES = [8, 16, 24, 32];
const DOCUMENT_KEYS = ["__reactContainer$fzelfjyxej8", "_reactListening5dehydibo78", "location"];
const SCREEN_RESOLUTIONS = [[1920, 1080], [1440, 900], [2560, 1440], [3840, 2160]];

const NAVIGATOR_KEYS = [
  "registerProtocolHandler−function registerProtocolHandler() { [native code] }",
  "storage−[object StorageManager]",
  "locks−[object LockManager]",
  "appCodeName−Mozilla",
  "permissions−[object Permissions]",
  "share−function share() { [native code] }",
  "webdriver−false",
  "managed−[object NavigatorManagedData]",
  "canShare−function canShare() { [native code] }",
  "vendor−Google Inc.",
  "mediaDevices−[object MediaDevices]",
  "vibrate−function vibrate() { [native code] }",
  "storageBuckets−[object StorageBucketManager]",
  "mediaCapabilities−[object MediaCapabilities]",
  "cookieEnabled−true",
  "virtualKeyboard−[object VirtualKeyboard]",
  "product−Gecko",
  "presentation−[object Presentation]",
  "onLine−true",
  "mimeTypes−[object MimeTypeArray]",
  "credentials−[object CredentialsContainer]",
  "serviceWorker−[object ServiceWorkerContainer]",
  "keyboard−[object Keyboard]",
  "gpu−[object GPU]",
  "doNotTrack",
  "serial−[object Serial]",
  "pdfViewerEnabled−true",
  "language−zh-CN",
  "geolocation−[object Geolocation]",
  "userAgentData−[object NavigatorUAData]",
  "getUserMedia−function getUserMedia() { [native code] }",
  "sendBeacon−function sendBeacon() { [native code] }",
  "hardwareConcurrency−32",
  "windowControlsOverlay−[object WindowControlsOverlay]",
];

const WINDOW_KEYS = [
  "0", "window", "self", "document", "name", "location", "customElements",
  "history", "navigation", "innerWidth", "innerHeight", "scrollX", "scrollY",
  "visualViewport", "screenX", "screenY", "outerWidth", "outerHeight",
  "devicePixelRatio", "screen", "chrome", "navigator", "onresize",
  "performance", "crypto", "indexedDB", "sessionStorage", "localStorage",
  "scheduler", "alert", "atob", "btoa", "fetch", "matchMedia", "postMessage",
  "queueMicrotask", "requestAnimationFrame", "setInterval", "setTimeout",
  "caches", "__NEXT_DATA__", "__BUILD_MANIFEST", "__NEXT_PRELOADREADY",
];

function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

// "%a %b %d %Y %H:%M:%S GMT-0500 (Eastern Standard Time)" in UTC-5.
function legacyParseTime(nowMs = Date.now()) {
  const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const d = new Date(nowMs - 5 * 3600 * 1000);
  const pad = (n) => String(n).padStart(2, "0");
  return `${days[d.getUTCDay()]} ${months[d.getUTCMonth()]} ${pad(d.getUTCDate())} ${d.getUTCFullYear()} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} GMT-0500 (Eastern Standard Time)`;
}

export function buildPowConfig(userAgent, scriptSources = null, dataBuild = "") {
  const res = pick(SCREEN_RESOLUTIONS);
  const script = scriptSources && scriptSources.length ? pick(scriptSources) : POW_DEFAULT_SCRIPT;
  return [
    res[0] + res[1],
    legacyParseTime(),
    4294705152,
    1,
    userAgent,
    script,
    dataBuild,
    "en-US",
    "en-US,es-US,en,es",
    Math.random(),
    pick(NAVIGATOR_KEYS),
    pick(DOCUMENT_KEYS),
    pick(WINDOW_KEYS),
    performance.now(),
    randomUUID(),
    "",
    pick(CORES),
    Date.now() - performance.now(),
    0, 0, 0, 0, 0, 0,
    0, // 0 = edge/chrome, 1 = firefox
  ];
}

// CPython-compatible JSON for the PoW config array. JSON.stringify matches
// json.dumps(separators=(",", ":"), ensure_ascii=False) for our alphabet
// EXCEPT whole floats: Python emits `999.0`, JS emits `999`. Plain ints must
// stay `3000`. Since JS numbers erase int/float, float slots are positional:
// indices 9 (random), 13 (perf ms), 17 (epoch-perf delta) per buildPowConfig.
const FLOAT_SLOTS = new Set([9, 13, 17]);

function pyScalar(value, isFloatSlot) {
  if (typeof value === "number") {
    if (isFloatSlot) return Number.isInteger(value) ? `${value}.0` : String(value);
    return String(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (value === null || value === undefined) return "null";
  return JSON.stringify(value);
}

function pyArray(items, offset = 0) {
  return `[${items.map((v, i) => pyScalar(v, FLOAT_SLOTS.has(offset + i))).join(",")}]`;
}

function b64encodeJson(value) {
  return Buffer.from(Array.isArray(value) ? pyArray(value, 0) : pyScalar(value, false), "utf8").toString("base64");
}

// Parse <script src> list + data-build from a bootstrap HTML page
// (mirrors ScriptSrcParser + the data-build fallback).
export function parsePowResources(html) {
  const sources = [];
  const scriptRe = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi;
  let m;
  while ((m = scriptRe.exec(html)) !== null) sources.push(m[1]);
  let dataBuild = "";
  for (const src of sources) {
    // Mirrors Python `re.search(r"c/[^/]*/_", src)`.
    const exact = src.match(/c\/[^/]*\/_/);
    if (exact) {
      dataBuild = exact[0];
      break;
    }
  }
  if (!dataBuild) {
    const attr = html.match(/<html[^>]*data-build="([^"]*)"/);
    if (attr) dataBuild = attr[1];
  }
  return { scriptSources: sources.length ? sources : [POW_DEFAULT_SCRIPT], dataBuild };
}

function powGenerate(seed, difficulty, config, limit = POW_MAX_ATTEMPTS) {
  const target = Buffer.from(difficulty, "hex");
  const diffLen = difficulty.length >> 1;
  const seedBytes = Buffer.from(seed, "utf8");
  // Slots 3 and 9 are the iterated nonces (i and i>>1); neighbors are static.
  // Absolute indices preserved so float slots (9, 13, 17) serialize correctly.
  const head = pyArray(config.slice(0, 3), 0).slice(0, -1);
  const mid = pyArray(config.slice(4, 9), 4).slice(1, -1);
  const tail = pyArray(config.slice(10), 10);
  const s1 = Buffer.from(`${head},`, "utf8");
  const s2mid = Buffer.from(`,${mid},`, "utf8");
  const s3 = Buffer.from(`,${tail.slice(1)}`, "utf8");
  for (let i = 0; i < limit; i++) {
    const iBuf = Buffer.from(String(i), "utf8");
    const halfBuf = Buffer.from(String(i >> 1), "utf8");
    const finalJson = Buffer.concat([s1, iBuf, s2mid, halfBuf, s3]);
    const encoded = finalJson.toString("base64");
    const digest = createHash("sha3-512").update(seedBytes).update(encoded, "utf8").digest();
    if (digest.subarray(0, diffLen).compare(target) <= 0) {
      return { answer: encoded, solved: true };
    }
  }
  const fallback = POW_ERROR_PREFIX + Buffer.from(JSON.stringify(seed), "utf8").toString("base64");
  return { answer: fallback, solved: false };
}

export function buildLegacyRequirementsToken(userAgent, scriptSources = null, dataBuild = "") {
  const config = buildPowConfig(userAgent, scriptSources, dataBuild);
  return "gAAAAAC" + b64encodeJson(config);
}

export function buildProofToken(seed, difficulty, userAgent, scriptSources = null, dataBuild = "") {
  const config = buildPowConfig(userAgent, scriptSources, dataBuild);
  const { answer, solved } = powGenerate(String(seed || ""), String(difficulty || ""), config);
  if (!solved) {
    throw new Error(`failed to solve proof token: difficulty=${difficulty}`);
  }
  return "gAAAAAB" + answer;
}

// Test hook: solve with a caller-supplied config (deterministic vectors).
export function solveProofWithConfig(seed, difficulty, config, limit = POW_MAX_ATTEMPTS) {
  return powGenerate(String(seed || ""), String(difficulty || ""), config, limit);
}
