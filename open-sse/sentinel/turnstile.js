/**
 * Turnstile challenge VM solver for the ChatGPT web handshake.
 *
 * Interpreter port of utils/turnstile.py from chatgpt2api (MIT License,
 * Copyright (c) 2026 kunkun — https://github.com/conmale289/chatgpt2api-v2).
 * The server sends an obfuscated token program (dx, XOR-decoded with the
 * requirements token); this VM executes it with mocked browser primitives
 * (performance.now, Math.random, Object.keys, localStorage key list,
 * Reflect.set) and returns a base64 result token. No DOM is required.
 *
 * Fidelity notes (CPython semantics that differ from naive JS):
 * - JSON integers vs floats are distinct: int 2 stringifies as "2" while
 *   float 2.0 stringifies as "2.0", and int+int concatenates to "NaN".
 *   The dx program is parsed with integer tagging to preserve this.
 * - json.dumps (func_15) uses ", "/"": "" separators and \uXXXX escapes.
 * - Mixed-type `<` and `-` follow Python rules (TypeError → False / 0).
 */

import { createRequire } from "node:module";

const INT_TAG = "__pyint";
const FLOAT_TAG = "__pyfloat";

function tagIntegers(text) {
  // Tag integer- AND float-form JSON number literals so int/float survive
  // parsing (Python distinguishes 2 from 2.0 in str() and json.dumps()).
  // String literals pass through untouched.
  const parts = String(text).split(/("(?:[^"\\]|\\.)*")/g);
  for (let i = 0; i < parts.length; i += 2) {
    parts[i] = parts[i].replace(/-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g, (m) => {
      if (/[.eE]/.test(m)) return `{"${FLOAT_TAG}":${m}}`;
      return `{"${INT_TAG}":${m}}`;
    });
  }
  return parts.join("");
}

function parseProgram(text) {
  return JSON.parse(tagIntegers(text));
}

// Diagnostic hook: parse a program the way the VM sees it (tagged numbers).
export function debugParseProgram(text) {
  return parseProgram(text);
}

function unwrap(value) {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    if (INT_TAG in value) return value[INT_TAG];
    if (FLOAT_TAG in value) return value[FLOAT_TAG];
  }
  return value;
}

function isPyInt(value) {
  return !!value && typeof value === "object" && !Array.isArray(value) && INT_TAG in value;
}

function isPyFloat(value) {
  if (!!value && typeof value === "object" && !Array.isArray(value) && FLOAT_TAG in value) return true;
  return typeof value === "number";
}

// CPython repr() for floats. JS String() differs in two cases:
//  - whole floats: Python "2.0", JS "2"
//  - exponents: Python "5e-07"/"1e+16", JS "5e-7"/"10000000000000000"
// Both engines emit shortest round-trip digits, so reformatting the JS
// digits into Python's layout is exact.
export function pyFloatRepr(n) {
  if (Number.isNaN(n)) return "nan";
  if (!Number.isFinite(n)) return n > 0 ? "inf" : "-inf";
  if (n === 0) return Object.is(n, -0) ? "-0.0" : "0.0";
  const abs = Math.abs(n);
  const useExp = abs >= 1e16 || abs < 1e-4;
  if (!useExp) {
    const s = String(n);
    return s.includes(".") || /[eEnN]/.test(s) ? s : `${s}.0`;
  }
  // Scientific layout: d[.ddd]e±XX (exponent sign + min 2 digits).
  const digits = [];
  {
    let t = String(abs);
    if (/[eE]/.test(t)) {
      const m = t.match(/^(\d)(?:\.(\d+))?[eE]([+-]?\d+)$/);
      const exp10 = parseInt(m[3], 10);
      const frac = (m[2] || "").replace(/0+$/, "");
      return `${n < 0 ? "-" : ""}${m[1]}${frac ? `.${frac}` : ""}e${exp10 < 0 ? "-" : "+"}${String(Math.abs(exp10)).padStart(2, "0")}`;
    }
    // Positional digits -> scientific: first significant digit + exponent.
    const clean = t.replace(".", "");
    const firstNZ = clean.search(/[1-9]/);
    const intLen = t.includes(".") ? t.indexOf(".") : t.length;
    const exp10 = firstNZ < intLen ? intLen - firstNZ - 1 : -(firstNZ - intLen + 1);
    const sig = (clean.slice(firstNZ) + "0".repeat(32)).slice(0, 32).replace(/0+$/, "") || "0";
    void digits;
    return `${n < 0 ? "-" : ""}${sig[0]}${sig.length > 1 ? `.${sig.slice(1)}` : ""}e${exp10 < 0 ? "-" : "+"}${String(Math.abs(exp10)).padStart(2, "0")}`;
  }
}

function pyRepr(value) {
  if (isPyInt(value)) return String(unwrap(value));
  if (isPyFloat(value) && typeof value === "object") {
    const n = unwrap(value);
    return Number.isInteger(n) ? `${n}.0` : String(n);
  }
  const v = unwrap(value);
  if (v === null || v === undefined) return "None";
  if (typeof v === "boolean") return v ? "True" : "False";
  if (typeof v === "number") return pyFloatRepr(v);
  if (typeof v === "string") return `'${v}'`;
  if (Array.isArray(v)) return `[${v.map(pyRepr).join(", ")}]`;
  if (v instanceof OrderedMap) return `{${[...v.values.entries()].map(([k, val]) => `${pyRepr(k)}: ${pyRepr(val)}`).join(", ")}}`;
  if (v instanceof Map) return `{${[...v.entries()].map(([k, val]) => `${pyRepr(k)}: ${pyRepr(val)}`).join(", ")}}`;
  if (typeof v === "object") {
    return `{${Object.entries(v).map(([k, val]) => `'${k}': ${pyRepr(val)}`).join(", ")}}`;
  }
  return String(v);
}

function pyDumps(value) {
  // json.dumps defaults: separators (", ", ": ") + ensure_ascii (\uXXXX).
  return dumpsWithAscii(unwrapDeep(value));
}

function unwrapDeep(value) {
  if (isPyInt(value)) return unwrap(value);
  if (Array.isArray(value)) return value.map(unwrapDeep);
  if (value && typeof value === "object" && !(value instanceof OrderedMap)) {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, unwrapDeep(v)]));
  }
  return value;
}

function dumpsWithAscii(value) {
  const out = [];
  const write = (v) => {
    // Mirrors json.dumps TypeError surface: custom objects, sets-as-maps and
    // callables are not serializable (callers treat the throw as skip).
    if (typeof v === "function") throw new Error("not serializable");
    if (v instanceof Map || v instanceof OrderedMap) throw new Error("not serializable");
    if (v === null || v === undefined) { out.push("null"); return; }
    if (typeof v === "boolean") { out.push(v ? "true" : "false"); return; }
    if (isPyInt(v)) { out.push(String(unwrap(v))); return; }
    if (isPyFloat(v) && typeof v === "object") {
      const n = unwrap(v);
      out.push(Number.isInteger(n) ? `${n}.0` : String(n));
      return;
    }
    if (typeof v === "number") { out.push(pyFloatRepr(v)); return; }
    if (typeof v === "string") { out.push(`"${escapeAscii(v)}"`); return; }
    if (Array.isArray(v)) { out.push("["); v.forEach((item, i) => { if (i) out.push(", "); write(item); }); out.push("]"); return; }
    if (typeof v === "object") {
      out.push("{");
      Object.entries(v).forEach(([k, item], i) => { if (i) out.push(", "); out.push(`"${escapeAscii(k)}": `); write(item); });
      out.push("}");
      return;
    }
    out.push("null");
  };
  const escapeAscii = (s) => String(s).replace(/["\\\b\f\n\r\t]/g, (ch) => ({
    '"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t",
  })[ch]).replace(/[^\x20-\x7e]/g, (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, "0")}`);
  write(value);
  return out.join("");
}

const TURNSTILE_SPECIALS = {
  "window.Math": "[object Math]",
  "window.Reflect": "[object Reflect]",
  "window.performance": "[object Performance]",
  "window.localStorage": "[object Storage]",
  "window.Object": "function Object() { [native code] }",
  "window.Reflect.set": "function set() { [native code] }",
  "window.performance.now": "function () { [native code] }",
  "window.Object.create": "function create() { [native code] }",
  "window.Object.keys": "function keys() { [native code] }",
  "window.Math.random": "function random() { [native code] }",
};

function turnstileToStr(value) {
  const v = unwrap(value);
  if (v === null || v === undefined) return "undefined";
  if (isPyInt(value)) return String(v);
  if (typeof v === "number") return pyFloatRepr(v);
  if (typeof v === "string") return TURNSTILE_SPECIALS[v] ?? v;
  if (Array.isArray(v) && v.every((item) => typeof unwrap(item) === "string" && !isPyInt(item) && !isPyFloat(item))) {
    return v.map((item) => unwrap(item)).join(",");
  }
  return pyRepr(value);
}

function xorString(text, key) {
  if (!key) return text;
  let out = "";
  for (let i = 0; i < text.length; i++) {
    out += String.fromCharCode(text.charCodeAt(i) ^ key.charCodeAt(i % key.length));
  }
  return out;
}

class OrderedMap {
  constructor() {
    this.keys = [];
    this.values = new Map();
  }
  add(key, value) {
    key = String(key);
    if (!this.values.has(key)) this.keys.push(key);
    this.values.set(key, value);
  }
}

function toPyFloat(value) {
  const v = unwrap(value);
  if (typeof v === "number") return v;
  if (typeof v === "boolean") return v ? 1 : 0;
  if (typeof v === "string") {
    if (v.trim() === "") throw new Error("bad float");
    const n = Number(v);
    if (Number.isNaN(n)) throw new Error("bad float");
    return n;
  }
  throw new Error("bad float");
}

export function solveTurnstileToken(dx, p) {
  let tokenList;
  try {
    const decoded = Buffer.from(String(dx || ""), "base64").toString("utf8");
    tokenList = parseProgram(xorString(decoded, String(p || "")));
  } catch {
    return null;
  }

  const processMap = new Map();
  // Register keys are numeric by value in Python (67.87 == lookup key).
  // Unwrap int/float tags so tagged wrappers compare by value, not identity.
  const normKey = (key) => unwrap(key);
  const startNs = process.hrtime.bigint();
  let result = "";

  const getValue = (key) => (processMap.has(normKey(key)) ? processMap.get(normKey(key)) : undefined);
  const setValue = (key, value) => { processMap.set(normKey(key), value); };
  const jsAbs = (value) => {
    try {
      return Math.abs(toPyFloat(value));
    } catch {
      return 0;
    }
  };
  const jsProp = (obj, key) => {
    if (obj instanceof OrderedMap) return obj.values.get(String(key));
    if (obj instanceof Map) return obj.get(unwrap(key));
    if (obj && typeof obj === "object" && !Array.isArray(obj)) return obj[unwrap(key)];
    if (Array.isArray(obj)) {
      const idx = Number(key);
      return Number.isInteger(idx) && idx >= 0 && idx < obj.length ? obj[idx] : undefined;
    }
    if (typeof obj === "string") {
      const keyText = turnstileToStr(key);
      if (keyText === "location" && obj === "window.document") return "https://chatgpt.com/";
      if (keyText && keyText !== "undefined" && keyText !== "None") return `${obj}.${keyText}`;
    }
    return undefined;
  };
  const callTarget = (target, args) => {
    if (typeof target === "string") {
      if (target === "window.performance.now") {
        const elapsedNs = Number(process.hrtime.bigint() - startNs);
        return (elapsedNs + Math.random()) / 1e6;
      }
      if (target === "window.Object.create") return new OrderedMap();
      if (target === "window.Object.keys") {
        if (args && args[0] === "window.localStorage") {
          return [
            "STATSIG_LOCAL_STORAGE_INTERNAL_STORE_V4",
            "STATSIG_LOCAL_STORAGE_STABLE_ID",
            "client-correlated-secret",
            "oai/apps/capExpiresAt",
            "oai-did",
            "STATSIG_LOCAL_STORAGE_LOGGING_REQUEST",
            "UiState.isNavigationCollapsed.1",
          ];
        }
        if (args && args[0] instanceof OrderedMap) return [...args[0].keys];
        if (args && args[0] instanceof Map) return [...args[0].keys()];
        if (args && args[0] && typeof args[0] === "object") return Object.keys(args[0]);
        return undefined;
      }
      if (target === "window.Math.random") return Math.random();
      if (target === "window.Reflect.set") {
        if (args.length >= 3) {
          const [obj, keyName, val] = args;
          if (obj instanceof OrderedMap) {
            obj.add(String(keyName), val);
            return true;
          }
          if (obj && typeof obj === "object") {
            obj[String(keyName)] = val;
            return true;
          }
        }
        return false;
      }
      return undefined;
    }
    if (typeof target === "function") return target(...args);
    return undefined;
  };

  const funcs = {};
  funcs[1] = (e, t) => processMap.set(normKey(e), xorString(turnstileToStr(getValue(e)), turnstileToStr(getValue(t))));
  funcs[2] = (e, t) => processMap.set(normKey(e), t);
  funcs[3] = (e) => {
    if (process.env.TURNSTILE_TRACE) {
      try {
        const { writeFileSync } = createRequire(import.meta.url)("node:fs");
        writeFileSync("/tmp/js_final.txt", String(e));
      } catch { /* ignore */ }
    }
    result = Buffer.from(String(e), "utf8").toString("base64");
  };
  funcs[5] = (e, t) => {
    const current = getValue(e);
    const incoming = getValue(t);
    if (Array.isArray(current)) {
      processMap.set(normKey(e), [...current, incoming]);
      return;
    }
    const cu = unwrap(current);
    const iu = unwrap(incoming);
    if (typeof cu === "string" || typeof iu === "string" || isPyFloat(current) || isPyFloat(incoming)) {
      processMap.set(normKey(e), turnstileToStr(current) + turnstileToStr(incoming));
      return;
    }
    processMap.set(normKey(e), "NaN");
  };
  funcs[6] = (e, t, n) => processMap.set(normKey(e), jsProp(getValue(t), getValue(n)));
  funcs[7] = (e, ...args) => { callTarget(getValue(e), args.map(getValue)); };
  funcs[8] = (e, t) => {
    if (!processMap.has(normKey(t))) throw new Error("missing register");
    processMap.set(normKey(e), processMap.get(normKey(t)));
  };
  funcs[13] = (e, t, ...args) => {
    try {
      callTarget(getValue(t), args);
    } catch (exc) {
      processMap.set(normKey(e), String(exc && exc.message ? exc.message : exc));
    }
  };
  funcs[14] = (e, t) => {
    const raw = getValue(t);
    if (typeof raw !== "string") throw new Error("not a string");
    processMap.set(normKey(e), parseProgram(raw));
  };
  funcs[15] = (e, t) => processMap.set(normKey(e), pyDumps(getValue(t)));
  funcs[17] = (e, t, ...args) => processMap.set(normKey(e), callTarget(getValue(t), args.map(getValue)));
  funcs[18] = (e) => processMap.set(normKey(e), new TextDecoder("utf-8", { fatal: true }).decode(Buffer.from(turnstileToStr(processMap.get(normKey(e))), "base64")));
  funcs[19] = (e) => processMap.set(normKey(e), Buffer.from(turnstileToStr(processMap.get(normKey(e))), "utf8").toString("base64"));
  funcs[20] = (e, t, n, ...args) => {
    if (unwrap(getValue(e)) === unwrap(getValue(t))) {
      const target = getValue(n);
      if (typeof target === "function") target(...args);
    }
  };
  funcs[21] = (e, t, n, r, ...args) => {
    let delta = 0;
    try {
      delta = toPyFloat(getValue(e)) - toPyFloat(getValue(t));
    } catch {
      delta = 0;
    }
    if (Math.abs(delta) > jsAbs(getValue(n))) {
      const target = getValue(r);
      if (typeof target === "function") target(...args);
    }
  };
  funcs[22] = (e, queue) => {
    const previous = [...(processMap.get(9) || [])];
    processMap.set(9, [...(queue || [])]);
    runQueue();
    processMap.set(normKey(e), "None");
    processMap.set(9, previous);
  };
  funcs[23] = (e, t, ...args) => {
    if (getValue(e) !== null && getValue(e) !== undefined && typeof getValue(t) === "function") {
      getValue(t)(...args);
    }
  };
  funcs[24] = (e, t, n) => processMap.set(normKey(e), jsProp(getValue(t), getValue(n)));
  funcs[27] = (e, t) => {
    const current = getValue(e);
    const incoming = getValue(t);
    if (Array.isArray(current)) {
      try {
        const idx = current.findIndex((item) => item === incoming);
        if (idx >= 0) current.splice(idx, 1);
      } catch {
        // ignore
      }
      return;
    }
    // Python int-int stays int (tagged); float results stay float.
    const cu = unwrap(current);
    const iu = unwrap(incoming);
    if (typeof cu === "number" && typeof iu === "number") {
      const diff = cu - iu;
      const bothInt = isPyInt(current) && isPyInt(incoming);
      processMap.set(normKey(e), bothInt && Number.isInteger(diff) ? { [INT_TAG]: diff } : diff);
      return;
    }
    processMap.set(normKey(e), 0);
  };
  funcs[29] = (e, t, n) => {
    const a = unwrap(getValue(t));
    const b = unwrap(getValue(n));
    let out = false;
    try {
      if ((typeof a === "number" && typeof b === "number") || (typeof a === "string" && typeof b === "string") || (typeof a === "boolean" && typeof b === "boolean")) {
        out = a < b;
      } else {
        throw new Error("incomparable");
      }
    } catch {
      out = false;
    }
    processMap.set(normKey(e), out);
  };
  funcs[30] = (e, t, n, r) => {
    const isArray = Array.isArray(r);
    const captureKeys = isArray ? n : [];
    const queue = isArray ? r : n;
    const subroutine = (...callArgs) => {
      const previous = [...(processMap.get(9) || [])];
      if (isArray) {
        captureKeys.forEach((key, index) => {
          if (index < callArgs.length) processMap.set(normKey(key), callArgs[index]);
        });
      }
      processMap.set(9, [...(queue || [])]);
      runQueue();
      processMap.set(9, previous);
    };
    subroutine._isSub = true;
    subroutine._queueLen = Array.isArray(queue) ? queue.length : -1;
    processMap.set(normKey(e), subroutine);
  };
  funcs[33] = (e, t, n) => {
    try {
      const tv = getValue(t);
      const nv = getValue(n);
      const out = toPyFloat(tv) * toPyFloat(nv);
      const tagged = isPyInt(tv) && isPyInt(nv) && Number.isInteger(out) ? { [INT_TAG]: out } : out;
      processMap.set(normKey(e), Number.isNaN(out) ? 0 : tagged);
    } catch {
      processMap.set(normKey(e), 0);
    }
  };
  funcs[34] = (e, t) => processMap.set(normKey(e), getValue(t));
  const noop = () => undefined;
  funcs[25] = noop;
  funcs[26] = noop;
  funcs[28] = noop;

  // Python raises TypeError on arity mismatch (call skipped). The gate must
  // be keyed by resolved FUNCTION: builtin ids are often aliased into float
  // registers, and a token id has no arity of its own.
  const ARITY_BY_FN = new Map();
  for (const [id, minArgs] of Object.entries({ 1: 2, 2: 2, 3: 1, 5: 2, 6: 3, 7: 1, 8: 2, 11: 2, 12: 1, 13: 2, 14: 2, 15: 2, 17: 2, 18: 1, 19: 1, 20: 3, 21: 4, 22: 2, 23: 2, 24: 3, 25: 0, 26: 0, 27: 2, 28: 0, 29: 3, 30: 3, 33: 3, 34: 2 })) {
    if (funcs[id] !== undefined) ARITY_BY_FN.set(funcs[id], minArgs);
  }
  let rqDepth = 0;
  // One trace array shared across nested runQueue invocations (a per-call
  // array would discard nested calls from the final trace).
  const trace = process.env.TURNSTILE_TRACE ? [] : null;
  const runQueue = (limit = 20000) => {
    rqDepth += 1;
    if (trace && rqDepth > 1) {
      try {
        const { appendFileSync } = createRequire(import.meta.url)("node:fs");
        const q = processMap.get(9);
        appendFileSync("/tmp/f22.log", `NESTED depth=${rqDepth} queueLen=${Array.isArray(q) ? q.length : typeof q} first=${JSON.stringify(Array.isArray(q) && q[0])?.slice(0, 60)}\n`);
      } catch { /* ignore */ }
    }
    let steps = 0;
    while (Array.isArray(processMap.get(9)) && processMap.get(9).length) {
      steps += 1;
      if (steps > limit) throw new Error("turnstile_vm_step_limit");
      const token = processMap.get(9).shift();
      if (!Array.isArray(token) || !token.length) continue;
      const fnId = unwrap(token[0]);
      const fn = processMap.get(fnId);
      if (trace && (steps === 431 || steps === 300)) {
        const snap = {};
        for (const [k, v] of processMap) {
          let desc;
          if (typeof v === "function") {
            desc = v._isSub ? "subroutine" : (Object.entries(funcs).find(([, f]) => f === v)?.[0] ?? "fn?");
          } else if (typeof v === "string" && v.length > 60) {
            desc = `str[${v.length}]:${v.slice(0, 60)}`;
          } else {
            try {
              desc = JSON.stringify(v)?.slice(0, 120) ?? typeof v;
            } catch {
              desc = typeof v;
            }
          }
          snap[String(k)] = desc;
        }
        try {
          const { writeFileSync } = createRequire(import.meta.url)("node:fs");
          writeFileSync(steps === 431 ? "/tmp/regs_js.json" : "/tmp/js_mid.json", JSON.stringify(snap));
        } catch { /* ignore */ }
      }
      if (typeof fn !== "function") {
        if (trace) trace.push(`SKIP nonfn ${JSON.stringify(fnId)}`);
        continue;
      }
      if (trace && (fnId === 86.42 || fnId === 54.19 || fnId === 71.27 || fnId === 25.22 || fnId === 21.66)) {
        const known = Object.entries(funcs).find(([, f]) => f === fn);
        trace.push(`SUBCHK ${JSON.stringify(fnId)} is=${known ? `func_${known[0]}` : (fn && fn._isSub ? "subroutine" : typeof fn)}`);
      }
      if (token.length - 1 < (ARITY_BY_FN.get(fn) ?? 0)) {
        if (trace) trace.push(`SKIP arity ${JSON.stringify(fnId)}`);
        continue;
      }
      if (trace) trace.push(`CALL ${JSON.stringify(fnId)} args=${JSON.stringify(token.slice(1)).slice(0, 120)}`);
      try {
        fn(...token.slice(1));
      } catch (e) {
        if (trace) trace.push(`THROW ${JSON.stringify(fnId)} ${String(e && e.message || e).slice(0, 80)}`);
        continue;
      }
    }
    if (trace) {
      try {
        const { writeFileSync } = createRequire(import.meta.url)("node:fs");
        writeFileSync("/tmp/ts_trace_js.txt", trace.join("\n"));
      } catch { /* trace unavailable */ }
    }
  };

  processMap.set(1, funcs[1]);
  processMap.set(2, funcs[2]);
  processMap.set(3, funcs[3]);
  processMap.set(5, funcs[5]);
  processMap.set(6, funcs[6]);
  processMap.set(7, funcs[7]);
  processMap.set(8, funcs[8]);
  processMap.set(9, tokenList);
  processMap.set(10, "window");
  funcs[11] = (e, t) => setValue(e, null);
  funcs[12] = (e) => setValue(e, processMap);
  processMap.set(11, funcs[11]);
  processMap.set(12, funcs[12]);
  processMap.set(13, funcs[13]);
  processMap.set(14, funcs[14]);
  processMap.set(15, funcs[15]);
  processMap.set(16, String(p || ""));
  processMap.set(17, funcs[17]);
  processMap.set(18, funcs[18]);
  processMap.set(19, funcs[19]);
  processMap.set(20, funcs[20]);
  processMap.set(21, funcs[21]);
  processMap.set(22, funcs[22]);
  processMap.set(23, funcs[23]);
  processMap.set(24, funcs[24]);
  processMap.set(25, funcs[25]);
  processMap.set(26, funcs[26]);
  processMap.set(27, funcs[27]);
  processMap.set(28, funcs[28]);
  processMap.set(29, funcs[29]);
  processMap.set(30, funcs[30]);
  processMap.set(33, funcs[33]);
  processMap.set(34, funcs[34]);

  runQueue();
  if (trace) {
    try {
      const { writeFileSync } = createRequire(import.meta.url)("node:fs");
      const snap = {};
      for (const [k, v] of processMap) {
        snap[String(k)] = typeof v === "function" ? "fn" : JSON.stringify(v)?.slice(0, 150) ?? typeof v;
      }
      writeFileSync("/tmp/regs_js_end.json", JSON.stringify(snap));
    } catch { /* ignore */ }
  }
  return result || null;
}
