/**
 * Unit tests for the OpenAI Web provider (chatgpt.com conversation API).
 * All upstream calls are mocked — no live network.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  OpenAIWebExecutor,
  toWebMessages,
  extractDeltaText,
  errorKind,
  isTerminalEvent,
  isChallengeWall,
  extractUpstreamDetail,
  resolveWebImageSlug,
  collectImagePointers,
  pointerDownloadCandidates,
  harvestSetCookies,
  jarCookieHeader,
  parseClearanceSolution,
} from "../../open-sse/executors/openai-web.js";
import { checkFallbackError } from "../../open-sse/services/accountFallback.js";
import { refreshOpenAIWebToken } from "../../open-sse/services/tokenRefresh/providers.js";
import openaiWebOAuth, { extractOpenAIWebCode } from "../../src/lib/oauth/providers/openai-web.js";
import { getExecutor } from "../../open-sse/executors/index.js";
import { PROVIDERS, PROVIDER_MODELS } from "../../open-sse/providers/index.js";

vi.mock("../../open-sse/utils/proxyFetch.js", () => ({
  proxyAwareFetch: vi.fn(),
}));

import { proxyAwareFetch } from "../../open-sse/utils/proxyFetch.js";

const originalFetch = global.fetch;

function sseResponse(events) {
  const text = events.map((e) => `data: ${typeof e === "string" ? e : JSON.stringify(e)}\n\n`).join("");
  return new Response(text, { status: 200, headers: { "Content-Type": "text/event-stream" } });
}

// Mocks the three requirements calls: bootstrap GET, prepare, finalize.
function mockRequirementsChain() {
  vi.mocked(proxyAwareFetch)
    .mockResolvedValueOnce(new Response("<html></html>", { status: 200 }))
    .mockResolvedValueOnce(new Response(JSON.stringify({ prepare_token: "prep-1" }), { status: 200 }))
    .mockResolvedValueOnce(new Response(JSON.stringify({ token: "sentinel-1" }), { status: 200 }));
}

describe("openai-web registry", () => {
  it("registers transport + models", () => {
    expect(PROVIDERS["openai-web"]?.baseUrl).toBe("https://chatgpt.com/backend-api/conversation");
    const ids = (PROVIDER_MODELS["openai-web"] || []).map((m) => m.id);
    expect(ids[0]).toBe("auto");
    expect(ids).toContain("gpt-5.6");
  });

  it("resolves through getExecutor to OpenAIWebExecutor", () => {
    expect(getExecutor("openai-web")).toBeInstanceOf(OpenAIWebExecutor);
  });
});

describe("toWebMessages", () => {
  it("folds system prompt into first user turn", () => {
    const turns = toWebMessages([
      { role: "system", content: "Be terse." },
      { role: "user", content: "Hi" },
    ]);
    expect(turns).toEqual([{ role: "user", text: "Be terse.\n\nHi" }]);
  });

  it("folds tool results as user text", () => {
    const turns = toWebMessages([
      { role: "user", content: "q" },
      { role: "tool", content: "result-data" },
    ]);
    expect(turns[1]).toEqual({ role: "user", text: "[tool result] result-data" });
  });

  it("drops empty turns", () => {
    expect(toWebMessages([{ role: "user", content: "  " }])).toEqual([]);
  });
});

describe("extractDeltaText", () => {
  it("emits incremental snapshot text", () => {
    const state = {};
    expect(extractDeltaText({ message: { author: { role: "assistant" }, content: { text: "Hello" } } }, state)).toBe("Hello");
    expect(extractDeltaText({ message: { author: { role: "assistant" }, content: { text: "Hello world" } } }, state)).toBe(" world");
  });

  it("appends patch deltas", () => {
    const state = {};
    expect(extractDeltaText({ p: "/message/content/parts/0", o: "append", v: "Hi" }, state)).toBe("Hi");
  });

  it("ignores non-assistant messages", () => {
    expect(extractDeltaText({ message: { author: { role: "user" }, content: { text: "x" } } }, {})).toBe("");
  });
});

describe("errorKind + isTerminalEvent", () => {
  it("classifies auth / rate / upstream", () => {
    expect(errorKind("whatever", 401)).toBe("auth");
    expect(errorKind("whatever", 429)).toBe("rate");
    expect(errorKind("arkose required", 0)).toBe("rate");
    expect(errorKind("token expired", 0)).toBe("auth");
    expect(errorKind("weird blob", 500)).toBe("upstream");
    // 403 is NOT blanket-auth: the web endpoint walls with 403 too
    expect(errorKind("Unusual activity has been detected", 403)).toBe("rate");
    expect(errorKind("token_invalidated", 403)).toBe("auth");
  });

  it("detects terminal events", () => {
    expect(isTerminalEvent({ message: { end_turn: true } })).toBe(true);
    expect(isTerminalEvent({ message: { status: "finished_successfully" } })).toBe(true);
    expect(isTerminalEvent({ message: { status: "in_progress" } })).toBe(false);
  });
});

describe("OpenAIWebExecutor.execute", () => {
  beforeEach(() => {
    vi.mocked(proxyAwareFetch).mockReset();
    global.fetch = vi.fn();
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  const creds = { accessToken: "at-test", providerSpecificData: {} };

  it("rejects empty messages with 400", async () => {
    const ex = new OpenAIWebExecutor();
    const result = await ex.execute({ model: "auto", body: { messages: [] }, stream: false, credentials: creds, log: null });
    expect(result.response.status).toBe(400);
  });

  it("returns OpenAI-shaped JSON for non-stream", async () => {
    mockRequirementsChain();
    vi.mocked(proxyAwareFetch).mockResolvedValueOnce(sseResponse([
      { message: { author: { role: "assistant" }, content: { text: "Hel" } } },
      { message: { author: { role: "assistant" }, content: { text: "Hello!" }, end_turn: true } },
    ]));
    const ex = new OpenAIWebExecutor();
    const result = await ex.execute({
      model: "auto",
      body: { messages: [{ role: "user", content: "Hi" }] },
      stream: false,
      credentials: creds,
      log: null,
    });
    expect(result.response.status).toBe(200);
    expect(result.responseFormat).toBe("openai");
    const json = await result.response.json();
    expect(json.choices[0].message.content).toBe("Hello!");
    // sentinel token attached to conversation headers
    const convCall = vi.mocked(proxyAwareFetch).mock.calls[3];
    expect(convCall[0]).toContain("/backend-api/conversation");
    expect(convCall[1].headers["OpenAI-Sentinel-Chat-Requirements-Token"]).toBe("sentinel-1");
    expect(convCall[1].headers["Authorization"]).toBe("Bearer at-test");
    // reference payload fidelity
    const sentBody = JSON.parse(convCall[1].body);
    expect(sentBody.conversation_origin).toBeNull();
    expect(sentBody.timezone).toBe("Asia/Shanghai");
    expect(sentBody.variant_purpose).toBe("comparison_implicit");
    expect(sentBody.client_contextual_info).toBeTruthy();
  });

  it("maps 401 upstream to auth error", async () => {
    mockRequirementsChain();
    vi.mocked(proxyAwareFetch)
      .mockResolvedValueOnce(new Response("unauthorized", { status: 401 }));
    const ex = new OpenAIWebExecutor();
    const result = await ex.execute({
      model: "auto",
      body: { messages: [{ role: "user", content: "Hi" }] },
      stream: false,
      credentials: creds,
      log: null,
    });
    expect(result.response.status).toBe(401);
  });

  it("streams OpenAI chunks ending with [DONE]", async () => {
    mockRequirementsChain();
    vi.mocked(proxyAwareFetch).mockResolvedValueOnce(sseResponse([
      { message: { author: { role: "assistant" }, content: { text: "Yo" }, end_turn: true } },
    ]));
    const ex = new OpenAIWebExecutor();
    const result = await ex.execute({
      model: "gpt-5.6",
      body: { messages: [{ role: "user", content: "Hi" }] },
      stream: true,
      credentials: creds,
      log: null,
    });
    const text = await result.response.text();
    expect(text).toContain("chat.completion.chunk");
    expect(text).toContain("data: [DONE]");
  });
});

describe("isChallengeWall + extractUpstreamDetail", () => {
  it("detects HTML verification walls", () => {
    expect(isChallengeWall("<html><head>", "text/html")).toBe(true);
    expect(isChallengeWall("<!DOCTYPE html><html>", "")).toBe(true);
    expect(isChallengeWall('{"detail":"nope"}', "application/json")).toBe(false);
  });

  it("extracts JSON detail, skips walls", () => {
    expect(extractUpstreamDetail('{"detail":"Unusual activity (abc)"}')).toBe("Unusual activity (abc)");
    expect(extractUpstreamDetail("<html>wall</html>")).toBeNull();
    expect(extractUpstreamDetail("")).toBeNull();
  });
});

describe("image pointer pipeline", () => {
  it("maps public image models to upstream slugs", () => {
    expect(resolveWebImageSlug("gpt-image-2")).toBe("gpt-5-3");
    expect(resolveWebImageSlug("gpt-image-2.5")).toBe("auto");
    expect(resolveWebImageSlug("unknown-xyz")).toBe("auto");
  });

  it("collects pointers only from trusted tool context", () => {
    const toolEvent = {
      message: {
        author: { role: "tool" },
        content: { text: "done" },
        metadata: { image_url: "file-service://file-abc123" },
      },
    };
    expect(collectImagePointers(toolEvent)).toContain("file-service://file-abc123");

    const sedimentEvent = {
      async_task_type: "image_gen",
      message: {
        author: { role: "assistant" },
        content: { text: "sediment://img-1 done" },
        metadata: { async_task_type: "image_gen" },
      },
    };
    expect(collectImagePointers(sedimentEvent)).toContain("sediment://img-1");

    // patch envelope variant (real SSE shape: {p, o, v: {message}})
    const patchEvent = {
      p: "",
      o: "add",
      v: {
        message: {
          author: { role: "tool" },
          content: { content_type: "multimodal_text", parts: [{ asset_pointer: "file-service://file-xyz" }] },
        },
      },
    };
    expect(collectImagePointers(patchEvent)).toContain("file-service://file-xyz");

    // message without author role is NOT trusted (mirrors reference gate)
    const noRoleEvent = { async_task_type: "image_gen", message: { content: { text: "sediment://img-9 done" } } };
    expect(collectImagePointers(noRoleEvent)).toEqual([]);

    // input attachment in a user message: never output
    const userEvent = { message: { author: { role: "user" }, content: { text: "edit file-service://file-xyz please" } } };
    expect(collectImagePointers(userEvent)).toEqual([]);

    // bare tool signal without pointers: nothing
    expect(collectImagePointers({ tool_invoked: true })).toEqual([]);
  });

  it("builds download candidates per pointer kind", () => {
    expect(pointerDownloadCandidates("https://cdn.example/i.png")).toEqual(["https://cdn.example/i.png"]);
    const cands = pointerDownloadCandidates("file-service://file-abc");
    expect(cands[0]).toBe("https://chatgpt.com/backend-api/files/file-abc/download");
    // sediment ids resolve via the conversation-scoped attachment endpoint first
    const sedCands = pointerDownloadCandidates("sediment://file-abc", "conv-123");
    expect(sedCands[0]).toBe("https://chatgpt.com/backend-api/conversation/conv-123/attachment/file-abc/download");
    expect(sedCands[1]).toBe("https://chatgpt.com/backend-api/files/file-abc/download");
    expect(pointerDownloadCandidates("")).toEqual([]);
  });

  it("executeImage resolves a tool pointer to b64_json", async () => {
    vi.mocked(proxyAwareFetch).mockReset();
    const pngBytes = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10, 0, 1, 2, 3]);
    vi.mocked(proxyAwareFetch)
      .mockResolvedValueOnce(new Response("<html></html>", { status: 200 })) // bootstrap
      .mockResolvedValueOnce(new Response(JSON.stringify({ prepare_token: "p" }), { status: 200 })) // requirements prepare
      .mockResolvedValueOnce(new Response(JSON.stringify({ token: "s" }), { status: 200 })) // requirements finalize
      .mockResolvedValueOnce(new Response(JSON.stringify({ conduit_token: "conduit-1" }), { status: 200 })) // image prepare
      .mockResolvedValueOnce(sseResponse([ // image conversation SSE
        {
          message: {
            author: { role: "tool" },
            content: { text: "rendered" },
            metadata: { output: "file-service://file-render1" },
          },
          async_task_type: "image_gen",
          end_turn: true,
        },
      ]))
      .mockResolvedValueOnce(new Response(pngBytes, { status: 200, headers: { "Content-Type": "image/png" } })); // download
    const ex = new OpenAIWebExecutor();
    const out = await ex.executeImage({
      model: "gpt-image-2.5",
      body: { prompt: "a red fox", n: 1, size: "1024x1024" },
      credentials: { accessToken: "at-test", providerSpecificData: {} },
      log: null,
    });
    expect(out.data).toHaveLength(1);
    expect(out.data[0].b64_json).toBe(pngBytes.toString("base64"));
    // image prepare handshake posts the full prepare shape
    const prepareCall = vi.mocked(proxyAwareFetch).mock.calls[3];
    expect(prepareCall[0]).toContain("/f/conversation/prepare");
    const prepareBody = JSON.parse(prepareCall[1].body);
    expect(prepareBody.client_prepare_state).toBe("success");
    expect(prepareBody.partial_query.content.parts).toEqual(["a red fox"]);
    // generation call carries the conduit token
    const convCall = vi.mocked(proxyAwareFetch).mock.calls[4];
    expect(convCall[1].headers["X-Conduit-Token"]).toBe("conduit-1");
  });

  it("executeImage throws a clean error on terminal text without asset", async () => {
    vi.mocked(proxyAwareFetch).mockReset();
    vi.mocked(proxyAwareFetch)
      .mockResolvedValueOnce(new Response("<html></html>", { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ prepare_token: "p" }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ token: "s" }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ conduit_token: "c" }), { status: 200 }))
      .mockResolvedValueOnce(sseResponse([
        { message: { author: { role: "assistant" }, content: { text: "I cannot draw that" }, end_turn: true } },
      ]));
    const ex = new OpenAIWebExecutor();
    await expect(ex.executeImage({
      model: "gpt-image-2.5",
      body: { prompt: "x" },
      credentials: { accessToken: "at-test", providerSpecificData: {} },
      log: null,
    })).rejects.toThrow(/no image asset/i);
  });
});

describe("cookie jar continuity", () => {
  it("harvests set-cookie pairs and builds a Cookie header", () => {
    const jar = {};
    harvestSetCookies(
      new Response("{}", { status: 200, headers: { "set-cookie": "oai-did=abc123; Path=/; HttpOnly" } }),
      jar
    );
    expect(jar["oai-did"]).toBe("abc123");
    expect(jarCookieHeader(jar, "cf_clearance=zzz")).toBe("cf_clearance=zzz; oai-did=abc123");
    expect(jarCookieHeader({}, "")).toBeNull();
  });

  it("forwards jar + pasted cookies on the conversation call", async () => {
    vi.mocked(proxyAwareFetch).mockReset();
    vi.mocked(proxyAwareFetch)
      .mockResolvedValueOnce(new Response("<html></html>", { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ prepare_token: "p" }), { status: 200 }))
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ token: "s" }), { status: 200, headers: { "set-cookie": "oai-did=jar1; Path=/" } })
      )
      .mockResolvedValueOnce(sseResponse([
        { message: { author: { role: "assistant" }, content: { text: "Hi" }, end_turn: true } },
      ]));
    const ex = new OpenAIWebExecutor();
    await ex.execute({
      model: "auto",
      body: { messages: [{ role: "user", content: "Hi" }] },
      stream: false,
      credentials: { accessToken: "at-test", providerSpecificData: { cookies: "extra=1" } },
      log: null,
    });
    const convCall = vi.mocked(proxyAwareFetch).mock.calls[3];
    expect(convCall[1].headers["Cookie"]).toBe("extra=1; oai-did=jar1");
  });
});

describe("wall cooldown", () => {
  it("rests flagged accounts for 10 minutes", () => {
    const r = checkFallbackError(429, "Unusual activity has been detected from your device", 0);
    expect(r.shouldFallback).toBe(true);
    expect(r.cooldownMs).toBe(10 * 60 * 1000);
    const w = checkFallbackError(429, "OpenAI Web verification wall (fingerprinted)", 0);
    expect(w.cooldownMs).toBe(10 * 60 * 1000);
  });
});

describe("clearance solver", () => {
  it("parses FlareSolverr solutions into jar + UA", () => {
    const out = parseClearanceSolution({
      solution: {
        cookies: [{ name: "cf_clearance", value: "abc" }, { name: "", value: "x" }],
        userAgent: "SolverUA/1.0",
      },
    });
    expect(out.jar).toEqual({ cf_clearance: "abc" });
    expect(out.userAgent).toBe("SolverUA/1.0");
    expect(parseClearanceSolution(null)).toEqual({ jar: {}, userAgent: null });
  });

  it("uses clearance cookies + UA on the conversation call", async () => {
    vi.mocked(proxyAwareFetch).mockReset();
    vi.mocked(proxyAwareFetch)
      .mockResolvedValueOnce(new Response(JSON.stringify({
        solution: { cookies: [{ name: "cf_clearance", value: "solved1" }, { name: "oai-did", value: "did-9" }], userAgent: "SolverUA/9" },
      }), { status: 200 }))
      .mockResolvedValueOnce(new Response("<html></html>", { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ prepare_token: "p" }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ token: "s" }), { status: 200 }))
      .mockResolvedValueOnce(sseResponse([
        { message: { author: { role: "assistant" }, content: { text: "Hi" }, end_turn: true } },
      ]));
    const ex = new OpenAIWebExecutor();
    await ex.execute({
      model: "auto",
      body: { messages: [{ role: "user", content: "Hi" }] },
      stream: false,
      credentials: {
        accessToken: "at-test",
        providerSpecificData: { clearanceUrl: "https://solver.example.com/" },
      },
      log: null,
    });
    const calls = vi.mocked(proxyAwareFetch).mock.calls;
    expect(calls[0][0]).toBe("https://solver.example.com/v1");
    const convHeaders = calls[4][1].headers;
    expect(convHeaders["Cookie"]).toContain("cf_clearance=solved1");
    expect(convHeaders["User-Agent"]).toBe("SolverUA/9");
    // oai-did cookie and OAI-Device-Id header must agree
    expect(convHeaders["OAI-Device-Id"]).toBe("did-9");
  });

  it("continues without clearance when the solver is down", async () => {
    vi.mocked(proxyAwareFetch).mockReset();
    vi.mocked(proxyAwareFetch)
      .mockResolvedValueOnce(new Response("Internal Server Error", { status: 500 }))
      .mockResolvedValueOnce(new Response("<html></html>", { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ prepare_token: "p" }), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ token: "s" }), { status: 200 }))
      .mockResolvedValueOnce(sseResponse([
        { message: { author: { role: "assistant" }, content: { text: "Hi" }, end_turn: true } },
      ]));
    const ex = new OpenAIWebExecutor();
    const result = await ex.execute({
      model: "auto",
      body: { messages: [{ role: "user", content: "Hi" }] },
      stream: false,
      credentials: {
        accessToken: "at-test",
        providerSpecificData: { clearanceUrl: "https://solver.example.com" },
      },
      log: null,
    });
    expect(result.response.status).toBe(200);
    const json = await result.response.json();
    expect(json.choices[0].message.content).toBe("Hi");
  });
});

describe("openai-web OAuth bridge", () => {
  const cfg = openaiWebOAuth.config;

  it("builds the platform authorize URL (not the generic OAuth endpoint)", () => {
    const url = openaiWebOAuth.buildAuthUrl(cfg, "http://localhost:9999/callback", "state-1", "challenge-1");
    expect(url.startsWith("https://auth.openai.com/api/accounts/authorize?")).toBe(true);
    const q = new URL(url).searchParams;
    expect(q.get("client_id")).toBe("app_2SKx67EdpoN0G6j64rFvigXD");
    expect(q.get("audience")).toBe("https://api.openai.com/v1");
    expect(q.get("redirect_uri")).toBe("https://platform.openai.com/auth/callback");
    expect(q.get("response_mode")).toBe("query");
    expect(q.get("code_challenge")).toBe("challenge-1");
    expect(q.get("state")).toBe("state-1");
    expect(q.get("auth0Client")).toBeTruthy();
  });

  it("extracts codes from callback URLs or raw strings", () => {
    expect(extractOpenAIWebCode("https://platform.openai.com/auth/callback?code=abc123&state=s.1")).toBe("abc123");
    expect(extractOpenAIWebCode("raw-code-xyz")).toBe("raw-code-xyz");
    expect(extractOpenAIWebCode("")).toBe("");
  });
});

describe("refreshOpenAIWebToken", () => {
  beforeEach(() => {
    global.fetch = vi.fn();
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it("returns null without refresh token", async () => {
    expect(await refreshOpenAIWebToken(null, null)).toBeNull();
  });

  it("exchanges refresh grant for new tokens", async () => {
    global.fetch.mockResolvedValueOnce(
      new Response(JSON.stringify({ access_token: "at2", refresh_token: "rt2", expires_in: 3600 }), { status: 200 })
    );
    const out = await refreshOpenAIWebToken("rt1", null);
    expect(out.accessToken).toBe("at2");
    expect(out.refreshToken).toBe("rt2");
    const [, opts] = global.fetch.mock.calls[0];
    expect(JSON.parse(opts.body).grant_type).toBe("refresh_token");
  });

  it("flags terminal refresh errors", async () => {
    global.fetch.mockResolvedValueOnce(new Response('{"error":"invalid_grant"}', { status: 400 }));
    const out = await refreshOpenAIWebToken("rt-expired-marker", null);
    expect(out?.error).toBe("unrecoverable_refresh_error");
  });
});
