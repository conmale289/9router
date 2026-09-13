/**
 * Cross-implementation vectors for the Sentinel PoW port (open-sse/sentinel/pow.js).
 * The expected answer was produced by the reference implementation
 * (utils/pow.py::_pow_generate) with the fixed config below — any divergence
 * means the JS port no longer matches byte-for-byte.
 */
import { describe, it, expect } from "vitest";
import {
  solveProofWithConfig,
  buildLegacyRequirementsToken,
  parsePowResources,
  POW_DEFAULT_SCRIPT,
} from "../../open-sse/sentinel/pow.js";

const FIXED_CONFIG = [
  3000,
  "Tue Sep 09 2025 10:00:00 GMT-0500 (Eastern Standard Time)",
  4294705152,
  1,
  "UA-TEST",
  "https://x.sdk.js",
  "c/build_/",
  "en-US",
  "en-US,es-US,en,es",
  0.5,
  "webdriver−false",
  "location",
  "window",
  1234.5,
  "uuid-1",
  "",
  16,
  999.0,
  0, 0, 0, 0, 0, 0,
  0,
];

// Reference answer for seed=testseed123 difficulty=0000 (nonce i=80113).
const EXPECTED_ANSWER =
  "WzMwMDAsIlR1ZSBTZXAgMDkgMjAyNSAxMDowMDowMCBHTVQtMDUwMCAoRWFzdGVybiBTdGFuZGFyZCBUaW1lKSIsNDI5NDcwNTE1Miw4MDExMywiVUEtVEVTVCIsImh0dHBzOi8veC5zZGsuanMiLCJjL2J1aWxkXy8iLCJlbi1VUyIsImVuLVVTLGVzLVVTLGVuLGVzIiw0MDA1Niwid2ViZHJpdmVy4oiSZmFsc2UiLCJsb2NhdGlvbiIsIndpbmRvdyIsMTIzNC41LCJ1dWlkLTEiLCIiLDE2LDk5OS4wLDAsMCwwLDAsMCwwLDBd";

describe("sentinel PoW port", () => {
  it("matches the reference solver byte-for-byte", () => {
    const { answer, solved } = solveProofWithConfig("testseed123", "0000", FIXED_CONFIG, 500000);
    expect(solved).toBe(true);
    expect(answer).toBe(EXPECTED_ANSWER);
  });

  it("emits whole floats Python-style (999.0) and plain ints bare", () => {
    const decoded = Buffer.from(
      solveProofWithConfig("s", "ff", FIXED_CONFIG, 5).answer,
      "base64"
    ).toString("utf8");
    expect(decoded).toContain("999.0");
    expect(decoded).toContain("[3000,");
    expect(decoded).not.toContain("3000.0");
  });

  it("builds legacy requirements tokens with the gAAAAAC prefix", () => {
    const token = buildLegacyRequirementsToken("UA-TEST", [POW_DEFAULT_SCRIPT], "c/build_/");
    expect(token.startsWith("gAAAAAC")).toBe(true);
    const decoded = JSON.parse(Buffer.from(token.slice(7), "base64").toString("utf8"));
    expect(Array.isArray(decoded)).toBe(true);
    expect(decoded).toHaveLength(25);
  });

  it("parses bootstrap script sources + data-build", () => {
    const { scriptSources, dataBuild } = parsePowResources(
      '<html data-build="abc123"><head><script src="https://chatgpt.com/_next/static/c/xyz/_/app.js"></script></head></html>'
    );
    expect(scriptSources).toHaveLength(1);
    expect(dataBuild).toBe("c/xyz/_");
    const fallback = parsePowResources("<html><head></head></html>");
    expect(fallback.scriptSources).toEqual([POW_DEFAULT_SCRIPT]);
    expect(fallback.dataBuild).toBe("");
  });
});
