// OpenAI Web image adapter — delegates to the executor, which speaks the
// chatgpt.com Web image path (prepare → image conversation SSE → pointer
// resolve → download) and returns OpenAI-shaped {created, data:[{b64_json}]}.
import { getExecutor } from "../../executors/index.js";

export default {
  useExecutor: true,

  // Stubs — required by imageGenerationCore interface but unused with useExecutor
  buildUrl: () => "",
  buildHeaders: () => ({}),
  buildBody: () => ({}),

  async executeViaExecutor(model, body, credentials, log) {
    const executor = getExecutor("openai-web");
    if (!executor || typeof executor.executeImage !== "function") {
      throw new Error("OpenAI Web executor not found");
    }
    return executor.executeImage({ model, body, credentials, log });
  },

  // Already OpenAI-shaped from executeImage — pass through.
  normalize: (responseBody) => responseBody,
};
