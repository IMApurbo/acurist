import type { Message } from "../types.js";
import { resolveModel } from "./config.js";

export interface ProxyResponse {
  text:      string;
  toolName?: string;
  toolInput?: Record<string, unknown>;
  usage?:    { input_tokens?: number; output_tokens?: number };
  stopReason?: string;
}

export class ProxyClient {
  constructor(private baseUrl: string, private model: string) {}

  async health(): Promise<boolean> {
    // Try /v1/models first (OpenAI-compatible proxies expose this but not /health),
    // then /v1, then /health. Strips any trailing /v1 from baseUrl first to avoid /v1/v1.
    const base = this.baseUrl.replace(/\/v1\/?$/, "");
    for (const suffix of ["/v1/models", "/v1", "/health"]) {
      try {
        const res = await fetch(`${base}${suffix}`, {
          headers: { "x-api-key": "local-proxy-key" },
          signal: AbortSignal.timeout(4000),
        });
        if (res.ok) return true;
      } catch {
        // try next
      }
    }
    return false;
  }

  async ask(
    messages: Message[],
    system:   string,
    signal?:  AbortSignal,
    tools?:   object[],
  ): Promise<ProxyResponse> {
    const timeout  = AbortSignal.timeout(120_000);
    const combined = signal ? AbortSignal.any([signal, timeout]) : timeout;

    // Resolve builtin alias → auto/ proxy model at send time
    const effectiveModel = resolveModel(this.model);

    const body: Record<string, unknown> = {
      model:      effectiveModel,
      max_tokens: 64000,
      system,
      messages,
      stream:     false,
    };
    if (tools && tools.length > 0) body.tools = tools;

    const res = await fetch(`${this.baseUrl}/v1/messages`, {
      method:  "POST",
      headers: {
        "Content-Type":       "application/json",
        "anthropic-version":  "2023-06-01",
        "x-api-key":          "local-proxy-key",
      },
      body: JSON.stringify(body),
      signal: combined as AbortSignal,
    });

    if (!res.ok) {
      const errBody = await res.text().catch(() => "");
      throw new Error(`Proxy ${res.status} ${res.statusText}\n${errBody}`);
    }

    const data = await res.json() as any;

    let text = "";
    let toolName: string | undefined;
    let toolInput: Record<string, unknown> | undefined;
    let toolBlockCount = 0;

    for (const block of (data.content ?? [])) {
      if (block.type === "text") {
        text += block.text ?? "";
      } else if (block.type === "tool_use") {
        toolBlockCount++;
        // Only grab the FIRST tool_use block. The system prompt enforces
        // "one tool per reply", so if the model (or a truncated response)
        // returns more than one, every block after the first is discarded
        // — but we no longer do that silently.
        if (toolName === undefined) {
          toolName  = block.name;
          toolInput = block.input ?? {};
        }
      }
    }

    if (toolBlockCount > 1) {
      console.warn(
        `[proxyClient] Response contained ${toolBlockCount} tool_use blocks; ` +
        `only the first ("${toolName}") was used, the rest were discarded.`
      );
    }

    const usage = data.usage
      ? { input_tokens: data.usage.input_tokens, output_tokens: data.usage.output_tokens }
      : undefined;

    const truncated = data.stop_reason === "max_tokens";
    if (truncated) {
      console.warn(
        "[proxyClient] Response was truncated (stop_reason=max_tokens). " +
        "The tool call / file write may be incomplete."
      );
      // A tool_use block cut off mid-generation can still deserialize to
      // valid-looking JSON (e.g. a string that just stops early), so we
      // can't detect truncation from toolInput's shape alone. Surface the
      // stop reason so callers (agent.ts) can decide whether it's safe to
      // execute a write_file/edit_file call with possibly-incomplete input.
      if (toolName === "write_file" && typeof toolInput?.content !== "string") {
        throw new Error(
          "Response truncated (max_tokens) while generating a write_file call, " +
          "and the file content could not be parsed at all. Aborting this tool call " +
          "rather than writing a corrupt/empty file."
        );
      }
    }

    return { text, toolName, toolInput, usage, stopReason: data.stop_reason };
  }
}
