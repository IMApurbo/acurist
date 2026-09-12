import { randomUUID } from "node:crypto";
import { ProxyClient } from "./proxyClient.js";
import { TOOL_SCHEMAS, executeTool, type ToolContext } from "./tools.js";
import { previewOrLog } from "./outputLog.js";
import { buildPluginSystemPrompt, getActivePluginNames } from "./pluginMarket.js";
import {
  loadAllMcpCapabilities,
  buildMcpSystemPrompt,
  callMcpTool,
  type McpCapabilities,
} from "./mcpManager.js";
import type { Message, TranscriptEvent, TokenUsage, ToolPermissionMap } from "../types.js";

const MAX_TURNS = 30;

function buildSystem(mcpCaps: McpCapabilities[], plugins: string): string {
  return `You are Acurist, a terminal AI agent on the user's Linux machine.

## Tool use rules (follow exactly)
- Call ONE tool per reply. Do NOT call two tools in the same message.
- Wait for the tool result before calling another tool.
- Do NOT narrate or describe what you are about to do before calling a tool. Just call it.
- Do NOT produce text like "I will now run..." or "Let me start a server..." before a tool call.
- After each tool result, decide the next single action and call that tool, or give a final answer.

## Background jobs
- Commands that run forever (HTTP servers, dev servers, watchers, GUI apps, while-true loops) are automatically detected and run in the background. You do NOT need to append & or set background:true for these — just call run_shell with the plain command.
- You will receive startup output (first 3 seconds) and a job_id. The process keeps running.
- To check on it later, call read_bg_log with that job_id.
- To stop it, call read_bg_log with kill:true.
- Never wait for a server to finish — it won't. Move on after seeing the startup output.

## File and shell rules
- Use read_file, write_file, edit_file, grep, glob for file work — not run_shell.
- No sudo. Use absolute paths. Each shell call is a fresh shell process (no state carries over).
- If the message contains @path/to/file, call read_file on that path first.
- If a write_file call is reported as truncated (cut off before finishing), do NOT retry write_file from scratch. Call append_file with ONLY the remaining content, continuing exactly from what was already written — never repeat content that's already on disk.

## Planning
- For multi-step tasks, call update_todos once at the start with the full plan, then execute steps one tool at a time.
- Do NOT call update_todos repeatedly between every single tool call.

## Asking the user
- Only call ask_user when you are genuinely blocked and cannot make progress without input.
${buildMcpSystemPrompt(mcpCaps)}${plugins}`;
}

export interface AgentDeps {
  proxy:               ProxyClient;
  cwd:                 string;
  emit:                (event: TranscriptEvent) => void;
  confirmShell:        (command: string, toolName?: string) => Promise<boolean>;
  askUser:             (question: string, options?: string[]) => Promise<string>;
  notify:              (message: string) => void;
  onUsage?:            (usage: TokenUsage) => void;
  toolPermissions?:    ToolPermissionMap;
  customSystemPrompt?: string;
}

export class Agent {
  private messages: Message[] = [];
  private usage: TokenUsage   = { inputTokens: 0, outputTokens: 0, totalTokens: 0 };

  constructor(private deps: AgentDeps) {}

  getMessages()                { return this.messages; }
  setMessages(msgs: Message[]) { this.messages = msgs; }
  getUsage()                   { return { ...this.usage }; }

  undo(): boolean {
    let i = this.messages.length - 1;
    while (i >= 0 && this.messages[i].role !== "assistant") i--;
    if (i < 0) return false;
    while (i >= 0 && this.messages[i].role !== "user") i--;
    if (i < 0) return false;
    this.messages = this.messages.slice(0, i);
    return true;
  }

  async send(userText: string, signal?: AbortSignal): Promise<void> {
    this.deps.emit({ kind: "user", text: userText, id: randomUUID() });

    const activePlugins = getActivePluginNames();
    if (activePlugins.length > 0) {
      this.deps.emit({ kind: "plugin_active", plugins: activePlugins, id: randomUUID() });
    }

    this.messages.push({ role: "user", content: [{ type: "text", text: userText }] });

    let mcpCaps: McpCapabilities[] = [];
    try { mcpCaps = await loadAllMcpCapabilities(); } catch {}

    const pluginPrompt = buildPluginSystemPrompt();
    const system = this.deps.customSystemPrompt
      ? `${this.deps.customSystemPrompt}\n\n---\n\n${buildSystem(mcpCaps, pluginPrompt)}`
      : buildSystem(mcpCaps, pluginPrompt);

    const ctx: ToolContext = {
      cwd:             this.deps.cwd,
      proxy:           this.deps.proxy,
      confirmShell:    (cmd, name) => this.deps.confirmShell(cmd, name),
      askUser:         this.deps.askUser,
      onTodos:         todos => this.deps.emit({ kind: "todos", todos: todos as any, id: randomUUID() }),
      notify:          m => this.deps.notify(m),
      toolPermissions: this.deps.toolPermissions,
      signal,
    };

    const mcpToolMap = new Map<string, string>();
    const mcpToolSchemas: object[] = [];
    for (const c of mcpCaps) {
      for (const t of c.tools) {
        mcpToolMap.set(t.name, c.server.url);
        mcpToolSchemas.push(t);
      }
    }
    const allTools = [...(TOOL_SCHEMAS as unknown as object[]), ...mcpToolSchemas];

    for (let turn = 0; turn < MAX_TURNS; turn++) {
      if (signal?.aborted) {
        this.deps.emit({ kind: "system", text: "Interrupted.", id: randomUUID() });
        return;
      }

      let resp;
      try {
        resp = await this.deps.proxy.ask(this.messages, system, signal, allTools);
      } catch (e: any) {
        if (signal?.aborted || e?.name === "AbortError") {
          this.deps.emit({ kind: "system", text: "Interrupted.", id: randomUUID() });
          return;
        }
        throw e;
      }

      if (resp.usage) {
        this.usage.inputTokens  += resp.usage.input_tokens  ?? 0;
        this.usage.outputTokens += resp.usage.output_tokens ?? 0;
        this.usage.totalTokens   = this.usage.inputTokens + this.usage.outputTokens;
        this.deps.onUsage?.({ ...this.usage });
      }

      // No tool call — final answer
      if (!resp.toolName) {
        // Push assistant text-only reply into history
        if (resp.text.trim()) {
          this.messages.push({ role: "assistant", content: [{ type: "text", text: resp.text }] });
          this.deps.emit({ kind: "assistant", text: resp.text, id: randomUUID() });
        }
        return;
      }

      // Warn (and let the user know in the transcript) if this turn's tool
      // call may be based on a truncated response, e.g. a write_file whose
      // content string got cut off mid-file.
      if (resp.stopReason === "max_tokens") {
        this.deps.emit({
          kind: "system",
          text: `Warning: model response was truncated (max_tokens) before calling "${resp.toolName}". ` +
                `Its input may be incomplete — check the result carefully.`,
          id: randomUUID(),
        });
      }

      const toolCallId = randomUUID();

      // Push assistant reply with tool_use content block (internal Anthropic API format)
      const assistantContent: any[] = [];
      if (resp.text.trim()) assistantContent.push({ type: "text", text: resp.text });
      assistantContent.push({ type: "tool_use", id: toolCallId, name: resp.toolName, input: resp.toolInput ?? {} });
      this.messages.push({ role: "assistant", content: assistantContent });

      // Emit any "thinking aloud" text the model produced before the tool call
      if (resp.text.trim()) {
        this.deps.emit({ kind: "assistant", text: resp.text, id: randomUUID() });
      }

      // Emit the tool call event for the UI
      this.deps.emit({ kind: "tool_call", name: resp.toolName, input: resp.toolInput ?? {}, id: randomUUID() });

      // Execute the tool
      const mcpUrl = mcpToolMap.get(resp.toolName);
      const result = mcpUrl
        ? await callMcpTool(mcpUrl, resp.toolName, resp.toolInput ?? {}, signal)
        : await executeTool(ctx, resp.toolName, resp.toolInput ?? {});

      this.deps.emit({ kind: "tool_result", name: resp.toolName, output: previewOrLog(result.output, resp.toolName), isError: result.isError, id: randomUUID() });

      // If this write_file/append_file call was itself built from a
      // truncated response, don't just report success/failure — feed back
      // the tail of what actually landed on disk as context, and steer the
      // model toward continuing with append_file rather than re-emitting
      // the whole file (which would just hit the same limit again).
      let toolResultText = result.output;
      if (
        resp.stopReason === "max_tokens" &&
        !result.isError &&
        (resp.toolName === "write_file" || resp.toolName === "append_file")
      ) {
        const written = typeof resp.toolInput?.content === "string" ? resp.toolInput.content as string : "";
        const tail = written.slice(-800); // last ~800 chars for continuation context
        toolResultText =
          `${result.output}\n\n` +
          `NOTE: this call was truncated (max_tokens) before the model finished generating. ` +
          `The file may not be complete yet. Here is the tail of what was actually written, for context:\n` +
          `-----\n${tail}\n-----\n` +
          `If the file is not yet complete, call append_file with ONLY the remaining content, ` +
          `continuing exactly after the text shown above. Do not repeat it.`;
      }

      // Feed result back as native tool_result content block
      this.messages.push({
        role:    "user",
        content: [{
          type:       "tool_result",
          tool_use_id: toolCallId,
          content:    toolResultText,
          is_error:   result.isError || undefined,
        }],
      });
    }

    this.deps.emit({ kind: "system", text: `Stopped after ${MAX_TURNS} turns.`, id: randomUUID() });
  }

  reset() { this.messages = []; }
}
