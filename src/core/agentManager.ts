/**
 * agentManager.ts — Custom agent management for Acurist
 *
 * /agent create              — interactive: AI generates a system prompt from your description
 * /agent use <name>          — activate a saved agent for this session
 * /agent info <name>         — show full details of a saved agent (system prompt, mcps, plugins)
 * /agent list                — list all saved agents
 * /agent delete <name>       — delete a saved agent
 *
 * CLI: acurist --agent <name>  — start with a specific agent active
 */

import { randomUUID } from "node:crypto";
import {
  getCustomAgents,
  saveCustomAgent,
  deleteCustomAgent as deleteAgentFromStore,
  getCustomAgent,
  getMcpServers,
  getPlugins,
  type CustomAgent,
} from "./config.js";
import { ProxyClient } from "./proxyClient.js";
import type { TranscriptEvent } from "../types.js";

const AGENT_CREATOR_SYSTEM_PROMPT = `You are an expert AI agent prompt engineer. Your job is to take a user's description of how they want their AI assistant to behave, and produce a clear, focused system prompt that will make the assistant act exactly as described.

Rules for the system prompt you produce:
- Write it in second person ("You are...", "Your role is...", "When asked...")
- Be specific about tone, expertise, restrictions, and behavior
- Include what the agent SHOULD do and what it SHOULD NOT do
- Keep it under 400 words — concise prompts work better
- Do NOT include generic boilerplate like "Be helpful and friendly" — assume that
- End with a sentence about the agent's output format/style if relevant

Respond with ONLY the system prompt text. No preamble, no explanation, no markdown fences.`;

/**
 * Use the proxy/AI to generate a system prompt from a plain-language description.
 */
async function generateSystemPrompt(
  description: string,
  proxy: ProxyClient
): Promise<string> {
  const resp = await proxy.ask(
    [{ role: "user", content: [{ type: "text", text: `Create a system prompt for this agent:\n\n${description}` }] }],
    AGENT_CREATOR_SYSTEM_PROMPT,
    undefined
  );
  return resp.text.trim();
}

export interface AgentManagerDeps {
  proxy: ProxyClient;
  emit: (e: TranscriptEvent) => void;
  /** Called with the system prompt when an agent is activated */
  onActivateAgent: (agent: CustomAgent | null) => void;
  /** Ask user for free-form input (used during /agent create flow) */
  askUser: (question: string, options?: string[]) => Promise<string>;
  /** Signal that the command is done (so busy spinner clears) */
  onCommandDone?: () => void;
}

/**
 * Build a human-readable summary of an agent's full configuration.
 */
function agentInfoText(agent: CustomAgent): string {
  const mcps = getMcpServers();
  const plugins = getPlugins();

  const lines: string[] = [
    `🤖 Agent: ${agent.name}`,
    `Created: ${new Date(agent.createdAt).toLocaleString()}`,
    ``,
    `Description:`,
    `  ${agent.description}`,
    ``,
    `System prompt:`,
    ...agent.systemPrompt.split("\n").map((l) => `  ${l}`),
  ];

  if (mcps.length > 0) {
    lines.push(``, `MCP servers (global — available to all agents):`);
    for (const s of mcps) lines.push(`  • ${s.name.padEnd(20)} ${s.url}`);
  } else {
    lines.push(``, `MCP servers: none configured  (/mcp add <name> <url>)`);
  }

  if (plugins.length > 0) {
    lines.push(``, `Active plugins:`);
    for (const p of plugins) lines.push(`  • ${p.name.padEnd(20)} v${p.version}  ${p.description.slice(0, 60)}`);
  } else {
    lines.push(``, `Plugins: none installed  (/plugin browse)`);
  }

  return lines.join("\n");
}

/**
 * Handle all /agent subcommands. Returns a message string (empty = silent).
 */
export async function handleAgentCommand(
  args: string[],
  deps: AgentManagerDeps
): Promise<string> {
  const { proxy, emit, onActivateAgent, askUser } = deps;
  const sub = args[0]?.toLowerCase() ?? "";

  switch (sub) {
    case "create": {
      // Interactive creation flow.
      // Important: askUser puts the UI into "ask" mode, which resolves back
      // to "busy" after the user answers. We must NOT set mode to busy again
      // ourselves — the calling code in App.tsx already handles drainQueue()
      // which clears busy when we return.
      emit({ kind: "system", id: randomUUID(), text: "🤖 Agent Creator — describe your agent and I'll generate a system prompt.\n\nWhat should this agent do? (Be as detailed as you like — role, behavior, tone, restrictions, etc.)" });

      let description: string;
      try {
        description = await askUser("Describe your agent's purpose and behavior:");
      } catch {
        return "Agent creation cancelled.";
      }

      if (!description.trim()) {
        return "Agent creation cancelled — no description provided.";
      }

      // Emit the generating message, then do the AI call.
      // We do NOT emit a "busy" mode change — the outer drainQueue handles that.
      emit({ kind: "system", id: randomUUID(), text: "⏳ Generating system prompt…" });

      let systemPrompt: string;
      try {
        systemPrompt = await generateSystemPrompt(description, proxy);
      } catch (e: any) {
        return `Failed to generate system prompt: ${e?.message ?? e}`;
      }

      emit({ kind: "system", id: randomUUID(), text: `Generated system prompt:\n\n${systemPrompt}` });

      let agentName: string;
      try {
        agentName = await askUser("Give this agent a name (letters, numbers, hyphens only):");
      } catch {
        return "Agent creation cancelled.";
      }

      agentName = agentName.trim().replace(/[^a-zA-Z0-9-_]/g, "-").toLowerCase();
      if (!agentName) {
        return "Agent creation cancelled — invalid name.";
      }

      const agent: CustomAgent = {
        name: agentName,
        description: description.trim(),
        systemPrompt,
        createdAt: new Date().toISOString(),
      };

      saveCustomAgent(agent);

      // Return the success message — the outer code will emit it via
      // emit({ kind: "system", text }) and then drainQueue() will clear
      // the busy spinner. No extra state changes needed here.
      return `✅ Agent "${agentName}" saved!\n\nActivate it with: /agent use ${agentName}\nOr start acurist with: acurist --agent ${agentName}`;
    }

    case "use": {
      const name = args[1];
      if (!name) {
        return "Usage: /agent use <name>  (see /agent list for names)";
      }
      if (name === "default" || name === "none" || name === "reset") {
        onActivateAgent(null);
        return "✅ Switched back to default Acurist agent.";
      }
      const agent = getCustomAgent(name);
      if (!agent) {
        return `No agent named "${name}". Use /agent list to see available agents.`;
      }
      onActivateAgent(agent);

      // Show a rich summary so the user knows exactly what they activated.
      return agentInfoText(agent) + `\n\n✅ Agent "${name}" is now active. Start chatting — responses will follow its custom behavior.`;
    }

    case "info": {
      const name = args[1];
      if (!name) {
        return "Usage: /agent info <name>";
      }
      const agent = getCustomAgent(name);
      if (!agent) {
        return `No agent named "${name}". Use /agent list.`;
      }
      return agentInfoText(agent);
    }

    case "list": {
      const agents = getCustomAgents();
      if (!agents.length) {
        return "No custom agents saved. Create one with: /agent create";
      }
      const lines = agents.map((a) =>
        `  ${a.name.padEnd(20)} ${a.description.slice(0, 60)}${a.description.length > 60 ? "…" : ""}`
      ).join("\n");
      return `Custom agents:\n${lines}\n\nUse: /agent use <name>  ·  /agent info <name>  ·  /agent delete <name>`;
    }

    case "delete": {
      const name = args[1];
      if (!name) {
        return "Usage: /agent delete <name>";
      }
      if (deleteAgentFromStore(name)) {
        return `Agent "${name}" deleted.`;
      }
      return `No agent named "${name}".`;
    }

    default:
      return (
        "Usage:\n" +
        "  /agent create           — create a new agent interactively\n" +
        "  /agent use <name>       — activate an agent for this session\n" +
        "  /agent use default      — reset to the default Acurist agent\n" +
        "  /agent info <name>      — show full details (system prompt, mcps, plugins)\n" +
        "  /agent list             — show all saved agents\n" +
        "  /agent delete <name>    — delete an agent\n\n" +
        "CLI: acurist --agent <name>  — start with an agent pre-loaded"
      );
  }
}
