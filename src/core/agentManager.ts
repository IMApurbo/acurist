/**
 * agentManager.ts — built-in agent persona switching for Acurist
 *
 * Acurist ships with a fixed set of agent personas (see agent.ts). There is
 * no free-form "create your own agent" flow anymore — pick one by name:
 *
 * /agent                 — list all built-in agents (same as /agent list)
 * /agent <name>          — activate a built-in agent for this session, e.g. /agent hacker
 * /agent list            — list all built-in agents
 * /agent info <name>     — show full details of an agent (system prompt)
 *
 * Whichever agent you last activated is remembered (see config.ts's
 * lastAgentId) and becomes the default the next time Acurist starts, unless
 * overridden by `--agent <name>` on the CLI.
 *
 * CLI: acurist --agent <name>  — start with a specific agent active
 */

import { AGENT_PERSONAS, DEFAULT_AGENT_ID, type AgentPersona } from "./agent.js";
import { getMcpServers, getPlugins, setLastAgentId } from "./config.js";
import type { TranscriptEvent } from "../types.js";

/**
 * Build a human-readable summary of an agent persona's full configuration.
 */
function agentInfoText(agent: AgentPersona): string {
  const mcps = getMcpServers();
  const plugins = getPlugins();

  const lines: string[] = [
    `🤖 Agent: ${agent.name}  (/agent ${agent.id})`,
    ``,
    `Description:`,
    `  ${agent.description}`,
    ``,
    `System prompt:`,
    ...agent.prompt.split("\n").map((l) => `  ${l}`),
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
 * Build the list of all built-in agents, marking whichever one is active.
 */
function agentListText(currentId: string): string {
  const lines = AGENT_PERSONAS.map((a) => {
    const marker = a.id === currentId ? "●" : " ";
    return `  ${marker} ${a.id.padEnd(16)} ${a.name.padEnd(16)} ${a.description}`;
  });
  return (
    `Built-in agents:\n${lines.join("\n")}\n\n` +
    `Use: /agent <name>  ·  /agent info <name>\n` +
    `Type "/agent " (with a trailing space) to pick one from the list.`
  );
}

export interface AgentManagerDeps {
  emit: (e: TranscriptEvent) => void;
  /** Called with the persona when an agent is activated */
  onActivateAgent: (agent: AgentPersona) => void;
  /** The currently active agent id, for highlighting in listings */
  currentAgentId: string;
}

/**
 * Handle all /agent subcommands. Returns a message string (empty = silent).
 */
export async function handleAgentCommand(
  args: string[],
  deps: AgentManagerDeps
): Promise<string> {
  const { onActivateAgent, currentAgentId } = deps;
  const sub = args[0]?.toLowerCase() ?? "";

  switch (sub) {
    case "":
    case "list": {
      return agentListText(currentAgentId);
    }

    case "info": {
      const name = args[1];
      if (!name) {
        return "Usage: /agent info <name>\n\n" + agentListText(currentAgentId);
      }
      const agent = AGENT_PERSONAS.find((a) => a.id === name.toLowerCase());
      if (!agent) {
        return `No agent named "${name}".\n\n` + agentListText(currentAgentId);
      }
      return agentInfoText(agent);
    }

    // Back-compat: "/agent use <name>" still works as an alias for "/agent <name>"
    case "use": {
      const name = args[1];
      if (!name) {
        return "Usage: /agent use <name>  (see /agent list for names)";
      }
      return activate(name);
    }

    default: {
      // "/agent <name>" — the primary form. Selecting from the picker under
      // "/agent " inserts one of these ids directly.
      return activate(sub);
    }
  }

  function activate(name: string): string {
    const id = name.toLowerCase();
    if (id === "default" || id === "reset") {
      const agent = AGENT_PERSONAS.find((a) => a.id === DEFAULT_AGENT_ID)!;
      onActivateAgent(agent);
      setLastAgentId(agent.id);
      return `✅ Switched to "${agent.name}" (default).`;
    }
    const agent = AGENT_PERSONAS.find((a) => a.id === id);
    if (!agent) {
      return `No agent named "${name}".\n\n` + agentListText(currentAgentId);
    }
    onActivateAgent(agent);
    setLastAgentId(agent.id);
    return agentInfoText(agent) + `\n\n✅ Agent "${agent.name}" is now active. Start chatting — responses will follow its behavior.`;
  }
}
