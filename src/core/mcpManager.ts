/**
 * MCP (Model Context Protocol) server manager.
 *
 * Acurist exposes MCP servers to the agent via two mechanisms:
 *  1. System-prompt injection — each server's description is appended so the
 *     model knows what extra capabilities are available.
 *  2. Tool-schema forwarding — if a server exposes a tools endpoint, its
 *     schemas are fetched and added to the TOOL_SCHEMAS list at turn time.
 *
 * The design mirrors Claude Code's MCP integration: servers are registered by
 * name + URL and their capabilities are fetched lazily.
 */

import fetch from "node-fetch";
import { getMcpServers } from "./config.js";
import type { McpServer } from "../types.js";

export interface McpToolSchema {
  name: string;
  description: string;
  input_schema: Record<string, any>;
  /** The server this tool came from — used to route calls back. */
  _mcpServer: string;
}

export interface McpCapabilities {
  server: McpServer;
  tools: McpToolSchema[];
  description?: string;
  error?: string;
}

// Cache capabilities per session to avoid re-fetching on every turn.
const capabilityCache = new Map<string, McpCapabilities>();

/** Fetch capabilities (tools list) from an MCP server. */
async function fetchCapabilities(server: McpServer): Promise<McpCapabilities> {
  const cached = capabilityCache.get(server.url);
  if (cached) return cached;

  try {
    const res = await fetch(`${server.url}/mcp/v1/tools`, {
      headers: { "Content-Type": "application/json" },
      signal: AbortSignal.timeout(8_000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const body = (await res.json()) as { tools?: McpToolSchema[]; description?: string };
    const caps: McpCapabilities = {
      server,
      tools: (body.tools ?? []).map((t) => ({ ...t, _mcpServer: server.url })),
      description: body.description,
    };
    capabilityCache.set(server.url, caps);
    return caps;
  } catch (e: any) {
    const caps: McpCapabilities = { server, tools: [], error: e?.message ?? String(e) };
    capabilityCache.set(server.url, caps);
    return caps;
  }
}

/** Refresh all registered MCP servers and return their capabilities. */
export async function loadAllMcpCapabilities(): Promise<McpCapabilities[]> {
  const servers = getMcpServers();
  return Promise.all(servers.map(fetchCapabilities));
}

/** Build the MCP section of the system prompt, listing each server's tools. */
export function buildMcpSystemPrompt(caps: McpCapabilities[]): string {
  if (!caps.length) return "";
  const lines: string[] = [
    "\n\n## MCP Servers\n",
    "The following external MCP (Model Context Protocol) servers are connected.\n",
    "Their tools are available in addition to the built-in ones. Call them the same way:\nTOOL: tool_name\nparam: value\n",
  ];
  for (const c of caps) {
    const status = c.error ? ` ⚠ (unreachable: ${c.error})` : "";
    lines.push(`\n### ${c.server.name}${status}`);
    if (c.description) lines.push(c.description);
    if (c.tools.length) {
      lines.push("Tools:");
      for (const t of c.tools) {
        lines.push(`  • ${t.name} — ${t.description}`);
      }
    } else if (!c.error) {
      lines.push("(no tools advertised)");
    }
  }
  return lines.join("\n");
}

/** Call a tool on a specific MCP server by POST to /mcp/v1/call. */
export async function callMcpTool(
  serverUrl: string,
  toolName: string,
  input: Record<string, any>,
  signal?: AbortSignal
): Promise<{ output: string; isError: boolean }> {
  try {
    const timeout = AbortSignal.timeout(30_000);
    const combined = signal ? AbortSignal.any([signal, timeout]) : timeout;
    const res = await fetch(`${serverUrl}/mcp/v1/call`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: toolName, input }),
      signal: combined as any,
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      return { output: `MCP error ${res.status}: ${body}`, isError: true };
    }
    const data = (await res.json()) as { output?: string; error?: string };
    if (data.error) return { output: data.error, isError: true };
    return { output: data.output ?? "(no output)", isError: false };
  } catch (e: any) {
    return { output: `MCP call failed: ${e?.message ?? e}`, isError: true };
  }
}

/** Clear the capability cache (e.g. after adding/removing a server). */
export function clearMcpCache() {
  capabilityCache.clear();
}
