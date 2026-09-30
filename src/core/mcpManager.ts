/**
 * MCP (Model Context Protocol) client manager.
 *
 * Transports supported
 *  1. Streamable HTTP (MCP spec 2025-03-26) — JSON-RPC 2.0 over POST, replies
 *     as JSON or as an SSE stream, optional Mcp-Session-Id. This is what real
 *     remote MCP servers speak (usually at a path like /mcp).
 *  2. "REST bridge" (legacy, Acurist-specific) — GET {url}/mcp/v1/tools and
 *     POST {url}/mcp/v1/call. Kept as an automatic fallback so existing
 *     bridges keep working.
 *
 * Not supported: stdio servers and the deprecated HTTP+SSE transport (/sse).
 * These produce a clear error instead of failing silently.
 *
 * Tools are exposed to the model under namespaced names
 * `mcp__<server>__<tool>` so they can never collide with built-in tools or
 * with same-named tools from another server.
 */

import fetch from "node-fetch";
import { getMcpServers } from "./config.js";
import type { McpServer } from "../types.js";

const PROTOCOL_VERSION = "2025-03-26";
const CAPS_TTL_OK_MS = 5 * 60_000;   // re-list tools every 5 min
const CAPS_TTL_ERR_MS = 15_000;      // retry a failed server after 15 s (not "forever")
const LIST_TIMEOUT_MS = 8_000;
const CALL_TIMEOUT_MS = 60_000;

export type McpTransport = "streamable-http" | "rest";

/** A tool as advertised by its server (original, un-namespaced name). */
export interface McpToolInfo {
  name: string;
  description: string;
  input_schema: Record<string, any>;
}

export interface McpCapabilities {
  server: McpServer;
  tools: McpToolInfo[];
  description?: string;
  transport?: McpTransport;
  error?: string;
}

export interface McpToolRoute {
  server: McpServer;
  /** Original tool name on the server. */
  toolName: string;
}

class McpHttpError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

const serverKey = (s: McpServer) => `${s.name}\n${s.url}`;

// ── helpers ──────────────────────────────────────────────────────────────────

function withTimeout(signal: AbortSignal | undefined, ms: number): AbortSignal {
  const t = AbortSignal.timeout(ms);
  return signal ? AbortSignal.any([signal, t]) : t;
}

function errMsg(e: any): string {
  return e?.name === "TimeoutError" ? "timed out" : (e?.message ?? String(e));
}

function normalizeSchema(raw: any): Record<string, any> {
  const s = raw && typeof raw === "object" ? { ...raw } : {};
  if (s.type !== "object") s.type = "object";
  if (!s.properties || typeof s.properties !== "object") s.properties = {};
  return s;
}

/** Parses complete SSE events out of `buf`; returns leftover + decoded JSON payloads. */
function drainSse(buf: string): { rest: string; messages: any[] } {
  const messages: any[] = [];
  for (;;) {
    const m = buf.match(/\r?\n\r?\n/);
    if (!m || m.index === undefined) break;
    const block = buf.slice(0, m.index);
    buf = buf.slice(m.index + m[0].length);
    const data = block
      .split(/\r?\n/)
      .filter((l) => l.startsWith("data:"))
      .map((l) => l.slice(5).replace(/^ /, ""))
      .join("\n");
    if (!data) continue;
    try { messages.push(JSON.parse(data)); } catch { /* ignore non-JSON events */ }
  }
  return { rest: buf, messages };
}

// ── Streamable HTTP client ───────────────────────────────────────────────────

class StreamableHttpClient {
  private sessionId?: string;
  private ready?: Promise<void>;
  private nextId = 1;

  constructor(private server: McpServer) {}

  private headers(): Record<string, string> {
    const h: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      ...(this.server.headers ?? {}),
    };
    if (this.sessionId) {
      h["Mcp-Session-Id"] = this.sessionId;
      h["MCP-Protocol-Version"] = PROTOCOL_VERSION;
    }
    return h;
  }

  /** POST one JSON-RPC message. With `wantId`, resolves with that request's result. */
  private async post(payload: unknown, signal: AbortSignal, wantId?: number): Promise<any> {
    const res = await fetch(this.server.url, {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify(payload),
      signal: signal as any,
    });
    const sid = res.headers.get("mcp-session-id");
    if (sid) this.sessionId = sid;

    if (!res.ok) {
      const body = (await res.text().catch(() => "")).slice(0, 300);
      throw new McpHttpError(res.status, `HTTP ${res.status}${body ? `: ${body}` : ""}`);
    }
    if (wantId === undefined) { await res.text().catch(() => {}); return null; } // notification → 202

    const ct = res.headers.get("content-type") ?? "";
    let reply: any;

    if (ct.includes("text/event-stream")) {
      // Read incrementally and stop at our reply — don't wait for the server to close the stream.
      let buf = "";
      const body: any = res.body;
      for await (const chunk of body) {
        buf += typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf-8");
        const { rest, messages } = drainSse(buf);
        buf = rest;
        reply = messages.find((m) => m && m.id === wantId && ("result" in m || "error" in m));
        if (reply) { try { body.destroy?.(); } catch {} break; }
      }
    } else {
      const text = await res.text();
      let json: any;
      try { json = JSON.parse(text); }
      catch { throw new McpHttpError(res.status, "response was not JSON-RPC (is this an MCP endpoint?)"); }
      reply = (Array.isArray(json) ? json : [json]).find((m) => m && m.id === wantId);
    }

    if (!reply) throw new McpHttpError(res.status, "no JSON-RPC reply received");
    if (reply.error) throw new Error(`${reply.error.message ?? "MCP error"} (code ${reply.error.code})`);
    return reply.result;
  }

  private async initialize(signal: AbortSignal): Promise<void> {
    this.sessionId = undefined;
    const id = this.nextId++;
    await this.post(
      {
        jsonrpc: "2.0", id, method: "initialize",
        params: { protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: "acurist", version: "1.0.0" } },
      },
      signal, id,
    );
    await this.post({ jsonrpc: "2.0", method: "notifications/initialized" }, signal);
  }

  private ensure(signal: AbortSignal): Promise<void> {
    if (!this.ready) {
      this.ready = this.initialize(signal).catch((e) => { this.ready = undefined; throw e; });
    }
    return this.ready;
  }

  async request(method: string, params: unknown, outer: AbortSignal | undefined, timeoutMs: number): Promise<any> {
    const signal = withTimeout(outer, timeoutMs);
    for (let attempt = 0; ; attempt++) {
      await this.ensure(signal);
      const id = this.nextId++;
      try {
        return await this.post({ jsonrpc: "2.0", id, method, params }, signal, id);
      } catch (e) {
        // Session expired / server restarted → re-initialize once and retry
        if (attempt === 0 && e instanceof McpHttpError && e.status === 404 && this.sessionId) {
          this.ready = undefined;
          continue;
        }
        throw e;
      }
    }
  }
}

// ── State ────────────────────────────────────────────────────────────────────

const clients = new Map<string, StreamableHttpClient>();
const transports = new Map<string, McpTransport>();
const capabilityCache = new Map<string, { at: number; caps: McpCapabilities }>();

function clientFor(server: McpServer): StreamableHttpClient {
  const k = serverKey(server);
  let c = clients.get(k);
  if (!c) { c = new StreamableHttpClient(server); clients.set(k, c); }
  return c;
}

// ── REST bridge (legacy) ─────────────────────────────────────────────────────

async function restList(server: McpServer): Promise<{ tools: McpToolInfo[]; description?: string }> {
  const res = await fetch(`${server.url.replace(/\/+$/, "")}/mcp/v1/tools`, {
    headers: { "Content-Type": "application/json", ...(server.headers ?? {}) },
    signal: AbortSignal.timeout(LIST_TIMEOUT_MS) as any,
  });
  if (!res.ok) throw new McpHttpError(res.status, `HTTP ${res.status}`);
  const body = (await res.json()) as { tools?: any[]; description?: string };
  return {
    description: body.description,
    tools: (body.tools ?? []).filter((t) => t && typeof t.name === "string").map((t) => ({
      name: t.name,
      description: String(t.description ?? ""),
      input_schema: normalizeSchema(t.input_schema ?? t.inputSchema),
    })),
  };
}

/** Tool output must always reach the agent as a string. */
function asText(v: unknown): string {
  if (typeof v === "string") return v;
  try { return JSON.stringify(v, null, 2) ?? String(v); } catch { return String(v); }
}

async function restCall(server: McpServer, toolName: string, input: Record<string, any>, signal?: AbortSignal) {
  const res = await fetch(`${server.url.replace(/\/+$/, "")}/mcp/v1/call`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(server.headers ?? {}) },
    body: JSON.stringify({ name: toolName, input }),
    signal: withTimeout(signal, CALL_TIMEOUT_MS) as any,
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    return { output: `MCP error ${res.status}: ${body}`, isError: true };
  }
  const data = (await res.json()) as { output?: unknown; error?: unknown };
  if (data.error) return { output: asText(data.error), isError: true };
  return { output: data.output === undefined ? "(no output)" : asText(data.output), isError: false };
}

// ── Capabilities ─────────────────────────────────────────────────────────────

async function listViaStreamable(server: McpServer): Promise<McpToolInfo[]> {
  const client = clientFor(server);
  const tools: McpToolInfo[] = [];
  let cursor: string | undefined;
  for (let page = 0; page < 20; page++) {
    const r = await client.request("tools/list", cursor ? { cursor } : {}, undefined, LIST_TIMEOUT_MS);
    for (const t of r?.tools ?? []) {
      if (!t || typeof t.name !== "string") continue;
      tools.push({
        name: t.name,
        description: String(t.description ?? t.title ?? ""),
        input_schema: normalizeSchema(t.inputSchema ?? t.input_schema),
      });
    }
    cursor = r?.nextCursor;
    if (!cursor) break;
  }
  return tools;
}

async function fetchCapabilities(server: McpServer): Promise<McpCapabilities> {
  const key = serverKey(server);
  const hit = capabilityCache.get(key);
  if (hit && Date.now() - hit.at < (hit.caps.error ? CAPS_TTL_ERR_MS : CAPS_TTL_OK_MS)) return hit.caps;

  let caps: McpCapabilities;
  try {
    try {
      const tools = await listViaStreamable(server);
      transports.set(key, "streamable-http");
      caps = { server, tools, transport: "streamable-http" };
    } catch (streamErr: any) {
      const notMcpEndpoint =
        streamErr instanceof McpHttpError && [400, 404, 405, 406, 415, 501].includes(streamErr.status);
      if (!notMcpEndpoint) throw streamErr; // down / auth / timeout: falling back wouldn't help
      try {
        const r = await restList(server);
        transports.set(key, "rest");
        caps = { server, tools: r.tools, description: r.description, transport: "rest" };
      } catch (restErr: any) {
        const sseHint = /\/sse\/?$/.test(server.url)
          ? " This looks like a legacy SSE-transport endpoint, which Acurist doesn't support — use the server's Streamable HTTP URL (often /mcp)."
          : "";
        throw new Error(
          `not a reachable MCP endpoint (Streamable HTTP: ${errMsg(streamErr)}; REST bridge: ${errMsg(restErr)}).${sseHint}`,
        );
      }
    }
  } catch (e: any) {
    const auth = e instanceof McpHttpError && (e.status === 401 || e.status === 403);
    caps = {
      server,
      tools: [],
      error: auth ? `authentication required (${e.message}) — re-add with --bearer <token>` : errMsg(e),
    };
    clients.delete(key); // drop any half-initialised session
  }
  capabilityCache.set(key, { at: Date.now(), caps });
  return caps;
}

/** Load (cached) capabilities for all registered MCP servers. */
export async function loadAllMcpCapabilities(): Promise<McpCapabilities[]> {
  return Promise.all(getMcpServers().map(fetchCapabilities));
}

/** Force a fresh probe of one server (used by /mcp add and /mcp list). */
export async function probeMcpServer(server: McpServer): Promise<McpCapabilities> {
  capabilityCache.delete(serverKey(server));
  clients.delete(serverKey(server));
  return fetchCapabilities(server);
}

// ── Naming / routing ─────────────────────────────────────────────────────────

const slug = (s: string) => s.replace(/[^a-zA-Z0-9_-]/g, "_") || "x";

interface NamedTool { ns: string; server: McpServer; tool: McpToolInfo }

function assignNames(caps: McpCapabilities[]): NamedTool[] {
  const used = new Set<string>();
  const out: NamedTool[] = [];
  for (const c of caps) {
    for (const t of c.tools) {
      const base = `mcp__${slug(c.server.name)}__${slug(t.name)}`.slice(0, 64);
      let ns = base, n = 2;
      while (used.has(ns)) { const suffix = `_${n++}`; ns = base.slice(0, 64 - suffix.length) + suffix; }
      used.add(ns);
      out.push({ ns, server: c.server, tool: t });
    }
  }
  return out;
}

/** API-ready tool schemas (clean fields only) plus a name → server/tool router. */
export function buildMcpToolSet(caps: McpCapabilities[]): {
  schemas: { name: string; description: string; input_schema: Record<string, any> }[];
  routes: Map<string, McpToolRoute>;
} {
  const schemas: { name: string; description: string; input_schema: Record<string, any> }[] = [];
  const routes = new Map<string, McpToolRoute>();
  for (const { ns, server, tool } of assignNames(caps)) {
    schemas.push({
      name: ns,
      description: `[MCP: ${server.name}] ${tool.description || tool.name}`.slice(0, 1000),
      input_schema: tool.input_schema,
    });
    routes.set(ns, { server, toolName: tool.name });
  }
  return { schemas, routes };
}

/** Build the MCP section of the system prompt, listing each server's tools. */
export function buildMcpSystemPrompt(caps: McpCapabilities[]): string {
  if (!caps.length) return "";
  const named = assignNames(caps);
  const lines: string[] = [
    "\n\n## MCP Servers\n",
    "External MCP (Model Context Protocol) servers are connected. Their tools are available as native tools " +
      "(named mcp__<server>__<tool>) in addition to the built-in ones — call them exactly like any other tool.\n",
  ];
  for (const c of caps) {
    const status = c.error ? ` ⚠ (unreachable: ${c.error})` : "";
    lines.push(`\n### ${c.server.name}${status}`);
    if (c.description) lines.push(c.description);
    const mine = named.filter((n) => n.server === c.server);
    if (mine.length) {
      lines.push("Tools:");
      for (const n of mine) lines.push(`  • ${n.ns} — ${n.tool.description || n.tool.name}`);
    } else if (!c.error) {
      lines.push("(no tools advertised)");
    }
  }
  return lines.join("\n");
}

// ── Calling ──────────────────────────────────────────────────────────────────

function formatToolResult(result: any): { output: string; isError: boolean } {
  const parts: string[] = [];
  for (const c of result?.content ?? []) {
    if (!c) continue;
    if (c.type === "text") parts.push(String(c.text ?? ""));
    else if (c.type === "image" || c.type === "audio")
      parts.push(`[${c.type}: ${c.mimeType ?? "unknown type"}, ${Math.round((String(c.data ?? "").length * 3) / 4)} bytes — not shown]`);
    else if (c.type === "resource" || c.type === "resource_link") {
      const r = c.resource ?? c;
      parts.push(typeof r.text === "string" ? r.text : `[resource: ${r.uri ?? "unknown"}]`);
    } else parts.push(asText(c));
  }
  if (!parts.length && result?.structuredContent !== undefined) parts.push(asText(result.structuredContent));
  return { output: parts.join("\n") || "(no output)", isError: !!result?.isError };
}

/** Call one tool (original, un-namespaced name) on a specific MCP server. */
export async function callMcpTool(
  server: McpServer,
  toolName: string,
  input: Record<string, any>,
  signal?: AbortSignal,
): Promise<{ output: string; isError: boolean }> {
  try {
    if (transports.get(serverKey(server)) === "rest") return await restCall(server, toolName, input, signal);
    const result = await clientFor(server).request("tools/call", { name: toolName, arguments: input }, signal, CALL_TIMEOUT_MS);
    return formatToolResult(result);
  } catch (e: any) {
    if (e?.name === "AbortError") return { output: "(interrupted by user)", isError: true };
    return { output: `MCP call failed: ${errMsg(e)}`, isError: true };
  }
}

/** Forget cached capabilities and sessions (after adding/removing a server). */
export function clearMcpCache() {
  capabilityCache.clear();
  clients.clear();
  transports.clear();
}
