import Conf from "conf";
import type { AgentConfig, McpServer, ToolPermissionMap } from "../types.js";

// ── Stored types ──────────────────────────────────────────────────────────────

export interface TelegramConfig { token: string; userId: string; autoStart: boolean }

export interface Plugin {
  name: string; description: string; version: string; author: string;
  systemPromptAddition: string; tools?: string[]; repo?: string;
  installedAt: string; marketplaceUrl?: string;
}

export interface Marketplace { name: string; url: string; addedAt: string }
export interface PromptTemplate { name: string; body: string; createdAt: string }
export interface CustomAgent { name: string; description: string; systemPrompt: string; createdAt: string }

// ── Built-in model aliases ────────────────────────────────────────────────────
// When one of these Anthropic model names is selected, and the proxy is a
// DeepSeek-based proxy (deeptunnel or compatible), we transparently route to
// the corresponding auto/ slot so the proxy picks the best real model.

export const BUILTIN_MODEL_MAP: Record<string, { autoId: string; note: string }> = {
  "claude-sonnet-4-6":       { autoId: "auto/best-coding", note: "default · smart & fast  → auto/best-coding" },
  "claude-haiku-4-5-20251001": { autoId: "auto/best-fast",   note: "lightweight · lowest latency  → auto/best-fast" },
};

/** Resolve a model id — if it's a builtin alias, return the proxy auto/ id. */
export function resolveModel(model: string): string {
  return BUILTIN_MODEL_MAP[model]?.autoId ?? model;
}

const OFFICIAL: Marketplace = {
  name: "official",
  url:  "https://raw.githubusercontent.com/IMApurbo/acurist-plugins/main/registry.json",
  addedAt: new Date().toISOString(),
};

const store = new Conf<{
  proxyBaseUrl:    string;
  model:           string;
  telegram:        TelegramConfig | null;
  plugins:         Plugin[];
  marketplaces:    Marketplace[];
  mcpServers:      McpServer[];
  toolPermissions: ToolPermissionMap;
  templates:       PromptTemplate[];
  inputHistory:    string[];
  customAgents:    CustomAgent[];
}>({
  projectName: "acurist",
  defaults: {
    proxyBaseUrl:    "http://localhost:8765",
    model:           "claude-sonnet-4-6",
    telegram:        null,
    plugins:         [],
    marketplaces:    [OFFICIAL],
    mcpServers:      [],
    toolPermissions: {},
    templates:       [],
    inputHistory:    [],
    customAgents:    [],
  },
});

// ── URL validation ────────────────────────────────────────────────────────────

/**
 * Returns true if `raw` is a valid http/https URL.
 * Rejects bare words like "auto", relative paths, etc.
 */
export function isValidHttpUrl(raw: string): boolean {
  try {
    const u = new URL(raw);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

// ── CLI flags ─────────────────────────────────────────────────────────────────

function flag(name: string): string | null {
  const args = process.argv.slice(2);
  const i = args.indexOf(`--${name}`);
  return i !== -1 && args[i + 1] ? args[i + 1] : null;
}

function hasFlag(name: string): boolean {
  return process.argv.includes(`--${name}`);
}

// ── AgentConfig ───────────────────────────────────────────────────────────────

export function loadConfig(): AgentConfig {
  const modeArg = flag("mode") as "auto" | "manual" | null
    ?? (hasFlag("manual") ? "manual" : hasFlag("auto") ? "auto" : null);
  // Use hard fallbacks so a fresh/corrupted store never yields undefined
  const rawProxy =
    process.env.ACURIST_PROXY ??
    store.get("proxyBaseUrl") ??
    "http://localhost:8765";
  // Guard against stored garbage values like "auto" that would cause
  // "Failed to parse URL from auto/v1/messages" at runtime.
  const proxyBaseUrl = isValidHttpUrl(rawProxy) ? rawProxy : "http://localhost:8765";
  const model =
    process.env.ACURIST_MODEL ??
    store.get("model") ??
    "claude-sonnet-4-6";
  return {
    proxyBaseUrl,
    model,
    cwd:             process.cwd(),
    mode:            modeArg ?? "auto",
    toolPermissions: store.get("toolPermissions") ?? {},
    startupAgent:    flag("agent") ?? undefined,
  };
}

export function setConfigValue(key: "proxyBaseUrl" | "model", value: string) {
  store.set(key, value);
}

export function getConfigPath() { return store.path; }

// ── Telegram ──────────────────────────────────────────────────────────────────

export function getTelegramConfig() { return store.get("telegram") ?? null; }
export function setTelegramConfig(cfg: TelegramConfig | null) {
  store.set("telegram", cfg as TelegramConfig);
}

// ── Plugins ───────────────────────────────────────────────────────────────────

export function getPlugins()                    { return store.get("plugins") ?? []; }
export function installPlugin(p: Plugin)        { store.set("plugins", [...getPlugins().filter(x => x.name !== p.name), p]); }
export function removePlugin(name: string)      { const before = getPlugins(); store.set("plugins", before.filter(p => p.name !== name)); return getPlugins().length < before.length; }
export function getPlugin(name: string)         { return getPlugins().find(p => p.name === name); }

// ── Marketplaces ──────────────────────────────────────────────────────────────

export function getMarketplaces() {
  const saved = store.get("marketplaces") ?? [];
  return saved.find(m => m.name === "official") ? saved : [OFFICIAL, ...saved];
}

export function addMarketplace(url: string, name?: string) {
  const list = getMarketplaces();
  const existing = list.find(m => m.url === url);
  if (existing) return existing;
  const entry: Marketplace = { name: name ?? url.replace(/^https?:\/\//, "").split("/")[0], url, addedAt: new Date().toISOString() };
  store.set("marketplaces", [...list, entry]);
  return entry;
}

export function removeMarketplace(nameOrUrl: string) {
  const mutable = getMarketplaces().filter(m => m.name !== "official");
  const after   = mutable.filter(m => m.name !== nameOrUrl && m.url !== nameOrUrl);
  store.set("marketplaces", [OFFICIAL, ...after]);
  return after.length < mutable.length;
}

// ── MCP Servers ───────────────────────────────────────────────────────────────

export function getMcpServers()                      { return store.get("mcpServers") ?? []; }
export function addMcpServer(name: string, url: string) {
  const list = getMcpServers();
  const existing = list.find(s => s.name === name || s.url === url);
  if (existing) return existing;
  const entry: McpServer = { name, url, addedAt: new Date().toISOString() };
  store.set("mcpServers", [...list, entry]);
  return entry;
}
export function removeMcpServer(nameOrUrl: string)   {
  const before = getMcpServers();
  store.set("mcpServers", before.filter(s => s.name !== nameOrUrl && s.url !== nameOrUrl));
  return getMcpServers().length < before.length;
}

// ── Tool Permissions ──────────────────────────────────────────────────────────

export function getToolPermissions()                   { return store.get("toolPermissions") ?? {}; }
export function setToolPermission(tool: string, mode: "auto" | "manual" | null) {
  const perms = getToolPermissions();
  if (mode === null) delete perms[tool]; else perms[tool] = mode;
  store.set("toolPermissions", perms);
}

// ── Prompt Templates ──────────────────────────────────────────────────────────

export function getTemplates()                         { return store.get("templates") ?? []; }
export function addTemplate(name: string, body: string) {
  const entry: PromptTemplate = { name, body, createdAt: new Date().toISOString() };
  store.set("templates", [...getTemplates().filter(t => t.name !== name), entry]);
  return entry;
}
export function removeTemplate(name: string)           { const before = getTemplates(); store.set("templates", before.filter(t => t.name !== name)); return getTemplates().length < before.length; }
export function getTemplate(name: string)              { return getTemplates().find(t => t.name === name); }

// ── Input History ─────────────────────────────────────────────────────────────

const MAX_HISTORY = 500;

export function getPersistentHistory()                 { return store.get("inputHistory") ?? []; }
export function appendPersistentHistory(entry: string) {
  const prev = getPersistentHistory();
  if (prev[prev.length - 1] === entry) return;
  store.set("inputHistory", [...prev, entry].slice(-MAX_HISTORY));
}

// ── Custom Agents ─────────────────────────────────────────────────────────────

export function getCustomAgents()                      { return store.get("customAgents") ?? []; }
export function saveCustomAgent(a: CustomAgent)        { store.set("customAgents", [...getCustomAgents().filter(x => x.name !== a.name), a]); }
export function deleteCustomAgent(name: string)        { const before = getCustomAgents(); store.set("customAgents", before.filter(a => a.name !== name)); return getCustomAgents().length < before.length; }
export function getCustomAgent(name: string)           { return getCustomAgents().find(a => a.name === name); }
