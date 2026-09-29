/**
 * pluginMarket.ts — Acurist plugin system
 *
 * ── Supported marketplace formats ────────────────────────────────────────────
 *
 * 1. Acurist native (any URL):
 *    { "name": "My Marketplace", "plugins": [{ "name": "git", "description": "...",
 *      "version": "1.0.0", "author": "...", "repo": "...", "systemPromptAddition": "..." }] }
 *
 * 2. Claude Code format (GitHub repo with .claude-plugin/marketplace.json):
 *    { "name": "...", "plugins": [{ "name": "git", "description": "...",
 *      "source": { "github": { "repo": "owner/repo-name" } } }] }
 *    → plugin.json fetched from https://raw.githubusercontent.com/{repo}/HEAD/plugin.json
 *    → SKILL.md fetched from https://raw.githubusercontent.com/{repo}/HEAD/skills/{name}/SKILL.md
 *
 * 3. GitHub shorthand for marketplace registration:
 *    /plugin marketplace add owner/repo
 *    → resolves to https://raw.githubusercontent.com/owner/repo/HEAD/.claude-plugin/marketplace.json
 *
 * ── Commands ─────────────────────────────────────────────────────────────────
 *   /plugin marketplace add <url|owner/repo>   — register a marketplace
 *   /plugin marketplace remove <name>          — unregister a marketplace
 *   /plugin marketplace list                   — list registered marketplaces
 *   /plugin browse [marketplace-name]          — fetch & display plugins (interactive)
 *   /plugin add <name>                         — install by name (searches all marketplaces)
 *   /plugin remove <name>                      — uninstall
 *   /plugin list                               — list installed
 *   /plugin info <name>                        — show details
 */

import fetch from "node-fetch";
import {
  getPlugins,
  installPlugin,
  removePlugin,
  getPlugin,
  getMarketplaces,
  addMarketplace,
  removeMarketplace,
} from "./config.js";
import type { Plugin, Marketplace } from "./config.js";

// ── Claude Code format types ──────────────────────────────────────────────────

interface ClaudeCodePluginEntry {
  name: string;
  description?: string;
  source?: {
    github?: {
      repo: string; // "owner/repo-name"
    };
  };
}

interface ClaudeCodeMarketplace {
  name?: string;
  plugins: ClaudeCodePluginEntry[];
}

/** plugin.json fetched from each skill's GitHub repo */
interface ClaudeCodePluginJson {
  name?: string;
  description?: string;
  version?: string;
  author?: string;
  // May include other metadata; systemPromptAddition comes from SKILL.md
}

// ── Marketplace JSON format (Acurist native) ──────────────────────────────────

interface AcuristMarketplaceManifest {
  name?: string;
  plugins: Omit<Plugin, "installedAt" | "marketplaceUrl">[];
}

type MarketplaceManifest = AcuristMarketplaceManifest | ClaudeCodeMarketplace;

// ── URL helpers ───────────────────────────────────────────────────────────────

const GITHUB_RAW = "https://raw.githubusercontent.com";

/**
 * Resolve an `owner/repo` shorthand or a full URL into a marketplace URL.
 * Supports:
 *   - "owner/repo"  → Claude Code marketplace at .claude-plugin/marketplace.json
 *   - "https://..." → returned as-is
 */
function resolveMarketplaceUrl(input: string): string {
  if (input.startsWith("http://") || input.startsWith("https://")) {
    return input;
  }
  // GitHub owner/repo shorthand
  if (/^[\w.-]+\/[\w.-]+$/.test(input)) {
    return `${GITHUB_RAW}/${input}/HEAD/.claude-plugin/marketplace.json`;
  }
  throw new Error(
    `Invalid marketplace address: "${input}". ` +
    `Use a full URL (https://...) or a GitHub repo shorthand (owner/repo).`
  );
}

/**
 * Build the raw GitHub URL for a plugin.json inside a skill repo.
 * repo = "owner/repo-name"
 */
function pluginJsonUrl(repo: string): string {
  return `${GITHUB_RAW}/${repo}/HEAD/plugin.json`;
}

/**
 * Build the raw GitHub URL for a SKILL.md inside a skill repo.
 * Tries skills/<name>/SKILL.md, the canonical Claude Code layout.
 */
function skillMdUrl(repo: string, skillName: string): string {
  return `${GITHUB_RAW}/${repo}/HEAD/skills/${skillName}/SKILL.md`;
}

// ── Fetch helpers ─────────────────────────────────────────────────────────────

async function fetchText(url: string): Promise<string> {
  const res = await fetch(url, { signal: AbortSignal.timeout(10_000) });
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${url}`);
  return res.text();
}

async function fetchJson<T = unknown>(url: string): Promise<T> {
  const text = await fetchText(url);
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new Error(`Invalid JSON from ${url}`);
  }
}

/**
 * Detect whether a manifest uses the Claude Code format.
 * Claude Code manifests have plugins with a `source.github.repo` field
 * instead of the Acurist `systemPromptAddition` field.
 */
function isClaudeCodeManifest(data: any): data is ClaudeCodeMarketplace {
  if (!Array.isArray(data?.plugins)) return false;
  // If at least one plugin has source.github.repo, it's Claude Code format
  return data.plugins.some(
    (p: any) => typeof p?.source?.github?.repo === "string"
  );
}

/**
 * Fetch the plugin.json + SKILL.md for a Claude Code skill repo and assemble
 * a full Acurist Plugin object. Returns null if we can't resolve it (non-fatal).
 */
async function resolveClaudeCodePlugin(
  entry: ClaudeCodePluginEntry,
  marketplaceUrl: string
): Promise<Plugin | null> {
  const repo = entry.source?.github?.repo;
  if (!repo) return null;

  let pluginMeta: ClaudeCodePluginJson = {};
  try {
    pluginMeta = await fetchJson<ClaudeCodePluginJson>(pluginJsonUrl(repo));
  } catch {
    // plugin.json is optional; fall back to marketplace entry metadata
  }

  // Skill name: prefer plugin.json name, then marketplace entry name
  const skillName = pluginMeta.name ?? entry.name;

  // Resolve author: guard against the field being an object in the raw JSON
  const rawAuthor = pluginMeta.author;
  const author =
    typeof rawAuthor === "string" && rawAuthor.trim()
      ? rawAuthor.trim()
      : repo.split("/")[0];

  // Try multiple SKILL.md candidate paths in order:
  //   1. skills/<skillName>/SKILL.md   (canonical Claude Code layout)
  //   2. skills/<entry.name>/SKILL.md  (entry name differs from plugin.json name)
  //   3. SKILL.md                      (root of repo, simpler repos)
  let systemPromptAddition = "";
  const skillMdCandidates = [
    skillMdUrl(repo, skillName),
    ...(entry.name !== skillName ? [skillMdUrl(repo, entry.name)] : []),
    `${GITHUB_RAW}/${repo}/HEAD/SKILL.md`,
  ];
  for (const url of skillMdCandidates) {
    try {
      systemPromptAddition = await fetchText(url);
      break; // found it
    } catch {
      // try next candidate
    }
  }

  return {
    name: skillName.toLowerCase().replace(/\s+/g, "-"),
    description:
      pluginMeta.description ?? entry.description ?? "(no description)",
    version: pluginMeta.version ?? "0.0.0",
    author,
    repo: `https://github.com/${repo}`,
    systemPromptAddition,
    installedAt: "",
    marketplaceUrl,
  };
}

/**
 * Fetch and normalise a marketplace URL into a list of Acurist Plugin objects.
 * Handles both Acurist native format and Claude Code format transparently.
 */
async function fetchMarketplace(
  url: string
): Promise<{ name?: string; plugins: Omit<Plugin, "installedAt" | "marketplaceUrl">[] }> {
  const data = await fetchJson<any>(url);

  // Support bare array (legacy)
  const manifest: any = Array.isArray(data) ? { plugins: data } : data;
  if (!Array.isArray(manifest.plugins)) {
    throw new Error(`Invalid marketplace format at ${url}`);
  }

  // ── Claude Code format ────────────────────────────────────────────────────
  if (isClaudeCodeManifest(manifest)) {
    const resolved = await Promise.all(
      manifest.plugins.map((entry: ClaudeCodePluginEntry) =>
        resolveClaudeCodePlugin(entry, url).catch(() => null)
      )
    );
    return {
      name: manifest.name,
      plugins: resolved.filter((p): p is Plugin => p !== null),
    };
  }

  // ── Acurist native format ─────────────────────────────────────────────────
  // Sanitize each plugin entry so downstream code can safely call string methods
  const sanitized: AcuristMarketplaceManifest = {
    name: manifest.name,
    plugins: (manifest as AcuristMarketplaceManifest).plugins.map((p) => ({
      name:                  (p.name                  ?? "unknown").toLowerCase().replace(/\s+/g, "-"),
      description:           p.description            ?? "(no description)",
      version:               p.version                ?? "0.0.0",
      author:                p.author                 ?? "unknown",
      repo:                  p.repo                   ?? "",
      systemPromptAddition:  p.systemPromptAddition   ?? "",
    })),
  };
  return sanitized;
}

/** Fetch plugins from all registered marketplaces, or just one if name given. */
export async function fetchAllPlugins(
  marketplaceName?: string
): Promise<{ plugin: Plugin; marketplace: Marketplace }[]> {
  const markets = getMarketplaces().filter(
    (m) => !marketplaceName || m.name === marketplaceName
  );

  const results: { plugin: Plugin; marketplace: Marketplace }[] = [];

  await Promise.all(
    markets.map(async (market) => {
      try {
        const manifest = await fetchMarketplace(market.url);
        for (const p of manifest.plugins) {
          results.push({
            plugin: { ...p, installedAt: "", marketplaceUrl: market.url },
            marketplace: market,
          });
        }
      } catch (e: any) {
        results.push({
          plugin: {
            name: `[error:${market.name}]`,
            description: `Could not fetch: ${e.message}`,
            version: "",
            author: "",
            systemPromptAddition: "",
            installedAt: "",
            marketplaceUrl: market.url,
          },
          marketplace: market,
        });
      }
    })
  );

  return results;
}

// ── ANSI helpers ──────────────────────────────────────────────────────────────

function dim(s: string) { return `\x1b[2m${s}\x1b[0m`; }
function bold(s: string) { return `\x1b[1m${s}\x1b[0m`; }
function green(s: string) { return `\x1b[32m${s}\x1b[0m`; }
function cyan(s: string) { return `\x1b[36m${s}\x1b[0m`; }
function red(s: string) { return `\x1b[31m${s}\x1b[0m`; }

// ── Async handler (called from App.tsx which awaits it) ───────────────────────

export async function handlePluginCommand(args: string[]): Promise<string> {
  const sub = args[0]?.toLowerCase() ?? "";

  // ── /plugin marketplace ... ─────────────────────────────────────────────────
  if (sub === "marketplace") {
    const msub = args[1]?.toLowerCase() ?? "";

    if (msub === "add") {
      const input = args[2];
      if (!input) {
        return (
          "Usage: /plugin marketplace add <url|owner/repo>\n" +
          "Examples:\n" +
          "  /plugin marketplace add netresearch/claude-code-skills\n" +
          "  /plugin marketplace add https://example.com/plugins/registry.json"
        );
      }

      let url: string;
      try {
        url = resolveMarketplaceUrl(input);
      } catch (e: any) {
        return red(`✗ ${e.message}`);
      }

      try {
        const manifest = await fetchMarketplace(url);
        const entry = addMarketplace(url, manifest.name);
        const count = manifest.plugins.length;
        const isGhShorthand = !input.startsWith("http");
        const sourceNote = isGhShorthand
          ? dim(`  GitHub: ${input}  →  Claude Code marketplace format\n`)
          : "";
        return (
          `✓ Marketplace "${entry.name}" added.\n` +
          `URL:     ${url}\n` +
          sourceNote +
          `Plugins: ${count} available\n\n` +
          `Run /plugin browse ${entry.name} to see them.`
        );
      } catch (e: any) {
        return red(`✗ Could not add marketplace: ${e.message}`);
      }
    }

    if (msub === "remove") {
      const nameOrUrl = args[2];
      if (!nameOrUrl) return "Usage: /plugin marketplace remove <name|url>";
      if (nameOrUrl === "official") return red("Cannot remove the official marketplace.");
      const ok = removeMarketplace(nameOrUrl);
      return ok
        ? `✓ Marketplace "${nameOrUrl}" removed.`
        : red(`Marketplace "${nameOrUrl}" not found.`);
    }

    if (msub === "list" || !msub) {
      const markets = getMarketplaces();
      const rows = markets.map((m) => {
        const tag = m.name === "official" ? dim(" [official]") : "";
        const isClaudeCode = m.url.includes("/.claude-plugin/marketplace.json");
        const fmtTag = isClaudeCode ? dim(" [claude-code]") : "";
        return `  ${bold(m.name.padEnd(16))} ${dim(m.url)}${tag}${fmtTag}`;
      });
      return (
        `Registered marketplaces (${markets.length}):\n` +
        rows.join("\n") +
        `\n\n` +
        `Add:    /plugin marketplace add <url|owner/repo>\n` +
        `Browse: /plugin browse [name]`
      );
    }

    return "Usage: /plugin marketplace <add|remove|list>";
  }

  // ── /plugin browse [marketplace] ────────────────────────────────────────────
  if (sub === "browse") {
    const marketName = args[1] ?? undefined;

    try {
      const all = await fetchAllPlugins(marketName);
      const installed = new Set(getPlugins().map((p) => p.name));

      if (all.length === 0) {
        return marketName
          ? red(`No plugins found in marketplace "${marketName}".`)
          : "No plugins found. Add a marketplace with /plugin marketplace add <url|owner/repo>.";
      }

      // Group by marketplace
      const byMarket = new Map<string, typeof all>();
      for (const item of all) {
        const key = item.marketplace.name;
        if (!byMarket.has(key)) byMarket.set(key, []);
        byMarket.get(key)!.push(item);
      }

      const sections: string[] = [];
      for (const [mname, items] of byMarket) {
        const isClaudeCode = items[0]?.marketplace.url.includes("/.claude-plugin/");
        const fmtHint = isClaudeCode ? dim(" (Claude Code format)") : "";
        sections.push(cyan(bold(`── ${mname} ──`)) + fmtHint);
        for (const { plugin: p } of items) {
          if (p.name.startsWith("[error:")) {
            sections.push(red(`  ✗ ${p.description}`));
            continue;
          }
          const isInst = installed.has(p.name);
          const badge = isInst ? green(" [installed]") : "";
          const action = isInst
            ? dim("  /plugin remove " + p.name)
            : dim("  /plugin add " + p.name);
          const versionStr = (p.version ?? "0.0.0");
          const descStr    = (p.description ?? "");
          sections.push(
            `  ${bold((p.name ?? "").padEnd(16))} v${versionStr.padEnd(7)} ${descStr}${badge}`
          );
          sections.push(action);
        }
      }

      const total = all.filter((a) => !a.plugin.name.startsWith("[error:")).length;
      const instCount = all.filter((a) => installed.has(a.plugin.name)).length;

      return (
        `${total} plugins available, ${instCount} installed\n\n` +
        sections.join("\n")
      );
    } catch (e: any) {
      return red(`✗ Browse failed: ${e.message}`);
    }
  }

  // ── /plugin add <name> ───────────────────────────────────────────────────────
  if (sub === "add") {
    const name = args[1]?.toLowerCase();
    if (!name) return "Usage: /plugin add <name>";

    if (getPlugin(name)) {
      return `Plugin "${name}" is already installed. Use /plugin remove ${name} first to reinstall.`;
    }

    let found: Plugin | undefined;
    try {
      const all = await fetchAllPlugins();
      const match = all.find((a) => a.plugin.name === name);
      if (match) found = match.plugin;
    } catch {
      // fall through to "not found"
    }

    if (!found) {
      return (
        red(`Plugin "${name}" not found in any registered marketplace.\n`) +
        `Run /plugin browse to see available plugins.\n` +
        `Run /plugin marketplace add <url|owner/repo> to add more marketplaces.`
      );
    }

    installPlugin({ ...found, installedAt: new Date().toISOString() });

    const hasPrompt = found.systemPromptAddition.trim().length > 0;
    return (
      green(`✓ Plugin "${name}" installed.\n`) +
      `${found.description}\n` +
      `Version: ${found.version}  Author: ${found.author}\n` +
      (found.repo ? `Repo:    ${found.repo}\n` : "") +
      `\n` +
      (hasPrompt
        ? dim(`Plugin's capabilities are now active in this session.`)
        : dim(`Note: no SKILL.md found — plugin has no system prompt addition.`))
    );
  }

  // ── /plugin remove <name> ────────────────────────────────────────────────────
  if (sub === "remove") {
    const name = args[1]?.toLowerCase();
    if (!name) return "Usage: /plugin remove <name>";
    const ok = removePlugin(name);
    return ok
      ? green(`✓ Plugin "${name}" removed.`)
      : red(`Plugin "${name}" is not installed.`);
  }

  // ── /plugin list ─────────────────────────────────────────────────────────────
  if (sub === "list") {
    const installed = getPlugins();
    if (installed.length === 0) {
      return (
        "No plugins installed.\n" +
        "Run /plugin browse to see available plugins.\n" +
        "Run /plugin marketplace list to see registered marketplaces."
      );
    }
    const rows = installed.map(
      (p) =>
        `  ${bold((p.name ?? "").padEnd(16))} v${(p.version ?? "0.0.0").padEnd(7)} ${p.description ?? ""}\n` +
        `  ${dim("installed " + p.installedAt?.slice(0, 10) + (p.marketplaceUrl ? "  from " + p.marketplaceUrl : ""))}`
    );
    return `Installed plugins (${installed.length}):\n\n${rows.join("\n\n")}`;
  }

  // ── /plugin info <name> ──────────────────────────────────────────────────────
  if (sub === "info") {
    const name = args[1]?.toLowerCase();
    if (!name) return "Usage: /plugin info <name>";

    const inst = getPlugin(name);
    let remote: Plugin | undefined;

    try {
      const all = await fetchAllPlugins();
      remote = all.find((a) => a.plugin.name === name)?.plugin;
    } catch {}

    const p = inst ?? remote;
    if (!p) return red(`Plugin "${name}" not found.`);

    const promptText    = p.systemPromptAddition ?? "";
    const promptPreview = promptText.trim().slice(0, 200);
    const truncated     = promptText.trim().length > 200 ? "…" : "";

    return (
      `${bold(p.name)} v${p.version}\n` +
      `${"─".repeat(40)}\n` +
      `${p.description}\n\n` +
      `Author:      ${p.author}\n` +
      `Repo:        ${p.repo ?? "n/a"}\n` +
      `Marketplace: ${p.marketplaceUrl ?? "n/a"}\n` +
      `Installed:   ${inst ? green("yes") + ` (${inst.installedAt?.slice(0, 10)})` : red("no")}\n\n` +
      `System prompt addition:\n${dim(promptPreview + truncated)}`
    );
  }

  // ── help ──────────────────────────────────────────────────────────────────────
  return (
    bold("Plugin commands:\n") +
    `  /plugin browse [name]              — browse & install from a marketplace\n` +
    `  /plugin add <name>                 — install a plugin\n` +
    `  /plugin remove <name>              — uninstall a plugin\n` +
    `  /plugin list                       — list installed plugins\n` +
    `  /plugin info <name>                — show plugin details\n` +
    `  /plugin marketplace list           — list registered marketplaces\n` +
    `  /plugin marketplace add <url|owner/repo>  — add a marketplace\n` +
    `  /plugin marketplace remove <name>  — remove a marketplace\n\n` +
    dim("Marketplace formats supported: Acurist native JSON, Claude Code (.claude-plugin/marketplace.json)")
  );
}

/** Build the combined system prompt addition from all installed plugins. */
export function buildPluginSystemPrompt(): string {
  const plugins = getPlugins();
  if (plugins.length === 0) return "";
  return "\n\n" + plugins.map((p) => p.systemPromptAddition.trim()).join("\n\n");
}

/**
 * Return the names of all installed plugins that actually contribute a
 * system-prompt addition (i.e. have a non-empty SKILL.md).  These are the
 * plugins that are genuinely "active" — ones with no SKILL.md are installed
 * but contribute nothing to the model's behaviour.
 */
export function getActivePluginNames(): string[] {
  return getPlugins()
    .filter((p) => p.systemPromptAddition.trim().length > 0)
    .map((p) => p.name);
}
