/**
 * pluginMarket.ts — Acurist plugin system
 *
 * ── Supported marketplace formats ────────────────────────────────────────────
 *
 * 1. Acurist native (any URL):
 *    { "name": "My Marketplace", "plugins": [{ "name": "git", "description": "...",
 *      "version": "1.0.0", "author": "...", "repo": "...", "systemPromptAddition": "..." }] }
 *
 * 2. Claude Code marketplaces (.claude-plugin/marketplace.json). Plugin
 *    `source` may be:
 *      - a relative path in the marketplace repo:  "./plugins/foo"  or  "./"
 *      - { "source": "github", "repo": "owner/name", "ref"?, "path"? }
 *      - { "source": "url", "url": "https://github.com/owner/name.git" }
 *    What Acurist loads from a plugin: its skills — SKILL.md folders listed in the
 *    entry's `skills` array, found under <plugin>/skills/*, or at the plugin root.
 *    Each one is installed as a real skill (~/.acurist/plugins/<plugin>/<skill>/,
 *    bundled scripts and references included) and is runnable as /<skill-name>.
 *    Commands / agents / hooks / .mcp.json are NOT executed (installing a plugin
 *    that only ships those succeeds but contributes nothing, and says so).
 *
 * 3. GitHub shorthand:  /plugin marketplace add owner/repo
 *    -> https://raw.githubusercontent.com/owner/repo/HEAD/.claude-plugin/marketplace.json
 *
 * Browsing only downloads the marketplace manifest; a plugin's skills are
 * fetched on demand by /plugin add and /plugin info (one repo-zip download,
 * which is not subject to the GitHub REST API's anonymous rate limit).
 *
 * ── Commands ─────────────────────────────────────────────────────────────────
 *   /plugin marketplace add <url|owner/repo>   register a marketplace
 *   /plugin marketplace remove <name>          unregister a marketplace
 *   /plugin marketplace list                   list registered marketplaces
 *   /plugin browse [marketplace-name]          list plugins
 *   /plugin add <name>[@marketplace]           install
 *   /plugin remove <name>                      uninstall
 *   /plugin list                               list installed
 *   /plugin info <name>[@marketplace]          show details
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
import {
  extractBundles, fetchGithubRepoEntries, writePluginSkills, removePluginSkills, pluginHasSkills,
  registerSkillPreload, parseFrontmatter, slugName, type SkillBundle,
} from "./skills.js";

// ── Types ─────────────────────────────────────────────────────────────────────

/** A plugin as listed in a marketplace. `load` fetches the heavy parts on demand. */
/** What `load()` returns: plugin metadata plus the skill folders found in the plugin. */
type LoadedPlugin = Partial<Plugin> & { skillBundles?: SkillBundle[] };

type ListedPlugin = Omit<Plugin, "installedAt" | "marketplaceUrl"> & {
  load?: () => Promise<LoadedPlugin>;
};

type PluginSource =
  | string
  | {
      source?: string;
      repo?: string;
      url?: string;
      ref?: string;
      path?: string;
      subdir?: string;
      github?: { repo: string }; // legacy shape this code used to expect
    };

interface ClaudeCodeEntry {
  name?: string;
  description?: string;
  version?: string;
  author?: string | { name?: string };
  source?: PluginSource;
  skills?: string[];
  [k: string]: unknown;
}

// ── URL / path helpers ────────────────────────────────────────────────────────

const GITHUB_RAW = "https://raw.githubusercontent.com";

const slugify = (s: string) => s.trim().toLowerCase().replace(/\s+/g, "-");
const stripSlashes = (p: string) => p.replace(/^\.?\/+/, "").replace(/\/+$/, "").replace(/^\.$/, "");
const joinPath = (...parts: string[]) => parts.filter(Boolean).join("/").replace(/\/+/g, "/");

/** Resolve an `owner/repo` shorthand or a full URL into a marketplace URL. */
function resolveMarketplaceUrl(input: string): string {
  if (input.startsWith("http://") || input.startsWith("https://")) return input;
  if (/^[\w.-]+\/[\w.-]+$/.test(input)) {
    return `${GITHUB_RAW}/${input}/HEAD/.claude-plugin/marketplace.json`;
  }
  throw new Error(
    `Invalid marketplace address: "${input}". ` +
    `Use a full URL (https://...) or a GitHub repo shorthand (owner/repo).`
  );
}

/** Directory a marketplace manifest lives in (the root that relative sources resolve from). */
function marketplaceBase(url: string): string {
  const m = url.match(/^(.*)\/\.claude-plugin\/[^/]+$/);
  return m ? m[1] : url.replace(/\/[^/]*$/, "");
}

function githubFromBase(base: string): { owner: string; repo: string; ref: string } | null {
  const m = base.match(/^https:\/\/raw\.githubusercontent\.com\/([^/]+)\/([^/]+)\/([^/]+)/);
  return m ? { owner: m[1], repo: m[2], ref: m[3] } : null;
}

function githubRepoFromUrl(u: string): string | null {
  const m = u.match(/github\.com[/:]([^/]+)\/([^/.]+?)(?:\.git)?\/?$/);
  return m ? `${m[1]}/${m[2]}` : null;
}

/** Where a Claude-Code-style entry's files live: `${base}/${dir}/...` */
function locate(entry: ClaudeCodeEntry, marketBase: string, pluginRoot = ""): { base: string; dir: string } | null {
  const s = entry.source;
  if (typeof s === "string") {
    if (/^https?:\/\//.test(s)) {
      const repo = githubRepoFromUrl(s);
      return repo ? { base: `${GITHUB_RAW}/${repo}/HEAD`, dir: "" } : null;
    }
    // metadata.pluginRoot is prepended to relative sources (unless already included)
    const rel = stripSlashes(s), root = stripSlashes(pluginRoot);
    const dir = root && rel !== root && !rel.startsWith(root + "/") ? joinPath(root, rel) : rel;
    return { base: marketBase, dir };
  }
  if (s && typeof s === "object") {
    const repo = s.repo ?? s.github?.repo;
    const sub  = stripSlashes(s.path ?? s.subdir ?? "");
    if ((s.source === "github" || s.github) && repo) {
      return { base: `${GITHUB_RAW}/${repo}/${s.ref ?? "HEAD"}`, dir: sub };
    }
    if ((s.source === "url" || s.source === "git-subdir" || s.source === "git") && s.url) {
      const r = githubRepoFromUrl(s.url);
      if (r) return { base: `${GITHUB_RAW}/${r}/${s.ref ?? "HEAD"}`, dir: sub };
    }
  }
  return null;
}

const authorName = (a: unknown): string | undefined =>
  typeof a === "string" && a.trim() ? a.trim()
  : a && typeof a === "object" && typeof (a as any).name === "string" ? (a as any).name : undefined;

// ── Fetch helpers ─────────────────────────────────────────────────────────────

async function fetchText(url: string): Promise<string> {
  const res = await fetch(url, { signal: AbortSignal.timeout(10_000) as any });
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

const tryText = (url: string) => fetchText(url).catch(() => null);

/** Sub-directory names of a repo path via the GitHub contents API (null if unavailable/rate-limited). */
async function listGithubDirs(gh: { owner: string; repo: string; ref: string }, dir: string): Promise<string[] | null> {
  try {
    const qs = gh.ref && gh.ref !== "HEAD" ? `?ref=${encodeURIComponent(gh.ref)}` : "";
    const headers: Record<string, string> = { Accept: "application/vnd.github+json", "User-Agent": "acurist" };
    if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
    const res = await fetch(`https://api.github.com/repos/${gh.owner}/${gh.repo}/contents/${dir}${qs}`, {
      headers, signal: AbortSignal.timeout(10_000) as any,
    });
    if (!res.ok) return null;
    const items = (await res.json()) as any[];
    return Array.isArray(items) ? items.filter((i) => i.type === "dir").map((i) => String(i.name)) : null;
  } catch {
    return null;
  }
}

// ── Skill loading ─────────────────────────────────────────────────────────────

/** Wrap a lone SKILL.md (fetched by URL) as a one-file bundle. */
function bundleFromMarkdown(md: string, fallbackName: string): SkillBundle | null {
  const { data, body } = parseFrontmatter(md);
  if (!body.trim()) return null;
  const n = typeof data.name === "string" ? data.name : "";
  const name = slugName(n) || slugName(fallbackName);
  if (!name) return null;
  return { name, root: "", files: new Map([["SKILL.md", Buffer.from(md, "utf8")]]) };
}

/**
 * Fetch a Claude Code plugin's plugin.json + skills and return the pieces
 * Acurist can use. Never throws for "nothing found" — returns no bundles.
 *
 * Primary route: download the repo zip once (GitHub) and pull whole skill
 * folders out of it, so bundled scripts/references come along and the REST
 * API rate limit is never touched. Fallback: fetch SKILL.md files one by one.
 */
async function loadClaudeCodePlugin(entry: ClaudeCodeEntry, marketBase: string, pluginRoot = ""): Promise<LoadedPlugin> {
  const loc = locate(entry, marketBase, pluginRoot);
  if (!loc) return { systemPromptAddition: "", skillBundles: [] };
  const { base, dir } = loc;
  const name = String(entry.name ?? "plugin");
  const gh = githubFromBase(base);

  let meta: any = {};
  let bundles: SkillBundle[] = [];
  const explicitOf = (m: any) =>
    Array.isArray(entry.skills) ? entry.skills : Array.isArray(m?.skills) ? m.skills : null;

  if (gh) {
    try {
      const entries = await fetchGithubRepoEntries(gh.owner, gh.repo, gh.ref === "HEAD" ? undefined : gh.ref);
      for (const rel of [".claude-plugin/plugin.json", "plugin.json"]) {
        const e = entries.find((x) => x.name === joinPath(dir, rel));
        if (e) { try { meta = JSON.parse(e.read().toString("utf8")); break; } catch { /* try next */ } }
      }
      const explicit = explicitOf(meta);
      const only = explicit
        ?.filter((x: unknown): x is string => typeof x === "string")
        .map((x: string) => joinPath(dir, stripSlashes(x)));
      bundles = extractBundles(entries, { prefix: dir, only: only?.length ? only : undefined, hint: name });
    } catch { /* fall through to per-file fetch */ }
  }

  if (!bundles.length) {
    for (const rel of [".claude-plugin/plugin.json", "plugin.json"]) {
      const t = await tryText(`${base}/${joinPath(dir, rel)}`);
      if (t) { try { meta = JSON.parse(t); break; } catch { /* try next */ } }
    }
    const explicit = explicitOf(meta);
    let skillPaths: string[];
    if (explicit) {
      skillPaths = explicit
        .filter((x: unknown): x is string => typeof x === "string")
        .map((x: string) => joinPath(dir, stripSlashes(x)));
    } else {
      skillPaths = [joinPath(dir, "skills", name), dir]; // SKILL.md at the plugin root too
    }
    skillPaths = [...new Set(skillPaths)].slice(0, 25);
    const fetched = await Promise.all(
      skillPaths.map(async (p) => {
        const url = /\.md$/i.test(p) ? `${base}/${p}` : `${base}/${joinPath(p, "SKILL.md")}`;
        const md = await tryText(url);
        return md ? bundleFromMarkdown(md, /skill\.md$/i.test(p) ? p.split("/").slice(-2, -1)[0] || name : p.split("/").pop() || name) : null;
      }),
    );
    const seen = new Set<string>();
    bundles = fetched.filter((b): b is SkillBundle => !!b && !seen.has(b.name) && !!seen.add(b.name));
  }

  return {
    systemPromptAddition: "",
    skillBundles: bundles,
    version: typeof meta.version === "string" ? meta.version : undefined,
    description: typeof meta.description === "string" ? meta.description : undefined,
    author: authorName(meta.author),
  };
}

/**
 * Fetch and normalise a marketplace into a list of plugins. Only the manifest
 * is downloaded here; `plugin.load()` fetches skills when needed.
 */
async function fetchMarketplace(url: string): Promise<{ name?: string; plugins: ListedPlugin[] }> {
  const data = await fetchJson<any>(url);

  // Support bare array (legacy)
  const manifest: any = Array.isArray(data) ? { plugins: data } : data;
  if (!Array.isArray(manifest.plugins)) throw new Error(`Invalid marketplace format at ${url}`);

  const base = marketplaceBase(url);
  const gh = githubFromBase(base);
  const pluginRoot: string = typeof manifest.metadata?.pluginRoot === "string" ? manifest.metadata.pluginRoot : "";

  const plugins: ListedPlugin[] = manifest.plugins
    .filter((p: unknown) => p && typeof p === "object")
    .map((p: ClaudeCodeEntry & { repo?: string; systemPromptAddition?: string }) => {
      const native = typeof p.systemPromptAddition === "string";
      // With metadata.pluginRoot, an entry may omit `source` and live at <pluginRoot>/<name>
      if (!native && !p.source && pluginRoot && p.name) p = { ...p, source: String(p.name) };
      const loc = !native && p.source ? locate(p, base, pluginRoot) : null;
      const ghSrc = loc ? githubFromBase(loc.base) : gh;
      const repo =
        p.repo ??
        (ghSrc ? `https://github.com/${ghSrc.owner}/${ghSrc.repo}${loc?.dir ? `/tree/${ghSrc.ref}/${loc.dir}` : ""}` : "");
      const listed: ListedPlugin = {
        name: slugify(String(p.name ?? "unknown")),
        description: p.description ?? "(no description)",
        version: p.version ?? "0.0.0",
        author: authorName(p.author) ?? ghSrc?.owner ?? "unknown",
        repo,
        systemPromptAddition: native ? (p.systemPromptAddition as string) : "",
      };
      if (!native && p.source) listed.load = () => loadClaudeCodePlugin(p, base, pluginRoot);
      return listed;
    });

  return { name: manifest.name, plugins };
}

/** Fetch plugins from all registered marketplaces (in registration order), or just one if name given. */
export async function fetchAllPlugins(
  marketplaceName?: string
): Promise<{ plugin: Plugin; marketplace: Marketplace; load?: () => Promise<LoadedPlugin> }[]> {
  const markets = getMarketplaces().filter((m) => !marketplaceName || m.name === marketplaceName);

  // Fetch in parallel but keep a stable order, so "first match wins" is deterministic.
  const perMarket = await Promise.all(
    markets.map(async (market) => {
      try {
        const manifest = await fetchMarketplace(market.url);
        return manifest.plugins.map(({ load, ...p }) => ({
          plugin: { ...p, installedAt: "", marketplaceUrl: market.url } as Plugin,
          marketplace: market,
          load,
        }));
      } catch (e: any) {
        return [{
          plugin: {
            name: `[error:${market.name}]`,
            description: `Could not fetch: ${e.message}`,
            version: "",
            author: "",
            systemPromptAddition: "",
            installedAt: "",
            marketplaceUrl: market.url,
          } as Plugin,
          marketplace: market,
          load: undefined,
        }];
      }
    })
  );
  return perMarket.flat();
}

/** Merge lazily-loaded fields onto a listed plugin, ignoring undefined/empty values. */
function mergeLoaded(p: Plugin, extra: LoadedPlugin): Plugin {
  const out: any = { ...p };
  for (const [k, v] of Object.entries(extra)) if (k !== "skillBundles" && v !== undefined && v !== "") out[k] = v;
  // systemPromptAddition may legitimately be "" (nothing found) — keep it in sync
  if (extra.systemPromptAddition !== undefined) out.systemPromptAddition = extra.systemPromptAddition;
  return out as Plugin;
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
        const entry = addMarketplace(url, manifest.name ? slugify(manifest.name) : undefined);
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

  // ── /plugin add <name>[@marketplace] ─────────────────────────────────────
  if (sub === "add") {
    const spec = args[1]?.toLowerCase();
    if (!spec) return "Usage: /plugin add <name>[@marketplace]";
    const [name, wantMarket] = spec.split("@");

    if (getPlugin(name)) {
      return `Plugin "${name}" is already installed. Use /plugin remove ${name} first to reinstall.`;
    }

    let matches: Awaited<ReturnType<typeof fetchAllPlugins>> = [];
    try {
      const all = await fetchAllPlugins();
      matches = all.filter(
        (a) => a.plugin.name === name && (!wantMarket || a.marketplace.name.toLowerCase() === wantMarket)
      );
    } catch {
      // fall through to "not found"
    }

    if (!matches.length) {
      return (
        red(`Plugin "${name}"${wantMarket ? ` in marketplace "${wantMarket}"` : ""} not found.\n`) +
        `Run /plugin browse to see available plugins.\n` +
        `Run /plugin marketplace add <url|owner/repo> to add more marketplaces.`
      );
    }

    const chosen = matches[0];
    let found = chosen.plugin;
    let bundles: SkillBundle[] = [];
    if (chosen.load) {
      try {
        const loaded = await chosen.load();
        bundles = loaded.skillBundles ?? [];
        found = mergeLoaded(found, loaded);
      } catch (e: any) {
        return red(`✗ Could not download "${name}": ${e.message}`);
      }
    }

    // Each skill becomes a real, individually callable skill on disk
    let skillNames: string[] = [];
    if (bundles.length) {
      try {
        skillNames = writePluginSkills(name, bundles);
      } catch (e: any) {
        return red(`✗ Could not save skills for "${name}": ${e.message}`);
      }
    }
    installPlugin({ ...found, skills: skillNames, installedAt: new Date().toISOString() });

    const promptText = (found.systemPromptAddition ?? "").trim();
    const others = matches.slice(1).map((m) => m.marketplace.name);
    const shownSkills = skillNames.slice(0, 30).map((n) => "/" + n).join("  ") + (skillNames.length > 30 ? `  …+${skillNames.length - 30} more` : "");
    return (
      green(`✓ Plugin "${name}" installed.\n`) +
      `${found.description}\n` +
      `Version: ${found.version}  Author: ${found.author}\n` +
      (found.repo ? `Repo:    ${found.repo}\n` : "") +
      (others.length ? dim(`Also in: ${others.join(", ")} — use ${name}@<marketplace> to pick.\n`) : "") +
      `\n` +
      (skillNames.length
        ? `Installed ${skillNames.length} skill${skillNames.length > 1 ? "s" : ""}: ${cyan(shownSkills)}\n` +
          dim(`Run any with /<name> [args] — or just describe the task and the model will load the right one. Active now.`)
        : promptText
          ? dim(`Loaded instructions (${promptText.length} chars) — active from your next message.`)
          : dim(
              `Note: no SKILL.md found, so this plugin adds nothing to the model. ` +
              `Acurist only loads skills — Claude Code plugins that ship just commands/agents/hooks aren't supported.`
            ))
    );
  }

  // ── /plugin remove <name> ────────────────────────────────────────────────────
  if (sub === "remove") {
    const name = args[1]?.toLowerCase();
    if (!name) return "Usage: /plugin remove <name>";
    const ok = removePlugin(name);
    removePluginSkills(name);
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
        `  ${dim("installed " + p.installedAt?.slice(0, 10) + (p.marketplaceUrl ? "  from " + p.marketplaceUrl : ""))}` +
        (p.skills?.length ? `\n  ${dim("skills: " + p.skills.slice(0, 12).map((n) => "/" + n).join(" ") + (p.skills.length > 12 ? ` …+${p.skills.length - 12}` : ""))}` : "")
    );
    return `Installed plugins (${installed.length}):\n\n${rows.join("\n\n")}`;
  }

  // ── /plugin info <name>[@marketplace] ────────────────────────────────────
  if (sub === "info") {
    const spec = args[1]?.toLowerCase();
    if (!spec) return "Usage: /plugin info <name>[@marketplace]";
    const [name, wantMarket] = spec.split("@");

    const inst = getPlugin(name);
    let remote: Plugin | undefined;
    let remoteSkills: string[] = [];

    if (!inst) {
      try {
        const all = await fetchAllPlugins();
        const m = all.find((a) => a.plugin.name === name && (!wantMarket || a.marketplace.name.toLowerCase() === wantMarket));
        if (m) {
          remote = m.plugin;
          if (m.load) {
            try {
              const loaded = await m.load();
              remoteSkills = (loaded.skillBundles ?? []).map((b) => b.name);
              remote = mergeLoaded(remote, loaded);
            } catch {}
          }
        }
      } catch {}
    }

    const p = inst ?? remote;
    if (!p) return red(`Plugin "${name}" not found.`);

    const promptText    = p.systemPromptAddition ?? "";
    const promptPreview = promptText.trim().slice(0, 400);
    const truncated     = promptText.trim().length > 400 ? "…" : "";
    const skillList     = inst?.skills ?? remoteSkills;
    const skillsLine    = skillList.length
      ? `Skills (${skillList.length}): ${skillList.slice(0, 30).map((n) => "/" + n).join(" ")}${skillList.length > 30 ? " …" : ""}\n\n`
      : "";

    return (
      `${bold(p.name)} v${p.version}\n` +
      `${"─".repeat(40)}\n` +
      `${p.description}\n\n` +
      `Author:      ${p.author}\n` +
      `Repo:        ${p.repo || "n/a"}\n` +
      `Marketplace: ${p.marketplaceUrl ?? "n/a"}\n` +
      `Installed:   ${inst ? green("yes") + ` (${inst.installedAt?.slice(0, 10)})` : red("no")}\n\n` +
      skillsLine +
      (promptText.trim() || !skillList.length
        ? `System prompt addition (${promptText.trim().length} chars):\n${dim(promptPreview || "(none)")}${truncated}`
        : dim("Skills are loaded on demand — run /<name>, or the model loads them when relevant."))
    );
  }

  // ── help ──────────────────────────────────────────────────────────────────────
  return (
    bold("Plugin commands:\n") +
    `  /plugin browse [name]              — browse & install from a marketplace\n` +
    `  /plugin add <name>[@marketplace]   — install a plugin
` +
    `  /plugin remove <name>              — uninstall a plugin\n` +
    `  /plugin list                       — list installed plugins\n` +
    `  /plugin info <name>[@marketplace]  — show plugin details
` +
    `  /plugin marketplace list           — list registered marketplaces\n` +
    `  /plugin marketplace add <url|owner/repo>  — add a marketplace\n` +
    `  /plugin marketplace remove <name>  — remove a marketplace\n\n` +
    dim("Marketplace formats supported: Acurist native JSON, Claude Code (.claude-plugin/marketplace.json)\n") +
    dim("Plugin skills are callable as /<skill-name>. Manage skills directly with /skill.")
  );
}

/** Build the combined system prompt addition from all installed plugins. */
export function buildPluginSystemPrompt(): string {
  const active = getPlugins().filter((p) => (p.systemPromptAddition ?? "").trim().length > 0);
  if (active.length === 0) return "";
  return (
    "\n\n## Installed plugins\n\n" +
    "The user installed the plugins below. Follow their instructions when the task matches.\n\n" +
    active
      .map((p) => `## Plugin: ${p.name}${p.version ? ` (v${p.version})` : ""}\n\n${p.systemPromptAddition.trim()}`)
      .join("\n\n")
  );
}

/**
 * Return the names of all installed plugins that actually contribute something
 * to the model: installed skills, or a native system-prompt addition.
 */
export function getActivePluginNames(): string[] {
  return getPlugins()
    .filter((p) => (p.systemPromptAddition ?? "").trim().length > 0 || (p.skills?.length ?? 0) > 0 || pluginHasSkills(p.name))
    .map((p) => p.name);
}

/**
 * Older Acurist versions flattened a plugin's skills into one big
 * `systemPromptAddition` blob ("### Skill: …" sections). Convert those into real
 * skills once, so they become callable as /<name> and stop bloating every prompt.
 */
function migrateLegacyPluginSkills(): void {
  for (const p of getPlugins()) {
    const blob = p.systemPromptAddition ?? "";
    if (!/^### Skill: /m.test(blob) || pluginHasSkills(p.name)) continue;
    const bundles: SkillBundle[] = [];
    for (const part of blob.split(/\n\n---\n\n/)) {
      const m = part.match(/^### Skill: ([^\n]*)\n(?:_([^\n]*)_\n)?\n*([\s\S]*)$/);
      if (!m || !m[3].trim()) continue;
      const name = slugName(m[1]);
      if (!name) continue;
      const md = `---\nname: ${name}\ndescription: ${JSON.stringify((m[2] ?? "").trim())}\n---\n\n${m[3].trim()}\n`;
      bundles.push({ name, root: "", files: new Map([["SKILL.md", Buffer.from(md, "utf8")]]) });
    }
    if (!bundles.length) continue;
    try {
      const names = writePluginSkills(p.name, bundles);
      installPlugin({ ...p, systemPromptAddition: "", skills: names });
    } catch { /* leave the plugin as it was */ }
  }
}
registerSkillPreload(migrateLegacyPluginSkills);
