/**
 * skills.ts — Acurist skills
 *
 * A *skill* is a folder (or single file) containing a SKILL.md: YAML
 * frontmatter (`name`, `description`, …) followed by Markdown instructions.
 *
 * ── Where skills come from (highest priority first) ─────────────────────────
 *   <cwd>/.acurist/skills/      project skills
 *   ~/.acurist/skills/          your skills            ← installs go here
 *   <cwd>/.claude/skills/       Claude Code project skills (read as-is)
 *   ~/.claude/skills/           Claude Code user skills (read as-is)
 *   ~/.acurist/plugins/<p>/…    skills that arrived through /plugin add
 *
 * ── Accepted shapes ─────────────────────────────────────────────────────────
 *   my-skill/SKILL.md           a skill folder (scripts/, references/ … welcome)
 *   SKILL.md                    a standalone file dropped straight into a skills dir
 *   something.md                standalone, if it has `name` + `description` frontmatter
 *   my-skill.skill              a packaged skill (ZIP) — AUTO-INSTALLED when it
 *                               appears in a skills dir, and installable via
 *                               `/skill install <file|url|owner/repo>`
 *
 * ── Using skills ────────────────────────────────────────────────────────────
 *   /<skill-name> [args]        run it directly (shows up in the / picker)
 *   the model                   sees a name+description index and loads a skill
 *                               itself with the `use_skill` tool when it matches
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import fetch from "node-fetch";
import { readZip, looksLikeZip, safeEntryName, type ZipEntry } from "./zip.js";

// ── Types ─────────────────────────────────────────────────────────────────────

export type SkillSource = "project" | "user" | "claude-project" | "claude-user" | "plugin";

export interface Skill {
  /** Invocation name (slug) — what you type after "/" */
  name: string;
  description: string;
  /** SKILL.md body, frontmatter stripped */
  body: string;
  /** Folder holding the skill (bundled scripts/resources live here) */
  dir: string;
  /** The SKILL.md (or standalone .md) file */
  file: string;
  /** True when the skill is a lone .md file rather than a folder */
  standalone: boolean;
  source: SkillSource;
  /** `/name` allowed (frontmatter `user-invocable: false` turns this off) */
  userInvocable: boolean;
  /** Listed to the model / loadable via use_skill (`disable-model-invocation: true` turns this off) */
  modelInvocable: boolean;
  argumentHint?: string;
}

export interface InstallResult { name: string; dir: string; files: number; replaced: boolean }

export interface SkillBundle {
  name: string;
  /** Path of the skill root inside the archive/repo ("" = archive root) */
  root: string;
  /** relative path (forward slashes) → bytes. Always contains SKILL.md */
  files: Map<string, Buffer>;
}

// ── Paths ─────────────────────────────────────────────────────────────────────

const homeDir = () => os.homedir() || process.env.HOME || process.env.USERPROFILE || ".";
export const userSkillsDir    = () => path.join(homeDir(), ".acurist", "skills");
export const pluginSkillsRoot = () => path.join(homeDir(), ".acurist", "plugins");

let skillsCwd = process.cwd();
export function setSkillsCwd(cwd: string) { skillsCwd = cwd; invalidateSkills(); }

interface Root { dir: string; source: SkillSource; depth: number; autoInstall: boolean }

function roots(): Root[] {
  const h = homeDir();
  return [
    { dir: path.join(skillsCwd, ".acurist", "skills"), source: "project",        depth: 3, autoInstall: true  },
    { dir: path.join(h, ".acurist", "skills"),         source: "user",           depth: 3, autoInstall: true  },
    { dir: path.join(skillsCwd, ".claude", "skills"),  source: "claude-project", depth: 3, autoInstall: false },
    { dir: path.join(h, ".claude", "skills"),          source: "claude-user",    depth: 3, autoInstall: false },
    { dir: pluginSkillsRoot(),                         source: "plugin",         depth: 3, autoInstall: false },
  ];
}

// ── Naming ────────────────────────────────────────────────────────────────────

export function slugName(s: string): string {
  return s.trim().toLowerCase()
    .replace(/[^a-z0-9_-]+/g, "-")
    .replace(/-{2,}/g, "-")
    .replace(/^[-_]+|[-_]+$/g, "")
    .slice(0, 64);
}

// ── Frontmatter ───────────────────────────────────────────────────────────────

type FmValue = string | boolean | string[];

const unquote = (v: string): string => {
  const t = v.trim();
  if (t.length >= 2 && ((t[0] === '"' && t.endsWith('"')) || (t[0] === "'" && t.endsWith("'")))) {
    const inner = t.slice(1, -1);
    return t[0] === '"' ? inner.replace(/\\"/g, '"').replace(/\\n/g, "\n").replace(/\\\\/g, "\\") : inner.replace(/''/g, "'");
  }
  return t;
};

/**
 * Small YAML-frontmatter reader covering what SKILL.md files actually use:
 * plain / quoted scalars, folded (`>`) and literal (`|`) block scalars,
 * multi-line plain scalars, simple `- item` lists and inline `[a, b]` lists.
 */
export function parseFrontmatter(raw: string): { data: Record<string, FmValue>; body: string } {
  const text = raw.replace(/^\uFEFF/, "").replace(/\r\n?/g, "\n");
  const m = text.match(/^---[ \t]*\n([\s\S]*?)\n(?:---|\.\.\.)[ \t]*(?:\n|$)/);
  if (!m) return { data: {}, body: text };

  const data: Record<string, FmValue> = {};
  const lines = m[1].split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim() || /^\s*#/.test(line)) continue;
    const kv = line.match(/^([A-Za-z0-9_.-]+)\s*:\s*(.*)$/);
    if (!kv) continue;
    const key = kv[1].toLowerCase();
    const rest = kv[2].trim();

    // Gather the indented continuation lines (blank lines included)
    const cont: string[] = [];
    let j = i + 1;
    while (j < lines.length && (lines[j].trim() === "" || /^\s+\S/.test(lines[j]) || /^-\s/.test(lines[j]))) {
      cont.push(lines[j]); j++;
    }
    while (cont.length && cont[cont.length - 1].trim() === "") cont.pop();

    const block = rest.match(/^([>|])[+-]?\d*\s*(?:#.*)?$/);
    if (block) {
      const body = cont.map((l) => l.replace(/^\s+/, ""));
      if (block[1] === "|") {
        data[key] = body.join("\n").trim();
      } else {
        // folded: single newlines → space, blank line → newline
        data[key] = body.join("\n").replace(/([^\n])\n(?!\n)/g, "$1 ").replace(/\n{2,}/g, "\n").trim();
      }
      i = j - 1; continue;
    }

    if (rest === "" && cont.some((l) => /^\s*-\s+/.test(l))) {
      data[key] = cont.filter((l) => /^\s*-\s+/.test(l)).map((l) => unquote(l.replace(/^\s*-\s+/, "")));
      i = j - 1; continue;
    }

    if (/^\[.*\]$/.test(rest)) {
      data[key] = rest.slice(1, -1).split(",").map((s) => unquote(s)).filter(Boolean);
      i = j - 1; continue;
    }

    let value = rest;
    const quoted = /^["']/.test(rest);
    if (!quoted) value = rest.replace(/\s+#.*$/, "");
    if (cont.length && !quoted) value = [value, ...cont.map((l) => l.trim())].filter(Boolean).join(" ");
    else if (cont.length && quoted && !/^(["']).*\1$/.test(rest)) {
      // quoted scalar that wraps across lines
      value = [rest, ...cont.map((l) => l.trim())].join(" ");
    }
    value = unquote(value);
    if (/^(true|false)$/i.test(value) && !quoted) data[key] = value.toLowerCase() === "true";
    else data[key] = value;
    i = j - 1;
  }
  return { data, body: text.slice(m[0].length) };
}

const asString = (v: FmValue | undefined): string | undefined =>
  typeof v === "string" ? v : Array.isArray(v) ? v.join(", ") : undefined;

const asBool = (v: FmValue | undefined): boolean | undefined =>
  typeof v === "boolean" ? v : typeof v === "string" ? (/^(true|yes)$/i.test(v) ? true : /^(false|no)$/i.test(v) ? false : undefined) : undefined;

function firstParagraph(body: string): string {
  for (const block of body.split(/\n{2,}/)) {
    const t = block.trim();
    if (!t || /^#{1,6}\s/.test(t) || /^(```|---|<)/.test(t)) continue;
    return t.replace(/\s+/g, " ").slice(0, 240);
  }
  return "";
}

/** Parse a SKILL.md string into a Skill (or null if it has no usable content). */
export function parseSkillMarkdown(
  md: string,
  fallbackName: string,
  where: { file: string; dir: string; standalone: boolean; source: SkillSource },
): Skill | null {
  const { data, body } = parseFrontmatter(md);
  const trimmed = body.trim();
  if (!trimmed) return null;
  const name = slugName(asString(data.name) ?? "") || slugName(fallbackName);
  if (!name) return null;
  const description = (asString(data.description) ?? firstParagraph(trimmed)).replace(/\s+/g, " ").trim();
  const invocable = asBool(data["user-invocable"]) ?? asBool(data["user_invocable"]);
  const noModel   = asBool(data["disable-model-invocation"]) ?? asBool(data["disable_model_invocation"]);
  return {
    name, description, body: trimmed, ...where,
    userInvocable: invocable !== false,
    modelInvocable: noModel !== true,
    argumentHint: asString(data["argument-hint"]) ?? asString(data["argument_hint"]),
  };
}

// ── Discovery (+ automatic .skill installation) ───────────────────────────────

const IGNORED_DIRS = new Set(["node_modules", "__MACOSX", ".git", ".installed", ".failed"]);
const isSkillMd = (n: string) => n.toLowerCase() === "skill.md";

let cache: { at: number; cwd: string; skills: Skill[] } | null = null;
let notices: string[] = [];
let preloadHook: (() => void) | null = null;
let preloaded = false;

/** pluginMarket registers a one-time migration here (legacy blob → real skills). */
export function registerSkillPreload(fn: () => void) { preloadHook = fn; }
export function invalidateSkills() { cache = null; }
/** Messages produced by auto-install since the last call (for the UI to show). */
export function takeSkillNotices(): string[] { const n = notices; notices = []; return n; }

function readSkillFile(file: string, fallback: string, dir: string, standalone: boolean, source: SkillSource): Skill | null {
  try {
    return parseSkillMarkdown(fs.readFileSync(file, "utf8"), fallback, { file, dir, standalone, source });
  } catch { return null; }
}

function scanDir(dir: string, source: SkillSource, depth: number, out: Skill[], isRoot: boolean): void {
  let entries: fs.Dirent[];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }

  // A folder with SKILL.md *is* a skill (don't descend further into it)
  const own = entries.find((e) => e.isFile() && isSkillMd(e.name));
  if (own) {
    const s = readSkillFile(path.join(dir, own.name), path.basename(dir), dir, !isRoot ? false : true, source);
    if (s) out.push(isRoot ? { ...s, standalone: true } : { ...s, standalone: false });
    if (!isRoot) return;
  }

  for (const e of entries) {
    if (e.name.startsWith(".") || IGNORED_DIRS.has(e.name)) continue;
    const full = path.join(dir, e.name);
    let isDir = e.isDirectory();
    if (e.isSymbolicLink()) { try { isDir = fs.statSync(full).isDirectory(); } catch { continue; } }

    if (isDir) {
      if (depth > 1) scanDir(full, source, depth - 1, out, false);
    } else if (isRoot && /\.md$/i.test(e.name) && !isSkillMd(e.name)) {
      // Loose markdown: only counts as a skill if it declares itself one
      try {
        const raw = fs.readFileSync(full, "utf8");
        const { data } = parseFrontmatter(raw);
        if (asString(data.name) && asString(data.description)) {
          const s = parseSkillMarkdown(raw, e.name.replace(/\.md$/i, ""), { file: full, dir, standalone: true, source });
          if (s) out.push(s);
        }
      } catch { /* unreadable */ }
    }
  }
}

/** Extract any dropped-in `*.skill` archives sitting directly in a skills dir. */
function autoInstallArchives(dir: string): void {
  let entries: fs.Dirent[];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    if (!e.isFile() || !/\.skill$/i.test(e.name)) continue;
    const file = path.join(dir, e.name);
    try {
      const results = installArchive(fs.readFileSync(file), e.name.replace(/\.skill$/i, ""), dir);
      const done = path.join(dir, ".installed");
      fs.mkdirSync(done, { recursive: true });
      fs.renameSync(file, path.join(done, e.name));
      notices.push(`Auto-installed skill${results.length > 1 ? "s" : ""} from ${e.name}: ${results.map((r) => "/" + r.name).join(", ")}`);
    } catch (err: any) {
      try { fs.renameSync(file, file + ".failed"); } catch { /* ignore */ }
      notices.push(`Could not install ${e.name}: ${err?.message ?? err} (renamed to ${e.name}.failed)`);
    }
  }
}

/** All skills currently available, newest on disk. Auto-installs new .skill files. */
export function loadSkills(force = false): Skill[] {
  if (!preloaded) { preloaded = true; try { preloadHook?.(); } catch { /* best effort */ } }
  const now = Date.now();
  if (!force && cache && cache.cwd === skillsCwd && now - cache.at < 2000) return cache.skills;

  const found: Skill[] = [];
  for (const r of roots()) {
    if (r.autoInstall) autoInstallArchives(r.dir);
    scanDir(r.dir, r.source, r.depth, found, true);
  }
  // First occurrence wins (roots are in priority order)
  const seen = new Set<string>();
  const skills = found.filter((s) => (seen.has(s.name) ? false : (seen.add(s.name), true)));
  skills.sort((a, b) => a.name.localeCompare(b.name));
  cache = { at: now, cwd: skillsCwd, skills };
  return skills;
}

export const findSkill = (name: string): Skill | undefined => {
  const n = slugName(name.replace(/^\//, ""));
  return loadSkills().find((s) => s.name === n);
};

// ── Extracting bundles from archives ──────────────────────────────────────────

const MAX_FILES_PER_SKILL = 500;
const MAX_SKILL_BYTES     = 20 * 1024 * 1024;
const MAX_SKILLS_PER_ARCHIVE = 100;

/** Drop the single top-level folder GitHub wraps repo zips in. */
export function stripTopDir(entries: ZipEntry[]): ZipEntry[] {
  const tops = new Set(entries.map((e) => e.name.split("/")[0]));
  if (tops.size !== 1) return entries;
  const top = [...tops][0];
  return entries
    .filter((e) => e.name !== top)
    .map((e) => ({ ...e, name: e.name.slice(top.length + 1) }));
}

/**
 * Find every skill inside a set of zip entries. A skill root is the folder
 * containing a SKILL.md; each file belongs to its nearest skill root.
 *   prefix – only look inside this sub-path
 *   only   – only keep skills whose root is at/under one of these paths
 */
export function extractBundles(
  entries: ZipEntry[],
  opts: { prefix?: string; only?: string[]; hint?: string } = {},
): SkillBundle[] {
  const prefix = (opts.prefix ?? "").replace(/^\/+|\/+$/g, "");
  const inPrefix = (n: string) => !prefix || n === prefix || n.startsWith(prefix + "/");
  const usable = entries.filter((e) => !e.isDir && inPrefix(e.name)
    && !e.name.split("/").some((p) => IGNORED_DIRS.has(p)));

  const rootSet = new Set<string>();
  for (const e of usable) {
    const base = e.name.split("/").pop()!;
    if (isSkillMd(base)) rootSet.add(e.name.includes("/") ? e.name.slice(0, e.name.lastIndexOf("/")) : "");
  }
  let skillRoots = [...rootSet];
  if (opts.only?.length) {
    const only = opts.only.map((o) => o.replace(/^\/+|\/+$/g, ""));
    skillRoots = skillRoots.filter((r) => only.some((o) =>
      r === o || r.startsWith(o + "/") || (o.toLowerCase().endsWith("/skill.md") && r === o.slice(0, -"/SKILL.md".length)) || o === ""));
  }
  skillRoots.sort((a, b) => b.length - a.length); // deepest first → nearest-root lookup
  skillRoots = skillRoots.slice(0, MAX_SKILLS_PER_ARCHIVE * 4);

  const bundles = new Map<string, SkillBundle>();
  const sizes = new Map<string, number>();
  for (const e of usable) {
    const root = skillRoots.find((r) => r === "" || e.name.startsWith(r + "/"));
    if (root === undefined) continue;
    const rel = root ? e.name.slice(root.length + 1) : e.name;
    if (!rel) continue;
    let b = bundles.get(root);
    if (!b) { b = { name: "", root, files: new Map() }; bundles.set(root, b); }
    if (b.files.size >= MAX_FILES_PER_SKILL) continue;
    const total = (sizes.get(root) ?? 0) + e.size;
    if (total > MAX_SKILL_BYTES) continue;
    sizes.set(root, total);
    b.files.set(isSkillMd(rel) && !rel.includes("/") ? "SKILL.md" : rel, e.read());
  }

  const out: SkillBundle[] = [];
  for (const b of bundles.values()) {
    const md = b.files.get("SKILL.md");
    if (!md) continue;
    const { data } = parseFrontmatter(md.toString("utf8"));
    const folder = b.root ? b.root.split("/").pop()! : (opts.hint ?? "");
    const name = slugName(asString(data.name) ?? "") || slugName(folder);
    if (!name) continue;
    b.name = name;
    out.push(b);
  }
  return out.slice(0, MAX_SKILLS_PER_ARCHIVE).sort((a, b) => a.name.localeCompare(b.name));
}

function writeBundle(destRoot: string, b: SkillBundle): InstallResult {
  const dest = path.resolve(destRoot, b.name);
  if (path.dirname(dest) !== path.resolve(destRoot)) throw new Error(`Refusing unsafe skill name "${b.name}"`);
  const replaced = fs.existsSync(dest);
  if (replaced) fs.rmSync(dest, { recursive: true, force: true });
  for (const [rel, data] of b.files) {
    const safe = safeEntryName(rel);
    if (!safe) continue;
    const target = path.resolve(dest, safe);
    if (!target.startsWith(dest + path.sep)) continue;
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, data);
    if (/\.(sh|py|js|rb|pl)$/i.test(rel)) { try { fs.chmodSync(target, 0o755); } catch { /* windows */ } }
  }
  return { name: b.name, dir: dest, files: b.files.size, replaced };
}

/** Install the skills in a `.skill`/zip buffer into `destRoot`. */
export function installArchive(buf: Buffer, hint: string, destRoot = userSkillsDir(), opts: { stripTop?: boolean; prefix?: string; only?: string[] } = {}): InstallResult[] {
  if (!looksLikeZip(buf)) throw new Error("not a valid .skill/zip archive");
  let entries = readZip(buf);
  if (opts.stripTop) entries = stripTopDir(entries);
  const bundles = extractBundles(entries, { hint, prefix: opts.prefix, only: opts.only });
  if (!bundles.length) throw new Error("no SKILL.md found inside the archive");
  fs.mkdirSync(destRoot, { recursive: true });
  const results = bundles.map((b) => writeBundle(destRoot, b));
  invalidateSkills();
  return results;
}

/** Install a single SKILL.md text as a skill folder. */
export function installMarkdown(md: string, hint: string, destRoot = userSkillsDir()): InstallResult {
  const { data, body } = parseFrontmatter(md);
  if (!body.trim()) throw new Error("the file is empty");
  const name = slugName(asString(data.name) ?? "") || slugName(hint);
  if (!name) throw new Error("could not work out a skill name — add `name:` to the frontmatter");
  fs.mkdirSync(destRoot, { recursive: true });
  const r = writeBundle(destRoot, { name, root: "", files: new Map([["SKILL.md", Buffer.from(md, "utf8")]]) });
  invalidateSkills();
  return r;
}

// ── Plugin-owned skills ───────────────────────────────────────────────────────

export function writePluginSkills(plugin: string, bundles: SkillBundle[]): string[] {
  const root = path.join(pluginSkillsRoot(), slugName(plugin) || "plugin");
  fs.rmSync(root, { recursive: true, force: true });
  fs.mkdirSync(root, { recursive: true });
  const names = bundles.map((b) => writeBundle(root, b).name);
  invalidateSkills();
  return names;
}
export function removePluginSkills(plugin: string): boolean {
  const root = path.join(pluginSkillsRoot(), slugName(plugin) || "plugin");
  const had = fs.existsSync(root);
  fs.rmSync(root, { recursive: true, force: true });
  invalidateSkills();
  return had;
}
export const pluginHasSkills = (plugin: string) =>
  fs.existsSync(path.join(pluginSkillsRoot(), slugName(plugin) || "plugin"));

// ── Installing from a path / URL / GitHub ─────────────────────────────────────

const expandHome = (p: string) => (p === "~" || p.startsWith("~/") || p.startsWith("~\\") ? path.join(homeDir(), p.slice(1)) : p);

export async function fetchBuffer(url: string, timeoutMs = 60_000): Promise<Buffer> {
  const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) as any, headers: { "User-Agent": "acurist" } });
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${url}`);
  return Buffer.from(await res.arrayBuffer());
}

const repoZipCache = new Map<string, Promise<ZipEntry[]>>();

/** Whole-repo zip from codeload (not subject to the REST API's 60 req/h limit). */
export function fetchGithubRepoEntries(owner: string, repo: string, ref?: string): Promise<ZipEntry[]> {
  const key = `${owner}/${repo}@${ref ?? "HEAD"}`;
  let p = repoZipCache.get(key);
  if (!p) {
    p = (async () => {
      const tryRefs = ref ? [ref] : ["HEAD"];
      let last: any;
      for (const r of tryRefs) {
        try {
          const buf = await fetchBuffer(`https://codeload.github.com/${owner}/${repo}/zip/${r}`);
          return stripTopDir(readZip(buf));
        } catch (e) { last = e; }
      }
      throw new Error(`could not download ${owner}/${repo}${ref ? `@${ref}` : ""}: ${last?.message ?? last}`);
    })();
    repoZipCache.set(key, p);
    p.catch(() => repoZipCache.delete(key));
  }
  return p;
}

interface GithubRef { owner: string; repo: string; ref?: string; subpath: string }

/** owner/repo[/sub/path][@ref]  ·  https://github.com/o/r[/tree|blob/<ref>/<path>] */
export function parseGithubRef(input: string): GithubRef | null {
  const url = input.match(/^https?:\/\/github\.com\/([^/\s]+)\/([^/\s#?]+?)(?:\.git)?(?:\/(?:tree|blob)\/([^/\s]+)(?:\/([^\s#?]*))?)?\/?$/);
  if (url) return { owner: url[1], repo: url[2], ref: url[3], subpath: (url[4] ?? "").replace(/\/+$/, "") };
  if (/^https?:|^[.~]|^\//.test(input) || /^[a-zA-Z]:[\\/]/.test(input)) return null;
  const sh = input.match(/^([\w.-]+)\/([\w.-]+)((?:\/[^\s@]+)*)(?:@([\w./-]+))?$/);
  if (sh) return { owner: sh[1], repo: sh[2], ref: sh[4], subpath: sh[3].replace(/^\/+|\/+$/g, "") };
  return null;
}

function copyDirSync(src: string, dest: string, budget = { files: 0, bytes: 0 }) {
  fs.mkdirSync(dest, { recursive: true });
  for (const e of fs.readdirSync(src, { withFileTypes: true })) {
    if (IGNORED_DIRS.has(e.name) || e.name === ".DS_Store") continue;
    const s = path.join(src, e.name), d = path.join(dest, e.name);
    if (e.isDirectory()) copyDirSync(s, d, budget);
    else if (e.isFile()) {
      const st = fs.statSync(s);
      if (++budget.files > MAX_FILES_PER_SKILL || (budget.bytes += st.size) > MAX_SKILL_BYTES) throw new Error("skill folder is too large");
      fs.copyFileSync(s, d);
    }
  }
}

function installFromDir(dir: string, destRoot: string): InstallResult[] {
  let found: Skill[] = [];
  scanDir(dir, "user", 4, found, true);
  // The folder itself is a skill → install just that (ignore examples nested inside it)
  const self = found.find((s) => path.resolve(s.file) === path.resolve(dir, path.basename(s.file)) && isSkillMd(path.basename(s.file)));
  if (self) found = [self];
  if (!found.length) throw new Error(`no SKILL.md found in ${dir}`);
  const results: InstallResult[] = [];
  fs.mkdirSync(destRoot, { recursive: true });
  for (const s of found) {
    if (s.standalone && /\.md$/i.test(s.file) && !isSkillMd(path.basename(s.file))) {
      results.push(installMarkdown(fs.readFileSync(s.file, "utf8"), s.name, destRoot));
      continue;
    }
    const dest = path.resolve(destRoot, s.name);
    if (path.resolve(s.dir) === dest) { results.push({ name: s.name, dir: dest, files: 0, replaced: false }); continue; }
    const replaced = fs.existsSync(dest);
    if (replaced) fs.rmSync(dest, { recursive: true, force: true });
    copyDirSync(s.dir, dest);
    // normalise file name so every loader finds it
    const lower = fs.readdirSync(dest).find((f) => isSkillMd(f) && f !== "SKILL.md");
    if (lower) fs.renameSync(path.join(dest, lower), path.join(dest, "SKILL.md"));
    results.push({ name: s.name, dir: dest, files: fs.readdirSync(dest).length, replaced });
  }
  invalidateSkills();
  return results;
}

/**
 * Install skills from: a local .skill/.zip/.md/folder, an http(s) URL to any of
 * those, a GitHub URL, or an `owner/repo[/path][@ref]` shorthand.
 */
export async function installSkillFrom(source: string, destRoot = userSkillsDir()): Promise<InstallResult[]> {
  const src = expandHome(source.trim().replace(/^["']|["']$/g, ""));
  if (!src) throw new Error("nothing to install");

  // 1. local path
  const abs = path.resolve(skillsCwd, src);
  if (fs.existsSync(abs)) {
    const st = fs.statSync(abs);
    if (st.isDirectory()) return installFromDir(abs, destRoot);
    const base = path.basename(abs);
    const buf = fs.readFileSync(abs);
    if (/\.(skill|zip)$/i.test(base) || looksLikeZip(buf)) {
      return installArchive(buf, base.replace(/\.(skill|zip)$/i, ""), destRoot);
    }
    if (/\.md$/i.test(base)) {
      const hint = isSkillMd(base) ? path.basename(path.dirname(abs)) : base.replace(/\.md$/i, "");
      return [installMarkdown(fs.readFileSync(abs, "utf8"), hint, destRoot)];
    }
    throw new Error(`don't know how to install "${base}" — expected a .skill, .zip, SKILL.md or a folder`);
  }

  // 2. GitHub (URL or shorthand)
  const gh = parseGithubRef(src);
  if (gh) {
    // a direct link to one file → fetch it raw
    if (/\.md$/i.test(gh.subpath) && gh.ref) {
      const md = (await fetchBuffer(`https://raw.githubusercontent.com/${gh.owner}/${gh.repo}/${gh.ref}/${gh.subpath}`)).toString("utf8");
      const hint = isSkillMd(path.basename(gh.subpath)) ? path.basename(path.dirname(gh.subpath)) || gh.repo : path.basename(gh.subpath, ".md");
      return [installMarkdown(md, hint, destRoot)];
    }
    const entries = await fetchGithubRepoEntries(gh.owner, gh.repo, gh.ref);
    const bundles = extractBundles(entries, { prefix: gh.subpath, hint: gh.repo });
    if (!bundles.length) throw new Error(`no SKILL.md found in ${gh.owner}/${gh.repo}${gh.subpath ? "/" + gh.subpath : ""}`);
    fs.mkdirSync(destRoot, { recursive: true });
    const results = bundles.map((b) => writeBundle(destRoot, b));
    invalidateSkills();
    return results;
  }

  // 3. any other URL
  if (/^https?:\/\//i.test(src)) {
    const buf = await fetchBuffer(src);
    const last = decodeURIComponent(new URL(src).pathname.split("/").filter(Boolean).pop() ?? "skill");
    if (looksLikeZip(buf)) return installArchive(buf, last.replace(/\.(skill|zip)$/i, ""), destRoot);
    const hint = isSkillMd(last) ? decodeURIComponent(new URL(src).pathname.split("/").filter(Boolean).slice(-2, -1)[0] ?? "skill") : last.replace(/\.md$/i, "");
    return [installMarkdown(buf.toString("utf8"), hint, destRoot)];
  }

  throw new Error(`"${source}" is not an existing file/folder, URL, or GitHub repo (owner/repo)`);
}

// ── Removing ──────────────────────────────────────────────────────────────────

export function removeSkill(name: string): { ok: boolean; message: string } {
  const s = findSkill(name);
  if (!s) return { ok: false, message: `Skill "${name}" not found. Run /skill list.` };
  if (s.source === "plugin") return { ok: false, message: `"${s.name}" comes from a plugin — use /plugin remove <plugin> instead.` };
  if (s.source === "claude-user" || s.source === "claude-project") {
    return { ok: false, message: `"${s.name}" lives in a Claude Code folder (${s.dir}) — delete it there if you really want it gone.` };
  }
  try {
    if (s.standalone) fs.rmSync(s.file, { force: true });
    else fs.rmSync(s.dir, { recursive: true, force: true });
  } catch (e: any) { return { ok: false, message: `Could not remove ${s.dir}: ${e?.message ?? e}` }; }
  invalidateSkills();
  return { ok: true, message: `Removed skill "${s.name}".` };
}

// ── Invocation ────────────────────────────────────────────────────────────────

/** Split an argument string on whitespace, honouring "double" and 'single' quotes. */
export function splitArgs(s: string): string[] {
  const out: string[] = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s))) out.push(m[1] ?? m[2] ?? m[3]);
  return out;
}

/** Fill $ARGUMENTS / $1..$9 / ${SKILL_DIR} placeholders. `usedArgs` tells the caller whether any were present. */
export function renderSkillBody(skill: Skill, args: string): { text: string; usedArgs: boolean } {
  const list = splitArgs(args);
  let used = false;
  let text = skill.body
    .replace(/\$\{(?:SKILL_DIR|CLAUDE_SKILL_DIR)\}/g, () => skill.dir)
    .replace(/\$ARGUMENTS\[(\d+)\]/g, (_, n) => { used = true; return list[Number(n)] ?? ""; })
    .replace(/\$ARGUMENTS/g, () => { used = true; return args; })
    .replace(/\$([1-9])(?!\d)/g, (_, n) => { used = true; return list[Number(n) - 1] ?? ""; });
  return { text, usedArgs: used };
}

/** Files bundled next to SKILL.md (relative paths), for the model to read on demand. */
export function listBundledFiles(skill: Skill, limit = 40): string[] {
  if (skill.standalone) return [];
  const out: string[] = [];
  const walk = (dir: string, rel: string) => {
    let es: fs.Dirent[];
    try { es = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of es) {
      if (out.length >= limit) return;
      if (e.name.startsWith(".") || IGNORED_DIRS.has(e.name)) continue;
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) walk(path.join(dir, e.name), r);
      else if (!(rel === "" && isSkillMd(e.name))) out.push(r);
    }
  };
  walk(skill.dir, "");
  return out;
}

/** Text returned to the model by the `use_skill` tool. */
export function skillToolOutput(skill: Skill, args = ""): string {
  const { text, usedArgs } = renderSkillBody(skill, args);
  const files = listBundledFiles(skill);
  return [
    `# Skill: ${skill.name}`,
    skill.description && `_${skill.description}_`,
    skill.standalone ? "" : `Skill directory: ${skill.dir}  (relative paths in the instructions resolve from here)`,
    files.length ? `Bundled files:\n${files.map((f) => `  - ${f}`).join("\n")}` : "",
    "",
    text,
    args && !usedArgs ? `\nARGUMENTS: ${args}` : "",
  ].join("\n").replace(/\n{3,}/g, "\n\n");
}

/** The user message sent to the model when a skill is run via /<name>. */
export function buildSkillInvocation(skill: Skill, args: string): string {
  const { text, usedArgs } = renderSkillBody(skill, args);
  const files = listBundledFiles(skill);
  return [
    `The user ran the skill /${skill.name}${args ? ` with arguments: ${args}` : ""}.`,
    `Follow the skill's instructions below to carry out the request.`,
    "",
    `<skill name="${skill.name}"${skill.standalone ? "" : ` dir="${skill.dir}"`}>`,
    text,
    !usedArgs && args ? `\nARGUMENTS: ${args}` : "",
    files.length ? `\nBundled files (read them with read_file when the instructions point to them):\n${files.map((f) => `- ${path.join(skill.dir, f)}`).join("\n")}` : "",
    `</skill>`,
    args ? "" : `\n(No arguments were given — use the conversation so far, or ask the user what to apply the skill to.)`,
  ].filter((l) => l !== "").join("\n");
}

/**
 * If `text` is "/<skill> args", return the prompt to send. `reserved` are
 * built-in command names, which always win over a skill of the same name
 * (reach those skills with `/skill run <name>`).
 */
export function resolveSkillCall(
  text: string,
  reserved: ReadonlySet<string>,
): { skill: Skill; args: string; prompt: string } | null {
  const m = text.trim().match(/^\/([^\s]+)(?:\s+([\s\S]*))?$/);
  if (!m) return null;
  let name = m[1];
  let args = (m[2] ?? "").trim();

  if (name.toLowerCase() === "skill") {
    const run = args.match(/^run\s+([^\s]+)(?:\s+([\s\S]*))?$/i);
    if (!run) return null;
    name = run[1]; args = (run[2] ?? "").trim();
  } else if (reserved.has(name.toLowerCase())) {
    return null;
  }

  const slug = slugName(name);
  const skill = loadSkills().find((s) => s.name === slug && s.userInvocable);
  if (!skill) return null;
  return { skill, args, prompt: buildSkillInvocation(skill, args) };
}

// ── Model-facing index ────────────────────────────────────────────────────────

const INDEX_MAX_CHARS = 9_000;
const DESC_MAX_CHARS  = 260;

/** System-prompt section listing skills the model may load with `use_skill`. */
export function buildSkillsIndexPrompt(): string {
  const skills = loadSkills().filter((s) => s.modelInvocable);
  if (!skills.length) return "";
  const lines: string[] = [];
  let used = 0;
  for (const s of skills) {
    const d = s.description.length > DESC_MAX_CHARS ? s.description.slice(0, DESC_MAX_CHARS - 1) + "…" : s.description;
    const line = used + d.length > INDEX_MAX_CHARS ? `- ${s.name}` : `- ${s.name}${d ? `: ${d}` : ""}`;
    used += line.length;
    lines.push(line);
  }
  return (
    "\n\n## Skills\n\n" +
    "The user has installed skills — packaged instructions for specific kinds of work. " +
    "When a request matches a skill's description, call the `use_skill` tool with its name BEFORE starting, " +
    "then follow the returned instructions. If the user's message already contains a <skill> block " +
    "(they ran /<skill-name>), follow it directly — do not load it again.\n\n" +
    "Available skills:\n" + lines.join("\n")
  );
}
