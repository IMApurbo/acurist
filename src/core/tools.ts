import { exec, spawn } from "node:child_process";
import { promisify } from "node:util";
import fs from "node:fs/promises";
import fsSync from "node:fs";
import os from "node:os";
import path from "node:path";
import fetch from "node-fetch";
import type { ProxyClient } from "./proxyClient.js";
import type { ToolPermissionMap } from "../types.js";

const execAsync = promisify(exec);

// ── Background jobs ───────────────────────────────────────────────────────────

interface BgJob { pid: number; logPath: string; command: string; startedAt: Date }
const bgJobs = new Map<string, BgJob>();
function bgId() { return `bg_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`; }

// ── Tool schemas ──────────────────────────────────────────────────────────────

export const TOOL_SCHEMAS = [
  {
    name: "run_shell",
    description: "Run a bash command. Use absolute paths (each call is a fresh shell). Never use sudo or cd. Long-running commands (HTTP servers, watchers, GUI apps, while-true loops) are automatically run in the background — you will receive startup output and a job_id to tail later with read_bg_log. Set background:true explicitly if unsure.",
    input_schema: {
      type: "object",
      properties: {
        command:         { type: "string",  description: "Bash command exactly as you'd type it." },
        timeout_seconds: { type: "integer", description: "Max seconds to wait for foreground commands. Default 60. Ignored for background jobs." },
        background:      { type: "boolean", description: "Force background mode. Auto-set for servers/watchers/GUI apps." },
        settle_seconds:  { type: "integer", description: "How long to capture startup output before returning for background jobs. Default 3." },
      },
      required: ["command"],
    },
  },
  {
    name: "read_bg_log",
    description: "Tail the log of a background job launched with run_shell (background: true).",
    input_schema: {
      type: "object",
      properties: {
        job_id:     { type: "string",  description: "job_id returned by run_shell." },
        tail_lines: { type: "integer", description: "Lines to read from the end. Default 50." },
        kill:       { type: "boolean", description: "Kill the process before reading." },
      },
      required: ["job_id"],
    },
  },
  {
    name: "read_file",
    description: "Read a file with line numbers. Use offset/limit for large files.",
    input_schema: {
      type: "object",
      properties: {
        path:   { type: "string",  description: "File path." },
        offset: { type: "integer", description: "1-based start line." },
        limit:  { type: "integer", description: "Max lines. Default 2000." },
      },
      required: ["path"],
    },
  },
  {
    name: "write_file",
    description: "Create or overwrite a file. Use edit_file to change only part of a file.",
    input_schema: {
      type: "object",
      properties: {
        path:    { type: "string" },
        content: { type: "string" },
      },
      required: ["path", "content"],
    },
  },
  {
    name: "append_file",
    description: "Append content to the END of an existing file (creates it if missing). Use this to CONTINUE a file after a write_file call was cut off for being too long — never repeat content that's already been written, only provide the new remaining text.",
    input_schema: {
      type: "object",
      properties: {
        path:    { type: "string" },
        content: { type: "string", description: "Only the NEW content to add at the end of the file. Do not repeat existing content." },
      },
      required: ["path", "content"],
    },
  },
  {
    name: "edit_file",
    description: "Edit a file using a natural-language instruction. Prefer over write_file for partial changes.",
    input_schema: {
      type: "object",
      properties: {
        path:        { type: "string", description: "File to edit." },
        instruction: { type: "string", description: "Precise description of the change." },
      },
      required: ["path", "instruction"],
    },
  },
  {
    name: "diff_file",
    description: "Edit a file and show a unified diff before applying. In manual mode the user approves first.",
    input_schema: {
      type: "object",
      properties: {
        path:        { type: "string" },
        instruction: { type: "string" },
      },
      required: ["path", "instruction"],
    },
  },
  {
    name: "grep",
    description: "Search file contents for a regex pattern.",
    input_schema: {
      type: "object",
      properties: {
        pattern: { type: "string" },
        path:    { type: "string", description: "Directory or file. Defaults to cwd." },
        glob:    { type: "string", description: "Filename glob filter, e.g. '*.ts'." },
      },
      required: ["pattern"],
    },
  },
  {
    name: "glob",
    description: "Find files matching a name pattern, newest first.",
    input_schema: {
      type: "object",
      properties: {
        pattern: { type: "string" },
        path:    { type: "string" },
      },
      required: ["pattern"],
    },
  },
  {
    name: "list_dir",
    description: "List immediate children of a directory.",
    input_schema: {
      type: "object",
      properties: {
        path:        { type: "string",  description: "Directory to list. Defaults to cwd." },
        show_hidden: { type: "boolean", description: "Include dot-files. Default false." },
      },
      required: [],
    },
  },
  {
    name: "web_fetch",
    description: "Fetch a URL and return its text content (HTML stripped).",
    input_schema: {
      type: "object",
      properties: {
        url:             { type: "string" },
        timeout_seconds: { type: "integer", description: "Default 15, max 120." },
      },
      required: ["url"],
    },
  },
  {
    name: "ask_user",
    description: "Ask the user a question when genuinely blocked.",
    input_schema: {
      type: "object",
      properties: {
        question: { type: "string" },
        options:  { type: "string", description: "Optional comma-separated choices, e.g. yes,no,cancel" },
      },
      required: ["question"],
    },
  },
  {
    name: "update_todos",
    description: "Show the current step-by-step plan. One todo per line.",
    input_schema: {
      type: "object",
      properties: {
        todos: {
          type: "string",
          description: "One todo per line as 'text | status' where status is pending, in_progress, or completed. Example:\nInstall deps | pending\nRun tests | in_progress",
        },
      },
      required: ["todos"],
    },
  },
  {
    name: "notify_user",
    description: "Send a short notification to the user.",
    input_schema: {
      type: "object",
      properties: { message: { type: "string" } },
      required: ["message"],
    },
  },
  {
    name: "copy_to_clipboard",
    description: "Copy text to the system clipboard.",
    input_schema: {
      type: "object",
      properties: { text: { type: "string" } },
      required: ["text"],
    },
  },
] as const;

// ── ToolContext ───────────────────────────────────────────────────────────────

export interface ToolContext {
  cwd:             string;
  proxy:           ProxyClient;
  confirmShell:    (command: string, toolName?: string) => Promise<boolean>;
  askUser:         (question: string, options?: string[]) => Promise<string>;
  onTodos:         (todos: { text: string; status: string }[]) => void;
  notify:          (message: string) => void;
  toolPermissions?: ToolPermissionMap;
  signal?:          AbortSignal;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function abs(cwd: string, p: string) { return path.isAbsolute(p) ? p : path.resolve(cwd, p); }

async function walk(dir: string, out: string[], depth = 0): Promise<void> {
  if (depth > 12) return;
  let entries: import("node:fs").Dirent[];
  try { entries = await fs.readdir(dir, { withFileTypes: true }) as import("node:fs").Dirent[]; } catch { return; }
  for (const e of entries) {
    if (e.name === "node_modules" || e.name === ".git") continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) await walk(full, out, depth + 1);
    else out.push(full);
  }
}

function globRe(pattern: string): RegExp {
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "\u0000").replace(/\*/g, "[^/]*")
    .replace(/\u0000/g, ".*").replace(/\?/g, ".");
  return new RegExp(`${escaped}$`);
}

// ── Tool implementations ──────────────────────────────────────────────────────

async function readFile(ctx: ToolContext, input: any): Promise<string> {
  const lines  = (await fs.readFile(abs(ctx.cwd, input.path), "utf-8")).split("\n");
  const offset = Math.max(1, input.offset ?? 1);
  const limit  = input.limit ?? 2000;
  return lines.slice(offset - 1, offset - 1 + limit).map((l, i) => `${offset + i}\t${l}`).join("\n");
}

/**
 * Ask for a full block of plain-text content (no tool schema involved), and
 * transparently continue the generation if it gets cut off by max_tokens.
 *
 * Technique: when a response is truncated, we don't retry from scratch (that
 * risks a different/inconsistent rewrite and wastes the tokens already
 * spent). Instead we append what was generated so far as the tail of the
 * ASSISTANT's turn (prefill) and ask again — the model then continues
 * writing exactly where it left off, using its own prior output as context,
 * rather than regenerating the whole thing. We loop this up to `maxRounds`
 * times to support arbitrarily large content within a bounded number of
 * extra round-trips.
 */
async function askFullText(
  ctx:        ToolContext,
  userPrompt: string,
  system:     string,
  maxRounds = 6,
): Promise<{ text: string; truncated: boolean }> {
  let messages: any[] = [{ role: "user", content: [{ type: "text", text: userPrompt }] }];
  let acc = "";

  for (let round = 0; round < maxRounds; round++) {
    const resp = await ctx.proxy.ask(messages, system, ctx.signal);
    acc += resp.text;

    if (resp.stopReason !== "max_tokens") {
      return { text: acc, truncated: false };
    }
    if (round === maxRounds - 1) {
      // Ran out of continuation attempts — return what we have, but flag it
      // so the caller can refuse to overwrite the real file with a partial.
      return { text: acc, truncated: true };
    }

    // Prefill: put everything generated so far back in as the assistant's
    // own (unfinished) turn, then re-ask on the same conversation. The
    // model picks up mid-stream using its previous output as context,
    // instead of starting over.
    messages = [
      ...messages,
      { role: "assistant", content: [{ type: "text", text: acc }] },
    ];
  }

  return { text: acc, truncated: true };
}

function stripFences(text: string): string {
  return text.trim().replace(/^```[a-zA-Z0-9]*\r?\n?/, "").replace(/\n?```\s*$/, "");
}

async function writeFile(ctx: ToolContext, input: any): Promise<string> {
  if (typeof input.content !== "string") {
    throw new Error(
      `write_file received non-string content (got ${typeof input.content}). ` +
      `This usually means the model's tool call was truncated or malformed — refusing to write.`
    );
  }
  const full = abs(ctx.cwd, input.path);
  await fs.mkdir(path.dirname(full), { recursive: true });
  await fs.writeFile(full, input.content, "utf-8");
  return `Wrote ${input.content.length} bytes to ${full}`;
}

/** Append content to an existing file (or create it). Used to continue a
 * write_file that got cut off by max_tokens without regenerating the whole
 * file from scratch. */
async function appendFile(ctx: ToolContext, input: any): Promise<string> {
  if (typeof input.content !== "string") {
    throw new Error(
      `append_file received non-string content (got ${typeof input.content}). ` +
      `The continuation call may itself have been truncated or malformed — refusing to append.`
    );
  }
  const full = abs(ctx.cwd, input.path);
  await fs.mkdir(path.dirname(full), { recursive: true });
  await fs.appendFile(full, input.content, "utf-8");
  const stat = await fs.stat(full);
  return `Appended ${input.content.length} bytes to ${full} (file is now ${stat.size} bytes total).`;
}

async function editFile(ctx: ToolContext, input: any): Promise<string> {
  const full     = abs(ctx.cwd, input.path);
  const original = await fs.readFile(full, "utf-8");
  const prompt   =
    `Apply this instruction and return ONLY the complete new file content — no commentary, no fences.\n\nInstruction: ${input.instruction}\n\n--- FILE (${input.path}) ---\n${original}`;

  const { text, truncated } = await askFullText(
    ctx, prompt,
    "You are a precise code-editing engine. Output only the full resulting file.",
  );
  const cleaned = stripFences(text);
  if (!cleaned) throw new Error("Model returned no content for edit_file");
  if (truncated) {
    throw new Error(
      `edit_file for ${full} was still truncated after multiple continuation attempts. ` +
      `Refusing to overwrite the existing file with an incomplete result. ` +
      `Try a smaller, more targeted instruction or split the edit into steps.`
    );
  }
  await fs.writeFile(full, cleaned, "utf-8");
  return `Edited ${full} (${cleaned.length} bytes)`;
}

function unifiedDiff(oldText: string, newText: string, filePath: string): string {
  const a = oldText.split("\n"), b = newText.split("\n");
  const header = [`--- a/${filePath}`, `+++ b/${filePath}`];

  // Guard against O(n*m) LCS blowing up memory on very large files, e.g. a
  // 20,000-line file diffed against another would allocate ~400M Uint32
  // cells (1.6GB+). Fall back to a coarse summary instead of OOMing.
  const cellBudget = 20_000_000; // ~80MB of Uint32Array
  if ((a.length + 1) * (b.length + 1) > cellBudget) {
    return [
      ...header,
      `(diff skipped: file too large for in-process LCS diff — ${a.length} → ${b.length} lines. ` +
      `Old size ${oldText.length}B, new size ${newText.length}B.)`,
    ].join("\n");
  }

  // Build LCS dp table iteratively (no recursion — avoids stack overflow on large files)
  const dp = Array.from({ length: a.length + 1 }, () => new Uint32Array(b.length + 1));
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      dp[i][j] = a[i-1] === b[j-1] ? dp[i-1][j-1] + 1 : Math.max(dp[i-1][j], dp[i][j-1]);

  // Traceback iteratively to produce diff tokens
  type Token = { tag: " " | "+" | "-"; text: string };
  const tokens: Token[] = [];
  let i = a.length, j = b.length;
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && a[i-1] === b[j-1]) {
      tokens.push({ tag: " ", text: a[i-1] }); i--; j--;
    } else if (j > 0 && (i === 0 || dp[i][j-1] >= dp[i-1][j])) {
      tokens.push({ tag: "+", text: b[j-1] }); j--;
    } else {
      tokens.push({ tag: "-", text: a[i-1] }); i--;
    }
  }
  tokens.reverse();

  // Check if there are any actual changes
  if (!tokens.some(t => t.tag !== " ")) return "(no changes)";

  // Emit hunks with correct @@ -oldStart,oldCount +newStart,newCount @@ headers
  const CONTEXT = 3;
  const result: string[] = [...header];
  let oldLine = 1, newLine = 1, ti = 0;

  while (ti < tokens.length) {
    // Skip context-only stretches to find next changed region
    if (tokens[ti].tag === " ") { oldLine++; newLine++; ti++; continue; }

    // Found a changed token — define hunk boundaries
    const hunkStart = Math.max(0, ti - CONTEXT);
    const hunkTokens: Token[] = [];

    // Collect until CONTEXT lines after last change
    let lastChanged = ti;
    let k = hunkStart;
    while (k < tokens.length) {
      hunkTokens.push(tokens[k]);
      if (tokens[k].tag !== " ") lastChanged = k;
      if (k > lastChanged + CONTEXT) break;
      k++;
    }

    // Compute old/new line numbers at hunk start
    let oldStartLine = 1, newStartLine = 1;
    for (let m = 0; m < hunkStart; m++) {
      if (tokens[m].tag !== "+") oldStartLine++;
      if (tokens[m].tag !== "-") newStartLine++;
    }

    const oldCount = hunkTokens.filter(t => t.tag !== "+").length;
    const newCount = hunkTokens.filter(t => t.tag !== "-").length;

    result.push(`@@ -${oldStartLine},${oldCount} +${newStartLine},${newCount} @@`);
    for (const t of hunkTokens) result.push(`${t.tag}${t.text}`);

    ti = lastChanged + CONTEXT + 1;
  }

  return result.join("\n");
}

async function diffFile(ctx: ToolContext, input: any): Promise<string> {
  const full     = abs(ctx.cwd, input.path);
  const original = await fs.readFile(full, "utf-8");
  const prompt   =
    `Apply this instruction and return ONLY the complete new file content.\n\nInstruction: ${input.instruction}\n\n--- FILE (${input.path}) ---\n${original}`;

  const { text, truncated } = await askFullText(
    ctx, prompt,
    "You are a precise code-editing engine. Output only the full resulting file.",
  );
  const newContent = stripFences(text);
  if (!newContent) throw new Error("Model returned no content for diff_file");
  if (truncated) {
    throw new Error(
      `diff_file for ${full} was still truncated after multiple continuation attempts. ` +
      `Refusing to produce a diff against an incomplete result. ` +
      `Try a smaller, more targeted instruction or split the edit into steps.`
    );
  }
  const diff = unifiedDiff(original, newContent, input.path);

  // Resolve permission: per-tool override → global wildcard → global mode (default auto)
  const perm = ctx.toolPermissions?.["diff_file"] ?? ctx.toolPermissions?.["*"];
  // diff_file has no standalone globalMode concept in ctx; default to auto (same as run_shell auto mode)
  const mode = perm ?? "auto";

  if (mode === "auto" || await ctx.confirmShell(diff, "diff_file")) {
    await fs.writeFile(full, newContent, "utf-8");
    return `Applied diff to ${full}\n${diff}`;
  }
  return `Diff rejected.\n${diff}`;
}

async function grep(ctx: ToolContext, input: any): Promise<string> {
  const base  = abs(ctx.cwd, input.path || ".");
  const files: string[] = [];
  await walk(base, files);
  const globFilter = input.glob ? globRe(input.glob) : null;
  const pattern    = new RegExp(input.pattern);
  const matches: string[] = [];
  for (const f of files) {
    if (globFilter && !globFilter.test(f.replace(base + path.sep, "").replace(/\\/g, "/"))) continue;
    let content: string;
    try { content = await fs.readFile(f, "utf-8"); } catch { continue; }
    content.split("\n").forEach((l, i) => {
      if (pattern.test(l)) matches.push(`${f}:${i+1}:${l.trim()}`);
    });
    if (matches.length > 300) break;
  }
  return matches.length ? matches.slice(0, 300).join("\n") : "(no matches)";
}

async function glob(ctx: ToolContext, input: any): Promise<string> {
  const base = abs(ctx.cwd, input.path || ".");
  const files: string[] = [];
  await walk(base, files);
  const re = globRe(input.pattern);
  const candidates = files.filter(f => re.test(f.replace(base + path.sep, "")));
  const settled = await Promise.allSettled(candidates.map(async f => ({ f, mtime: (await fs.stat(f)).mtimeMs })));
  const valid = settled.filter((r): r is PromiseFulfilledResult<{ f: string; mtime: number }> => r.status === "fulfilled").map(r => r.value);
  valid.sort((a, b) => b.mtime - a.mtime);
  return valid.length ? valid.map(x => x.f).join("\n") : "(no matches)";
}

async function listDir(ctx: ToolContext, input: any): Promise<string> {
  const dir     = abs(ctx.cwd, input.path || ctx.cwd);
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const lines   = entries
    .filter(e => input.show_hidden || !e.name.startsWith("."))
    .map(e => `${e.isDirectory() ? "d" : "f"}  ${e.name}`);
  return lines.join("\n") || "(empty)";
}

async function webFetch(input: any, signal?: AbortSignal): Promise<string> {
  const ms      = Math.min(Math.max(1, input.timeout_seconds ?? 15), 120) * 1000;
  const timeout = AbortSignal.timeout(ms);
  const combined = signal ? AbortSignal.any([signal, timeout]) : timeout;
  const raw  = await (await fetch(input.url, { headers: { "User-Agent": "acurist" }, signal: combined as any })).text();
  return raw
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ").trim().slice(0, 8000);
}

async function copyToClipboard(input: any): Promise<string> {
  const cmd = process.platform === "darwin" ? "pbcopy"
    : (await execAsync("which xclip 2>/dev/null").catch(() => ({ stdout: "" }))).stdout.trim()
      ? "xclip -selection clipboard"
      : "xsel --clipboard --input";
  await new Promise<void>((resolve, reject) => {
    const child = spawn(cmd, { shell: true, stdio: ["pipe", "ignore", "ignore"] });
    child.stdin.write(input.text);
    child.stdin.end();
    child.on("close", code => code === 0 ? resolve() : reject(new Error(`clipboard exited ${code}`)));
    child.on("error", reject);
  });
  return "Copied to clipboard.";
}

// ── Shell execution ───────────────────────────────────────────────────────────

function needsConfirm(toolName: string, perms?: ToolPermissionMap, globalMode = "auto"): boolean {
  const p = perms?.[toolName];
  if (p === "auto") return false;
  if (p === "manual") return true;
  return globalMode === "manual";
}

// Patterns that indicate a command will run indefinitely
const LONG_RUNNING_PATTERNS = [
  /\bpython3?\s+.*-m\s+http\.server\b/,
  /\bpython3?\s+.*-m\s+(flask|uvicorn|gunicorn|django)\b/,
  /\buvicorn\b/, /\bgunicorn\b/, /\bnodemon\b/, /\bwatchdog\b/,
  /\bnpx?\s+(serve|vite|next|nuxt|gatsby|astro|remix|parcel)\b/,
  /\byarn\s+(start|dev|serve)\b/, /\bnpm\s+(start|run\s+dev|run\s+serve)\b/,
  /\bnode\s+.*server\b/, /\bnode\s+.*app\b/, /\bdeno\s+serve\b/,
  /\btail\s+-f\b/, /\bwatch\b/, /\binotifywait\b/,
  /\bnc\s+-l\b/, /\bnetcat\b.*-l\b/,
  /\bfirefox\b/, /\bchrome\b/, /\bchromium\b/, /\bxdg-open\b/,
  /\bwireguard\b/, /\bopenvpn\b/,
  /^\s*while\s+true\b/, /^\s*while\s*:\s*;/,
  /\bsleep\s+infinity\b/,
];

function looksLongRunning(cmd: string): boolean {
  return LONG_RUNNING_PATTERNS.some(re => re.test(cmd));
}

/** Spawn a detached background job, wait settleMs for startup output, return it. */
async function spawnBackground(
  command: string,
  cwd: string,
  settleMs = 3000,
): Promise<{ output: string; isError: boolean }> {
  const jobId     = bgId();
  const logPath   = path.join(os.tmpdir(), `${jobId}.log`);
  const logStream = fsSync.createWriteStream(logPath, { flags: "a" });
  await new Promise<void>(r => logStream.once("open", () => r()));

  const child = spawn("/bin/bash", ["-c", command], {
    cwd, env: process.env, detached: true, stdio: ["ignore", "pipe", "pipe"],
  });

  logStream.write(`[acurist] job ${jobId} | cmd: ${command} | pid: ${child.pid} | ${new Date().toISOString()}\n`);

  const startupChunks: string[] = [];
  let exited = false;
  let exitCode: number | null = null;

  child.stdout.on("data", (d: Buffer) => { logStream.write(d); startupChunks.push(d.toString()); });
  child.stderr.on("data", (d: Buffer) => { logStream.write(d); startupChunks.push(d.toString()); });
  child.on("close", (code) => {
    exited = true; exitCode = code;
    logStream.write(`\n[acurist] exited — code: ${code ?? "?"} — ${new Date().toISOString()}\n`);
    logStream.end();
    bgJobs.delete(jobId);
  });
  child.unref();
  bgJobs.set(jobId, { pid: child.pid!, logPath, command, startedAt: new Date() });

  // Wait up to settleMs for startup output (or early exit indicating crash)
  await new Promise<void>(r => {
    const t = setTimeout(r, settleMs);
    child.on("close", () => { clearTimeout(t); r(); });
  });

  const startupOut = startupChunks.join("").trim();

  if (exited) {
    // Died immediately — treat as a foreground failure
    return {
      output: `Process exited immediately (code ${exitCode ?? "?"}).\n${startupOut.slice(0, 1500) || "(no output)"}`,
      isError: exitCode !== 0,
    };
  }

  const header  = `Background job running.\n  job_id: ${jobId}\n  pid:    ${child.pid}\n  log:    ${logPath}\nUse read_bg_log job_id="${jobId}" to tail output.`;
  const startup = startupOut ? `\n\nStartup output (first ${settleMs / 1000}s):\n${startupOut.slice(0, 1500)}` : "";
  return { output: header + startup, isError: false };
}

async function runShell(ctx: ToolContext, input: any): Promise<{ output: string; isError: boolean }> {

  if (needsConfirm("run_shell", ctx.toolPermissions)) {
    const ok = await ctx.confirmShell(input.command, "run_shell");
    if (!ok) return { output: "Cancelled by user.", isError: false };
  }

  // ── Background mode (explicit flag OR auto-detected long-running pattern) ──
  if (input.background || looksLongRunning(input.command as string)) {
    const settleMs = input.settle_seconds ? (input.settle_seconds as number) * 1000 : 3000;
    return spawnBackground(input.command as string, ctx.cwd, settleMs);
  }

  // ── Foreground mode ───────────────────────────────────────────────────────
  const timeoutMs = (input.timeout_seconds ?? 60) * 1000;

  const output = await new Promise<string>(resolve => {
    const child = spawn("/bin/bash", ["-c", input.command], { cwd: ctx.cwd, env: process.env, detached: true });
    const chunks: string[] = [];
    let bytes = 0;

    const onData = (d: Buffer) => { bytes += d.length; if (bytes <= 10 * 1024 * 1024) chunks.push(d.toString()); };
    child.stdout.on("data", onData);
    child.stderr.on("data", onData);

    const kill = (reason: string) => {
      try { process.kill(-child.pid!, "SIGKILL"); } catch {}
      try { child.kill("SIGKILL"); } catch {}
      resolve(chunks.join("").trim() || reason);
    };

    const timer = setTimeout(() => kill(`(timed out after ${Math.round(timeoutMs/1000)}s)`), timeoutMs);
    const onAbort = () => kill("(interrupted by user)");
    ctx.signal?.addEventListener("abort", onAbort);

    child.on("close", () => { clearTimeout(timer); ctx.signal?.removeEventListener("abort", onAbort); resolve(chunks.join("").trim() || "(no output)"); });
    child.on("error", err => { clearTimeout(timer); ctx.signal?.removeEventListener("abort", onAbort); resolve(`Error: ${err.message}`); });
  });

  return { output: output || "(no output)", isError: false };
}

// ── Dispatcher ────────────────────────────────────────────────────────────────

export async function executeTool(
  ctx:   ToolContext,
  name:  string,
  input: Record<string, unknown>,
): Promise<{ output: string; isError: boolean }> {
  try {
    switch (name) {
      case "run_shell":        return runShell(ctx, input);
      case "read_bg_log": {
        const jobId   = input.job_id as string;
        const job     = bgJobs.get(jobId);
        let logPath   = job?.logPath ?? (String(jobId).startsWith("/") ? String(jobId) : undefined);
        if (!logPath) {
          const candidate = path.join(os.tmpdir(), `${jobId}.log`);
          try { await fs.access(candidate); logPath = candidate; }
          catch { return { output: `No job "${jobId}". Known: ${[...bgJobs.keys()].join(", ") || "none"}`, isError: true }; }
        }
        if (input.kill && job) {
          try { process.kill(-job.pid, "SIGTERM"); } catch {}
          bgJobs.delete(jobId);
        }
        const tailLines = (input.tail_lines as number) ?? 50;
        let log: string;
        try { log = await fs.readFile(logPath, "utf-8"); }
        catch { return { output: `Log not found: ${logPath}`, isError: true }; }
        const lines = log.split("\n");
        return { output: lines.slice(-tailLines).join("\n"), isError: false };
      }
      case "read_file":        return { output: await readFile(ctx, input),   isError: false };
      case "write_file":       return { output: await writeFile(ctx, input),  isError: false };
      case "append_file":      return { output: await appendFile(ctx, input), isError: false };
      case "edit_file":        return { output: await editFile(ctx, input),   isError: false };
      case "diff_file":        return { output: await diffFile(ctx, input),   isError: false };
      case "grep":             return { output: await grep(ctx, input),       isError: false };
      case "glob":             return { output: await glob(ctx, input),       isError: false };
      case "list_dir":         return { output: await listDir(ctx, input),    isError: false };
      case "web_fetch":        return { output: await webFetch(input, ctx.signal), isError: false };
      case "ask_user": {
        const opts = typeof input.options === "string"
          ? input.options.split(",").map((s: string) => s.trim()).filter(Boolean)
          : Array.isArray(input.options) ? input.options : undefined;
        const answer = await ctx.askUser(input.question as string, opts);
        return { output: answer, isError: false };
      }
      case "update_todos": {
        let todos: { text: string; status: string }[];
        if (typeof input.todos === "string") {
          todos = input.todos.split("\n").map((l: string) => l.trim()).filter(Boolean).map((l: string) => {
            const sep = l.lastIndexOf("|");
            if (sep === -1) return { text: l.trim(), status: "pending" };
            return { text: l.slice(0, sep).trim(), status: l.slice(sep + 1).trim() };
          });
        } else {
          todos = (input.todos as any[]) ?? [];
        }
        ctx.onTodos(todos);
        return { output: "Todos updated.", isError: false };
      }
      case "notify_user":
        ctx.notify((input.message as string) ?? "");
        return { output: "Notified.", isError: false };
      case "copy_to_clipboard": return { output: await copyToClipboard(input), isError: false };
      default:                  return { output: `Unknown tool: ${name}`,      isError: true };
    }
  } catch (e: any) {
    return { output: `Error: ${e?.message ?? String(e)}`, isError: true };
  }
}
