import { exec, spawn } from "node:child_process";
import { promisify } from "node:util";
import fs from "node:fs/promises";
import fsSync from "node:fs";
import os from "node:os";
import path from "node:path";
import fetch from "node-fetch";
import type { ProxyClient } from "./proxyClient.js";
import type { ToolPermissionMap } from "../types.js";
import { parseTodoString, normalizeTodoArray } from "./todoParse.js";

const execAsync = promisify(exec);

// ── Background jobs ───────────────────────────────────────────────────────────

interface BgJob { pid: number; logPath: string; command: string; startedAt: Date }
const bgJobs = new Map<string, BgJob>();
function bgId() { return `bg_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`; }

// ── Tool schemas ──────────────────────────────────────────────────────────────

export const TOOL_SCHEMAS = [
  {
    name: "run_shell",
    description: "Run a bash command. Use absolute paths (each call is a fresh shell). Never use cd. Long-running commands (HTTP servers, watchers, GUI apps, while-true loops) are automatically run in the background — you will receive startup output and a job_id to tail later with read_bg_log. Set background:true explicitly if unsure.",
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
    description: "Create a new file, or completely REPLACE an existing one. `content` is written to disk verbatim as the ENTIRE file, so it must be the full final file text — never a diff, a snippet, or a placeholder like '... rest unchanged ...'. To change only part of an existing file use edit_file. Parent directories are created automatically. For a very large file, write the first part here and add the rest with append_file.",
    input_schema: {
      type: "object",
      properties: {
        path:    { type: "string", description: "File to create or overwrite. Absolute path preferred; a relative path resolves against the working directory. An existing file at this path is replaced entirely." },
        content: { type: "string", description: "The COMPLETE file content, exactly as it should appear on disk: raw text only — no markdown code fences, no commentary, no line numbers. Must be the last parameter; write nothing after it." },
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
        path:    { type: "string", description: "File to append to. Same path that was used with write_file." },
        content: { type: "string", description: "Only the NEW content to add at the end of the file, as raw text (no markdown code fences, no commentary). Do not repeat existing content. Must be the last parameter; write nothing after it." },
      },
      required: ["path", "content"],
    },
  },
  {
    name: "edit_file",
    description: "Edit an EXISTING file from a natural-language instruction. A separate model rewrites the whole file and the result replaces the original, so the instruction must be precise and self-contained. Prefer this over write_file for partial changes. The file must already exist (use write_file to create one); read_file it first so you can name exact functions or lines.",
    input_schema: {
      type: "object",
      properties: {
        path:        { type: "string", description: "Path of the EXISTING file to edit." },
        instruction: { type: "string", description: "Self-contained description of the change. The editing model sees only the file and this text, not the conversation: name the function/section/line and state exactly what to add, remove or replace, quoting the literal new text when it is short. Everything not mentioned is left unchanged." },
      },
      required: ["path", "instruction"],
    },
  },
  {
    name: "diff_file",
    description: "Same as edit_file (EXISTING file, natural-language instruction, whole file rewritten by a separate model) but the unified diff is shown first and returned in the result. In manual mode the user approves the diff before it is applied.",
    input_schema: {
      type: "object",
      properties: {
        path:        { type: "string", description: "Path of the EXISTING file to edit." },
        instruction: { type: "string", description: "Self-contained description of the change. The editing model sees only the file and this text, not the conversation: name the function/section/line and state exactly what to add, remove or replace, quoting the literal new text when it is short. Everything not mentioned is left unchanged." },
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

function abs(cwd: string, p: string) {
  // Expand a leading "~" — models often send "~/x" and path.resolve would
  // otherwise create a literal "~" directory inside cwd.
  if (p === "~" || p.startsWith("~/")) p = path.join(os.homedir(), p.slice(1));
  return path.isAbsolute(p) ? p : path.resolve(cwd, p);
}

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

/** Like walk(), but also accepts a single FILE as the base (grep/glob on one file). */
async function collectFiles(base: string): Promise<{ files: string[]; root: string }> {
  const st = await fs.stat(base); // throws ENOENT with a clear message
  if (st.isFile()) return { files: [base], root: path.dirname(base) };
  const files: string[] = [];
  await walk(base, files);
  return { files, root: base };
}

const toPosix = (p: string) => p.split(path.sep).join("/");

/** Coerce a model-supplied number (models sometimes send "10" or 10.5). */
function toInt(v: unknown, dflt: number, min = 0): number {
  const n = typeof v === "string" ? parseInt(v, 10) : typeof v === "number" ? Math.trunc(v) : NaN;
  return Number.isFinite(n) ? Math.max(min, n) : dflt;
}

/**
 * Glob → anchored RegExp over a POSIX-style relative path.
 * Supports **, *, ?, {a,b}, [abc]. A pattern with no "/" matches at any depth
 * (ripgrep/gitignore behaviour), so "*.ts" finds src/a.ts too.
 */
function globRe(pattern: string): RegExp {
  let pat = pattern.replace(/\\/g, "/").replace(/^\.\//, "");
  if (!pat.includes("/")) pat = "**/" + pat;
  let re = "", braceDepth = 0;
  for (let i = 0; i < pat.length; i++) {
    const c = pat[i];
    if (c === "*") {
      if (pat[i + 1] === "*") {
        i++;
        if (pat[i + 1] === "/") { i++; re += "(?:.*/)?"; } // "**/" = zero or more dirs
        else re += ".*";
      } else re += "[^/]*";
    }
    else if (c === "?") re += "[^/]";
    else if (c === "{") { braceDepth++; re += "(?:"; }
    else if (c === "}" && braceDepth > 0) { braceDepth--; re += ")"; }
    else if (c === "," && braceDepth > 0) re += "|";
    else if (c === "[") { const end = pat.indexOf("]", i + 1); if (end > i) { re += pat.slice(i, end + 1); i = end; } else re += "\\["; }
    else re += c.replace(/[.+^${}()|\\\]]/g, "\\$&");
  }
  return new RegExp(`^${re}$`);
}

// ── Tool implementations ──────────────────────────────────────────────────────

const MAX_READ_CHARS = 120_000;
const MAX_LINE_CHARS = 2_000;

async function readFile(ctx: ToolContext, input: any): Promise<string> {
  if (typeof input.path !== "string" || !input.path) throw new Error("read_file requires a non-empty string path");
  const full = abs(ctx.cwd, input.path);
  const st = await fs.stat(full);
  if (st.isDirectory()) throw new Error(`${full} is a directory — use list_dir`);
  const buf = await fs.readFile(full);
  if (buf.subarray(0, 8192).includes(0)) throw new Error(`${full} looks like a binary file (${buf.length} bytes) — not reading it as text`);
  const lines  = buf.toString("utf-8").split("\n");
  const offset = toInt(input.offset, 1, 1);
  const limit  = toInt(input.limit, 2000, 1);

  const out: string[] = [];
  let chars = 0, i = 0;
  for (; i < limit && offset - 1 + i < lines.length; i++) {
    let l = lines[offset - 1 + i].replace(/\r$/, "");
    if (l.length > MAX_LINE_CHARS) l = l.slice(0, MAX_LINE_CHARS) + `… [+${l.length - MAX_LINE_CHARS} chars truncated]`;
    const row = `${offset + i}\t${l}`;
    if (chars + row.length > MAX_READ_CHARS) break;
    out.push(row); chars += row.length + 1;
  }
  const next = offset + i;
  if (next <= lines.length && i > 0) out.push(`… [stopped at line ${next - 1} of ${lines.length}; call read_file with offset=${next} to continue]`);
  return out.join("\n");
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
    // The API rejects an assistant prefill ending in whitespace, so trim it;
    // the model re-emits any needed newline when it continues.
    const prefill = acc.replace(/\s+$/, "");
    if (!prefill) return { text: acc, truncated: true };
    acc = prefill;
    messages = [
      messages[0],
      { role: "assistant", content: [{ type: "text", text: prefill }] },
    ];
  }

  return { text: acc, truncated: true };
}

// ── Whole-file rewrite plumbing (edit_file / diff_file) ───────────────────────

const FILE_BEGIN = "<<<ACURIST_FILE_BEGIN>>>";
const FILE_END   = "<<<ACURIST_FILE_END>>>";

const REWRITE_SYSTEM =
  "You are a precise code-editing engine. Reply with the complete resulting file placed between the two marker lines you are given, and nothing else.";

function buildRewritePrompt(displayPath: string, instruction: string, original: string): string {
  return (
    `Apply the instruction below to the file and reply with the COMPLETE new file content: every line of the file, ` +
    `changed or unchanged — never a diff, a snippet, or a placeholder such as "rest of file unchanged". ` +
    `Do not add any commentary and do not wrap the content in markdown code fences. Use exactly this layout:\n` +
    `${FILE_BEGIN}\n<the full new file content>\n${FILE_END}\n` +
    `Anything outside the two marker lines is discarded.\n\n` +
    `Instruction: ${instruction}\n\n` +
    `--- FILE (${displayPath}) ---\n${original}\n--- END OF FILE ---`
  );
}

const FENCE_LINE = /^[ \t]*```/;
const PROSE_LEAD =
  /^(?:sure|certainly|of course|okay|ok|here(?:'s| is| are)|below is|i(?:'ve| have|'ll| will)|the (?:updated|modified|complete|full|new|edited) (?:file|version|content|code)|this (?:updated|modified|new) )/i;
const PROSE_TAIL = /^(?:let me know|i hope (?:this|that)|hope this helps|feel free to|this (?:change|edit|update) )/i;
const PLACEHOLDER_RE =
  /^[ \t]*(?:\/\/|#|\/\*|<!--|--|;)?[ \t]*(?:\.{3}|…)[ \t]*(?:rest|remaining|existing|unchanged|previous|same|other)\b[^\n]*$|(?:rest|remainder) of (?:the )?(?:file|code|content|function|class)[^\n]*(?:unchanged|same|omitted|here)/im;

const firstLine = (t: string) => t.split(/\r?\n/).find(l => l.trim() !== "") ?? "";
const lastLine  = (t: string) => [...t.split(/\r?\n/)].reverse().find(l => l.trim() !== "") ?? "";

/**
 * Pull the new file body out of the model's reply WITHOUT damaging it.
 *
 * 1. Preferred: the body between FILE_BEGIN / FILE_END. Everything outside the
 *    markers (preambles, "hope this helps", stray fences) is discarded. A BEGIN
 *    with no END means the reply was cut off or malformed — refuse rather than
 *    write a partial file.
 * 2. Fallback (model ignored the markers): unwrap a single fenced block even if
 *    prose surrounds it, but only when the original has no fences of its own
 *    (e.g. a .md file) and there is exactly one fenced block. Anything
 *    ambiguous is rejected instead of being written to disk.
 */
function extractModelFile(text: string, original: string, kind: string, full: string): string {
  const b = text.indexOf(FILE_BEGIN);
  if (b !== -1) {
    let body = text.slice(b + FILE_BEGIN.length).replace(/^[ \t]*\r?\n/, "");
    const e = body.lastIndexOf(FILE_END);
    if (e === -1) {
      throw new Error(
        `${kind} for ${full}: the model's reply has no closing ${FILE_END} marker, so it was probably cut off. ` +
        `Refusing to overwrite the file with possibly-incomplete content. Retry with a smaller, more targeted instruction.`
      );
    }
    body = body.slice(0, e).replace(/\r?\n$/, "");
    return body;
  }

  let out = text.replace(/^\s*--- FILE \([^\n]*\) ---\r?\n/, "");
  const lines = out.split(/\r?\n/);
  const fenceIdx = lines.flatMap((l, i) => (FENCE_LINE.test(l) ? [i] : []));
  const origHasFence = original.split(/\r?\n/).some(l => FENCE_LINE.test(l));

  if (!origHasFence && fenceIdx.length > 0) {
    if (fenceIdx.length !== 2) {
      throw new Error(
        `${kind} for ${full}: the model's reply contains ${fenceIdx.length} markdown fence lines mixed with the content, ` +
        `so the file body can't be identified safely. Refusing to write. Retry with a more specific instruction.`
      );
    }
    return lines.slice(fenceIdx[0] + 1, fenceIdx[1]).join("\n");
  }

  const fl = firstLine(out), ll = lastLine(out);
  if ((PROSE_LEAD.test(fl.trim()) && !PROSE_LEAD.test(firstLine(original).trim())) ||
      (PROSE_TAIL.test(ll.trim()) && !PROSE_TAIL.test(lastLine(original).trim()))) {
    throw new Error(
      `${kind} for ${full}: the model's reply looks like it contains explanatory prose around the file ` +
      `("${(PROSE_LEAD.test(fl.trim()) ? fl : ll).trim().slice(0, 60)}…"). Refusing to write prose into the file. ` +
      `Retry with a more specific instruction.`
    );
  }
  return out;
}

/** Restore the original's line endings and trailing newline, which models routinely drop. */
function normalizeFileEnds(text: string, original: string): string {
  let out = text;
  const origCRLF = original.includes("\r\n");
  if (origCRLF && !out.includes("\r\n")) out = out.replace(/\n/g, "\r\n");
  const eol = origCRLF ? "\r\n" : "\n";
  const origEndsNL = /\n$/.test(original);
  if (origEndsNL && !/\n$/.test(out)) out += eol;
  if (!origEndsNL && /\n$/.test(out)) out = out.replace(/\r?\n+$/, "");
  return out;
}

/** Refuse rewrites that look like the model answered with prose, a snippet, or a placeholder instead of the file. */
function assertPlausibleRewrite(kind: string, full: string, original: string, next: string) {
  if (!next.trim()) throw new Error(`Model returned no content for ${kind}`);
  if (next.includes(FILE_BEGIN) || next.includes(FILE_END)) {
    throw new Error(`${kind} for ${full}: stray ${FILE_BEGIN}/${FILE_END} marker left in the model's output. Refusing to write. Retry.`);
  }
  if (PLACEHOLDER_RE.test(next) && !PLACEHOLDER_RE.test(original)) {
    throw new Error(
      `${kind} for ${full}: the model used a placeholder (e.g. "... rest unchanged ...") instead of writing the full file. ` +
      `Refusing to overwrite. Retry with a smaller, more targeted instruction.`
    );
  }
  if (original.length > 200 && next.length < original.length * 0.3) {
    throw new Error(
      `${kind} for ${full} would shrink the file from ${original.length} to ${next.length} chars ` +
      `(<30%). This usually means the model replied with an explanation instead of the full file. ` +
      `Refusing to overwrite. Retry with a more specific instruction or use write_file.`
    );
  }
}

/**
 * Shared front half of edit_file / diff_file: validate input, read the file,
 * have the model rewrite it, and return a cleaned + validated result.
 */
async function rewriteViaModel(
  ctx: ToolContext, kind: "edit_file" | "diff_file", input: any,
): Promise<{ full: string; original: string; next: string; mtimeMs: number }> {
  if (typeof input.path !== "string" || !input.path) throw new Error(`${kind} requires a non-empty string path`);
  if (typeof input.instruction !== "string" || !input.instruction.trim()) {
    throw new Error(`${kind} requires a non-empty string instruction describing exactly what to change`);
  }
  const full = abs(ctx.cwd, input.path);
  let st: import("node:fs").Stats;
  try { st = await fs.stat(full); }
  catch (e: any) {
    if (e?.code === "ENOENT") throw new Error(`${full} does not exist — ${kind} only edits existing files; use write_file to create it`);
    throw e;
  }
  if (st.isDirectory()) throw new Error(`${full} is a directory — ${kind} needs a file path`);
  const buf = await fs.readFile(full);
  if (buf.subarray(0, 8192).includes(0)) throw new Error(`${full} looks like a binary file (${buf.length} bytes) — ${kind} only edits text files`);
  const original = buf.toString("utf-8");

  const { text, truncated } = await askFullText(
    ctx, buildRewritePrompt(input.path, input.instruction, original), REWRITE_SYSTEM,
  );
  if (truncated) {
    throw new Error(
      `${kind} for ${full} was still truncated after multiple continuation attempts. ` +
      `Refusing to overwrite the existing file with an incomplete result. ` +
      `Try a smaller, more targeted instruction or split the edit into steps.`
    );
  }
  const next = normalizeFileEnds(extractModelFile(text, original, kind, full), original);
  assertPlausibleRewrite(kind, full, original, next);
  return { full, original, next, mtimeMs: st.mtimeMs };
}

async function assertUnchangedOnDisk(full: string, mtimeMs: number, kind: string) {
  const st = await fs.stat(full);
  if (st.mtimeMs !== mtimeMs) {
    throw new Error(`${kind}: ${full} was modified while the edit was being generated. Re-read the file and retry.`);
  }
}

async function confirmWrite(ctx: ToolContext, tool: string, detail: string): Promise<boolean> {
  return ctx.confirmShell(detail, tool);
}

/** Extensions where a file legitimately starts/ends with a ``` fence. */
const FENCE_OK_EXT = new Set([".md", ".markdown", ".mdx", ".rst", ".txt", ".adoc"]);

/** A whole-file body wrapped in a markdown fence is a model formatting slip for any non-doc file type. */
function assertNoFenceWrapper(tool: string, full: string, content: string) {
  if (FENCE_OK_EXT.has(path.extname(full).toLowerCase())) return;
  if (/^\s*```[\w+-]*[ \t]*\r?\n/.test(content)) {
    throw new Error(
      `${tool}: content for ${full} starts with a markdown code fence (\`\`\`). \`content\` is written to disk verbatim, ` +
      `so send the raw file text only — no fences, no commentary. Nothing was written; call ${tool} again with the raw content.`
    );
  }
}

async function writeFile(ctx: ToolContext, input: any): Promise<string> {
  if (typeof input.path !== "string" || !input.path) throw new Error("write_file requires a non-empty string path");
  if (typeof input.content !== "string") {
    throw new Error(
      `write_file received non-string content (got ${typeof input.content}). ` +
      `This usually means the tool call was cut off or malformed — nothing was written. ` +
      `Retry with a SHORTER first chunk via write_file, then add the remaining parts with append_file.`
    );
  }
  const full = abs(ctx.cwd, input.path);
  assertNoFenceWrapper("write_file", full, input.content);

  let existing: string | null = null;
  try {
    const st = await fs.stat(full);
    if (st.isDirectory()) throw new Error(`${full} is a directory — write_file needs a file path`);
    existing = st.size <= 5_000_000 ? await fs.readFile(full, "utf-8") : "";
  } catch (e: any) {
    if (e?.code !== "ENOENT") throw e;
  }
  const newLines = input.content.split("\n").length;
  const detail = existing === null
    ? `write_file ${full} (new file, ${newLines} lines)`
    : `write_file ${full} (OVERWRITING existing file: ${existing.split("\n").length} → ${newLines} lines)`;
  if (!(await confirmWrite(ctx, "write_file", detail))) return "Cancelled by user.";
  await fs.mkdir(path.dirname(full), { recursive: true });
  await fs.writeFile(full, input.content, "utf-8");
  return `${existing === null ? "Created" : "Overwrote"} ${full} — ${Buffer.byteLength(input.content)} bytes, ${newLines} lines`;
}

/** Append content to an existing file (or create it). Used to continue a
 * write_file that got cut off by max_tokens without regenerating the whole
 * file from scratch. */
async function appendFile(ctx: ToolContext, input: any): Promise<string> {
  if (typeof input.path !== "string" || !input.path) throw new Error("append_file requires a non-empty string path");
  if (typeof input.content !== "string") {
    throw new Error(
      `append_file received non-string content (got ${typeof input.content}). ` +
      `The continuation call may itself have been truncated or malformed — nothing was appended. ` +
      `Retry with a smaller chunk.`
    );
  }
  const full = abs(ctx.cwd, input.path);
  assertNoFenceWrapper("append_file", full, input.content);
  if (!(await confirmWrite(ctx, "append_file", `append_file ${full} (+${input.content.split("\n").length} lines)`))) return "Cancelled by user.";
  await fs.mkdir(path.dirname(full), { recursive: true });
  await fs.appendFile(full, input.content, "utf-8");
  const stat = await fs.stat(full);
  return `Appended ${Buffer.byteLength(input.content)} bytes to ${full} (file is now ${stat.size} bytes total).`;
}

async function editFile(ctx: ToolContext, input: any): Promise<string> {
  const { full, original, next, mtimeMs } = await rewriteViaModel(ctx, "edit_file", input);
  if (next === original) return `No changes made to ${full} (model returned identical content).`;
  if (!(await confirmWrite(ctx, "edit_file", unifiedDiff(original, next, input.path)))) return "Edit rejected.";
  await assertUnchangedOnDisk(full, mtimeMs, "edit_file");
  await fs.writeFile(full, next, "utf-8");
  return `Edited ${full} (${Buffer.byteLength(next)} bytes)`;
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

  const changed: number[] = [];
  tokens.forEach((t, idx) => { if (t.tag !== " ") changed.push(idx); });
  if (changed.length === 0) return "(no changes)";

  // Prefix line counters: oldAt[k] / newAt[k] = 1-based line numbers of token k
  const oldAt: number[] = [], newAt: number[] = [];
  { let o = 1, n = 1;
    for (const t of tokens) { oldAt.push(o); newAt.push(n); if (t.tag !== "+") o++; if (t.tag !== "-") n++; } }

  // Group changes into hunks; merge groups whose context would touch/overlap
  const CONTEXT = 3;
  const ranges: [number, number][] = [];
  for (const c of changed) {
    const lo = Math.max(0, c - CONTEXT), hi = Math.min(tokens.length - 1, c + CONTEXT);
    const last = ranges[ranges.length - 1];
    if (last && lo <= last[1] + 1) last[1] = Math.max(last[1], hi);
    else ranges.push([lo, hi]);
  }

  const result: string[] = [...header];
  for (const [lo, hi] of ranges) {
    const slice = tokens.slice(lo, hi + 1);
    const oldCount = slice.filter(t => t.tag !== "+").length;
    const newCount = slice.filter(t => t.tag !== "-").length;
    // Unified-diff convention: an empty side reports start-1
    const oldStart = oldCount === 0 ? oldAt[lo] - 1 : oldAt[lo];
    const newStart = newCount === 0 ? newAt[lo] - 1 : newAt[lo];
    result.push(`@@ -${oldStart},${oldCount} +${newStart},${newCount} @@`);
    for (const t of slice) result.push(`${t.tag}${t.text}`);
  }
  return result.join("\n");
}

async function diffFile(ctx: ToolContext, input: any): Promise<string> {
  const { full, original, next, mtimeMs } = await rewriteViaModel(ctx, "diff_file", input);
  if (next === original) return `No changes: model returned identical content for ${full}.`;
  const diff = unifiedDiff(original, next, input.path);

  // confirmShell resolves per-tool override → global mode (auto/manual) itself.
  // (Previously this defaulted to "auto" here, so manual mode never prompted.)
  if (await ctx.confirmShell(diff, "diff_file")) {
    await assertUnchangedOnDisk(full, mtimeMs, "diff_file");
    await fs.writeFile(full, next, "utf-8");
    return `Applied diff to ${full}\n${diff}`;
  }
  return `Diff rejected.\n${diff}`;
}

const MAX_GREP_MATCHES = 300;
const MAX_GREP_FILE_BYTES = 2_000_000;
const MAX_GLOB_RESULTS = 500;

async function grep(ctx: ToolContext, input: any): Promise<string> {
  if (typeof input.pattern !== "string" || !input.pattern) throw new Error("grep requires a non-empty string pattern");
  const base = abs(ctx.cwd, input.path || ".");
  const { files, root } = await collectFiles(base);
  const globFilter = input.glob ? globRe(String(input.glob)) : null;
  const pattern    = new RegExp(input.pattern);
  const matches: string[] = [];
  let capped = false;
  outer:
  for (const f of files) {
    if (globFilter && !globFilter.test(toPosix(path.relative(root, f)))) continue;
    let content: string;
    try {
      const st = await fs.stat(f);
      if (st.size > MAX_GREP_FILE_BYTES) continue;
      const buf = await fs.readFile(f);
      if (buf.subarray(0, 4096).includes(0)) continue; // binary
      content = buf.toString("utf-8");
    } catch { continue; }
    const ls = content.split("\n");
    for (let i = 0; i < ls.length; i++) {
      if (!pattern.test(ls[i])) continue;
      const t = ls[i].trim();
      matches.push(`${f}:${i + 1}:${t.length > 300 ? t.slice(0, 300) + "…" : t}`);
      if (matches.length >= MAX_GREP_MATCHES) { capped = true; break outer; }
    }
  }
  if (!matches.length) return "(no matches)";
  return matches.join("\n") + (capped ? `\n… stopped at ${MAX_GREP_MATCHES} matches — narrow the pattern, path or glob` : "");
}

async function glob(ctx: ToolContext, input: any): Promise<string> {
  if (typeof input.pattern !== "string" || !input.pattern) throw new Error("glob requires a non-empty string pattern");
  const base = abs(ctx.cwd, input.path || ".");
  const { files, root } = await collectFiles(base);
  const re = globRe(input.pattern);
  const candidates = files.filter(f => re.test(toPosix(path.relative(root, f))));
  const settled = await Promise.allSettled(candidates.map(async f => ({ f, mtime: (await fs.stat(f)).mtimeMs })));
  const valid = settled.filter((r): r is PromiseFulfilledResult<{ f: string; mtime: number }> => r.status === "fulfilled").map(r => r.value);
  valid.sort((a, b) => b.mtime - a.mtime);
  if (!valid.length) return "(no matches)";
  const shown = valid.slice(0, MAX_GLOB_RESULTS).map(x => x.f).join("\n");
  return valid.length > MAX_GLOB_RESULTS ? `${shown}\n… +${valid.length - MAX_GLOB_RESULTS} more (newest ${MAX_GLOB_RESULTS} shown)` : shown;
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
        const todos: { text: string; status: string }[] =
          typeof input.todos === "string"
            ? parseTodoString(input.todos)
            : normalizeTodoArray(input.todos);
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
