import chalk from "chalk";
import wrapAnsi from "wrap-ansi";
import type { TranscriptEvent } from "../types.js";
import { renderMarkdown } from "./markdown.js";
import { buildBannerLines } from "./banner.js";
import { parseTodoString } from "../core/todoParse.js";
import { readFullOutput } from "../core/outputLog.js";
import fs from "node:fs";

// ── scrollback line model ────────────────────────────────────────────
function wrapLine(text: string, width: number): string[] {
  const safeWidth = Math.max(1, width);
  return wrapAnsi(text, safeWidth, { trim: false, hard: true }).split("\n");
}

/** Truncate a string to maxLen, appending "…" if cut. */
function trunc(s: string, maxLen: number): string {
  if (!s) return "";
  const flat = s.replace(/\n/g, "↵ ").replace(/\s+/g, " ").trim();
  return flat.length > maxLen ? flat.slice(0, maxLen - 1) + "…" : flat;
}

/**
 * Build the Claude-Code-style tool call header line.
 *
 * ⏺ write_file  hello.py
 * ⏺ run_shell   ls -la /home/user
 * ⏺ edit_file   src/index.ts — replace console.log with logger.info
 * ⏺ grep        "TODO" in src/
 * ⏺ web_fetch   https://example.com
 */
function toolCallLine(name: string, input: Record<string, any>, width: number, expanded = false): string[] {
  const PREFIX = "⏺ ";

  // Primary value — what you'd show right next to the tool name
  let primary = "";
  // Secondary value — shown dimmed after two spaces (like a subtitle)
  let secondary = "";

  switch (name) {
    case "run_shell":
      primary = input.command ?? "";
      break;
    case "read_file":
      primary = input.path ?? "";
      break;
    case "write_file":
      primary = input.path ?? "";
      if (input.content) secondary = `${String(input.content).split("\n").length} lines`;
      break;
    case "edit_file":
      primary = input.path ?? "";
      secondary = input.instruction ?? input.old_str?.slice(0, 60) ?? "";
      break;
    case "grep":
      primary = `"${input.pattern ?? ""}"`;
      secondary = `in ${input.path || "."}`;
      break;
    case "glob":
      primary = input.pattern ?? "";
      break;
    case "web_fetch":
      primary = input.url ?? "";
      break;
    case "notify_user":
      primary = input.message ?? "";
      break;
    case "ask_user":
      primary = input.question ?? "";
      break;
    case "update_todos": {
      // input.todos is a newline-delimited string: "step | status\nstep | status"
      const count = typeof input.todos === "string"
        ? parseTodoString(input.todos).length
        : Array.isArray(input.todos) ? input.todos.length : 0;
      primary = `${count} step${count !== 1 ? "s" : ""}`;
      break;
    }
    case "append_file":
      primary = input.path ?? "";
      if (input.content) secondary = `+${String(input.content).split("\n").length} lines`;
      break;
    case "diff_file":
      primary = input.path ?? "";
      secondary = input.instruction ?? "";
      break;
    case "list_dir":
      primary = input.path ?? "(cwd)";
      break;
    case "read_bg_log":
      primary = input.job_id ?? "";
      if (input.kill) secondary = "kill";
      break;
    case "copy_to_clipboard":
      primary = String(input.text ?? "").slice(0, 60);
      break;
    default:
      primary = JSON.stringify(input);
  }

  // Available width for the value portion after "⏺ toolname  " (2 cols reserved for the ▸/▾ marker)
  const nameTag = `${PREFIX}${name}  `;
  const remaining = Math.max(20, width - nameTag.length - 2);

  // If secondary fits, show "primary  secondary"; else just primary
  let valueStr: string;
  if (secondary) {
    const secTrunc = trunc(secondary, Math.floor(remaining * 0.4));
    const priTrunc = trunc(primary, remaining - secTrunc.length - 2);
    valueStr = chalk.bold(priTrunc) + chalk.dim("  " + secTrunc);
  } else {
    valueStr = chalk.bold(trunc(primary, remaining));
  }

  const marker = chalk.cyan.dim(expanded ? " ▾" : " ▸");
  const line = chalk.magenta(PREFIX + chalk.magenta.bold(name) + "  ") + chalk.white(valueStr) + marker;
  const out = ["", ...wrapLine(line, width)];
  if (!expanded) return out;

  // Expanded: the complete, untruncated tool call — every argument in full.
  const IND = "    ";
  const CAP = 200; // per-argument line cap (a write_file body can be huge)
  const entries = Object.entries(input ?? {});
  if (entries.length === 0) out.push(IND + chalk.dim("(no arguments)"));
  for (const [k, v] of entries) {
    const raw = typeof v === "string" ? v : (JSON.stringify(v, null, 2) ?? String(v));
    const vLines = raw.replace(/\r/g, "").replace(/\t/g, "  ").split("\n");
    const key = chalk.cyan(k + ":");
    if (vLines.length === 1 && k.length + 2 + vLines[0].length <= width - IND.length) {
      out.push(IND + key + " " + chalk.white(vLines[0]));
      continue;
    }
    out.push(IND + key);
    for (const l of vLines.slice(0, CAP)) {
      for (const seg of wrapLine(l, Math.max(1, width - IND.length - 2))) out.push(IND + "  " + chalk.white(seg));
    }
    if (vLines.length > CAP) out.push(IND + "  " + chalk.dim(`… +${vLines.length - CAP} more lines`));
  }
  return out;
}

/**
 * Tool result — indented, gray, with the Claude-Code "⎿" prefix.
 * Long output gets the truncation hint already baked in by outputLog.ts
 * (previewOrLog). Here we just render what we received.
 */
function toolResultLines(
  output: string,
  isError: boolean,
  width: number,
  opts: { expandable: boolean; expanded: boolean; logPath?: string } = { expandable: false, expanded: false },
): string[] {
  const color = (t: string) => (isError ? chalk.red(t) : chalk.gray(t));
  const full = opts.expanded && opts.logPath ? readFullOutput(opts.logPath) : null;
  const body = (full ?? output).trim() || "(empty)";

  // Every rendered row must be exactly one terminal row (the scroll/selection
  // math depends on it), so long lines are hard-wrapped rather than left to
  // the terminal.
  const rows: string[] = [];
  body.split("\n").forEach((line, i) => {
    const clean = line.replace(/\r/g, "").replace(/\t/g, "    ");
    wrapLine(clean, Math.max(1, width - 4)).forEach((seg, j) => {
      const pfx = i === 0 && j === 0 ? (isError ? "✗ " : "⎿ ") : "  ";
      rows.push("  " + color(pfx + seg));
    });
  });

  if (opts.expandable) {
    rows.push("    " + chalk.cyan.dim(opts.expanded ? "▾ click to collapse" : "▸ click to expand full output"));
  }
  return rows;
}

/**
 * Whether clicking this event toggles anything: every tool call (full
 * arguments), and tool results whose output was truncated (full text is in a
 * log file). Results with a missing log file (e.g. a loaded session) aren't.
 */
export function isToggleable(event: TranscriptEvent): boolean {
  if (event.kind === "tool_call") return true;
  if (event.kind === "tool_result") return !!event.logPath && fs.existsSync(event.logPath);
  return false;
}

/** Renders one transcript event into the exact terminal rows it occupies. */
export function eventToLines(event: TranscriptEvent, width: number, expanded = false): string[] {
  switch (event.kind) {
    case "user": {
      const line = chalk.green.bold(`› ${event.text}`);
      return ["", ...wrapLine(line, width)];
    }

    case "assistant": {
      const rendered = renderMarkdown(event.text);
      return ["", ...rendered.split("\n")];
    }

    case "tool_call": {
      return toolCallLine(event.name, event.input as Record<string, any>, width, expanded);
    }

    case "tool_result": {
      return toolResultLines(event.output, event.isError, width, {
        expandable: isToggleable(event),
        expanded,
        logPath: event.logPath,
      });
    }

    case "todos": {
      return [];
    }

    case "plugin_active": {
      // Compact one-liner styled like Claude Code's context indicators:
      //   ◈ plugins  frontend-design · pentester
      const names = event.plugins.join(chalk.dim(" · "));
      const line = chalk.cyan("◈ ") + chalk.cyan.bold("plugins") + chalk.dim("  ") + chalk.cyan(names);
      return [wrapLine(line, width)[0]];
    }

    case "system": {
      return ["", ...wrapLine(chalk.yellow(event.text), width)];
    }

    case "banner": {
      // Rebuilt from scratch at the current width every time (never cached
      // as fixed strings) so the box-drawing border stays exactly `width`
      // columns wide after a terminal resize instead of wrapping/breaking.
      return buildBannerLines(event.config, width);
    }

    default:
      return [];
  }
}
