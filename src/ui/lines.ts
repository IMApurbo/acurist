import chalk from "chalk";
import wrapAnsi from "wrap-ansi";
import type { TranscriptEvent } from "../types.js";
import { renderMarkdown } from "./markdown.js";
import { buildBannerLines } from "./banner.js";

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
function toolCallLine(name: string, input: Record<string, any>, width: number): string[] {
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
      const todoStr = typeof input.todos === "string" ? input.todos : "";
      const count = todoStr.trim() ? todoStr.trim().split("\n").length : 0;
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

  // Available width for the value portion after "⏺ toolname  "
  const nameTag = `${PREFIX}${name}  `;
  const remaining = Math.max(20, width - nameTag.length);

  // If secondary fits, show "primary  secondary"; else just primary
  let valueStr: string;
  if (secondary) {
    const secTrunc = trunc(secondary, Math.floor(remaining * 0.4));
    const priTrunc = trunc(primary, remaining - secTrunc.length - 2);
    valueStr = chalk.bold(priTrunc) + chalk.dim("  " + secTrunc);
  } else {
    valueStr = chalk.bold(trunc(primary, remaining));
  }

  const line = chalk.magenta(PREFIX + chalk.magenta.bold(name) + "  ") + chalk.white(valueStr);
  return ["", ...wrapLine(line, width)];
}

/**
 * Tool result — indented, gray, with the Claude-Code "⎿" prefix.
 * Long output gets the truncation hint already baked in by outputLog.ts
 * (previewOrLog). Here we just render what we received.
 */
function toolResultLines(output: string, isError: boolean, width: number): string[] {
  const prefix = isError ? chalk.red("✗ ") : chalk.gray("⎿ ");
  const body = output.trim() || "(empty)";
  const lines = body.split("\n");

  return lines.map((line, i) => {
    const pfx = i === 0 ? prefix : "  ";
    const colored = isError ? chalk.red(pfx + line) : chalk.gray(pfx + line);
    return "  " + colored;
  });
}

/** Renders one transcript event into the exact terminal rows it occupies. */
export function eventToLines(event: TranscriptEvent, width: number): string[] {
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
      return toolCallLine(event.name, event.input as Record<string, any>, width);
    }

    case "tool_result": {
      return toolResultLines(event.output, event.isError, width);
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
