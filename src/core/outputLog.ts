import fs from "node:fs";
import path from "node:path";
import os from "node:os";

const LOG_DIR = path.join(os.tmpdir(), "acurist", String(process.pid));
fs.mkdirSync(LOG_DIR, { recursive: true });

let counter = 0;

const PREVIEW_LINES = 16;
const PREVIEW_CHARS = 1200;

/**
 * Claude-Code-style output handling: short output is shown in full;
 * long output is truncated in the transcript and written to a file the
 * user (or the model, via read_file) can open for the complete text.
 */
export interface PreviewResult {
  /** What the transcript shows (full text if short, else a 16-line preview). */
  text: string;
  /** Set only when the output was truncated: file holding the complete text. */
  logPath?: string;
}

export function previewOrLogEx(output: string, label: string): PreviewResult {
  const lines = output.split("\n");
  if (output.length <= PREVIEW_CHARS && lines.length <= PREVIEW_LINES) {
    return { text: output };
  }

  counter += 1;
  const file = path.join(LOG_DIR, `${counter}-${label.replace(/[^a-z0-9_-]/gi, "_")}.log`);
  fs.writeFileSync(file, output, "utf-8");

  const preview = lines.slice(0, PREVIEW_LINES).join("\n");
  const omitted = lines.length - PREVIEW_LINES;
  return {
    text:
      `${preview}\n` +
      `… +${omitted > 0 ? omitted : 0} more lines (${output.length} chars total)\n` +
      `Full output: ${file}`,
    logPath: file,
  };
}

export function previewOrLog(output: string, label: string): string {
  return previewOrLogEx(output, label).text;
}

const EXPAND_MAX_LINES = 3000;
const EXPAND_MAX_CHARS = 300_000;
const EXPAND_MAX_BYTES = 1_200_000;

/**
 * Reads the complete output back from its log file for click-to-expand.
 * Capped so a 10 MB dump can't freeze the terminal UI; the cap is announced
 * in the text along with the file path. Returns null if the file is gone.
 */
export function readFullOutput(file: string): string | null {
  let fd: number | undefined;
  try {
    const size = fs.statSync(file).size;
    const buf = Buffer.alloc(Math.min(size, EXPAND_MAX_BYTES));
    fd = fs.openSync(file, "r");
    fs.readSync(fd, buf, 0, buf.length, 0);
    let text = buf.toString("utf-8");
    let clipped = size > EXPAND_MAX_BYTES;
    const ls = text.split("\n");
    if (ls.length > EXPAND_MAX_LINES) { text = ls.slice(0, EXPAND_MAX_LINES).join("\n"); clipped = true; }
    if (text.length > EXPAND_MAX_CHARS) { text = text.slice(0, EXPAND_MAX_CHARS); clipped = true; }
    return clipped ? `${text}\n… output continues — open ${file} for the rest` : text;
  } catch {
    return null;
  } finally {
    if (fd !== undefined) { try { fs.closeSync(fd); } catch {} }
  }
}
