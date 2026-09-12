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
export function previewOrLog(output: string, label: string): string {
  const lines = output.split("\n");
  if (output.length <= PREVIEW_CHARS && lines.length <= PREVIEW_LINES) {
    return output;
  }

  counter += 1;
  const file = path.join(LOG_DIR, `${counter}-${label.replace(/[^a-z0-9_-]/gi, "_")}.log`);
  fs.writeFileSync(file, output, "utf-8");

  const preview = lines.slice(0, PREVIEW_LINES).join("\n");
  const omitted = lines.length - PREVIEW_LINES;
  return (
    `${preview}\n` +
    `… +${omitted > 0 ? omitted : 0} more lines (${output.length} chars total)\n` +
    `Full output: ${file}`
  );
}
