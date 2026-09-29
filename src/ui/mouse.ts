import { PassThrough } from "node:stream";
import { EventEmitter } from "node:events";
import { spawn } from "node:child_process";

// ── Terminal mouse reporting (SGR 1006) ─────────────────────────────────────
// Enabling mouse reporting lets the app receive wheel + click/drag events, so
// the wheel can scroll the transcript and ↑/↓ stay free for input history.
// The trade-off is that the terminal's own text selection is replaced by the
// in-app selection implemented in App.tsx (drag = select + auto-copy).
export const ENABLE_MOUSE  = "\x1b[?1000h\x1b[?1002h\x1b[?1006h";
export const DISABLE_MOUSE = "\x1b[?1006l\x1b[?1002l\x1b[?1000l";

export type MouseKind = "down" | "up" | "drag" | "wheelUp" | "wheelDown";
export interface MouseEv {
  kind: MouseKind;
  x: number; // 1-based screen column
  y: number; // 1-based screen row
  shift: boolean;
  alt: boolean;
  ctrl: boolean;
}

export const mouseEvents = new EventEmitter();

const SGR_MOUSE = /\x1b\[<(\d+);(\d+);(\d+)([Mm])/g;
const PARTIAL_SGR_MOUSE = /\x1b\[<[\d;]*$/;

/** Decodes one SGR mouse report. Returns null for events we ignore. */
export function decodeSgrMouse(b: number, x: number, y: number, final: string): MouseEv | null {
  const shift = (b & 4) !== 0;
  const alt   = (b & 8) !== 0;
  const ctrl  = (b & 16) !== 0;
  const motion = (b & 32) !== 0;
  const wheel  = (b & 64) !== 0;
  const low = b & 3;
  const base = { x, y, shift, alt, ctrl };
  if (wheel) {
    if (low === 0) return { kind: "wheelUp", ...base };
    if (low === 1) return { kind: "wheelDown", ...base };
    return null; // horizontal wheel
  }
  if (low !== 0) return null; // only the left button matters
  if (motion) return final === "M" ? { kind: "drag", ...base } : null;
  return { kind: final === "M" ? "down" : "up", ...base };
}

/** Strips SGR mouse reports out of a chunk; returns the remaining input. */
export function extractMouse(chunk: string, carry: string): { rest: string; carry: string; events: MouseEv[] } {
  let s = carry + chunk;
  let newCarry = "";
  const m = s.match(PARTIAL_SGR_MOUSE);
  if (m) {
    newCarry = m[0];
    s = s.slice(0, s.length - m[0].length);
  }
  const events: MouseEv[] = [];
  const rest = s.replace(SGR_MOUSE, (_all, b, x, y, f) => {
    const ev = decodeSgrMouse(Number(b), Number(x), Number(y), f);
    if (ev) events.push(ev);
    return "";
  });
  return { rest, carry: newCarry, events };
}

/**
 * A stdin stand-in for Ink. Mouse reports are pulled out (and emitted on
 * `mouseEvents`) BEFORE Ink sees the data, so they never get typed into the
 * input box. Everything else is forwarded untouched.
 */
export function createFilteredStdin(): NodeJS.ReadStream {
  const src = process.stdin;
  const out = new PassThrough() as any;
  out.isTTY = src.isTTY;
  out.setRawMode = (mode: boolean) => { src.setRawMode?.(mode); return out; };
  out.ref = () => { src.ref(); return out; };
  out.unref = () => { src.unref(); return out; };

  let carry = "";
  src.setEncoding("utf8");
  src.on("data", (chunk: string | Buffer) => {
    const r = extractMouse(typeof chunk === "string" ? chunk : chunk.toString("utf8"), carry);
    carry = r.carry;
    for (const ev of r.events) mouseEvents.emit("mouse", ev);
    if (r.rest) out.write(r.rest);
  });
  return out as NodeJS.ReadStream;
}

// ── Text helpers (ANSI-aware, terminal-cell aware) ──────────────────────────
const ANSI_TOKEN = /\x1b\[[0-9;?]*[ -\/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g;
const SGR_ONLY   = /^\x1b\[[0-9;]*m$/;

export function stripAnsi(s: string): string {
  return s.replace(ANSI_TOKEN, "");
}

/** Terminal cell width of one code point (0 = combining, 2 = wide/emoji). */
export function cellWidth(cp: number): number {
  if (cp === 0 || (cp >= 0x300 && cp <= 0x36f) || (cp >= 0x200b && cp <= 0x200f) || cp === 0xfe0f) return 0;
  if (
    (cp >= 0x1100 && cp <= 0x115f) || (cp >= 0x2e80 && cp <= 0xa4cf) ||
    (cp >= 0xac00 && cp <= 0xd7a3) || (cp >= 0xf900 && cp <= 0xfaff) ||
    (cp >= 0xfe30 && cp <= 0xfe6f) || (cp >= 0xff00 && cp <= 0xff60) ||
    (cp >= 0xffe0 && cp <= 0xffe6) || (cp >= 0x1f300 && cp <= 0x1faff) ||
    (cp >= 0x20000 && cp <= 0x3fffd)
  ) return 2;
  return 1;
}

/** Maps screen column range [c0, c1] (inclusive) of plain text to a substring. */
export function sliceCols(plain: string, c0: number, c1: number): string {
  let col = 0;
  let out = "";
  for (const ch of plain) {
    const w = cellWidth(ch.codePointAt(0)!);
    const start = col;
    const end = col + Math.max(w, 1) - 1;
    col += w;
    if (end < c0) continue;
    if (start > c1) break;
    out += ch;
  }
  return out;
}

/** Total cell width of a plain string. */
export function plainWidth(plain: string): number {
  let w = 0;
  for (const ch of plain) w += cellWidth(ch.codePointAt(0)!);
  return w;
}

/**
 * Re-renders an ANSI line with screen columns [c0, c1] (inclusive) inverted.
 * Inverse is re-asserted after every SGR inside the range so resets in the
 * original styling can't cancel the highlight.
 */
export function highlightLine(line: string, c0: number, c1: number): string {
  let out = "";
  let col = 0;
  let on = false;
  let last = 0;
  const flushText = (text: string) => {
    for (const ch of text) {
      const w = cellWidth(ch.codePointAt(0)!);
      const inSel = col + Math.max(w, 1) - 1 >= c0 && col <= c1;
      if (inSel && !on) { out += "\x1b[7m"; on = true; }
      if (!inSel && on) { out += "\x1b[27m"; on = false; }
      out += ch;
      col += w;
    }
  };
  for (const m of line.matchAll(ANSI_TOKEN)) {
    flushText(line.slice(last, m.index));
    out += m[0];
    if (on && SGR_ONLY.test(m[0])) out += "\x1b[7m";
    last = m.index! + m[0].length;
  }
  flushText(line.slice(last));
  if (on) out += "\x1b[27m";
  return out;
}

/** Column range of the whitespace-delimited word under column `col`. */
export function wordRangeAt(plain: string, col: number): [number, number] | null {
  const cells: { ch: string; c0: number; c1: number }[] = [];
  let c = 0;
  for (const ch of plain) {
    const w = cellWidth(ch.codePointAt(0)!);
    cells.push({ ch, c0: c, c1: c + Math.max(w, 1) - 1 });
    c += w;
  }
  const i = cells.findIndex((k) => col >= k.c0 && col <= k.c1);
  if (i === -1 || /\s/.test(cells[i].ch)) return null;
  let a = i, b = i;
  while (a > 0 && !/\s/.test(cells[a - 1].ch)) a--;
  while (b < cells.length - 1 && !/\s/.test(cells[b + 1].ch)) b++;
  return [cells[a].c0, cells[b].c1];
}

// ── Clipboard ───────────────────────────────────────────────────────────────
/** Copies text using OSC 52 (works over SSH / most modern terminals) plus a native tool as fallback. */
export function copyToSystemClipboard(text: string): void {
  try {
    process.stdout.write(`\x1b]52;c;${Buffer.from(text, "utf8").toString("base64")}\x07`);
  } catch {}
  const candidates: [string, string[]][] =
    process.platform === "darwin" ? [["pbcopy", []]]
    : process.platform === "win32" ? [["clip", []]]
    : [["wl-copy", []], ["xclip", ["-selection", "clipboard"]], ["xsel", ["--clipboard", "--input"]]];
  const tryNext = (i: number) => {
    if (i >= candidates.length) return;
    const [cmd, args] = candidates[i];
    try {
      const child = spawn(cmd, args, { stdio: ["pipe", "ignore", "ignore"] });
      child.on("error", () => tryNext(i + 1));
      child.stdin.on("error", () => {});
      child.stdin.write(text);
      child.stdin.end();
    } catch {
      tryNext(i + 1);
    }
  };
  tryNext(0);
}
