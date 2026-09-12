import chalk from "chalk";
import os from "os";
import type { AgentConfig } from "../types.js";

const ANSI_RE = /\x1B\[[0-9;]*m/g;

const visLen = (s: string) => s.replace(ANSI_RE, "").length;

// Pad a pre-styled string to a target VISUAL width
function vpad(styled: string, width: number): string {
  const diff = width - visLen(styled);
  return diff > 0 ? styled + " ".repeat(diff) : styled;
}

// Cyan → magenta gradient across a plain string
const RAMP = ["#00e5ff","#4db8ff","#8797ff","#b47dff","#cc00e5"];
function grad(s: string): string {
  return [...s].map((ch, i) => {
    if (ch === " ") return " ";
    const hex = RAMP[Math.round((i / Math.max(s.length - 1, 1)) * (RAMP.length - 1))]!;
    return chalk.hex(hex)(ch);
  }).join("");
}

export function buildBannerLines(config: AgentConfig, columns: number): string[] {
  // ── Exact inner width = columns - 2 (left │ and right │) ──────────────────
  const inner = columns - 2;          // chars between the two outer │
  const L = Math.floor(inner / 2);    // left section width  (includes the ─ of divider)
  const R = inner - L - 1;            // right section width (─1 for the │ divider itself)

  // Left & right usable TEXT width (─1 for the leading space inside each cell)
  const LT = L - 1;
  const RT = R - 1;

  // ── Box-drawing pieces (all exactly the right char counts) ────────────────
  const b = (s: string) => chalk.hex("#5ab1ff")(s);
  const TOP = b("╭" + "─".repeat(L) + "┬" + "─".repeat(R) + "╮");
  const BOT = b("╰" + "─".repeat(inner) + "╯");
  const SEP = b("│");

  function row(leftStyled: string, rightStyled: string): string {
    return SEP + " " + vpad(leftStyled, LT - 1) + " " + SEP + " " + vpad(rightStyled, RT - 1) + " " + SEP;
  }

  // ── Colours ───────────────────────────────────────────────────────────────
  const cy  = (s: string) => chalk.hex("#00e5ff")(s);
  const vi  = (s: string) => chalk.hex("#8797ff")(s);
  const mg  = (s: string) => chalk.hex("#cc00e5")(s);
  const dim = (s: string) => chalk.dim(s);
  const lbl = (s: string) => chalk.hex("#8797ff").bold(s);
  const val = (s: string) => chalk.hex("#00e5ff")(s);

  // ── System info ───────────────────────────────────────────────────────────
  const platform = os.type().replace("Windows_NT","Windows").replace("Darwin","macOS");
  const totalMem = Math.round(os.totalmem() / 1073741824);
  const usedMem  = Math.round((os.totalmem() - os.freemem()) / 1073741824);
  const clock    = new Date().toLocaleTimeString([], { hour:"2-digit", minute:"2-digit" });
  const cores    = os.cpus().length;

  function si(label: string, value: string) { return lbl(label) + val(value); }

  // ── Left & right cell content (must be same length array) ─────────────────
  const ver    = config.version ? " " + dim(`v${config.version}`) : "";
  const author = config.author  ? dim(`by ${config.author}`) : "";
  const mode   = config.mode === "auto"
    ? chalk.green("* auto") + dim(" · no confirm")
    : chalk.yellow("+ manual") + dim(" · confirm each");

  // Mini 2-line logo (26 chars wide — safe on any terminal > 60)
  const L0 = grad("▄▀█ █▀▀ █ █ █▀█ █ █▀ ▀█▀");
  const L1 = grad("█▀█ █▄▄ █▄█ █▀▄ █ ▄█  █ ");

  const leftCells  = [ L0, L1, chalk.bold.hex("#00e5ff")("✻ Acurist") + ver, author, mode ];
  const rightCells = [
    si("os    ", platform),
    si("cpu   ", `${cores} cores · ${totalMem} GB`),
    si("mem   ", `${usedMem} / ${totalMem} GB`),
    si("time  ", clock),
    si("model ", config.model.slice(0, RT - 8)),
  ];

  const rowCount = Math.max(leftCells.length, rightCells.length);
  const bodyRows = Array.from({ length: rowCount }, (_, i) =>
    row(leftCells[i] ?? "", rightCells[i] ?? "")
  );

  // ── Single-line footer (cwd) ───────────────────────────────────────────────
  const cwdLabel  = dim("cwd ") + dim(config.cwd.slice(0, inner - 6));
  const footer    = SEP + " " + vpad(cwdLabel, inner - 2) + " " + SEP;

  return ["", TOP, ...bodyRows, footer, BOT, ""];
}
