import chalk from "chalk";
import type { AgentConfig } from "../types.js";

// Cyan → magenta gradient across a plain string
const RAMP = ["#00e5ff", "#4db8ff", "#8797ff", "#b47dff", "#cc00e5"];
function grad(s: string, bold = false): string {
  return [...s].map((ch, i) => {
    if (ch === " ") return " ";
    const hex = RAMP[Math.round((i / Math.max(s.length - 1, 1)) * (RAMP.length - 1))]!;
    return bold ? chalk.hex(hex).bold(ch) : chalk.hex(hex)(ch);
  }).join("");
}

/**
 * Compact, borderless, left-aligned banner: logo, name/version, and a
 * gradient author credit. No box-drawing, no system-info panel, no
 * mode/cwd — those are already shown live in the bottom status bar.
 */
export function buildBannerLines(config: AgentConfig, _columns: number): string[] {
  const pad = " ";

  // Mini 2-line logo
  const L0 = grad("▄▀█ █▀▀ █ █ █▀█ █ █▀ ▀█▀");
  const L1 = grad("█▀█ █▄▄ █▄█ █▀▄ █ ▄█  █ ");

  const ver = config.version ? chalk.dim(` v${config.version}`) : "";
  const title = chalk.bold.hex("#00e5ff")("✻ Acurist") + ver;

  const lines: string[] = ["", pad + L0, pad + L1, "", pad + title];
  if (config.author) {
    // Name keeps its exact case and spacing, painted with the same gradient.
    const credit =
      chalk.hex("#5ab1ff").dim("‹ ") +
      chalk.hex("#8797ff").dim("engineered by ") +
      grad(config.author, true) +
      chalk.hex("#5ab1ff").dim(" ›");
    lines.push(pad + credit);
  }
  lines.push("");
  return lines;
}
