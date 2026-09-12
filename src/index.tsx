#!/usr/bin/env node
import React from "react";
import { render } from "ink";
import App from "./ui/App.js";
import { loadConfig } from "./core/config.js";
import { launchDeeptunnelIfNeeded, stopDeeptunnel } from "./core/deeptunnelLauncher.js";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const pkg = require("../package.json") as { version: string; author?: string };

// ── full-terminal takeover ──────────────────────────────────────────
// Same trick vim/htop use: switch to the terminal's alternate screen
// buffer so our output lives on its own canvas instead of scrolling into
// the user's normal history, and hide the (Ink-drawn) cursor. Both are
// restored on every exit path — normal completion, /exit, Ctrl+C, a
// signal, or a crash — so the user's shell is left exactly as it was.
//
// The alt screen buffer has no scrollback of its own, so unlike a plain
// terminal app we can't lean on the terminal's native mouse-wheel/
// Shift+PageUp scrolling to review older messages — App.tsx renders the
// whole transcript itself and implements its own PageUp/PageDown/Home/End
// scrolling over it (see the scrollback section there) so history is
// still fully browsable while the screen stays fixed.
//
// IMPORTANT: because of that, nothing should be console.log()'d here
// before render() runs — Ink owns the whole buffer once it starts, and
// anything printed before it (like the old welcome banner) can get pushed
// out of view the moment the app's own content fills the terminal, with
// no way to scroll back to it. The banner is rendered *inside* the Ink
// app instead (see ui/banner.ts), as the first entry in the same
// self-managed scrollback everything else uses.
const ENTER_ALT_SCREEN = "\x1b[?1049h";
const LEAVE_ALT_SCREEN = "\x1b[?1049l";
const HIDE_CURSOR = "\x1b[?25l";
const SHOW_CURSOR = "\x1b[?25h";

let restored = false;
function restoreTerminal() {
  if (restored) return;
  restored = true;
  process.stdout.write(SHOW_CURSOR + LEAVE_ALT_SCREEN);
}

async function main() {
  const config = { ...loadConfig(), version: pkg.version, author: pkg.author };

  // ── Auto-launch deeptunnel ──────────────────────────────────────────────
  // If DEEPSEEK_TOKEN is set and no proxy is already listening on the
  // configured URL, spawn deeptunnel in the background so the user gets
  // the full DeepSeek experience without a separate terminal.
  // Output is forwarded to stderr (invisible behind the Ink alt-screen).
  await launchDeeptunnelIfNeeded(config.proxyBaseUrl);

  process.stdout.write(ENTER_ALT_SCREEN + HIDE_CURSOR);
  process.on("exit", () => {
    stopDeeptunnel();
    restoreTerminal();
  });
  // SIGINT (Ctrl+C) is handled in App.tsx via useInput so we get the
  // two-press pattern (first press interrupts busy, second exits).
  process.on("SIGINT", () => {});
  process.on("SIGTERM", () => {
    stopDeeptunnel();
    restoreTerminal();
    process.exit(143);
  });
  process.on("uncaughtException", (err) => {
    stopDeeptunnel();
    restoreTerminal();
    console.error(err);
    process.exit(1);
  });

  const instance = render(<App config={config} />);
  await instance.waitUntilExit();
  stopDeeptunnel();
  restoreTerminal();
}

main().catch((err) => {
  restoreTerminal();
  console.error(err);
  process.exit(1);
});
