/**
 * deeptunnelLauncher.ts — start the native TypeScript deeptunnel proxy
 *
 * When acurist starts and DEEPSEEK_TOKEN is set, this launches the
 * embedded Node.js DeepSeek → Anthropic proxy (no Python required).
 *
 * Model selection via ACURIST_DS_MODEL env var or --ds-model CLI flag:
 *   fast   (default) — DeepSeek V3 / fast
 *   expert           — DeepSeek R1 / reasoning
 *
 * Web search is enabled by default; set ACURIST_DS_SEARCH=false to disable.
 * Thinking mode is off by default; set ACURIST_DS_THINK=true to enable.
 */

import { DeepTunnelServer, type DeepTunnelServerOpts } from "./deeptunnelServer.js";

export { DeepTunnelServerOpts };

let _server: DeepTunnelServer | null = null;

/** Parse deeptunnel-relevant flags from process.argv */
function parseDeeptunnelFlags(): DeepTunnelServerOpts {
  const args = process.argv.slice(2);
  const opts: DeepTunnelServerOpts = {};
  const mi = args.indexOf("--ds-model");
  if (mi !== -1 && args[mi + 1]) opts.model = args[mi + 1] as "fast" | "expert";
  if (args.includes("--ds-think")) opts.think = true;
  if (args.includes("--ds-no-search")) opts.search = false;
  return opts;
}

/** Check if the proxy is already reachable at the given base URL. */
async function isProxyAlive(baseUrl: string): Promise<boolean> {
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 1500);
    const res = await fetch(`${baseUrl}/health`, { signal: ctrl.signal });
    clearTimeout(timer);
    return res.ok;
  } catch {
    return false;
  }
}

/**
 * Extract port from a URL string safely. Returns defaultPort on any failure.
 */
function extractPort(rawUrl: string | undefined | null, defaultPort: number): number {
  if (!rawUrl) return defaultPort;
  try {
    const u = new URL(rawUrl);
    return parseInt(u.port || String(defaultPort), 10) || defaultPort;
  } catch {
    return defaultPort;
  }
}

/**
 * Normalize the proxy base URL — ensure it's a valid http(s) URL.
 * Falls back to http://localhost:PORT if the stored value is bad.
 */
function normalizeProxyUrl(raw: string | undefined | null, port: number): string {
  if (!raw) return `http://localhost:${port}`;
  try {
    const u = new URL(raw);
    if (u.protocol === "http:" || u.protocol === "https:") return raw;
    return `http://localhost:${port}`;
  } catch {
    return `http://localhost:${port}`;
  }
}

/**
 * Launch the embedded deeptunnel proxy if the proxy is not already reachable
 * and DEEPSEEK_TOKEN is set. Returns the server instance or null.
 */
export async function launchDeeptunnelIfNeeded(
  proxyBaseUrl: string,
  cliOpts: DeepTunnelServerOpts = {}
): Promise<DeepTunnelServer | null> {
  const token = process.env.DEEPSEEK_TOKEN;
  if (!token) {
    return null; // no token — user is using a real Anthropic API key
  }

  const flagOpts = parseDeeptunnelFlags();
  const merged: DeepTunnelServerOpts = { ...cliOpts, ...flagOpts };

  // Resolve options with env-var fallbacks
  const model  = (merged.model  ?? process.env.ACURIST_DS_MODEL ?? "fast") as "fast" | "expert";
  const search = merged.search ?? (process.env.ACURIST_DS_SEARCH !== "false");
  const think  = merged.think  ?? (process.env.ACURIST_DS_THINK === "true");

  // Extract port safely — proxyBaseUrl may be undefined or a non-URL string
  const defaultPort = 8765;
  const port = merged.port ?? extractPort(proxyBaseUrl, defaultPort);
  const safeUrl = normalizeProxyUrl(proxyBaseUrl, port);

  if (await isProxyAlive(safeUrl)) {
    return null; // already running — don't start a second instance
  }

  const server = new DeepTunnelServer(token, { port, model, search, think });

  try {
    await server.start();
    _server = server;
    return server;
  } catch (err: any) {
    process.stderr.write(`[deeptunnel] Failed to start: ${err?.message}\n`);
    return null;
  }
}

/** Stop the embedded proxy (called on acurist exit). */
export function stopDeeptunnel(): void {
  if (_server) {
    _server.stop();
    _server = null;
  }
}
