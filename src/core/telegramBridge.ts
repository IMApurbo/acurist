/**
 * telegramBridge.ts — Telegram bot bridge for Acurist
 *
 * Slash commands:
 *   /telegram config <token> <userid>  — save token + userid (persisted)
 *   /telegram start                    — start polling (uses saved config)
 *   /telegram stop                     — stop polling
 *   /telegram status                   — show current state
 *
 * Telegram commands (sent from Telegram chat):
 *   /telegram stop  — immediately stop the bridge
 *   /esc or /interrupt — interrupt the current agent turn
 *   /help — show available commands
 *   Any slash command the terminal supports
 *
 * Features:
 *   - Sends "Acurist is online" when bridge starts
 *   - Sends "Acurist going offline" when bridge stops/closed
 *   - Messages sent BEFORE the bridge started are ignored (offset skipping)
 *   - Tool output (truncated) is forwarded to Telegram
 *   - /telegram stop from Telegram triggers immediate stop
 *   - ESC / /interrupt from Telegram interrupts current agent turn
 */

import fetch from "node-fetch";
import { randomUUID } from "node:crypto";
import type { MutableRefObject } from "react";
import type { TranscriptEvent } from "../types.js";
import type { Agent } from "./agent.js";
import { getTelegramConfig, setTelegramConfig } from "./config.js";

// ── helpers ───────────────────────────────────────────────────────────────────

const ANSI_RE = /\x1b\[[0-9;]*[A-Za-z]/g;
export function stripAnsi(s: string): string {
  return s.replace(ANSI_RE, "");
}

async function tgPost(token: string, method: string, body: Record<string, any>): Promise<any> {
  const res = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15_000),
  });
  return res.json();
}

async function tgGet(
  token: string,
  method: string,
  params: Record<string, any> = {},
  signal?: AbortSignal
): Promise<any> {
  const url = new URL(`https://api.telegram.org/bot${token}/${method}`);
  for (const [k, v] of Object.entries(params)) {
    url.searchParams.set(k, String(v));
  }
  const timeout = AbortSignal.timeout(30_000);
  const combined = signal ? AbortSignal.any([signal, timeout]) : timeout;
  const res = await fetch(url.toString(), { signal: combined as any });
  return res.json();
}

async function sendMessage(token: string, chatId: string, text: string): Promise<void> {
  if (!text.trim()) return;
  for (let i = 0; i < text.length; i += 4000) {
    await tgPost(token, "sendMessage", {
      chat_id: chatId,
      text: text.slice(i, i + 4000),
    }).catch(() => {});
  }
}

/**
 * Get the latest update_id from Telegram WITHOUT processing any messages.
 * Used to skip messages sent before the bridge started.
 */
async function getLatestUpdateId(token: string): Promise<number> {
  try {
    // Request with timeout=0 to get only buffered updates, don't wait for new ones
    const data: any = await tgGet(token, "getUpdates", { timeout: 0, limit: 100 });
    if (!data.ok || !data.result?.length) return 0;
    // Get the highest update_id and return it + 1 so all old messages are skipped
    const maxId = Math.max(...data.result.map((u: any) => u.update_id));
    // Acknowledge by setting offset = maxId + 1
    await tgGet(token, "getUpdates", { offset: maxId + 1, timeout: 0 });
    return maxId + 1;
  } catch {
    return 0;
  }
}

// ── bridge state (module-level singleton) ─────────────────────────────────────

let bridgeStop: (() => void) | null = null;
// Exposed so App.tsx can call abort from ESC key
let currentAgentAbort: AbortController | null = null;

export function isBridgeRunning(): boolean {
  return bridgeStop !== null;
}

export function getTgAgentAbort(): AbortController | null {
  return currentAgentAbort;
}

function doStop(token?: string, userId?: string) {
  const stopFn = bridgeStop;
  if (stopFn) {
    stopFn();
    bridgeStop = null;
    // Send offline notification if we have credentials
    if (token && userId) {
      sendMessage(token, userId, "🔴 Acurist going offline.").catch(() => {});
    }
  }
}

function doStart(
  token: string,
  userId: string,
  agentRef: MutableRefObject<Agent | null>,
  emit: (e: TranscriptEvent) => void,
  onStop?: () => void
) {
  if (bridgeStop) doStop(token, userId);

  let stopped = false;
  let offset = 0;
  let currentPollAbort: AbortController | null = null as AbortController | null;

  // Wrap emit so agent replies also go to Telegram
  const wrappedEmit = (event: TranscriptEvent): void => {
    emit(event);
    if (event.kind === "assistant") {
      sendMessage(token, userId, stripAnsi(event.text));
    } else if (event.kind === "system") {
      sendMessage(token, userId, `ℹ️ ${stripAnsi(event.text)}`);
    } else if (event.kind === "tool_call") {
      const val =
        event.input.command ??
        event.input.path ??
        event.input.url ??
        event.input.message ??
        "";
      sendMessage(token, userId, `⏺ ${event.name}${val ? "  " + String(val).slice(0, 80) : ""}`);
    } else if (event.kind === "tool_result") {
      // Send truncated tool output to Telegram (first 600 chars)
      const output = stripAnsi(event.output ?? "");
      if (output.trim()) {
        const preview = output.length > 600
          ? output.slice(0, 600) + `\n… (truncated, ${output.length} chars total)`
          : output;
        const icon = event.isError ? "❌" : "✅";
        sendMessage(token, userId, `${icon} ${event.name}:\n${preview}`);
      }
    }
  };

  if (agentRef.current) {
    (agentRef.current as any).deps.emit = wrappedEmit;
  }

  (async () => {
    // Skip all messages that were sent before we started (drain old queue)
    emit({ kind: "system", id: randomUUID(), text: "Telegram: Skipping queued messages from before start…" });
    offset = await getLatestUpdateId(token);
    emit({ kind: "system", id: randomUUID(), text: `Telegram: Ready. Offset set to ${offset} (ignoring older messages).` });

    // Send online notification
    await sendMessage(token, userId, "🟢 Acurist is online. Send me a message to get started!\n\n/help — available commands");

    while (!stopped) {
      try {
        const pollAbort = new AbortController();
        currentPollAbort = pollAbort;
        const data: any = await tgGet(token, "getUpdates", {
          offset,
          timeout: 25,
          allowed_updates: "message",
        }, pollAbort.signal);
        currentPollAbort = null;

        if (!data.ok) {
          await new Promise((r) => setTimeout(r, 5_000));
          continue;
        }

        for (const update of data.result ?? []) {
          offset = update.update_id + 1;
          const msg = update.message;
          if (!msg?.text) continue;

          const fromId = String(msg.from?.id ?? "");
          if (fromId !== userId) {
            await sendMessage(token, fromId, "⛔ Unauthorised.");
            continue;
          }

          const text: string = msg.text.trim();
          if (!text) continue;

          // Handle Telegram-side /telegram stop immediately
          if (text === "/telegram stop" || text === "/stop") {
            await sendMessage(token, userId, "🔴 Stopping Acurist bridge…");
            emit({ kind: "system", id: randomUUID(), text: "Telegram: /stop received — stopping bridge." });
            // Stop the bridge (will send offline message)
            stopped = true;
            (currentPollAbort as AbortController | null)?.abort();
            onStop?.();
            return;
          }

          // Handle ESC / interrupt from Telegram
          if (text === "/esc" || text === "/interrupt") {
            const agAbort = currentAgentAbort;
            if (agAbort) {
              agAbort.abort();
              await sendMessage(token, userId, "⏹ Agent interrupted.");
            } else {
              await sendMessage(token, userId, "ℹ️ No active agent turn to interrupt.");
            }
            continue;
          }

          // Handle /help from Telegram
          if (text === "/help") {
            await sendMessage(token, userId,
              "🤖 Acurist Telegram Commands:\n\n" +
              "/help — show this message\n" +
              "/esc or /interrupt — interrupt current agent turn\n" +
              "/telegram stop — stop the bridge\n" +
              "/clear — clear conversation\n" +
              "/undo — undo last exchange\n\n" +
              "Any other message is sent to the agent."
            );
            continue;
          }

          emit({ kind: "system", id: randomUUID(), text: `Telegram → ${text}` });

          const controller = new AbortController();
          currentAgentAbort = controller;
          try {
            await agentRef.current?.send(text, controller.signal);
          } catch (e: any) {
            if (e?.name !== "AbortError") {
              await sendMessage(token, userId, `❌ Error: ${e?.message ?? e}`);
            }
          } finally {
            currentAgentAbort = null;
          }
        }
      } catch {
        if (stopped) break;
        await new Promise((r) => setTimeout(r, 5_000));
      }
    }

    // Send offline notification when loop exits naturally
    if (!stopped) {
      await sendMessage(token, userId, "🔴 Acurist going offline.");
    }
  })();

  bridgeStop = () => {
    stopped = true;
    const cpA: AbortController | null = currentPollAbort;
    if (cpA !== null) cpA.abort();
    const caA: AbortController | null = currentAgentAbort;
    if (caA !== null) caA.abort();
  };
}

// ── public handler (called from App.tsx runSlash) ─────────────────────────────

export interface TelegramHandlerDeps {
  agentRef: MutableRefObject<Agent | null>;
  emit: (e: TranscriptEvent) => void;
  /** Called when Telegram requests a stop from the chat side */
  onTelegramStop?: () => void;
}

export function handleTelegramCommand(
  args: string[],
  deps: TelegramHandlerDeps
): string {
  const { agentRef, emit, onTelegramStop } = deps;
  const sub = args[0]?.toLowerCase() ?? "";

  switch (sub) {
    case "config": {
      const [, token, userId] = args;
      if (!token || !userId) {
        return "Usage: /telegram config <bot-token> <user-id>\nGet token from @BotFather, user ID from @userinfobot.";
      }
      setTelegramConfig({ token, userId, autoStart: false });
      return `Telegram config saved.\nToken: ${token.slice(0, 10)}…  User ID: ${userId}\nRun /telegram start to connect.`;
    }

    case "start": {
      const cfg = getTelegramConfig();
      if (!cfg) {
        return "No Telegram config found. Run /telegram config <token> <user-id> first.";
      }
      if (isBridgeRunning()) {
        return "Telegram bridge is already running. Run /telegram stop first.";
      }
      doStart(cfg.token, cfg.userId, agentRef, emit, () => {
        // Called when Telegram chat sends /stop
        const savedCfg = getTelegramConfig();
        if (savedCfg) setTelegramConfig({ ...savedCfg, autoStart: false });
        bridgeStop = null;
        onTelegramStop?.();
      });
      setTelegramConfig({ ...cfg, autoStart: true });
      return `Telegram bridge started. Polling for messages from user ${cfg.userId}…\n📨 Only messages sent AFTER this point will be processed.`;
    }

    case "stop": {
      if (!isBridgeRunning()) {
        return "Telegram bridge is not running.";
      }
      const cfg = getTelegramConfig();
      doStop(cfg?.token, cfg?.userId);
      if (cfg) setTelegramConfig({ ...cfg, autoStart: false });
      return "Telegram bridge stopped.";
    }

    case "status": {
      const cfg = getTelegramConfig();
      if (!cfg) return "No Telegram config saved.";
      return (
        `Token:     ${cfg.token.slice(0, 10)}…\n` +
        `User ID:   ${cfg.userId}\n` +
        `Bridge:    ${isBridgeRunning() ? "🟢 running" : "🔴 stopped"}\n` +
        `Auto-start: ${cfg.autoStart ? "yes" : "no"}`
      );
    }

    default:
      return (
        "Usage:\n" +
        "  /telegram config <token> <user-id>  — save credentials\n" +
        "  /telegram start                     — start bridge\n" +
        "  /telegram stop                      — stop bridge\n" +
        "  /telegram status                    — show current state"
      );
  }
}

/** Call on startup to auto-start the bridge if it was running before. */
export function maybeAutoStartTelegram(deps: TelegramHandlerDeps): void {
  const cfg = getTelegramConfig();
  if (cfg?.autoStart) {
    doStart(cfg.token, cfg.userId, deps.agentRef, deps.emit, deps.onTelegramStop);
  }
}
