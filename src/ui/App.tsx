import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { randomUUID } from "node:crypto";
import path from "node:path";
import fs from "node:fs/promises";
import { Box, Text, useApp, useInput, usePaste, useStdout } from "ink";
import Spinner from "ink-spinner";
import InputBox from "./InputBox.js";
import { Agent, getAgentPersona, type AgentPersona } from "../core/agent.js";
import { ProxyClient } from "../core/proxyClient.js";
import type { AgentConfig, PermissionMode, TokenUsage, TranscriptEvent, Todo } from "../types.js";
import {
  setConfigValue,
  getToolPermissions,
  setToolPermission,
  getTemplates,
  addTemplate,
  removeTemplate,
  getTemplate,
  getPersistentHistory,
  appendPersistentHistory,
  addMcpServer,
  removeMcpServer,
  getMcpServers,
  getLastAgentId,
  setLastAgentId,
  isValidHttpUrl,
  BUILTIN_MODEL_MAP,
} from "../core/config.js";
import { SLASH_COMMANDS } from "../core/slashCommands.js";
import { eventToLines } from "./lines.js";
import {
  mouseEvents, highlightLine, stripAnsi, sliceCols, plainWidth, wordRangeAt, copyToSystemClipboard,
  type MouseEv,
} from "./mouse.js";
import { handleTelegramCommand, maybeAutoStartTelegram, isBridgeRunning } from "../core/telegramBridge.js";
import { handlePluginCommand } from "../core/pluginMarket.js";
import { saveSession, loadSession, listSessions } from "../core/session.js";
import { clearMcpCache } from "../core/mcpManager.js";
import { handleAgentCommand } from "../core/agentManager.js";
import wrapAnsi from "wrap-ansi";

/** How many terminal rows `text` will take up when wrapped to `width` */
function wrapAnsiLineCount(text: string, width: number): number {
  return wrapAnsi(text, Math.max(1, width), { trim: false, hard: true }).split("\n").length;
}

const MIN_WIDTH = 60;

type Mode =
  | { kind: "idle" }
  | { kind: "busy"; label: string }
  | { kind: "confirm"; command: string; resolve: (ok: boolean) => void }
  | {
      kind: "ask";
      question: string;
      options?: string[];
      resolve: (answer: string) => void;
      draft: string;
    };

export default function App({ config }: { config: AgentConfig }) {
  const { exit } = useApp();
  const { stdout } = useStdout();
  const [size, setSize] = useState(() => ({
    columns: stdout?.columns ?? 80,
    rows: stdout?.rows ?? 24,
  }));
  useEffect(() => {
    if (!stdout) return;
    const onResize = () => {
      setSize({ columns: stdout.columns ?? 80, rows: stdout.rows ?? 24 });
    };
    stdout.on("resize", onResize);
    return () => {
      stdout.off("resize", onResize);
    };
  }, [stdout]);
  const columns = size.columns;
  const rows = size.rows;
  const [events, setEvents] = useState<TranscriptEvent[]>(() => [
    { kind: "banner", config, id: randomUUID() },
  ]);
  const [history, setHistory] = useState<string[]>([]);
  const [mode, setMode] = useState<Mode>({ kind: "idle" });
  const [inputHeight, setInputHeight] = useState(3);
  const [scrollOffset, setScrollOffset] = useState(0);
  const lineCacheRef = useRef(new Map<string, { width: number; lines: string[] }>());
  const [permMode, setPermMode] = useState<PermissionMode>(config.mode);
  const [toolPerms, setToolPerms] = useState(() => getToolPermissions());
  const [tokenUsage, setTokenUsage] = useState<TokenUsage>({ inputTokens: 0, outputTokens: 0, totalTokens: 0 });
  const [activeToolName, setActiveToolName] = useState<string | null>(null);
  const [todos, setTodos] = useState<Todo[]>([]);

  // ── Active agent persona ────────────────────────────────────────────
  // Always one of the built-in AGENT_PERSONAS (see agent.ts). Startup
  // priority: --agent <n> CLI flag > last agent used (remembered across
  // restarts) > "hacker" default.
  const [activeAgent, setActiveAgent] = useState<AgentPersona>(() =>
    getAgentPersona(config.startupAgent ?? getLastAgentId() ?? undefined)
  );
  const activeAgentRef = useRef<AgentPersona>(activeAgent);
  activeAgentRef.current = activeAgent;

  // ── Message queue for busy state ──────────────────────────────────
  // Messages typed while the agent is busy go here and run one by one.
  const messageQueueRef = useRef<string[]>([]);
  const [queueLength, setQueueLength] = useState(0);

  // ── Live config state — mutable without restart ────────────────────
  // config is a frozen plain object passed in at startup; writing to the
  // Conf store via setConfigValue() does NOT update it. We keep separate
  // reactive copies so that /model and /proxy take effect immediately.
  const DEFAULT_PROXY = "http://localhost:8765";
  const [liveModel, setLiveModel] = useState(config.model);
  const [liveProxy, setLiveProxy] = useState(config.proxyBaseUrl);

  const proxy = useMemo(() => new ProxyClient(liveProxy, liveModel), [liveProxy, liveModel]);
  const agentRef = useRef<Agent | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const permModeRef = useRef(permMode);
  permModeRef.current = permMode;
  const confirmQueueRef = useRef<{ command: string; resolve: (ok: boolean) => void }[]>([]);
  // Track whether the agent loop is processing a queued message
  const processingQueueRef = useRef(false);

  const emit = useCallback((event: TranscriptEvent) => {
    if (event.kind === "todos") {
      // Sticky panel: replace the previous list, don't append to scrollback
      setTodos(event.todos);
      return;
    }
    setEvents((prev) => [...prev, event]);
    // Track which tool is currently running for the busy-status label
    if (event.kind === "tool_call") setActiveToolName(event.name);
    if (event.kind === "tool_result") setActiveToolName(null);
  }, []);

  // Auto-hide the todo panel shortly after every item is completed
  useEffect(() => {
    if (todos.length === 0 || !todos.every((t) => t.status === "completed")) return;
    const timer = setTimeout(() => setTodos([]), 2000);
    return () => clearTimeout(timer);
  }, [todos]);

  useEffect(() => {
    let cancelled = false;
    proxy.health().then((ok) => {
      if (cancelled) return;
      emit({
        kind: "system",
        text: ok
          ? `✓ Proxy reachable (${liveProxy})`
          : `Could not reach the proxy at ${liveProxy}.\n` +
            `  • If using DeepSeek: set DEEPSEEK_TOKEN and the proxy auto-starts.\n` +
            `  • If using a local server: run it first (e.g. \`python server.py\`).\n` +
            `  • To point elsewhere: ACURIST_PROXY=<url>  or  /proxy <url>`,
        id: randomUUID(),
      });
    });

    // Show active agent on startup, and remember it as the one to resume
    // next time (covers the case where --agent picked it, not just /agent).
    setLastAgentId(activeAgent.id);
    emit({
      kind: "system",
      id: randomUUID(),
      text: `🤖 Agent "${activeAgent.name}" active. Type /agent to switch (or /agent list to see all).`,
    });

    // Auto-start Telegram bridge if it was running before
    maybeAutoStartTelegram({
      agentRef,
      emit,
      onTelegramStop: () => {
        emit({ kind: "system", id: randomUUID(), text: "Telegram bridge was stopped from Telegram." });
      },
    });

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const pumpConfirmQueue = useCallback(() => {
    const next = confirmQueueRef.current.shift();
    if (next) {
      setMode({ kind: "confirm", command: next.command, resolve: next.resolve });
    }
  }, []);

  const toolPermsRef = useRef(toolPerms);
  toolPermsRef.current = toolPerms;

  const confirmShell = useCallback(
    (command: string, toolName?: string) =>
      new Promise<boolean>((resolve) => {
        const effectiveMode =
          (toolName && toolPermsRef.current[toolName]) ?? permModeRef.current;
        if (effectiveMode === "auto") {
          resolve(true);
          return;
        }
        setMode((current) => {
          if (current.kind === "confirm") {
            confirmQueueRef.current.push({ command, resolve });
            return current;
          }
          return { kind: "confirm", command, resolve };
        });
      }),
    []
  );

  const askUser = useCallback(
    (question: string, options?: string[]) =>
      new Promise<string>((resolve) => {
        setMode({ kind: "ask", question, options, resolve, draft: "" });
      }),
    []
  );

  const notify = useCallback((message: string) => {
    stdout?.write("\u0007"); // terminal bell
    if (message) emit({ kind: "system", id: "notify", text: `🔔 ${message}` });
  }, [stdout, emit]);

  if (!agentRef.current) {
    agentRef.current = new Agent({
      proxy,
      cwd: config.cwd,
      emit,
      confirmShell,
      askUser,
      notify,
      toolPermissions: toolPermsRef.current,
      onUsage: (u) => setTokenUsage(u),
      agentId: activeAgent.id,
    });
  }

  // Update agent's active persona when it changes
  useEffect(() => {
    if (agentRef.current) {
      (agentRef.current as any).deps.agentId = activeAgent.id;
    }
  }, [activeAgent]);

  // ── Queue processor ───────────────────────────────────────────────
  // After any send finishes, drain the queue sequentially.
  const drainQueue = useCallback(async () => {
    if (processingQueueRef.current) return;
    while (messageQueueRef.current.length > 0) {
      const next = messageQueueRef.current.shift()!;
      setQueueLength(messageQueueRef.current.length);
      processingQueueRef.current = true;

      setHistory((h) => [...h, next]);
      if (!next.startsWith("/")) appendPersistentHistory(next);
      setScrollOffset(0);

      const controller = new AbortController();
      abortRef.current = controller;
      setMode({ kind: "busy", label: `Thinking (Esc / Ctrl+C to interrupt)${messageQueueRef.current.length > 0 ? ` · ${messageQueueRef.current.length} queued` : ""}` });

      try {
        if (next.startsWith("/")) {
          // Await so async slash commands (plugin, agent) fully complete
          // before drainQueue sets mode→idle.
          await runSlashRef.current(next);
        } else {
          await agentRef.current!.send(next, controller.signal);
        }
      } catch (e: any) {
        if (e?.name !== "AbortError") {
          emit({ kind: "system", id: randomUUID(), text: `Error: ${e?.message ?? e}` });
        }
      } finally {
        abortRef.current = null;
        processingQueueRef.current = false;
        // Run finished (or was interrupted) → drop the sticky todo panel
        setTodos([]);
      }
    }
    setMode({ kind: "idle" });
    setQueueLength(0);
  }, [emit]);

  // Keep runSlash accessible inside drainQueue without circular deps
  const runSlashRef = useRef<(cmd: string) => Promise<void>>(() => Promise.resolve());

  const runSlash = useCallback(
    async (cmd: string): Promise<void> => {
      const [name, ...rest] = cmd.slice(1).split(" ");
      const arg = rest.join(" ").trim();
      switch (name) {
        // ── help ────────────────────────────────────────────────────────────
        case "help":
          emit({
            kind: "system",
            id: randomUUID(),
            text:
              SLASH_COMMANDS.map((c) => `${c.usage.padEnd(36)} ${c.description}`).join("\n") +
              "\n\n" +
              "Esc (while busy)   interrupt the current turn\n" +
              "Ctrl+J             insert a newline without submitting\n" +
              "Tab (after /)      complete the highlighted slash command\n" +
              "↑ / ↓, wheel       scroll the transcript one line\n" +
              "PageUp / PageDown  scroll the transcript one page\n" +
              "Home / End         jump to the oldest / latest message\n" +
              "Ctrl+↑ / Ctrl+↓    recall previous prompts (when input is empty)",
          });
          break;

        // ── clear ───────────────────────────────────────────────────────────
        case "clear":
          setEvents([]);
          setTodos([]);
          agentRef.current?.reset();
          break;

        // ── undo ────────────────────────────────────────────────────────────
        case "undo": {
          const ok = agentRef.current?.undo() ?? false;
          if (ok) {
            setEvents((prev) => {
              let i = prev.length - 1;
              while (i >= 0 && prev[i].kind !== "assistant") i--;
              while (i >= 0 && prev[i].kind !== "user") i--;
              return i >= 0 ? prev.slice(0, i) : prev;
            });
            emit({ kind: "system", id: randomUUID(), text: "↩ Last exchange removed — ready to retry." });
          } else {
            emit({ kind: "system", id: randomUUID(), text: "Nothing to undo." });
          }
          break;
        }

        // ── mode ─────────────────────────────────────────────────────────────
        case "mode":
          if (arg === "auto" || arg === "manual") {
            setPermMode(arg);
            emit({
              kind: "system",
              id: randomUUID(),
              text: `Global mode → ${arg}${arg === "auto" ? " (no confirmation for shell/write tools)" : " (confirm before shell/write tools)"}`,
            });
          } else {
            const perms = toolPermsRef.current;
            const overrides = Object.entries(perms).map(([t, m]) => `  ${t}: ${m}`).join("\n");
            emit({
              kind: "system",
              id: randomUUID(),
              text: `Global mode: ${permModeRef.current}\nPer-tool overrides:\n${overrides || "  (none)"}`,
            });
          }
          break;

        // ── perm ─────────────────────────────────────────────────────────────
        case "perm": {
          const [tool, modeArg] = rest;
          if (!tool) {
            const perms = getToolPermissions();
            const lines = Object.entries(perms).map(([t, m]) => `  ${t}: ${m}`).join("\n");
            emit({ kind: "system", id: randomUUID(), text: `Per-tool permissions:\n${lines || "  (none set)"}` });
          } else if (modeArg === "auto" || modeArg === "manual") {
            setToolPermission(tool, modeArg);
            setToolPerms(getToolPermissions());
            emit({ kind: "system", id: randomUUID(), text: `${tool} → ${modeArg}` });
          } else if (modeArg === "reset") {
            setToolPermission(tool, null);
            setToolPerms(getToolPermissions());
            emit({ kind: "system", id: randomUUID(), text: `${tool} permission reset to global default.` });
          } else {
            emit({ kind: "system", id: randomUUID(), text: "Usage: /perm <tool> auto|manual|reset" });
          }
          break;
        }

        // ── model ────────────────────────────────────────────────────────────
        case "model": {
          // /model auto  — pick the smart default (auto/best-coding alias)
          // Also resets the proxy URL to the default, because builtins assume
          // the deeptunnel proxy; a custom proxy set earlier would break them.
          if (arg === "auto") {
            const autoModel = "claude-sonnet-4-6";
            setConfigValue("model", autoModel);
            setLiveModel(autoModel);
            setConfigValue("proxyBaseUrl", DEFAULT_PROXY);
            setLiveProxy(DEFAULT_PROXY);
            const mapped = BUILTIN_MODEL_MAP[autoModel].autoId;
            emit({
              kind: "system", id: randomUUID(),
              text: `Model set to auto (${autoModel} → ${mapped} via proxy). Proxy reset to ${DEFAULT_PROXY}.`,
            });
            break;
          }

          // /model list  — fetch available models from the proxy
          if (arg === "list") {
            let proxyModels: string[] = [];
            try {
              const res = await fetch(`${liveProxy}/v1/models`, {
                headers: { "x-api-key": "local-proxy-key" },
                signal: AbortSignal.timeout(5000),
              });
              if (res.ok) {
                const data = await res.json() as any;
                proxyModels = (data.data ?? [])
                  .map((m: any) => String(m.id ?? ""))
                  .filter(Boolean);
              }
            } catch {
              // proxy not running — fall through, show builtins only
            }

            // Builtin aliases always shown first with their auto/ mapping
            const builtinIds = new Set(Object.keys(BUILTIN_MODEL_MAP));
            const extra = proxyModels.filter(id => !builtinIds.has(id));

            const lines: string[] = [
              `Current model: ${liveModel}`,
              "",
              "Built-in (auto-routed via proxy):",
              ...Object.entries(BUILTIN_MODEL_MAP).map(([id, { autoId, note }]) =>
                `  ${id.padEnd(36)} ${id === liveModel ? "(active)" : "       "} ${note}`
              ),
            ];

            if (extra.length) {
              lines.push("", "Proxy models:");
              lines.push(...extra.map(id =>
                `  ${id.padEnd(36)} ${id === liveModel ? "(active)" : "       "} proxy`
              ));
            }

            lines.push("", "Usage: /model <name>   or   /model auto");
            emit({ kind: "system", id: randomUUID(), text: lines.join("\n") });
            break;
          }

          // /model <name>  — switch model
          if (arg) {
            setConfigValue("model", arg);
            setLiveModel(arg);
            const alias = BUILTIN_MODEL_MAP[arg];
            // Switching to a builtin also resets the proxy so the auto/ routing works
            if (alias) {
              setConfigValue("proxyBaseUrl", DEFAULT_PROXY);
              setLiveProxy(DEFAULT_PROXY);
              emit({
                kind: "system", id: randomUUID(),
                text: `Model set to ${arg} (routes to ${alias.autoId} via proxy). Proxy reset to ${DEFAULT_PROXY}.`,
              });
            } else {
              emit({ kind: "system", id: randomUUID(), text: `Model set to ${arg}.` });
            }
          } else {
            // /model with no arg  — show current model + its resolved alias
            const alias = BUILTIN_MODEL_MAP[liveModel];
            const routeNote = alias ? `\n  → routes to ${alias.autoId} via proxy` : "";
            emit({
              kind: "system", id: randomUUID(),
              text: `Current model: ${liveModel}${routeNote}\nUse /model list · /model auto · /model <name> to change.`,
            });
          }
          break;
        }

        // ── proxy ─────────────────────────────────────────────────────────────
        case "proxy":
          if (arg) {
            if (!isValidHttpUrl(arg)) {
              emit({
                kind: "system", id: randomUUID(),
                text: `Invalid proxy URL "${arg}". Must start with http:// or https://\nExample: /proxy http://localhost:8765`,
              });
            } else {
              setConfigValue("proxyBaseUrl", arg);
              setLiveProxy(arg);
              emit({ kind: "system", id: randomUUID(), text: `Proxy set to ${arg}.` });
            }
          } else {
            emit({
              kind: "system", id: randomUUID(),
              text: `Current proxy: ${liveProxy}\nUsage: /proxy <url>  (e.g. /proxy http://localhost:8765)`,
            });
          }
          break;

        // ── save ──────────────────────────────────────────────────────────────
        case "save": {
          const sessionName = arg || `session-${Date.now()}`;
          const msgs = agentRef.current?.getMessages() ?? [];
          saveSession(sessionName, liveModel, liveProxy, msgs, events)
            .then((p) => emit({ kind: "system", id: randomUUID(), text: `💾 Session saved → ${p}` }))
            .catch((e) => emit({ kind: "system", id: randomUUID(), text: `Save failed: ${e?.message}` }));
          break;
        }

        // ── load ──────────────────────────────────────────────────────────────
        case "load": {
          if (!arg) {
            emit({ kind: "system", id: randomUUID(), text: "Usage: /load <name>  (see /sessions for names)" });
            break;
          }
          loadSession(arg)
            .then((sess) => {
              agentRef.current?.setMessages(sess.messages);
              setEvents(sess.transcript);
              emit({ kind: "system", id: randomUUID(), text: `📂 Session "${arg}" loaded (saved ${sess.savedAt}).` });
            })
            .catch((e) => emit({ kind: "system", id: randomUUID(), text: `Load failed: ${e?.message}` }));
          break;
        }

        // ── sessions ──────────────────────────────────────────────────────────
        case "sessions":
          listSessions()
            .then((list) => {
              if (!list.length) {
                emit({ kind: "system", id: randomUUID(), text: "No saved sessions. Use /save <name> to create one." });
              } else {
                const lines = list.map((s) => `  ${s.name.padEnd(30)} ${s.savedAt}`).join("\n");
                emit({ kind: "system", id: randomUUID(), text: `Saved sessions:\n${lines}` });
              }
            })
            .catch((e) => emit({ kind: "system", id: randomUUID(), text: `Error listing sessions: ${e?.message}` }));
          break;

        // ── export ────────────────────────────────────────────────────────────
        case "export": {
          const filename = arg || `acurist-export-${Date.now()}.md`;
          const outPath = path.resolve(config.cwd, filename);
          const md = events
            .map((e) => {
              if (e.kind === "user") return `**User:** ${e.text}`;
              if (e.kind === "assistant") return `**Acurist:** ${e.text}`;
              if (e.kind === "system") return `*${e.text}*`;
              if (e.kind === "tool_call")
                return `\`[tool: ${e.name}]\` \`\`\`json\n${JSON.stringify(e.input, null, 2)}\n\`\`\``;
              if (e.kind === "tool_result")
                return `\`[result: ${e.name}]\`\n\`\`\`\n${e.output}\n\`\`\``;
              return "";
            })
            .filter(Boolean)
            .join("\n\n");
          fs.writeFile(outPath, `# Acurist Session Export\n\n${md}\n`, "utf-8")
            .then(() => emit({ kind: "system", id: randomUUID(), text: `📄 Transcript exported → ${outPath}` }))
            .catch((e) => emit({ kind: "system", id: randomUUID(), text: `Export failed: ${e?.message}` }));
          break;
        }

        // ── template ──────────────────────────────────────────────────────────
        case "template": {
          const [sub, tName, ...tBodyParts] = rest;
          const tBody = tBodyParts.join(" ");
          switch (sub) {
            case "add":
              if (!tName || !tBody) {
                emit({ kind: "system", id: randomUUID(), text: 'Usage: /template add <name> <body>  (use {file} for placeholder)' });
              } else {
                addTemplate(tName, tBody);
                emit({ kind: "system", id: randomUUID(), text: `Template "${tName}" saved.` });
              }
              break;
            case "remove":
              if (removeTemplate(tName)) {
                emit({ kind: "system", id: randomUUID(), text: `Template "${tName}" removed.` });
              } else {
                emit({ kind: "system", id: randomUUID(), text: `No template named "${tName}".` });
              }
              break;
            case "list": {
              const tmpls = getTemplates();
              if (!tmpls.length) {
                emit({ kind: "system", id: randomUUID(), text: "No templates saved. Use /template add <name> <body>." });
              } else {
                const lines = tmpls.map((t) => `  ${t.name.padEnd(20)} ${t.body}`).join("\n");
                emit({ kind: "system", id: randomUUID(), text: `Templates:\n${lines}` });
              }
              break;
            }
            case "use": {
              const tmpl = getTemplate(tName);
              if (!tmpl) {
                emit({ kind: "system", id: randomUUID(), text: `No template named "${tName}". Use /template list.` });
              } else {
                const filled = tBody ? tmpl.body.replace("{file}", tBody) : tmpl.body;
                handleSubmit(filled);
              }
              break;
            }
            default:
              emit({ kind: "system", id: randomUUID(), text: "Usage: /template add|use|list|remove [name] [body]" });
          }
          break;
        }

        // ── history ───────────────────────────────────────────────────────────
        case "history": {
          const hist = getPersistentHistory();
          if (!hist.length) {
            emit({ kind: "system", id: randomUUID(), text: "No persistent history yet." });
            break;
          }
          const query = arg.toLowerCase();
          const matches = query
            ? hist.filter((h) => h.toLowerCase().includes(query)).slice(-20)
            : hist.slice(-20);
          if (!matches.length) {
            emit({ kind: "system", id: randomUUID(), text: `No history matches "${arg}".` });
          } else {
            const lines = matches.map((h, i) => `  ${String(i + 1).padStart(2)}  ${h.slice(0, 120)}`).join("\n");
            emit({ kind: "system", id: randomUUID(), text: `History${query ? ` (matching "${arg}")` : ""}:\n${lines}` });
          }
          break;
        }

        // ── mcp ───────────────────────────────────────────────────────────────
        case "mcp": {
          const [sub, ...mcpArgs] = rest;
          switch (sub) {
            case "add": {
              const [mcpName, mcpUrl] = mcpArgs;
              if (!mcpName || !mcpUrl) {
                emit({ kind: "system", id: randomUUID(), text: "Usage: /mcp add <name> <url>" });
              } else {
                addMcpServer(mcpName, mcpUrl);
                clearMcpCache();
                emit({ kind: "system", id: randomUUID(), text: `🔌 MCP server "${mcpName}" added (${mcpUrl}).` });
              }
              break;
            }
            case "remove": {
              const nameOrUrl = mcpArgs.join(" ");
              if (removeMcpServer(nameOrUrl)) {
                clearMcpCache();
                emit({ kind: "system", id: randomUUID(), text: `MCP server "${nameOrUrl}" removed.` });
              } else {
                emit({ kind: "system", id: randomUUID(), text: `No MCP server matching "${nameOrUrl}".` });
              }
              break;
            }
            case "list": {
              const servers = getMcpServers();
              if (!servers.length) {
                emit({ kind: "system", id: randomUUID(), text: "No MCP servers configured. Use /mcp add <name> <url>." });
              } else {
                const lines = servers.map((s) => `  ${s.name.padEnd(20)} ${s.url}`).join("\n");
                emit({ kind: "system", id: randomUUID(), text: `MCP servers:\n${lines}` });
              }
              break;
            }
            default:
              emit({ kind: "system", id: randomUUID(), text: "Usage: /mcp add <name> <url> | /mcp remove <name> | /mcp list" });
          }
          break;
        }

        // ── telegram ──────────────────────────────────────────────────────────
        case "telegram": {
          const text = handleTelegramCommand(rest, {
            agentRef,
            emit,
            onTelegramStop: () => {
              emit({ kind: "system", id: randomUUID(), text: "Telegram bridge stopped from Telegram." });
            },
          });
          if (text) emit({ kind: "system", id: randomUUID(), text });
          break;
        }

        // ── plugin ────────────────────────────────────────────────────────────
        case "plugin": {
          emit({ kind: "system", id: randomUUID(), text: "⏳ Fetching marketplace data…" });
          try {
            const text = await handlePluginCommand(rest);
            emit({ kind: "system", id: randomUUID(), text });
          } catch (e: any) {
            emit({ kind: "system", id: randomUUID(), text: `Plugin error: ${e?.message ?? e}` });
          }
          break;
        }

        // ── agent ─────────────────────────────────────────────────────────────
        case "agent": {
          try {
            const text = await handleAgentCommand(rest, {
              emit,
              currentAgentId: activeAgentRef.current.id,
              onActivateAgent: (agent) => {
                setActiveAgent(agent);
                activeAgentRef.current = agent;
                if (agentRef.current) {
                  (agentRef.current as any).deps.agentId = agent.id;
                }
              },
            });
            if (text) emit({ kind: "system", id: randomUUID(), text });
          } catch (e: any) {
            emit({ kind: "system", id: randomUUID(), text: `Agent error: ${e?.message ?? e}` });
          }
          break;
        }

        // ── exit ──────────────────────────────────────────────────────────────
        case "exit":
        case "quit":
          exit();
          break;

        default:
          emit({ kind: "system", id: randomUUID(), text: `Unknown command: /${name}. Try /help.` });
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [emit, exit, events, config, proxy, askUser]
  );

  // Keep runSlashRef up to date
  runSlashRef.current = runSlash;

  const handleSubmit = useCallback(
    async (text: string) => {
      setScrollOffset(0);

      // If agent is currently busy, queue the message instead of running it now
      if (mode.kind === "busy" || processingQueueRef.current) {
        messageQueueRef.current.push(text);
        setQueueLength(messageQueueRef.current.length);
        emit({ kind: "system", id: randomUUID(), text: `⏸ Queued (position ${messageQueueRef.current.length}): ${text.slice(0, 60)}${text.length > 60 ? "…" : ""}` });
        return;
      }

      setHistory((h) => [...h, text]);
      if (!text.startsWith("/")) appendPersistentHistory(text);

      if (text.startsWith("/")) {
        await runSlash(text);
        return;
      }

      // Pre-resolve @url mentions
      let resolved = text;
      const urlMentionRe = /@(https?:\/\/\S+)/g;
      const urlMatches = [...text.matchAll(urlMentionRe)];
      if (urlMatches.length) {
        emit({ kind: "system", id: randomUUID(), text: `🌐 Fetching ${urlMatches.length} URL(s)…` });
        for (const m of urlMatches) {
          try {
            const res = await fetch(m[1]);
            const raw = await res.text();
            const stripped = raw
              .replace(/<script[\s\S]*?<\/script>/gi, "")
              .replace(/<style[\s\S]*?<\/style>/gi, "")
              .replace(/<[^>]+>/g, " ")
              .replace(/\s+/g, " ")
              .trim()
              .slice(0, 6000);
            resolved = resolved.replace(m[0], `[Content of ${m[1]}]:\n${stripped}`);
          } catch (e: any) {
            resolved = resolved.replace(m[0], `[Failed to fetch ${m[1]}: ${e?.message}]`);
          }
        }
      }

      const controller = new AbortController();
      abortRef.current = controller;
      setMode({ kind: "busy", label: "Thinking (Esc / Ctrl+C to interrupt)" });
      processingQueueRef.current = true;
      try {
        await agentRef.current!.send(resolved, controller.signal);
      } catch (e: any) {
        if (e?.name !== "AbortError") {
          emit({ kind: "system", id: randomUUID(), text: `Error: ${e?.message ?? e}` });
        }
      } finally {
        abortRef.current = null;
        processingQueueRef.current = false;
        // Drain any queued messages after this one finishes
        await drainQueue();
      }
    },
    [emit, runSlash, mode.kind, drainQueue]
  );

  usePaste(
    (text) => {
      setMode((m) => (m.kind === "ask" && !m.options ? { ...m, draft: m.draft + text } : m));
    },
    { isActive: mode.kind === "ask" && !mode.options }
  );

  const panelWidth = Math.max(1, columns - 4);
  const modePanelHeight =
    mode.kind === "confirm"
      ? 1 + 2 + 1 + wrapAnsiLineCount(mode.command, panelWidth) + 1
      : mode.kind === "ask"
        ? 1 + 2 + wrapAnsiLineCount(mode.question, panelWidth) + (mode.options ? mode.options.length : 1)
        : mode.kind === "busy"
          ? 1 + 1
          : 0;
  const footerHeight = 1;
  const inputMarginTop = 1;
  const MAX_TODO_ROWS = 8;
  const shownTodos = todos.slice(0, MAX_TODO_ROWS);
  const hiddenTodos = todos.length - shownTodos.length;
  const todoPanelHeight =
    todos.length === 0 ? 0 : 1 /*marginTop*/ + 1 /*header*/ + shownTodos.length + (hiddenTodos > 0 ? 1 : 0);
  const reservedRows = modePanelHeight + todoPanelHeight + inputMarginTop + inputHeight + footerHeight;

  const allLines = useMemo(() => {
    const cache = lineCacheRef.current;
    const seen = new Set<string>();
    const out: string[] = [];
    for (const event of events) {
      seen.add(event.id);
      const cached = cache.get(event.id);
      const lines =
        cached && cached.width === columns ? cached.lines : eventToLines(event, columns);
      cache.set(event.id, { width: columns, lines });
      out.push(...lines);
    }
    for (const id of cache.keys()) {
      if (!seen.has(id)) cache.delete(id);
    }
    return out;
  }, [events, columns]);

  const scrolled = scrollOffset > 0;
  const viewportRows = Math.max(3, rows - reservedRows - (scrolled ? 1 : 0));
  const total = allLines.length;
  const maxScroll = Math.max(0, total - viewportRows);
  const clampedOffset = Math.min(scrollOffset, maxScroll);
  const endIdx = total - clampedOffset;
  const startIdx = Math.max(0, endIdx - viewportRows);
  const visibleLines = allLines.slice(startIdx, endIdx);

  // ── Mouse: wheel scroll + drag-to-select (auto-copies on release) ───
  // Selection is stored in ABSOLUTE transcript line indexes so it stays
  // attached to the text while scrolling.
  type SelPoint = { line: number; col: number };
  const [sel, setSel] = useState<{ a: SelPoint; b: SelPoint } | null>(null);
  const [copyHint, setCopyHint] = useState<string | null>(null);
  const copyHintTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const anchorRef = useRef<SelPoint | null>(null);
  const draggingRef = useRef(false);
  const lastClickRef = useRef<{ t: number; line: number; col: number; count: number } | null>(null);
  // Latest layout numbers for the (mount-once) mouse handler below
  const layoutRef = useRef({ startIdx: 0, visibleCount: 0, viewportRows: 3, scrolled: false, maxScroll: 0, allLines: [] as string[] });
  layoutRef.current = { startIdx, visibleCount: visibleLines.length, viewportRows, scrolled, maxScroll, allLines };

  // Last known pointer position while dragging, and a hook the layout effect
  // below uses to re-aim the selection end after an auto-scroll step.
  const lastMouseRef = useRef<{ x: number; y: number } | null>(null);
  const refreshHeadRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    let autoTimer: ReturnType<typeof setInterval> | null = null;
    const stopAuto = () => {
      if (autoTimer) { clearInterval(autoTimer); autoTimer = null; }
    };
    const order = (a: SelPoint, b: SelPoint): [SelPoint, SelPoint] =>
      a.line < b.line || (a.line === b.line && a.col <= b.col) ? [a, b] : [b, a];

    const textOf = (a: SelPoint, b: SelPoint): string => {
      const [st, en] = order(a, b);
      const L = layoutRef.current.allLines;
      const out: string[] = [];
      for (let i = st.line; i <= en.line; i++) {
        const plain = stripAnsi(L[i] ?? "");
        const c0 = i === st.line ? st.col : 0;
        const c1 = i === en.line ? en.col : Infinity;
        out.push(sliceCols(plain, c0, c1).replace(/\s+$/, ""));
      }
      return out.join("\n");
    };

    const finishSelect = (a: SelPoint, b: SelPoint) => {
      setSel({ a, b });
      const text = textOf(a, b);
      if (!text.trim()) return;
      copyToSystemClipboard(text);
      setCopyHint(`Copied ${text.length} char${text.length === 1 ? "" : "s"}`);
      if (copyHintTimerRef.current) clearTimeout(copyHintTimerRef.current);
      copyHintTimerRef.current = setTimeout(() => setCopyHint(null), 1500);
    };

    // Screen (x, y) → transcript position, clamped to the visible viewport
    const posAt = (x: number, y: number): SelPoint | null => {
      const L = layoutRef.current;
      if (L.visibleCount === 0) return null;
      const top = L.scrolled ? 2 : 1;
      const r = Math.max(0, Math.min(L.visibleCount - 1, y - top));
      return { line: L.startIdx + r, col: Math.max(0, x - 1) };
    };

    const onMouse = (ev: MouseEv) => {
      const L = layoutRef.current;
      if (ev.kind === "wheelUp")   { setScrollOffset((o) => Math.min(L.maxScroll, o + 3)); return; }
      if (ev.kind === "wheelDown") { setScrollOffset((o) => Math.max(0, o - 3)); return; }

      const top = L.scrolled ? 2 : 1;

      if (ev.kind === "down") {
        stopAuto();
        const inView = ev.y >= top && ev.y < top + L.visibleCount;
        if (!inView) { setSel(null); draggingRef.current = false; return; }
        const p = posAt(ev.x, ev.y)!;
        const now = Date.now();
        const last = lastClickRef.current;
        const same = !!last && now - last.t < 450 && last.line === p.line && Math.abs(last.col - p.col) <= 1;
        const count = same ? Math.min(3, last!.count + 1) : 1;
        lastClickRef.current = { t: now, line: p.line, col: p.col, count };
        if (count === 1) {
          anchorRef.current = p;
          draggingRef.current = true;
          setSel(null); // highlight appears once the mouse moves
          return;
        }
        draggingRef.current = false;
        const plain = stripAnsi(L.allLines[p.line] ?? "");
        if (count === 2) {
          const r = wordRangeAt(plain, p.col);           // double-click → word
          if (r) finishSelect({ line: p.line, col: r[0] }, { line: p.line, col: r[1] });
        } else {                                         // triple-click → whole line
          finishSelect({ line: p.line, col: 0 }, { line: p.line, col: Math.max(0, plainWidth(plain) - 1) });
        }
        return;
      }

      if (ev.kind === "drag" && draggingRef.current && anchorRef.current) {
        lastMouseRef.current = { x: ev.x, y: ev.y };
        const p = posAt(ev.x, ev.y);
        if (p) setSel({ a: anchorRef.current, b: p });

        // Pointer on/above the first row or on/below the last row → keep
        // scrolling while the button is held, even if the mouse stops moving
        // (terminals only send motion events when the pointer actually moves).
        const bottom = top + L.viewportRows - 1;
        const atEdge = ev.y <= top || ev.y >= bottom;
        if (atEdge && !autoTimer) {
          autoTimer = setInterval(() => {
            const m = lastMouseRef.current;
            const LL = layoutRef.current;
            if (!draggingRef.current || !m) { stopAuto(); return; }
            const t = LL.scrolled ? 2 : 1;
            const bot = t + LL.viewportRows - 1;
            if (m.y <= t)        setScrollOffset((o) => Math.min(LL.maxScroll, o + 1));
            else if (m.y >= bot) setScrollOffset((o) => Math.max(0, o - 1));
            else                 stopAuto();
          }, 45);
        } else if (!atEdge) {
          stopAuto();
        }
        return;
      }

      if (ev.kind === "up" && draggingRef.current) {
        stopAuto();
        draggingRef.current = false;
        const a = anchorRef.current;
        const p = posAt(ev.x, ev.y);
        if (!a || !p) return;
        if (a.line === p.line && a.col === p.col) { setSel(null); return; } // plain click
        finishSelect(a, p);                                                  // select-to-copy
      }
    };

    // After each auto-scroll step the viewport shows different lines, so
    // re-aim the selection end at whatever is now under the pointer.
    refreshHeadRef.current = () => {
      const a = anchorRef.current;
      const m = lastMouseRef.current;
      if (!draggingRef.current || !a || !m) return;
      const p = posAt(m.x, m.y);
      if (p) setSel({ a, b: p });
    };

    mouseEvents.on("mouse", onMouse);
    return () => {
      stopAuto();
      refreshHeadRef.current = null;
      mouseEvents.off("mouse", onMouse);
    };
  }, []);

  // Viewport moved (auto-scroll / wheel while dragging) → update selection end
  useEffect(() => {
    refreshHeadRef.current?.();
  }, [startIdx]);

  // Drop the highlight if the transcript shrank underneath it (/clear, /load…)
  useEffect(() => {
    if (sel && (sel.a.line >= allLines.length || sel.b.line >= allLines.length)) setSel(null);
  }, [allLines.length, sel]);

  // ── Input box is ALWAYS enabled — typing queues messages when busy ─
  // We only disable it during confirm/ask prompts that need the keyboard.
  const inputDisabled = mode.kind === "confirm" || mode.kind === "ask";

  // Track whether Ctrl+C was pressed once (to require a second press to exit when idle)
  const ctrlCPressedRef = useRef(false);
  const ctrlCTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Footer hint shown after the first Ctrl+C while idle
  const [exitHint, setExitHint] = useState(false);

  useInput(
    (input, key) => {
      setSel(null); // any key press clears the mouse selection highlight
      // ── Ctrl+C: interrupt-then-exit (two-press) ───────────────────
      // First press while busy  → interrupt (same as Esc), no exit
      // First press while idle  → show "Press again to exit" hint, start timer
      // Second press or timeout → exit
      if (key.ctrl && input === "c") {
        if (mode.kind === "busy") {
          // Interrupt the running task; reset the "second press to exit" state
          abortRef.current?.abort();
          messageQueueRef.current = [];
          setQueueLength(0);
          setMode({ kind: "idle" });
          setActiveToolName(null);
          processingQueueRef.current = false;
          emit({ kind: "system", id: randomUUID(), text: "⏹ Interrupted. Message queue cleared. (Ctrl+C again to quit)" });
          ctrlCPressedRef.current = false;
          setExitHint(false);
          if (ctrlCTimerRef.current) clearTimeout(ctrlCTimerRef.current);
        } else if (!ctrlCPressedRef.current) {
          // First press while idle — show footer hint and arm the timer
          ctrlCPressedRef.current = true;
          setExitHint(true);
          if (ctrlCTimerRef.current) clearTimeout(ctrlCTimerRef.current);
          ctrlCTimerRef.current = setTimeout(() => {
            ctrlCPressedRef.current = false;
            setExitHint(false);
          }, 2000);
        } else {
          // Second press within the window — exit
          if (ctrlCTimerRef.current) clearTimeout(ctrlCTimerRef.current);
          exit();
        }
        return;
      }
      // Any other key clears the pending Ctrl+C
      if (ctrlCPressedRef.current && !key.ctrl) {
        ctrlCPressedRef.current = false;
        setExitHint(false);
        if (ctrlCTimerRef.current) clearTimeout(ctrlCTimerRef.current);
      }

      // ↑/↓ are input-history keys now (InputBox); the mouse wheel and
      // PageUp/PageDown/Home/End scroll the transcript.
      if (key.pageUp) {
        setScrollOffset((o) => Math.min(maxScroll, o + viewportRows));
        return;
      }
      if (key.pageDown) {
        setScrollOffset((o) => Math.max(0, o - viewportRows));
        return;
      }
      if (key.home) {
        setScrollOffset(maxScroll);
        return;
      }
      if (key.end) {
        setScrollOffset(0);
        return;
      }
      if (mode.kind === "busy") {
        if (key.escape) {
          abortRef.current?.abort();
          // Clear the queue too when user interrupts
          messageQueueRef.current = [];
          setQueueLength(0);
          setMode({ kind: "idle" });
          setActiveToolName(null);
          processingQueueRef.current = false;
          emit({ kind: "system", id: randomUUID(), text: "⏹ Interrupted. Message queue cleared." });
        }
        return;
      }
      if (mode.kind === "confirm") {
        if (input.toLowerCase() === "y" || key.return) {
          mode.resolve(true);
          if (confirmQueueRef.current.length > 0) pumpConfirmQueue();
          else setMode({ kind: "busy", label: "Running (Esc / Ctrl+C to interrupt)" });
        } else if (input.toLowerCase() === "n" || key.escape) {
          mode.resolve(false);
          if (confirmQueueRef.current.length > 0) pumpConfirmQueue();
          else setMode({ kind: "busy", label: "Thinking (Esc / Ctrl+C to interrupt)" });
        }
      } else if (mode.kind === "ask" && !mode.options) {
        if (key.return) {
          mode.resolve(mode.draft);
          setMode({ kind: "busy", label: "Thinking (Esc / Ctrl+C to interrupt)" });
        } else if (key.backspace || key.delete) {
          setMode({ ...mode, draft: mode.draft.slice(0, -1) });
        } else if (!key.ctrl && !key.meta && input) {
          setMode({ ...mode, draft: mode.draft + input });
        }
      } else if (mode.kind === "ask" && mode.options) {
        const n = parseInt(input, 10);
        if (!isNaN(n) && n >= 1 && n <= mode.options.length) {
          mode.resolve(mode.options[n - 1]);
          setMode({ kind: "busy", label: "Thinking (Esc / Ctrl+C to interrupt)" });
        }
      }
    },
    { isActive: true }
  );

  if (columns < MIN_WIDTH) {
    return (
      <Box flexDirection="column" paddingX={1}>
        <Text color="yellow" bold>
          Terminal too narrow
        </Text>
        <Text dimColor>
          Acurist needs at least {MIN_WIDTH} columns to render (currently {columns}). Please
          widen your terminal window.
        </Text>
      </Box>
    );
  }

  return (
    <Box flexDirection="column">
      {scrolled && (
        <Box>
          <Text dimColor>
            ── scrolled up · {startIdx} line{startIdx === 1 ? "" : "s"} above · PageDown/End to
            return to live ──
          </Text>
        </Box>
      )}
      <Box flexDirection="column" height={viewportRows} overflow="hidden">
        {visibleLines.map((line, i) => {
          const abs = startIdx + i;
          let shown = line;
          if (sel) {
            const [st, en] =
              sel.a.line < sel.b.line || (sel.a.line === sel.b.line && sel.a.col <= sel.b.col)
                ? [sel.a, sel.b] : [sel.b, sel.a];
            if (abs >= st.line && abs <= en.line) {
              shown = highlightLine(line, abs === st.line ? st.col : 0, abs === en.line ? en.col : 100000);
            }
          }
          return <Text key={abs}>{shown || " "}</Text>;
        })}
      </Box>

      {todos.length > 0 && (
        <Box marginTop={1} flexDirection="column">
          <Text color="cyan" bold>
            ☰ Todos {todos.filter((t) => t.status === "completed").length}/{todos.length}
          </Text>
          {shownTodos.map((t, i) => (
            <Text key={i} wrap="truncate-end">
              {t.status === "completed" ? (
                <Text color="green">  ✔ <Text dimColor strikethrough>{t.text}</Text></Text>
              ) : t.status === "in_progress" ? (
                <Text color="yellow">  ◐ <Text bold>{t.text}</Text></Text>
              ) : (
                <Text dimColor>  ○ {t.text}</Text>
              )}
            </Text>
          ))}
          {hiddenTodos > 0 && <Text dimColor>  … +{hiddenTodos} more</Text>}
        </Box>
      )}

      {mode.kind === "confirm" && (
        <Box marginTop={1} flexDirection="column" borderStyle="round" borderColor="yellow" paddingX={1} width={columns}>
          <Text color="yellow" bold>
            Run this command?
          </Text>
          <Text>{mode.command}</Text>
          <Text dimColor>[y] yes   [n] no   (switch to /mode auto to stop asking)</Text>
        </Box>
      )}

      {mode.kind === "ask" && (
        <Box marginTop={1} flexDirection="column" borderStyle="round" borderColor="blue" paddingX={1} width={columns}>
          <Text color="blue" bold>
            {mode.question}
          </Text>
          {mode.options ? (
            mode.options.map((o, i) => (
              <Text key={i}>
                {"  "}[{i + 1}] {o}
              </Text>
            ))
          ) : (
            <Text>
              {"> "}
              {mode.draft}
              <Text color="blue">▏</Text>
            </Text>
          )}
        </Box>
      )}

      {mode.kind === "busy" && (
        <Box marginTop={1}>
          <Text color="magenta">
            <Spinner type="dots" />{" "}
            {activeToolName
              ? <><Text color="magenta" bold>⏺ {activeToolName}</Text><Text color="magenta"> running…</Text></>
              : <Text color="magenta">{mode.label}…</Text>
            }
            {queueLength > 0 && <Text dimColor> · {queueLength} message{queueLength === 1 ? "" : "s"} queued</Text>}
          </Text>
        </Box>
      )}

      <Box marginTop={1}>
        <InputBox
          onSubmit={handleSubmit}
          history={history}
          disabled={inputDisabled}
          cwd={config.cwd}
          onHeightChange={setInputHeight}
          busyMode={mode.kind === "busy"}
        />
      </Box>

      <Box justifyContent="space-between">
        {exitHint ? (
          <Text color="yellow" bold>Press Ctrl+C again to exit</Text>
        ) : copyHint ? (
          <Text color="green" bold>✔ {copyHint}</Text>
        ) : (
        <Text dimColor>
          {liveModel}
          {BUILTIN_MODEL_MAP[liveModel]
            ? <Text dimColor> →{BUILTIN_MODEL_MAP[liveModel].autoId}</Text>
            : ""}
          <Text color="cyan"> · agent:{activeAgent.name}</Text>
          {" "}· mode:{permMode}
          {isBridgeRunning() ? <Text color="green"> · tg:on</Text> : ""}
          {" "}· {config.cwd}
        </Text>
        )}
        {tokenUsage.totalTokens > 0 && (
          <Text dimColor>
            {" "}↑{tokenUsage.inputTokens.toLocaleString()} ↓{tokenUsage.outputTokens.toLocaleString()} tok
          </Text>
        )}
      </Box>
    </Box>
  );
}
