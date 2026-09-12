import React, { useEffect, useMemo, useRef, useState } from "react";
import fs from "node:fs";
import path from "node:path";
import { Box, Text, useInput, usePaste, useStdout } from "ink";
import { SLASH_COMMANDS, type SubOption } from "../core/slashCommands.js";
import { getPersistentHistory } from "../core/config.js";

// ── @file mentions ──────────────────────────────────────────────────
// Two modes, mirroring Claude Code's `@` picker:
//   1. No "/" typed yet ("@foo")   → fuzzy-search file names anywhere in
//      the project (fast, cached recursive walk).
//   2. A "/" is present ("@src/",
//      "@../", "@../../lib/ut")     → browse that exact directory's
//      contents, so the user can drill into folders and back out again
//      with "../", "../../", etc. Selecting a folder keeps the mention
//      open (so you can keep drilling); selecting a file closes it.
const IGNORED_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next", ".cache"]);
const MAX_FILES = 5000;
const MAX_DIR_ENTRIES = 500;
const CACHE_TTL_MS = 5000;

// -- mode 1: cached recursive walk, used for plain "@query" fuzzy search --
let fileCache: { cwd: string; files: string[]; builtAt: number } | null = null;

function walkForMentions(dir: string, base: string, out: string[]): void {
  if (out.length >= MAX_FILES) return;
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    if (out.length >= MAX_FILES) return;
    if (e.name.startsWith(".") && e.name !== ".env") continue;
    if (IGNORED_DIRS.has(e.name)) continue;
    const full = path.join(dir, e.name);
    const rel = path.relative(base, full);
    if (e.isDirectory()) {
      walkForMentions(full, base, out);
    } else {
      out.push(rel);
    }
  }
}

function getProjectFiles(cwd: string): string[] {
  const now = Date.now();
  if (fileCache && fileCache.cwd === cwd && now - fileCache.builtAt < CACHE_TTL_MS) {
    return fileCache.files;
  }
  const files: string[] = [];
  walkForMentions(cwd, cwd, files);
  fileCache = { cwd, files, builtAt: now };
  return files;
}

// -- mode 2: single-directory listing, used once the query contains "/" --
interface DirEntry {
  name: string;
  isDir: boolean;
}

const dirCache = new Map<string, { entries: DirEntry[]; builtAt: number }>();

function listDirEntries(absDir: string): DirEntry[] {
  const now = Date.now();
  const cached = dirCache.get(absDir);
  if (cached && now - cached.builtAt < CACHE_TTL_MS) return cached.entries;

  let dirents: fs.Dirent[];
  try {
    dirents = fs.readdirSync(absDir, { withFileTypes: true });
  } catch {
    dirCache.set(absDir, { entries: [], builtAt: now });
    return [];
  }
  const out: DirEntry[] = [];
  for (const e of dirents) {
    if (out.length >= MAX_DIR_ENTRIES) break;
    if (e.name.startsWith(".") && e.name !== ".env") continue;
    if (IGNORED_DIRS.has(e.name)) continue;
    out.push({ name: e.name, isDir: e.isDirectory() });
  }
  out.sort((a, b) => (a.isDir === b.isDir ? a.name.localeCompare(b.name) : a.isDir ? -1 : 1));
  dirCache.set(absDir, { entries: out, builtAt: now });
  return out;
}

/** A single row in the @ suggestion list, regardless of which mode built it. */
interface Mention {
  /** What's shown in the picker, e.g. "src/ui/" or "src/ui/App.tsx". */
  display: string;
  /** What replaces the in-progress "@query" when chosen (no leading "@"). */
  insert: string;
  isDir: boolean;
}

/** Finds an in-progress "@query" token ending at the cursor (end of value),
 * so suggestions only show while actively typing a mention. */
function activeMentionQuery(value: string): string | null {
  const at = value.lastIndexOf("@");
  if (at === -1) return null;
  const tail = value.slice(at + 1);
  if (tail.includes(" ") || tail.includes("\n") || tail.includes("@")) return null;
  return tail;
}

function buildMentions(query: string, cwd: string): Mention[] {
  // @url mentions: if the query looks like a URL, offer it as a single item
  // so the user sees confirmation that it will be fetched on submit.
  if (query.startsWith("http://") || query.startsWith("https://")) {
    return [{ display: `fetch: ${query}`, insert: query, isDir: false }];
  }

  const slash = query.lastIndexOf("/");

  if (slash === -1) {
    // Mode 1: fuzzy search by filename anywhere in the project.
    const files = getProjectFiles(cwd);
    const q = query.toLowerCase();
    const scored = files
      .filter((f) => f.toLowerCase().includes(q))
      .map((f) => {
        const base = path.basename(f).toLowerCase();
        // Prefix-of-basename matches float to the top, like Claude Code's picker.
        const score = base.startsWith(q) ? 0 : f.toLowerCase().indexOf(q);
        return { f, score };
      })
      .sort((a, b) => a.score - b.score || a.f.length - b.f.length)
      .slice(0, 8);
    return scored.map(({ f }) => ({ display: f, insert: f, isDir: false }));
  }

  // Mode 2: browse the exact directory the user has typed, e.g.
  // "src/ui/Inp" -> list src/ui/, filtered to entries starting with "Inp".
  // "../../" -> list two levels above cwd.
  const dirPart = query.slice(0, slash);
  const prefix = query.slice(slash + 1).toLowerCase();
  const absDir = path.resolve(cwd, dirPart || ".");
  const entries = listDirEntries(absDir);

  const rows: Mention[] = [];
  if ("..".startsWith(prefix)) {
    rows.push({ display: "../", insert: `${dirPart}/..`, isDir: true });
  }
  for (const e of entries) {
    if (!e.name.toLowerCase().startsWith(prefix)) continue;
    const insert = `${dirPart}/${e.name}`;
    rows.push({ display: e.isDir ? `${insert}/` : insert, insert, isDir: e.isDir });
  }
  return rows.slice(0, 10);
}

interface Props {
  onSubmit: (value: string) => void;
  history: string[];
  disabled?: boolean;
  placeholder?: string;
  promptLabel?: string;
  /** Working directory to search for @-mentioned files. Defaults to process.cwd(). */
  cwd?: string;
  /** Called whenever the total rendered height of this box (including its
   * slash-command / @-mention popovers) changes, in terminal rows — lets
   * the parent reserve exactly enough space for it above. */
  onHeightChange?: (rows: number) => void;
  /** When true, the input is still typeable but shows a "queuing" hint.
   * Messages submitted in this mode are queued, not run immediately. */
  busyMode?: boolean;
}

// Large / multi-line pastes are collapsed into a short placeholder in the
// visible input (same idea as Claude Code) so the box doesn't balloon to
// hundreds of lines; the real text is swapped back in right before submit.
const PASTE_CHAR_THRESHOLD = 400;
const pasteStore = new Map<string, string>();
let pasteCounter = 0;

function makePlaceholder(text: string): string {
  pasteCounter += 1;
  const lines = text.split("\n").length;
  const words = text.trim().split(/\s+/).filter(Boolean).length;
  const placeholder = `[Pasted text: ${lines} line${lines === 1 ? "" : "s"}, ${words} word${
    words === 1 ? "" : "s"
  } #${pasteCounter}]`;
  pasteStore.set(placeholder, text);
  return placeholder;
}

function expandPastes(s: string): string {
  let out = s;
  for (const [placeholder, text] of pasteStore) {
    out = out.split(placeholder).join(text);
  }
  return out;
}

export default function InputBox({
  onSubmit,
  history,
  disabled,
  placeholder = "Type a message, or /help for commands…",
  // (busyMode placeholder shown separately)
  promptLabel = "›",
  cwd = process.cwd(),
  onHeightChange,
  busyMode = false,
}: Props) {
  const [value, setValue] = useState("");
  const [cursor, setCursor] = useState(0);
  const [historyIndex, setHistoryIndex] = useState<number | null>(null);

  // Merged history: persistent (cross-session) + current session, deduplicated.
  const mergedHistory = useMemo(() => {
    const persistent = getPersistentHistory();
    const combined = [...persistent];
    for (const h of history) {
      if (!combined.includes(h)) combined.push(h);
    }
    return combined;
  }, [history]);
  const [suggestIndex, setSuggestIndex] = useState(0);
  const { stdout } = useStdout();
  const columns = stdout?.columns ?? 80;

  // Helper: replace `value` and move the caret to an explicit position in
  // one go, so callers never forget to keep the two in sync.
  const replaceValue = (next: string, nextCursor: number) => {
    setValue(next);
    setCursor(Math.max(0, Math.min(nextCursor, next.length)));
  };

  // ── Two-level slash-command completion ────────────────────────────
  // Level 1 (command picker): user is typing "/foo" with no space yet →
  //   show all commands whose name starts with "foo".
  // Level 2 (sub-option picker): user typed "/agent " (command + space) →
  //   show that command's subOptions, filtered by whatever they've typed so
  //   far after the space. Tab inserts the highlighted sub-option in-place.

  /** Level-1: top-level command matches (no space in value yet) */
  const matches = useMemo(() => {
    if (!value.startsWith("/") || value.includes(" ") || value.includes("\n")) return [];
    const q = value.slice(1).toLowerCase();
    return SLASH_COMMANDS.filter((c) => c.name.startsWith(q));
  }, [value]);

  /** Level-2: sub-option matches (value is "/cmd subprefix") */
  const subMatches = useMemo((): SubOption[] => {
    // Must start with "/" and contain exactly one space (command typed, sub typing)
    if (!value.startsWith("/") || value.includes("\n")) return [];
    const spaceIdx = value.indexOf(" ");
    if (spaceIdx === -1) return []; // no space yet → level-1 handles it
    const cmdName = value.slice(1, spaceIdx).toLowerCase();
    const cmd = SLASH_COMMANDS.find((c) => c.name === cmdName);
    if (!cmd?.subOptions?.length) return [];
    // Check there's only ONE space so far (don't show after "/cmd sub arg")
    const afterSpace = value.slice(spaceIdx + 1);
    if (afterSpace.includes(" ")) return []; // second word already typed
    const q = afterSpace.toLowerCase();
    return cmd.subOptions.filter((s) => s.name.startsWith(q));
  }, [value]);

  // Mentions are resolved against the text up to the caret (not the whole
  // value) so typing "@foo" in the middle of an existing sentence works.
  const textBeforeCursor = value.slice(0, cursor);
  const mentionQuery = useMemo(() => activeMentionQuery(textBeforeCursor), [textBeforeCursor]);

  const fileMatches = useMemo(() => {
    if (mentionQuery === null) return [];
    return buildMentions(mentionQuery, cwd);
  }, [mentionQuery, cwd]);

  const showingFileSuggestions = fileMatches.length > 0;

  useEffect(() => {
    setSuggestIndex(0);
  }, [value]);

  // Derived booleans for clarity in the key handler and renderer
  const showingSuggestions = matches.length > 0;
  const showingSubOptions = !showingSuggestions && subMatches.length > 0;

  // Ink puts the terminal into bracketed-paste mode for the lifetime of this
  // hook and hands back the ENTIRE pasted string in one call, no matter how
  // large it is or how many chunks the terminal/OS split it into — this is
  // what makes big copy-pastes actually work, matching Claude Code.
  usePaste(
    (text) => {
      if (disabled) return;
      const insert =
        text.length > PASTE_CHAR_THRESHOLD || text.includes("\n") ? makePlaceholder(text) : text;
      setValue((v) => v.slice(0, cursor) + insert + v.slice(cursor));
      setCursor((c) => c + insert.length);
    },
    { isActive: !disabled }
  );

  useInput(
    (input, key) => {
      if (disabled) return;

      const showingSuggestions = matches.length > 0;

      // ── Level-1: top-level command completion ─────────────────────
      if (showingSuggestions && key.tab) {
        const next = `/${matches[Math.min(suggestIndex, matches.length - 1)].name} `;
        replaceValue(next, next.length);
        return;
      }
      if (showingSuggestions && key.upArrow) {
        setSuggestIndex((i) => Math.max(0, i - 1));
        return;
      }
      if (showingSuggestions && key.downArrow) {
        setSuggestIndex((i) => Math.min(matches.length - 1, i + 1));
        return;
      }

      // ── Level-2: sub-option completion ────────────────────────────
      // Tab inserts the highlighted sub-option after the command, preserving
      // any args hint so the user knows what to type next.
      if (showingSubOptions && key.tab) {
        const chosen = subMatches[Math.min(suggestIndex, subMatches.length - 1)];
        const spaceIdx = value.indexOf(" ");
        const cmd = value.slice(0, spaceIdx + 1); // "/agent "
        const next = `${cmd}${chosen.name} `;
        replaceValue(next, next.length);
        return;
      }
      if (showingSubOptions && key.upArrow) {
        setSuggestIndex((i) => Math.max(0, i - 1));
        return;
      }
      if (showingSubOptions && key.downArrow) {
        setSuggestIndex((i) => Math.min(subMatches.length - 1, i + 1));
        return;
      }

      // @-file mentions: Tab or Enter accepts the highlighted entry. Picking
      // a directory inserts "path/" and keeps the mention open so the user
      // can keep drilling in (or type "../" to back out); picking a file
      // inserts "path " and closes the mention, same as the slash-command
      // picker above.
      if (showingFileSuggestions && (key.tab || key.return) && !key.shift && !key.meta) {
        const at = textBeforeCursor.lastIndexOf("@");
        const chosen = fileMatches[Math.min(suggestIndex, fileMatches.length - 1)];
        const inserted = chosen.isDir ? `${chosen.insert}/` : `${chosen.insert} `;
        replaceValue(value.slice(0, at + 1) + inserted + value.slice(cursor), at + 1 + inserted.length);
        return;
      }
      if (showingFileSuggestions && key.upArrow) {
        setSuggestIndex((i) => Math.max(0, i - 1));
        return;
      }
      if (showingFileSuggestions && key.downArrow) {
        setSuggestIndex((i) => Math.min(fileMatches.length - 1, i + 1));
        return;
      }
      if (showingFileSuggestions && key.escape) {
        // Bail out of the mention (a trailing space ends the "@query" match)
        // without closing the whole input box.
        replaceValue(value.slice(0, cursor) + " " + value.slice(cursor), cursor + 1);
        return;
      }

      // ── caret movement ──────────────────────────────────────────────
      // Plain ←/→ move one character. Ctrl/Meta+←/→ jump by word, matching
      // the usual terminal/readline convention (and Claude Code's input).
      if (key.leftArrow) {
        if (key.ctrl || key.meta) {
          const before = value.slice(0, cursor);
          const trimmed = before.replace(/\s+$/, "");
          const wordStart = trimmed.search(/\S+$/);
          setCursor(wordStart === -1 ? 0 : wordStart);
        } else {
          setCursor((c) => Math.max(0, c - 1));
        }
        return;
      }
      if (key.rightArrow) {
        if (key.ctrl || key.meta) {
          const after = value.slice(cursor);
          const match = after.match(/^\s*\S+/);
          setCursor((c) => (match ? c + match[0].length : value.length));
        } else {
          setCursor((c) => Math.min(value.length, c + 1));
        }
        return;
      }
      // Home/End (and common Emacs-style bindings) jump to the start/end
      // of the current line rather than the whole (possibly multi-line)
      // value, matching normal text-editor behavior.
      if (key.home || (key.ctrl && input === "a")) {
        const lineStart = value.lastIndexOf("\n", cursor - 1) + 1;
        setCursor(lineStart);
        return;
      }
      if (key.end || (key.ctrl && input === "e")) {
        const nextNewline = value.indexOf("\n", cursor);
        setCursor(nextNewline === -1 ? value.length : nextNewline);
        return;
      }

      if (key.return) {
        if (key.shift || key.meta) {
          replaceValue(value.slice(0, cursor) + "\n" + value.slice(cursor), cursor + 1);
          return;
        }
        const trimmed = value.trim();
        if (trimmed) onSubmit(expandPastes(trimmed));
        replaceValue("", 0);
        setHistoryIndex(null);
        return;
      }

      if (key.ctrl && input === "j") {
        replaceValue(value.slice(0, cursor) + "\n" + value.slice(cursor), cursor + 1);
        return;
      }

      // Plain ↑/↓ scroll the transcript now (see App.tsx) — and, in most
      // terminals, that's also what the mouse wheel sends while an app is
      // on the alt screen (the "alternate scroll" feature vim/less/htop
      // rely on for wheel support without implementing mouse reporting
      // themselves). Recall stays available on Ctrl+↑/Ctrl+↓ instead.
      if (key.upArrow && key.ctrl && value === "") {
        if (mergedHistory.length === 0) return;
        const idx = historyIndex === null ? mergedHistory.length - 1 : Math.max(0, historyIndex - 1);
        setHistoryIndex(idx);
        replaceValue(mergedHistory[idx], mergedHistory[idx].length);
        return;
      }

      if (key.downArrow && key.ctrl && historyIndex !== null) {
        const idx = historyIndex + 1;
        if (idx >= mergedHistory.length) {
          setHistoryIndex(null);
          replaceValue("", 0);
        } else {
          setHistoryIndex(idx);
          replaceValue(mergedHistory[idx], mergedHistory[idx].length);
        }
        return;
      }

      if (key.backspace || key.delete) {
        // A pasted-text placeholder like "[Pasted text: 1 line, 125
        // words #3]" is an opaque token standing in for the real
        // clipboard content stored in pasteStore. Deleting it one
        // character at a time (the old behavior) breaks the exact-string
        // match expandPastes relies on, leaving mangled bracket text in
        // the input that doesn't turn back into the pasted content on
        // submit. So: if the text immediately before the caret is a
        // complete placeholder, remove the whole thing in one keystroke
        // and drop it from the store; otherwise just remove the character
        // immediately before the caret, wherever it is.
        const before = value.slice(0, cursor);
        const after = value.slice(cursor);
        const placeholderMatch = before.match(/\[Pasted text: \d+ lines?, \d+ words? #\d+\]$/);
        if (placeholderMatch) {
          pasteStore.delete(placeholderMatch[0]);
          const newBefore = before.slice(0, before.length - placeholderMatch[0].length);
          replaceValue(newBefore + after, newBefore.length);
          return;
        }
        if (cursor === 0) return;
        replaceValue(before.slice(0, -1) + after, cursor - 1);
        return;
      }

      if (key.ctrl && input === "u") {
        replaceValue("", 0);
        return;
      }

      // Typed (non-paste) characters only reach here — usePaste intercepts
      // pasted text on its own event channel above, so this never has to
      // guess whether a given chunk was typed or pasted. Inserted at the
      // caret so mid-line edits work, not just appends.
      if (!key.ctrl && !key.meta && input) {
        replaceValue(value.slice(0, cursor) + input + value.slice(cursor), cursor + input.length);
      }
    },
    { isActive: !disabled }
  );

  const lines = value.length ? value.split("\n") : [""];

  // Which row/column the caret is on, so we can split just that row into
  // a "before caret" / "after caret" pair when rendering.
  const cursorRow = textBeforeCursor.split("\n").length - 1;
  const cursorCol = textBeforeCursor.length - (textBeforeCursor.lastIndexOf("\n") + 1);

  // Report our total rendered height (popovers + bordered input box) so
  // the parent can reserve exactly this many rows for the live area.
  const slashPanelRows = showingSuggestions && !disabled ? matches.length + 3 : 0;
  const subPanelRows   = showingSubOptions   && !disabled ? subMatches.length + 3 : 0;
  const mentionPanelRows = showingFileSuggestions && !disabled ? fileMatches.length + 3 : 0;
  const inputBoxRows = 2 + lines.length; // border top + bottom, plus content lines
  const totalRows = slashPanelRows + subPanelRows + mentionPanelRows + inputBoxRows;
  const lastReportedRef = useRef<number | null>(null);
  useEffect(() => {
    if (lastReportedRef.current !== totalRows) {
      lastReportedRef.current = totalRows;
      onHeightChange?.(totalRows);
    }
  }, [totalRows, onHeightChange]);

  return (
    <Box flexDirection="column" width={columns}>
      {showingSuggestions && !disabled && (
        <Box flexDirection="column" borderStyle="round" borderColor="gray" paddingX={1}>
          {matches.map((c, i) => (
            <Text key={c.name} color={i === suggestIndex ? "cyan" : undefined}>
              {i === suggestIndex ? "❯ " : "  "}
              <Text bold={i === suggestIndex}>{c.usage}</Text>
              <Text dimColor>{"  " + c.description}</Text>
            </Text>
          ))}
          <Text dimColor>Tab to complete · ↑↓ to select · Enter to run as typed</Text>
        </Box>
      )}
      {showingSubOptions && !disabled && (
        <Box flexDirection="column" borderStyle="round" borderColor="gray" paddingX={1}>
          {subMatches.map((s, i) => (
            <Text key={s.name} color={i === suggestIndex ? "cyan" : undefined}>
              {i === suggestIndex ? "❯ " : "  "}
              <Text bold={i === suggestIndex}>{s.name}</Text>
              {s.args && <Text color="yellow">{" " + s.args}</Text>}
              <Text dimColor>{"  " + s.description}</Text>
            </Text>
          ))}
          <Text dimColor>Tab to complete · ↑↓ to select · Enter to run as typed</Text>
        </Box>
      )}
      {showingFileSuggestions && !disabled && (
        <Box flexDirection="column" borderStyle="round" borderColor="gray" paddingX={1}>
          {fileMatches.map((f, i) => (
            <Text key={f.display} color={i === suggestIndex ? "cyan" : f.isDir ? "blue" : undefined}>
              {i === suggestIndex ? "❯ " : "  "}
              {f.display}
            </Text>
          ))}
          <Text dimColor>Tab/Enter to select · ↑↓ to move · Esc to keep typing</Text>
        </Box>
      )}
      <Box
        borderStyle="round"
        borderColor={disabled ? "gray" : busyMode ? "yellow" : "cyan"}
        paddingX={1}
        flexDirection="column"
      >
        {lines.map((line, i) => {
          const showCaretHere = !disabled && i === cursorRow;
          const isEmptyPlaceholderLine = !line && i === 0 && value === "";
          const effectivePlaceholder = busyMode
            ? "Type to queue next message (Esc cancels & clears queue)…"
            : placeholder;
          const charUnderCursor = isEmptyPlaceholderLine ? "" : line.slice(cursorCol, cursorCol + 1);
          const afterCursor = isEmptyPlaceholderLine ? effectivePlaceholder : line.slice(cursorCol + 1);
          return (
            <Box key={i}>
              <Text color={disabled ? "gray" : busyMode ? "yellow" : "cyan"} bold>
                {i === 0 ? `${busyMode ? "⏸" : promptLabel} ` : "  "}
              </Text>
              {showCaretHere ? (
                <>
                  <Text>{line.slice(0, cursorCol)}</Text>
                  {/* Block cursor: recolor the character that's already there
                      (or a blank cell, at end of line) instead of inserting an
                      extra glyph — some fonts render a separate bar character
                      wider/taller than a normal cell, which looked like the
                      text was "magnifying" as the caret moved. */}
                  <Text backgroundColor="cyan" color="black">
                    {charUnderCursor || " "}
                  </Text>
                  <Text dimColor={isEmptyPlaceholderLine}>{afterCursor}</Text>
                </>
              ) : (
                <Text dimColor={!line && value === ""}>{line || (i === 0 ? placeholder : "")}</Text>
              )}
            </Box>
          );
        })}
      </Box>
    </Box>
  );
}
