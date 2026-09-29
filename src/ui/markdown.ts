import { Marked } from "marked";
import { markedTerminal } from "marked-terminal";

// marked-terminal v6+ is a plugin registered via marked.use(), not a
// renderer class you construct yourself — that's the correct integration
// for marked v12. (An earlier version of this file used the old
// `new TerminalRenderer()` pattern, which silently did nothing here and
// let raw markdown syntax like `*` bullets and `###` headings pass
// through unrendered.)
//
// A fresh Marked instance is built per call (instead of calling the global
// `marked.use()` once at import time) so the reflow width always matches
// the terminal's *current* column count. Doing this once at module load
// baked in whatever width the terminal happened to be at process start —
// resize the window (or run inside a tmux/screen pane that gets resized)
// before your first reply and every code block / table afterward would
// wrap at the stale width instead of the real one.
function buildRenderer(): Marked {
  const width = process.stdout.columns ? process.stdout.columns - 4 : 76;
  const instance = new Marked();
  instance.use(
    markedTerminal({
      width,
      reflowText: true,
    }) as any
  );
  return instance;
}

/** Render a chunk of markdown to an ANSI string suitable for an Ink <Text>. */
export function renderMarkdown(src: string): string {
  try {
    const out = buildRenderer().parse(src, { async: false }) as string;
    return out.replace(/\n+$/, "");
  } catch {
    return src;
  }
}
