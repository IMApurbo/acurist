export interface ParsedTodo { text: string; status: string }

const VALID_TODO_STATUS = new Set(["pending", "in_progress", "completed"]);

function normTodoStatus(s: string): string {
  const v = s.trim().toLowerCase().replace(/[\s-]+/g, "_");
  if (v === "done" || v === "complete" || v === "finished") return "completed";
  if (v === "inprogress" || v === "active" || v === "running" || v === "doing" || v === "started") return "in_progress";
  if (v === "todo" || v === "to_do" || v === "not_started" || v === "notstarted" || v === "open" || v === "queued" || v === "planned") return "pending";
  return v;
}

/**
 * Parses the newline-delimited "text | status" string sent to update_todos.
 * Lines without a valid trailing "| status" (stray answer text, code fences,
 * trees, etc.) are ignored. If NO line has a valid status, falls back to
 * treating each plain line as a pending todo.
 */
export function parseTodoString(raw: string): ParsedTodo[] {
  const lines = raw.split("\n").map((l) => l.trim()).filter(Boolean);
  const strict: ParsedTodo[] = [];
  for (const l of lines) {
    const sep = l.lastIndexOf("|");
    if (sep === -1) continue;
    const status = normTodoStatus(l.slice(sep + 1));
    const text = l.slice(0, sep).trim();
    if (text && VALID_TODO_STATUS.has(status)) strict.push({ text, status });
  }
  if (strict.length) return strict;
  return lines
    .filter((l) => !l.startsWith("```"))
    .map((text) => ({ text, status: "pending" }));
}

/** Accepts an array of strings or {text|content|title|step, status} objects. */
export function normalizeTodoArray(raw: unknown): ParsedTodo[] {
  if (!Array.isArray(raw)) return [];
  const out: ParsedTodo[] = [];
  for (const item of raw) {
    if (typeof item === "string") { out.push(...parseTodoString(item)); continue; }
    if (!item || typeof item !== "object") continue;
    const o = item as Record<string, unknown>;
    const text = [o.text, o.content, o.title, o.step, o.task].find((v) => typeof v === "string" && v.trim()) as string | undefined;
    if (!text) continue;
    const status = typeof o.status === "string" ? normTodoStatus(o.status) : "pending";
    out.push({ text: text.trim(), status: VALID_TODO_STATUS.has(status) ? status : "pending" });
  }
  return out;
}
