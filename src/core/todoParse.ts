export interface ParsedTodo { text: string; status: string }

const VALID_TODO_STATUS = new Set(["pending", "in_progress", "completed"]);

function normTodoStatus(s: string): string {
  const v = s.trim().toLowerCase().replace(/[\s-]+/g, "_");
  if (v === "done" || v === "complete" || v === "finished") return "completed";
  if (v === "inprogress" || v === "active" || v === "running") return "in_progress";
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
