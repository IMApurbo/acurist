export type Role = "user" | "assistant";

export interface TextBlock   { type: "text"; text: string }
export interface ToolUseBlock{ type: "tool_use"; id: string; name: string; input: Record<string, unknown> }
export interface ToolResultBlock { type: "tool_result"; tool_use_id: string; content: string; is_error?: boolean }

export type ContentBlock = TextBlock | ToolUseBlock | ToolResultBlock;
export interface Message { role: Role; content: ContentBlock[] }

// ── Transcript events shown in the UI ─────────────────────────────────────────
export type TranscriptEvent =
  | { kind: "user";         text: string;                           id: string }
  | { kind: "assistant";    text: string;                           id: string }
  | { kind: "tool_call";    name: string; input: Record<string, unknown>; id: string }
  | { kind: "tool_result";  name: string; output: string; isError: boolean; id: string }
  | { kind: "system";       text: string;                           id: string }
  | { kind: "banner";       config: AgentConfig;                    id: string }
  | { kind: "todos";        todos: Todo[];                          id: string }
  | { kind: "plugin_active";plugins: string[];                      id: string };

export interface Todo {
  text:   string;
  status: "pending" | "in_progress" | "completed";
}

export type PermissionMode    = "auto" | "manual";
export type ToolPermissionMap = Partial<Record<string, PermissionMode>>;

export interface AgentConfig {
  proxyBaseUrl:     string;
  model:            string;
  cwd:              string;
  mode:             PermissionMode;
  toolPermissions?: ToolPermissionMap;
  version?:         string;
  author?:          string;
  startupAgent?:    string;
}

export interface TokenUsage {
  inputTokens:  number;
  outputTokens: number;
  totalTokens:  number;
}

export interface McpServer {
  name:     string;
  url:      string;
  addedAt:  string;
}

export interface SavedSession {
  version:      1;
  savedAt:      string;
  model:        string;
  proxyBaseUrl: string;
  messages:     Message[];
  transcript:   TranscriptEvent[];
}
