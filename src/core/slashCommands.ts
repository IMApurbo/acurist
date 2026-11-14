import { AGENT_PERSONAS } from "./agent.js";
import { loadSkills, resolveSkillCall } from "./skills.js";

export interface SlashCommandSpec {
  name: string;
  usage: string;
  description: string;
  /** True for entries generated from installed skills (not built-in commands) */
  isSkill?: boolean;
  /** Sub-options shown after the user types "/command " */
  subOptions?: SubOption[];
}

export interface SubOption {
  /** The sub-command word, e.g. "create" */
  name: string;
  /** Short description shown in the picker */
  description: string;
  /** Optional hint about further args, e.g. "<name>" */
  args?: string;
}

export const SLASH_COMMANDS: SlashCommandSpec[] = [
  { name: "help",       usage: "/help",                                       description: "show available commands" },
  { name: "clear",      usage: "/clear",                                       description: "clear transcript and reset context" },
  { name: "undo",       usage: "/undo",                                        description: "remove the last user+assistant exchange" },
  {
    name: "mode",       usage: "/mode auto|manual",                            description: "toggle global shell permission mode",
    subOptions: [
      { name: "auto",   description: "run shell/write tools without confirmation" },
      { name: "manual", description: "confirm before every shell/write tool" },
    ],
  },
  {
    name: "perm",       usage: "/perm <tool> auto|manual|reset",               description: "set per-tool permission override",
    subOptions: [
      { name: "auto",   description: "always allow this tool without confirmation", args: "<tool>" },
      { name: "manual", description: "always confirm before this tool",             args: "<tool>" },
      { name: "reset",  description: "remove per-tool override, use global mode",   args: "<tool>" },
    ],
  },
  {
    name: "model",      usage: "/model [list|<name>]",                         description: "show current model, list available, or switch",
    subOptions: [
      { name: "list",   description: "show available models from proxy + built-in defaults" },
    ],
  },
  { name: "proxy",      usage: "/proxy [<url>]",                               description: "show or set proxy base URL (persisted)" },
  { name: "save",       usage: "/save <name>",                                 description: "save session to ~/.acurist/sessions/<name>.json" },
  { name: "load",       usage: "/load <name>",                                 description: "restore a saved session" },
  { name: "sessions",   usage: "/sessions",                                    description: "list saved sessions" },
  { name: "export",     usage: "/export [filename]",                           description: "dump transcript to a Markdown file in cwd" },
  {
    name: "template",   usage: "/template <add|use|list|remove> [args]",       description: "manage prompt templates",
    subOptions: [
      { name: "add",    description: "save a new template",    args: "<name> <body>" },
      { name: "use",    description: "expand and send a template", args: "<name> [file]" },
      { name: "list",   description: "show all saved templates" },
      { name: "remove", description: "delete a template",      args: "<name>" },
    ],
  },
  { name: "history",    usage: "/history [query]",                             description: "fuzzy-search persistent input history" },
  {
    name: "mcp",        usage: "/mcp <add|remove|list|tools> [args]",               description: "manage MCP server connections",
    subOptions: [
      { name: "add",    description: "connect an MCP server (http)", args: "<name> <url> [--bearer <token>]" },
      { name: "remove", description: "disconnect an MCP server", args: "<name|url>" },
      { name: "list",   description: "show servers + live connection status" },
      { name: "tools",  description: "list the tools MCP servers expose", args: "[name]" },
    ],
  },
  {
    name: "telegram",   usage: "/telegram <config|start|stop|status>",         description: "Telegram bot bridge",
    subOptions: [
      { name: "config", description: "set bot token and user ID" },
      { name: "start",  description: "start the Telegram bridge" },
      { name: "stop",   description: "stop the Telegram bridge" },
      { name: "status", description: "show bridge status" },
    ],
  },
  {
    name: "plugin",     usage: "/plugin <browse|add|remove|list|info|marketplace>", description: "plugin marketplace",
    subOptions: [
      { name: "browse",       description: "list available plugins from all marketplaces" },
      { name: "add",          description: "install a plugin",         args: "<name>" },
      { name: "remove",       description: "uninstall a plugin",       args: "<name>" },
      { name: "list",         description: "show installed plugins" },
      { name: "info",         description: "show plugin details",      args: "<name>" },
      { name: "marketplace",  description: "manage plugin marketplaces" },
    ],
  },
  {
    name: "skill",      usage: "/skill <list|install|remove|info|reload>", description: "manage skills — any skill runs as /<skill-name>",
    subOptions: [
      { name: "list",    description: "show installed skills" },
      { name: "install", description: "install a .skill file, SKILL.md, folder, URL or owner/repo", args: "<src>" },
      { name: "remove",  description: "uninstall a skill",        args: "<name>" },
      { name: "info",    description: "show a skill's details",   args: "<name>" },
      { name: "run",     description: "run a skill (same as /<name>)", args: "<name> [args]" },
      { name: "reload",  description: "rescan skill folders" },
    ],
  },
  {
    name: "agent",      usage: "/agent <name>",                                description: "switch the active agent persona — pick from the list",
    subOptions: [
      ...AGENT_PERSONAS.map((a) => ({ name: a.id, description: a.description })),
      { name: "list",   description: "show all built-in agents" },
      { name: "info",   description: "show an agent's full system prompt", args: "<name>" },
    ],
  },
  { name: "exit",       usage: "/exit",                                         description: "quit" },
];

/** Names that always belong to built-in commands (a skill of the same name needs `/skill run <name>`). */
export const RESERVED_COMMAND_NAMES: ReadonlySet<string> = new Set([...SLASH_COMMANDS.map((c) => c.name), "quit"]);

/** Built-in commands followed by one entry per user-invocable skill. Cheap: skills are cached. */
export function getSlashCommands(): SlashCommandSpec[] {
  let skills: ReturnType<typeof loadSkills> = [];
  try { skills = loadSkills(); } catch { /* skills are optional */ }
  const extra: SlashCommandSpec[] = skills
    .filter((s) => s.userInvocable && !RESERVED_COMMAND_NAMES.has(s.name))
    .map((s) => ({
      name: s.name,
      usage: `/${s.name}${s.argumentHint ? " " + s.argumentHint : " [args]"}`,
      description: `skill · ${s.description || "(no description)"}`,
      isSkill: true,
    }));
  return [...SLASH_COMMANDS, ...extra];
}

/** If `text` is "/<skill> args", the prompt to send the model plus what to show in the transcript. */
export function resolveSlashSkill(text: string): { prompt: string; display: string; name: string } | null {
  if (!text.startsWith("/")) return null;
  const call = resolveSkillCall(text, RESERVED_COMMAND_NAMES);
  return call ? { prompt: call.prompt, display: text.trim(), name: call.skill.name } : null;
}
