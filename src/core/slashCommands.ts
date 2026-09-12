export interface SlashCommandSpec {
  name: string;
  usage: string;
  description: string;
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
    name: "mcp",        usage: "/mcp <add|remove|list> [args]",               description: "manage MCP server connections",
    subOptions: [
      { name: "add",    description: "connect a new MCP server", args: "<name> <url>" },
      { name: "remove", description: "disconnect an MCP server", args: "<name|url>" },
      { name: "list",   description: "show all configured MCP servers" },
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
    name: "agent",      usage: "/agent <create|use|info|list|delete> [name]",  description: "manage custom AI agents",
    subOptions: [
      { name: "create", description: "create a new agent interactively" },
      { name: "use",    description: "activate an agent for this session",      args: "<name>" },
      { name: "info",   description: "show system prompt + mcps + plugins",     args: "<name>" },
      { name: "list",   description: "show all saved agents" },
      { name: "delete", description: "delete a saved agent",                    args: "<name>" },
    ],
  },
  { name: "exit",       usage: "/exit",                                         description: "quit" },
];
