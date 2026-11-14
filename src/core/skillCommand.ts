/**
 * skillCommand.ts — the `/skill` command.
 *
 *   /skill                          list installed skills
 *   /skill install <src>            install from a .skill file, SKILL.md, folder,
 *                                   URL, or GitHub (owner/repo[/path][@ref])
 *   /skill remove <name>            uninstall
 *   /skill info <name>              show a skill's details
 *   /skill run <name> [args]        run a skill (same as /<name> [args])
 *   /skill reload                   rescan skill folders now
 *
 * Any skill can also be run directly with /<skill-name> [args].
 */

import {
  loadSkills, findSkill, installSkillFrom, removeSkill, invalidateSkills, takeSkillNotices,
  listBundledFiles, userSkillsDir, type Skill,
} from "./skills.js";
import path from "node:path";

const dim   = (s: string) => `\x1b[2m${s}\x1b[0m`;
const bold  = (s: string) => `\x1b[1m${s}\x1b[0m`;
const green = (s: string) => `\x1b[32m${s}\x1b[0m`;
const cyan  = (s: string) => `\x1b[36m${s}\x1b[0m`;
const red   = (s: string) => `\x1b[31m${s}\x1b[0m`;

const SOURCE_LABEL: Record<Skill["source"], string> = {
  project: "project", user: "user", "claude-project": "claude (project)", "claude-user": "claude (user)", plugin: "plugin",
};

const looksLikeSource = (s: string) =>
  /^https?:\/\//i.test(s) || /\.(skill|zip|md)$/i.test(s) || /^[.~\/]/.test(s) || /^[\w.-]+\/[\w.-]+/.test(s);

export const SKILL_HELP =
  bold("Skill commands:\n") +
  `  /<skill-name> [args]               — run any installed skill\n` +
  `  /skill list                        — list installed skills\n` +
  `  /skill install <src>               — install from a .skill file, SKILL.md, folder, URL or GitHub owner/repo[/path]\n` +
  `  /skill remove <name>               — uninstall a skill\n` +
  `  /skill info <name>                 — show a skill's details\n` +
  `  /skill reload                      — rescan skill folders\n\n` +
  dim(`Auto-install: drop a .skill file into ${userSkillsDir()} (or ./.acurist/skills) and it installs itself.\n`) +
  dim(`Also read: ./.claude/skills and ~/.claude/skills (Claude Code skills work as-is).`);

function listText(): string {
  const skills = loadSkills(true);
  if (!skills.length) {
    return (
      "No skills installed.\n\n" +
      `Install one:   /skill install <file.skill | SKILL.md | folder | url | owner/repo>\n` +
      `Or drop a .skill file / skill folder into ${userSkillsDir()}\n` +
      `Or browse:     /plugin browse`
    );
  }
  const w = Math.min(28, Math.max(...skills.map((s) => s.name.length)) + 1);
  const rows = skills.map((s) => {
    const flags = [!s.userInvocable ? "model-only" : "", !s.modelInvocable ? "manual-only" : ""].filter(Boolean).join(", ");
    const desc = s.description.length > 80 ? s.description.slice(0, 79) + "…" : s.description;
    return `  ${cyan("/" + s.name.padEnd(w))} ${desc}\n  ${" ".repeat(w + 2)}${dim(SOURCE_LABEL[s.source] + (flags ? " · " + flags : ""))}`;
  });
  return `${skills.length} skill${skills.length > 1 ? "s" : ""} installed:\n\n${rows.join("\n")}\n\n${dim("Run one with /<name> [args].")}`;
}

function infoText(s: Skill): string {
  const files = listBundledFiles(s, 15);
  return (
    `${bold("/" + s.name)}${s.argumentHint ? " " + dim(s.argumentHint) : ""}\n${"─".repeat(40)}\n` +
    `${s.description || "(no description)"}\n\n` +
    `Source:   ${SOURCE_LABEL[s.source]}\n` +
    `Location: ${s.file}\n` +
    `Size:     ${s.body.length} chars` +
    (files.length ? `\nFiles:    ${files.join(", ")}` : "") +
    `\n\n${dim(s.body.slice(0, 400))}${s.body.length > 400 ? "…" : ""}`
  );
}

export async function installAndReport(source: string): Promise<string> {
  try {
    const results = await installSkillFrom(source);
    invalidateSkills();
    const lines = results.map((r) => `  ${green("✓")} /${r.name}${r.replaced ? dim(" (updated)") : ""}`);
    const shown = lines.slice(0, 40).join("\n") + (lines.length > 40 ? `\n  …and ${lines.length - 40} more` : "");
    return (
      green(`Installed ${results.length} skill${results.length > 1 ? "s" : ""}`) + dim(` → ${path.relative(process.cwd(), results[0].dir) || results[0].dir}`) + "\n" +
      shown + "\n\n" + dim("Ready now — run with /<name>, or just describe the task and the model will pick it up.")
    );
  } catch (e: any) {
    return red(`✗ Could not install: ${e?.message ?? e}`);
  }
}

export async function handleSkillCommand(args: string[]): Promise<string> {
  const sub = (args[0] ?? "").toLowerCase();
  const rest = args.slice(1).join(" ").trim();

  if (!sub || sub === "list" || sub === "ls") {
    const notices = takeSkillNotices();
    return (notices.length ? notices.map((n) => dim("• " + n)).join("\n") + "\n\n" : "") + listText();
  }

  if (sub === "reload" || sub === "refresh" || sub === "rescan") {
    invalidateSkills();
    const n = loadSkills(true).length;
    const notices = takeSkillNotices();
    return (notices.length ? notices.join("\n") + "\n" : "") + green(`✓ ${n} skill${n === 1 ? "" : "s"} loaded.`);
  }

  if (sub === "install" || sub === "add" || sub === "i") {
    if (!rest) return "Usage: /skill install <file.skill | SKILL.md | folder | url | owner/repo[/path][@ref]>";
    return installAndReport(rest);
  }

  if (sub === "remove" || sub === "rm" || sub === "uninstall" || sub === "delete") {
    if (!rest) return "Usage: /skill remove <name>";
    const r = removeSkill(rest);
    return r.ok ? green("✓ " + r.message) : red(r.message);
  }

  if (sub === "info" || sub === "show") {
    if (!rest) return "Usage: /skill info <name>";
    const s = findSkill(rest);
    return s ? infoText(s) : red(`Skill "${rest}" not found. Run /skill list.`);
  }

  if (sub === "run") return rest ? red(`Skill "${rest.split(/\s+/)[0]}" not found. Run /skill list.`) : "Usage: /skill run <name> [args]";

  if (sub === "help") return SKILL_HELP;

  // `/skill ./thing.skill`, `/skill owner/repo` → treat as an install
  if (looksLikeSource(args.join(" ").trim())) return installAndReport(args.join(" ").trim());

  return red(`Unknown subcommand "${sub}".\n`) + SKILL_HELP;
}
