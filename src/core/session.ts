import fs from "node:fs/promises";
import path from "node:path";
import type { Message, TranscriptEvent } from "../types.js";

export interface SessionFile {
  version: 1;
  savedAt: string;
  model: string;
  proxyBaseUrl: string;
  messages: Message[];
  transcript: TranscriptEvent[];
}

/** Default directory: ~/.acurist/sessions/ */
function sessionsDir(): string {
  const home = process.env.HOME ?? process.env.USERPROFILE ?? ".";
  return path.join(home, ".acurist", "sessions");
}

function sessionPath(name: string): string {
  const safe = name.replace(/[^a-z0-9_-]/gi, "_");
  return path.join(sessionsDir(), `${safe}.json`);
}

export async function saveSession(
  name: string,
  model: string,
  proxyBaseUrl: string,
  messages: Message[],
  transcript: TranscriptEvent[]
): Promise<string> {
  const dir = sessionsDir();
  await fs.mkdir(dir, { recursive: true });
  const file: SessionFile = {
    version: 1,
    savedAt: new Date().toISOString(),
    model,
    proxyBaseUrl,
    messages,
    transcript,
  };
  const p = sessionPath(name);
  await fs.writeFile(p, JSON.stringify(file, null, 2), "utf-8");
  return p;
}

export async function loadSession(name: string): Promise<SessionFile> {
  const p = sessionPath(name);
  const raw = await fs.readFile(p, "utf-8");
  const data = JSON.parse(raw) as SessionFile;
  if (data.version !== 1) throw new Error(`Unknown session version: ${data.version}`);
  return data;
}

export async function listSessions(): Promise<{ name: string; savedAt: string }[]> {
  const dir = sessionsDir();
  try {
    const entries = await fs.readdir(dir);
    const results: { name: string; savedAt: string }[] = [];
    for (const e of entries) {
      if (!e.endsWith(".json")) continue;
      try {
        const raw = await fs.readFile(path.join(dir, e), "utf-8");
        const data = JSON.parse(raw) as SessionFile;
        results.push({ name: e.replace(/\.json$/, ""), savedAt: data.savedAt });
      } catch {
        // skip corrupt files
      }
    }
    results.sort((a, b) => b.savedAt.localeCompare(a.savedAt));
    return results;
  } catch {
    return [];
  }
}
