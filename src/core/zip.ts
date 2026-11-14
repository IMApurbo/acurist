/**
 * zip.ts — minimal, dependency-free ZIP reader.
 *
 * A `.skill` file is just a ZIP archive containing a skill folder (with a
 * SKILL.md inside). GitHub's codeload endpoint also hands out ZIPs, which is
 * how we fetch whole skill folders without hitting the rate-limited REST API.
 *
 * Supports "stored" (0) and "deflate" (8) entries, which covers every archive
 * produced by zip, Info-ZIP, Python's zipfile, Claude's skill packager and
 * GitHub. ZIP64 and encryption are not supported (and rejected clearly).
 */

import zlib from "node:zlib";

export interface ZipEntry {
  /** Normalised, forward-slash path with no leading "/" or "./" */
  name: string;
  isDir: boolean;
  size: number;
  /** Decompress and return the entry's bytes */
  read(): Buffer;
}

const EOCD_SIG = 0x06054b50;
const CEN_SIG  = 0x02014b50;
const LOC_SIG  = 0x04034b50;

/** Normalise an entry name and reject anything that could escape the target dir. */
export function safeEntryName(raw: string): string | null {
  const n = raw.replace(/\\/g, "/").replace(/^(\.\/)+/, "").replace(/^\/+/, "");
  if (!n) return null;
  const parts = n.split("/");
  if (parts.some((p) => p === ".." )) return null;       // path traversal
  if (/^[a-zA-Z]:/.test(parts[0])) return null;           // windows drive
  return n;
}

export function looksLikeZip(buf: Buffer): boolean {
  if (buf.length >= 4 && buf.readUInt32LE(0) === LOC_SIG) return true;
  return buf.length >= 22 && buf.readUInt32LE(0) === EOCD_SIG; // empty zip
}

export function readZip(buf: Buffer): ZipEntry[] {
  // Locate the End Of Central Directory record (scan backwards over a possible comment)
  let eocd = -1;
  const min = Math.max(0, buf.length - 22 - 0xffff);
  for (let i = buf.length - 22; i >= min; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIG) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error("Not a valid zip/.skill file (no central directory found)");

  const total  = buf.readUInt16LE(eocd + 10);
  let   offset = buf.readUInt32LE(eocd + 16);
  if (total === 0xffff || offset === 0xffffffff) throw new Error("ZIP64 archives are not supported");

  const entries: ZipEntry[] = [];
  for (let i = 0; i < total; i++) {
    if (offset + 46 > buf.length || buf.readUInt32LE(offset) !== CEN_SIG) {
      throw new Error("Corrupt zip: bad central directory entry");
    }
    const flags      = buf.readUInt16LE(offset + 8);
    const method     = buf.readUInt16LE(offset + 10);
    const compSize   = buf.readUInt32LE(offset + 20);
    const size       = buf.readUInt32LE(offset + 24);
    const nameLen    = buf.readUInt16LE(offset + 28);
    const extraLen   = buf.readUInt16LE(offset + 30);
    const commentLen = buf.readUInt16LE(offset + 32);
    const localOff   = buf.readUInt32LE(offset + 42);
    const rawName    = buf.toString("utf8", offset + 46, offset + 46 + nameLen);
    offset += 46 + nameLen + extraLen + commentLen;

    const name = safeEntryName(rawName);
    if (!name) continue;
    const isDir = rawName.endsWith("/");

    entries.push({
      name: isDir ? name.replace(/\/+$/, "") : name,
      isDir,
      size,
      read() {
        if (isDir) return Buffer.alloc(0);
        if (flags & 1) throw new Error(`"${name}" is encrypted — not supported`);
        if (localOff + 30 > buf.length || buf.readUInt32LE(localOff) !== LOC_SIG) {
          throw new Error(`Corrupt zip: bad local header for "${name}"`);
        }
        const lName  = buf.readUInt16LE(localOff + 26);
        const lExtra = buf.readUInt16LE(localOff + 28);
        const start  = localOff + 30 + lName + lExtra;
        const data   = buf.subarray(start, start + compSize);
        if (method === 0) return Buffer.from(data);
        if (method === 8) return zlib.inflateRawSync(data);
        throw new Error(`"${name}" uses unsupported compression method ${method}`);
      },
    });
  }
  return entries;
}
