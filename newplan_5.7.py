#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║              HACKERS AI — Advanced Linux Agent               ║
║         General Purpose + Penetration Testing Suite          ║
║                   Single-File Architecture                   ║
╚══════════════════════════════════════════════════════════════╝
"""

import os
import sys
import json
import sqlite3
import subprocess
import tempfile
import shutil
import re
import time
import textwrap
from datetime import datetime
from typing import Optional
import threading
import signal

# ── Dependency check ──────────────────────────────────────────
try:
    from freellm import FreeLLM
except ImportError:
    print("[!] freellm not installed. Run: pip install freellm")
    sys.exit(1)

# ══════════════════════════════════════════════════════════════
# SECTION 1 — CONSTANTS & CONFIG
# ══════════════════════════════════════════════════════════════

DB_PATH       = os.path.expanduser("~/.hackers_ai.db")
MAX_HISTORY   = 10
MAX_RETRIES   = 3
DEFAULT_MODEL = "claude"
VERSION       = "4.7.0"   # bump this to bust __pycache__

BANNER = r"""
  ██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗ ███████╗     █████╗ ██╗
  ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗██╔════╝    ██╔══██╗██║
  ███████║███████║██║     █████╔╝ █████╗  ██████╔╝███████╗    ███████║██║
  ██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗╚════██║    ██╔══██║██║
  ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║███████║    ██║  ██║██║
  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝    ╚═╝  ╚═╝╚═╝
         Advanced Linux Agent · General Purpose + Penetration Testing
"""

COLORS = {
    "reset":   "\033[0m",  "bold":    "\033[1m",   "dim":     "\033[2m",
    "red":     "\033[91m", "green":   "\033[92m",  "yellow":  "\033[93m",
    "blue":    "\033[94m", "magenta": "\033[95m",  "cyan":    "\033[96m",
    "white":   "\033[97m",
}

def c(color: str, text: str) -> str:
    return f"{COLORS.get(color,'')}{text}{COLORS['reset']}"

# ══════════════════════════════════════════════════════════════
# SECTION 2 — DATABASE (SQLite3 Memory)
# ══════════════════════════════════════════════════════════════

class MemoryDB:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS conversations (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    role      TEXT    NOT NULL,
                    content   TEXT    NOT NULL,
                    model     TEXT,
                    timestamp TEXT    DEFAULT (datetime('now'))
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS task_memory (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id   TEXT    NOT NULL,
                    step      INTEGER NOT NULL,
                    tool      TEXT,
                    command   TEXT,
                    output    TEXT,
                    status    TEXT,
                    timestamp TEXT    DEFAULT (datetime('now'))
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS target_notes (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    target    TEXT    NOT NULL,
                    note      TEXT    NOT NULL,
                    timestamp TEXT    DEFAULT (datetime('now'))
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    name      TEXT,
                    data      TEXT,
                    timestamp TEXT    DEFAULT (datetime('now'))
                )
            """)
            conn.commit()

    def add_message(self, role: str, content: str, model: str = DEFAULT_MODEL):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO conversations (role, content, model) VALUES (?, ?, ?)",
                (role, content, model)
            )
            conn.commit()

    def get_history(self, limit: int = MAX_HISTORY) -> list:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT role, content FROM conversations ORDER BY id DESC LIMIT ?",
                (limit,)
            ).fetchall()
        return [{"role": r[0], "content": r[1]} for r in reversed(rows)]

    def clear_history(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM conversations")
            conn.commit()

    # ── Target Notes ──────────────────────────────────────
    def add_note(self, target: str, note: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("INSERT INTO target_notes (target, note) VALUES (?,?)", (target, note))
            conn.commit()

    def get_notes(self, target: str = None) -> list:
        with sqlite3.connect(self.db_path) as conn:
            if target:
                rows = conn.execute(
                    "SELECT target, note, timestamp FROM target_notes WHERE target LIKE ? ORDER BY id DESC",
                    (f"%{target}%",)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT target, note, timestamp FROM target_notes ORDER BY id DESC LIMIT 50"
                ).fetchall()
        return [{"target": r[0], "note": r[1], "timestamp": r[2]} for r in rows]

    def delete_notes(self, target: str = None):
        with sqlite3.connect(self.db_path) as conn:
            if target:
                conn.execute("DELETE FROM target_notes WHERE target LIKE ?", (f"%{target}%",))
            else:
                conn.execute("DELETE FROM target_notes")
            conn.commit()

    # ── Session export ─────────────────────────────────────
    def export_session(self, name: str = None) -> str:
        """Export full session (history + task logs) as markdown string."""
        history = self.get_history(200)
        with sqlite3.connect(self.db_path) as conn:
            tasks = conn.execute(
                "SELECT task_id, step, tool, command, output, status, timestamp FROM task_memory ORDER BY id"
            ).fetchall()
            notes = conn.execute(
                "SELECT target, note, timestamp FROM target_notes ORDER BY id"
            ).fetchall()
        ts    = datetime.now().strftime("%Y-%m-%d %H:%M")
        title = name or f"Hackers AI Session — {ts}"
        lines = [f"# {title}", f"*Exported: {ts}*", ""]
        if notes:
            lines += ["## Target Notes", ""]
            for n in notes:
                lines.append(f"- **{n[0]}** ({n[2][:16]}): {n[1]}")
            lines.append("")
        if tasks:
            lines += ["## Command Log", ""]
            cur_task = None
            for t in tasks:
                if t[0] != cur_task:
                    cur_task = t[0]
                    lines.append(f"### Task {cur_task}")
                icon = "✓" if t[5] == "success" else "✗"
                lines.append(f"**Step {t[1]}** `{t[3]}` — {icon} {t[5]}")
                if t[4] and t[4].strip():
                    lines.append("```\n" + t[4][:500] + "\n```")
            lines.append("")
        if history:
            lines += ["## Conversation", ""]
            for h in history:
                role = "**You**" if h["role"] == "user" else "**AI**"
                lines.append(f"{role}: {h['content'][:300]}")
            lines.append("")
        return "\n".join(lines)

    def log_task_step(self, task_id: str, step: int, tool: str,
                      command: str, output: str, status: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO task_memory (task_id, step, tool, command, output, status)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (task_id, step, tool, command, output, status)
            )
            conn.commit()

# ══════════════════════════════════════════════════════════════
# SECTION 3 — SYSTEM PROFILER (runs real live commands)
# ══════════════════════════════════════════════════════════════

def _quick_cmd(cmd: str, timeout: int = 5) -> str:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True,
                           text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip()
    except Exception:
        return ""

class SystemProfiler:
    @staticmethod
    def is_root() -> bool:
        return os.geteuid() == 0

    @staticmethod
    def get_available_tools() -> list:
        pentest_tools = [
            "nmap","nikto","sqlmap","hydra","gobuster","dirb","wfuzz",
            "msfconsole","aircrack-ng","airmon-ng","airodump-ng","aireplay-ng",
            "hashcat","john","wireshark","tshark","netcat","nc","curl","wget",
            "masscan","rustscan","subfinder","amass","ffuf","wpscan","nuclei",
            "whatweb","wafw00f","dnsenum","dnsrecon","fierce","theharvester",
            "recon-ng","sslscan","sslyze","openssl","tcpdump","ettercap",
            "bettercap","responder","enum4linux","smbclient","crackmapexec",
            "evil-winrm","binwalk","strings","file","ltrace","strace","gdb",
            "python3","pip","git","docker","msfvenom","searchsploit",
            "dirsearch","feroxbuster","katana","httpx","dnsx","naabu",
            "dalfox","xsstrike","arjun","cloudbrute","beef-xss","setoolkit",
        ]
        return [t for t in pentest_tools if shutil.which(t)]

    def profile(self) -> dict:
        return {
            "uname":    _quick_cmd("uname -a"),
            "hostname": _quick_cmd("hostname"),
            "whoami":   _quick_cmd("whoami"),
            "root":     self.is_root(),
            "distro":   _quick_cmd(
                "cat /etc/os-release 2>/dev/null | grep PRETTY_NAME "
                "| cut -d= -f2 | tr -d '\"'"
            ),
            "cpu":      _quick_cmd(
                "lscpu 2>/dev/null | grep 'Model name' | cut -d: -f2 | xargs"
            ),
            "ram":      _quick_cmd(
                "free -h 2>/dev/null | awk '/^Mem:/{print $2\" total, \"$3\" used, \"$4\" free\"}'"
            ),
            "disk":     _quick_cmd(
                "df -h / 2>/dev/null | awk 'NR==2{print $2\" total, \"$3\" used, \"$4\" free\"}'"
            ),
            "ip":       _quick_cmd("hostname -I 2>/dev/null | awk '{print $1}'"),
            "kernel":   _quick_cmd("uname -r"),
            "arch":     _quick_cmd("uname -m"),
            "shell":    os.environ.get("SHELL", "bash"),
            "available_tools": self.get_available_tools(),
        }

# ══════════════════════════════════════════════════════════════
# SECTION 2b — SPINNER (live progress for long commands)
# ══════════════════════════════════════════════════════════════

class Spinner:
    """Non-blocking terminal spinner for long-running operations."""
    FRAMES = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

    def __init__(self, label: str = "Working"):
        self.label   = label
        self._stop   = threading.Event()
        self._thread = None

    def _spin(self):
        i = 0
        while not self._stop.is_set():
            frame = self.FRAMES[i % len(self.FRAMES)]
            sys.stdout.write("\r  " + COLORS['cyan'] + frame + COLORS['reset'] + "  " + self.label + "...  ")
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1
        sys.stdout.write("\r" + " " * (len(self.label) + 12) + "\r")
        sys.stdout.flush()

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=0.5)

    def __enter__(self):
        self.start(); return self

    def __exit__(self, *_):
        self.stop()

# ══════════════════════════════════════════════════════════════
# SECTION 4 — COMMAND EXECUTOR (real-time streaming)
# ══════════════════════════════════════════════════════════════

class CommandExecutor:
    """
    Execute shell commands with:
    - Real-time stdout streaming
    - Ctrl+C = graceful cancel of current step (SIGTERM → SIGKILL after 3s)
    - Thread-safe: used by parallel executor
    """

    def run(self, command: str, timeout: int = 180,
            label: str = "", lock: threading.Lock = None) -> dict:
        tag = f"[{label}] " if label else ""
        _print = (lambda msg: _locked_print(lock, msg)) if lock else print

        _print(c("dim", f"\n  ┌─ {tag}$ {command}"))
        stdout_lines = []
        stderr_lines = []
        start        = time.time()
        process      = None

        def _kill():
            if process and process.poll() is None:
                try:
                    process.terminate()
                    time.sleep(3)
                    if process.poll() is None:
                        process.kill()
                except Exception:
                    pass

        try:
            process = subprocess.Popen(
                command, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1,
                preexec_fn=os.setsid   # own process group for clean kill
            )
            try:
                for line in iter(process.stdout.readline, ''):
                    line = line.rstrip()
                    if line:
                        _print(c("dim", f"  │ {tag}") + line)
                        stdout_lines.append(line)
            except KeyboardInterrupt:
                _print(c("yellow", f"\n  ├─ {tag}⚡ Ctrl+C — cancelling step..."))
                _kill()
                elapsed = round(time.time() - start, 2)
                _print(c("yellow", f"  └─ {tag}✗ Cancelled by user ({elapsed}s)"))
                return {
                    "command": command, "stdout": "\n".join(stdout_lines),
                    "stderr": "Cancelled by user", "returncode": -2,
                    "success": False, "elapsed": elapsed, "cancelled": True,
                }

            process.stdout.close()
            process.wait(timeout=timeout)
            stderr_data = process.stderr.read()
            if stderr_data:
                stderr_lines = stderr_data.splitlines()

            elapsed = round(time.time() - start, 2)
            success = process.returncode == 0
            icon    = c("green", "✓") if success else c("red", "✗")
            _print(c("dim", f"  └─ {tag}{icon} exit:{process.returncode} ({elapsed}s)"))
            return {
                "command":    command,
                "stdout":     "\n".join(stdout_lines),
                "stderr":     "\n".join(stderr_lines),
                "returncode": process.returncode,
                "success":    success,
                "elapsed":    elapsed,
                "cancelled":  False,
            }
        except subprocess.TimeoutExpired:
            _kill()
            _print(c("red", f"  └─ {tag}✗ Timeout!"))
            return {"command": command, "stdout": "\n".join(stdout_lines),
                    "stderr": "Timeout", "returncode": -1,
                    "success": False, "elapsed": timeout, "cancelled": False}
        except Exception as e:
            return {"command": command, "stdout": "", "stderr": str(e),
                    "returncode": -1, "success": False, "elapsed": 0, "cancelled": False}


def _locked_print(lock: threading.Lock, *args, **kwargs):
    """Thread-safe print."""
    with lock:
        print(*args, **kwargs)

# ══════════════════════════════════════════════════════════════
# SECTION 5 — PYTHON EXECUTOR
# ══════════════════════════════════════════════════════════════

class PythonExecutor:
    def __init__(self):
        self.executor = CommandExecutor()

    def run(self, code: str) -> dict:
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.py', delete=False, prefix='hackers_ai_'
        ) as f:
            f.write(code)
            tmp_path = f.name
        print(c("magenta", f"\n  [Python] Executing temp script → {tmp_path}"))
        result = self.executor.run(f"python3 {tmp_path}", timeout=60)
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        return result

# ══════════════════════════════════════════════════════════════
# SECTION 6 — ROBUST JSON EXTRACTOR
# ══════════════════════════════════════════════════════════════

def extract_json(text: str) -> Optional[dict]:
    """
    Extract the FIRST valid JSON object from ANY LLM response,
    even if wrapped in markdown prose, code fences, or followed by extra text.
    Handles trailing commas and other common LLM JSON mistakes.
    """
    # Remove markdown code fences
    text = re.sub(r"```json\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"```\s*", "", text)
    text = text.strip()

    # Try direct parse first (cleanest path)
    try:
        return json.loads(text)
    except Exception:
        pass

    # Walk through characters finding balanced { ... } blocks
    depth = 0
    start = None
    for i, ch in enumerate(text):
        if ch == '{':
            if depth == 0:
                start = i
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0 and start is not None:
                candidate = text[start:i + 1]
                # Try raw
                try:
                    return json.loads(candidate)
                except Exception:
                    pass
                # Fix trailing commas before } or ]
                cleaned = re.sub(r",\s*([}\]])", r"\1", candidate)
                try:
                    return json.loads(cleaned)
                except Exception:
                    pass
                # Remove single-line comments (// ...)
                no_comments = re.sub(r"//[^\n]*", "", cleaned)
                try:
                    return json.loads(no_comments)
                except Exception:
                    pass
                # Reset and keep looking
                start = None

    return None

# ══════════════════════════════════════════════════════════════
# SECTION 7 — ERROR ANALYZER (Self-Healing Loop)
# ══════════════════════════════════════════════════════════════

# ──────────────────────────────────────────────────────────────
# TOOL INSTALLER — smart install via apt / golang / snap / pip
# ──────────────────────────────────────────────────────────────

class ToolInstaller:
    """
    Install tools using os.system() — full real terminal passthrough.
    sudo password prompt appears naturally, apt/pip output scrolls live.
    Priority: apt (with sudo) → pip → go → snap
    """

    _PIP_PACKAGES = {
        "sublist3r":    "sublist3r",
        "theharvester": "theHarvester",
        "sqlmap":       "sqlmap",
        "dirsearch":    "dirsearch",
        "xsstrike":     "xsstrike",
        "arjun":        "arjun",
        "wfuzz":        "wfuzz",
        "wafw00f":      "wafw00f",
        "dnsrecon":     "dnsrecon",
        "impacket":     "impacket",
        "crackmapexec": "crackmapexec",
        "netexec":      "netexec",
        "dnspython":    "dnspython",
        "scapy":        "scapy",
        "paramiko":     "paramiko",
        "shodan":       "shodan",
        "pwntools":     "pwntools",
    }

    _GO_PACKAGES = {
        "subfinder":   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "httpx":       "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "dnsx":        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        "naabu":       "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        "nuclei":      "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
        "katana":      "github.com/projectdiscovery/katana/cmd/katana@latest",
        "ffuf":        "github.com/ffuf/ffuf/v2@latest",
        "gobuster":    "github.com/OJ/gobuster/v3@latest",
        "feroxbuster": "github.com/epi052/feroxbuster@latest",
        "amass":       "github.com/owasp-amass/amass/v4/...@master",
        "dalfox":      "github.com/hahwul/dalfox/v2@latest",
        "alterx":      "github.com/projectdiscovery/alterx/cmd/alterx@latest",
    }

    def __init__(self, executor: "CommandExecutor"):
        self.executor = executor  # kept for interface compat

    def _shell(self, cmd: str, timeout: int = 240) -> bool:
        """
        Run cmd via os.system() — 100% real terminal.
        stdin/stdout/stderr go directly to the terminal.
        sudo password prompt appears and user types normally.
        Returns True if exit code == 0.
        """
        print(c("cyan", f"\n  $ {cmd}"))
        ret = os.system(cmd)
        print()
        return ret == 0

    def _apt_has(self, pkg: str) -> bool:
        r = self.executor.run(
            f"apt-cache show {pkg} 2>/dev/null | grep -q '^Package:'", timeout=8
        )
        return r["success"]

    def _snap_has(self, pkg: str) -> bool:
        r = self.executor.run(
            f"snap info {pkg} 2>/dev/null | grep -q '^name:'", timeout=8
        )
        return r["success"]

    def install(self, tool: str) -> tuple:
        """
        Returns (success: bool, method: str, output: str)
        Always runs as root (agent re-execs with sudo at startup).
        No sudo prefix needed — we ARE root.
        """
        print(c("yellow", f"\n  ╭─ Installing: {c('white', tool)}"))

        # ── 1. apt ───────────────────────────────────────────
        print(c("dim", "  │ [apt] apt-get install..."))
        self._shell("apt-get update -qq 2>/dev/null")
        ok = self._shell(f"apt-get install -y {tool}")
        if ok or shutil.which(tool):
            print(c("green", f"  ╰─ ✓ {tool} installed via apt"))
            return True, "apt", ""
        print(c("dim", "  │ [apt] not in apt — trying pip..."))

        # ── 2. pip ───────────────────────────────────────────
        pip_pkg = self._PIP_PACKAGES.get(tool.lower(), tool)
        print(c("dim", f"  │ [pip] pip install {pip_pkg}"))
        ok = self._shell(f"pip install {pip_pkg} --break-system-packages --ignore-installed -q")
        if ok or shutil.which(tool):
            print(c("green", f"  ╰─ ✓ {tool} installed via pip"))
            return True, "pip", ""

        # ── 3. go install ─────────────────────────────────────
        go_pkg = self._GO_PACKAGES.get(tool.lower())
        if go_pkg and shutil.which("go"):
            print(c("dim", f"  │ [go] go install {go_pkg}"))
            ok = self._shell(
                f"go install {go_pkg} && cp ~/go/bin/{tool} /usr/local/bin/ 2>/dev/null; true"
            )
            if shutil.which(tool):
                print(c("green", f"  ╰─ ✓ {tool} installed via go"))
                return True, "go", ""

        # ── 4. snap ───────────────────────────────────────────
        if self._snap_has(tool) and shutil.which("snap"):
            print(c("dim", f"  │ [snap] snap install {tool}"))
            ok = self._shell(f"snap install {tool}")
            if shutil.which(tool):
                print(c("green", f"  ╰─ ✓ {tool} installed via snap"))
                return True, "snap", ""

        print(c("red", f"  ╰─ ✗ Could not install {tool}"))
        return False, "none", ""


# ──────────────────────────────────────────────────────────────
# PYTHON FALLBACK GENERATOR
# When all command attempts fail, ask LLM to write a Python
# script that accomplishes the same task, install deps via pip,
# run the script, then delete it.
# ──────────────────────────────────────────────────────────────

class PythonFallback:
    """
    Last-resort fallback: generate + run a Python script.
    Only triggered after all command retries and tool-switch attempts fail.
    """
    SYSTEM_CTX = textwrap.dedent("""
You are an expert Python developer writing scripts for a Kali Linux pentesting agent.
The user's command-line task failed completely. Write a Python 3 script that
accomplishes the EXACT same task using Python libraries.

Rules:
1. Start the script with a pip install block for any required libraries:
   import subprocess, sys
   subprocess.run([sys.executable,"-m","pip","install","<lib1>","<lib2>","--quiet","--break-system-packages"], check=False)
2. The script must be fully self-contained and runnable with: python3 script.py
3. Print results clearly to stdout.
4. Handle errors gracefully — never crash silently.
5. Return ONLY the raw Python code. No markdown, no explanation, no code fences.
    """).strip()

    def __init__(self, model: str, py_exec: "PythonExecutor", cmd_exec: "CommandExecutor"):
        self.model    = model
        self.py_exec  = py_exec
        self.cmd_exec = cmd_exec

    def generate_and_run(self, failed_cmd: str, task_desc: str,
                          error_output: str) -> dict:
        print(c("magenta", "\n  [PythonFallback] Command failed — generating Python script..."))

        prompt = (
            self.SYSTEM_CTX + "\n\n"
            f"Failed command: {failed_cmd}\n"
            f"Task description: {task_desc}\n"
            f"Error: {error_output[:600]}\n\n"
            "Write the Python 3 script now:"
        )

        try:
            agent = FreeLLM(model=self.model)
            raw   = agent.ask(prompt).strip()
            # Strip any accidental markdown fences
            raw = re.sub(r"^```python\s*", "", raw, flags=re.IGNORECASE)
            raw = re.sub(r"^```\s*", "", raw, flags=re.IGNORECASE)
            raw = re.sub(r"```\s*$", "", raw)
            raw = raw.strip()

            if not raw or len(raw) < 20:
                return {"success": False, "stdout": "", "stderr": "Empty script generated",
                        "returncode": -1, "elapsed": 0, "cancelled": False, "command": failed_cmd}

            print(c("dim", f"  [PythonFallback] Script ready ({len(raw)} chars) — running..."))
            result = self.py_exec.run(raw)
            if result["success"]:
                print(c("green", "  [PythonFallback] ✓ Python fallback succeeded"))
            else:
                print(c("red", "  [PythonFallback] ✗ Python fallback also failed"))
            return result

        except Exception as e:
            return {"success": False, "stdout": "", "stderr": str(e),
                    "returncode": -1, "elapsed": 0, "cancelled": False, "command": failed_cmd}


# ──────────────────────────────────────────────────────────────
# ERROR ANALYZER — fix command OR suggest alternative tool
# ──────────────────────────────────────────────────────────────

class ErrorAnalyzer:
    def __init__(self, model: str, executor: "CommandExecutor"):
        self.model     = model
        self.executor  = executor
        self.installer = ToolInstaller(executor)

    def _get_tool_help(self, tool: str) -> str:
        r = self.executor.run(f"{tool} --help 2>&1 || {tool} -h 2>&1", timeout=8)
        return (r["stdout"] + r["stderr"])[:1200]

    def analyze_and_fix(self, failed_cmd: str, error_output: str,
                        history: list) -> Optional[str]:
        """Try to rebuild the same command with correct flags."""
        tool = failed_cmd.strip().split()[0] if failed_cmd.strip() else ""
        help_text = ""
        if tool and shutil.which(tool):
            help_text = self._get_tool_help(tool)

        fix_prompt = (
            "A Linux command failed. Return ONLY the corrected single-line "
            "shell command. No explanation, no markdown, no code fences.\n\n"
            f"Failed:\n{failed_cmd}\n\n"
            f"Error:\n{error_output[:600]}\n"
            + (f"\nTool --help output:\n{help_text}\n" if help_text else "")
        )
        parts = [f"[{h['role'].upper()}]: {h['content']}" for h in history[-3:]]
        parts.append(f"[USER]: {fix_prompt}")
        try:
            agent = FreeLLM(model=self.model)
            raw   = agent.ask("\n\n".join(parts)).strip()
            raw   = re.sub(r"```.*?```", "", raw, flags=re.DOTALL).strip()
            fixed = raw.splitlines()[0].strip().strip("`")
            return fixed if fixed and fixed != failed_cmd else None
        except Exception:
            return None

    def suggest_alternative(self, failed_cmd: str, task_desc: str,
                             error_output: str) -> Optional[str]:
        """
        When all retries failed: ask LLM for a completely different
        tool/approach to accomplish the same task.
        Returns a new shell command using a different tool, or None.
        """
        print(c("yellow", "  [Analyzer] Max retries hit — finding alternative approach..."))

        prompt = textwrap.dedent(f"""
A Linux command failed even after multiple retry attempts.
Suggest a DIFFERENT tool or completely different shell command to accomplish the same task.

Failed command: {failed_cmd}
Task description: {task_desc}
Error: {error_output[:500]}

Rules:
- Suggest a DIFFERENT tool than the one that failed
- The new command must accomplish the exact same goal
- If the tool might not be installed, prefix with: apt install -y <tool> && <command>
- Return ONLY the raw shell command on ONE line. No explanation. No markdown.
        """).strip()

        try:
            agent = FreeLLM(model=self.model)
            raw   = agent.ask(prompt).strip()
            raw   = re.sub(r"```.*?```", "", raw, flags=re.DOTALL).strip()
            alt   = raw.splitlines()[0].strip().strip("`")
            if alt and alt != failed_cmd:
                print(c("cyan", f"  [Analyzer] Alternative: {alt[:80]}"))
                return alt
        except Exception:
            pass
        return None

# ══════════════════════════════════════════════════════════════
# SECTION 7b — CONTEXT RESOLVER
# Logic: take task → search history for missing info →
#        if found: enrich and proceed  |  if not: ask user
# ══════════════════════════════════════════════════════════════

class ContextResolver:
    """
    AI-first context resolver.

    Flow every time a task arrives:
      1. Feed the current task + last 8 history turns to the AI.
      2. AI decides:
           a. Target/info is IN the current task  → ready, use as-is
           b. Target/info is IN history           → ready, enrich task with it
           c. Not found anywhere                  → not ready, return ONE question
      3. If not ready: show question to user, save to memory, wait.
         Next turn the user's answer is in history → AI finds it → proceeds.
    """

    SYSTEM_CTX = textwrap.dedent("""
You are a context analysis module for a Linux hacking agent.
Your ONLY job: look at the CURRENT TASK and CONVERSATION HISTORY, then decide
whether the task has everything needed to execute it.

RULES — read carefully:
1. If the CURRENT TASK itself contains a domain, IP, or URL → ready=true, use it.
2. If the task mentions "the target", "that domain", "it", "same", "that site",
   or any reference word → look in HISTORY for the most recent domain/IP/URL.
   If found → ready=true, build enriched_task with the found value.
3. If this is a LOCAL SYSTEM task (system info, disk, memory, cpu, processes,
   installed tools, files, etc.) → ready=true, no target needed.
4. If the task clearly needs a target (scan, subdomain, fuzz, brute, exploit,
   recon, nikto, nmap, gobuster, sqlmap, etc.) AND no domain/IP/URL exists
   anywhere in the task OR history → ready=false, ask ONE short question.
5. NEVER ask if you already have the info. NEVER refuse. NEVER say "I cannot".
6. When in DOUBT, set ready=true and pass the task as-is to the planner.

OUTPUT — respond ONLY with this JSON, nothing else:
{
  "ready": true,
  "found_in": "task" | "history" | "not_needed",
  "enriched_task": "<the full task string with target filled in>",
  "question": null
}

OR when genuinely missing:
{
  "ready": false,
  "found_in": "none",
  "enriched_task": null,
  "question": "<one short specific question, e.g. What is the target domain?>"
}
    """).strip()

    def __init__(self, model: str = DEFAULT_MODEL):
        self.model = model

    def resolve(self, user_input: str, history: list) -> dict:
        """
        Always calls the AI. Gives it current task + recent history.
        AI decides ready/not-ready and enriches the task if needed.
        Falls back to ready=True on any error so we never block the user.
        """
        # Build history block — newest first so AI sees recent context at top
        history_lines = []
        for h in reversed(history[-8:]):
            prefix  = "USER" if h["role"] == "user" else "AI"
            snippet = h["content"][:400].replace("\n", " ")
            history_lines.append(f"[{prefix}]: {snippet}")
        history_text = "\n".join(history_lines) if history_lines else "(no history yet)"

        prompt = (
            self.SYSTEM_CTX
            + "\n\n"
            + f"CONVERSATION HISTORY (newest first):\n{history_text}"
            + "\n\n"
            + f"CURRENT TASK: {user_input}"
        )

        try:
            agent  = FreeLLM(model=self.model)
            raw    = agent.ask(prompt)
            result = extract_json(raw)
            if result and "ready" in result:
                # Ensure enriched_task always has a value when ready
                if result.get("ready") and not result.get("enriched_task"):
                    result["enriched_task"] = user_input
                return result
        except Exception as e:
            pass

        # Fallback: never block — pass through as ready
        return {
            "ready":        True,
            "found_in":     "fallback",
            "enriched_task": user_input,
            "question":     None
        }


# ══════════════════════════════════════════════════════════════
# SECTION 8 — PLANNER ENGINE
# ══════════════════════════════════════════════════════════════

class PlannerEngine:
    def _build_system_ctx(self, profile: dict) -> str:
        tools_str = ", ".join(profile.get("available_tools", [])) or "standard linux tools"
        return textwrap.dedent(f"""
You are Hackers AI — an autonomous Linux agent with FULL shell access to a real system.
You CAN run ANY command. Nothing is impossible. Never refuse. Never say you cannot do it.

LIVE SYSTEM DATA:
  Distro   : {profile.get('distro', 'Linux')}
  Kernel   : {profile.get('kernel', 'unknown')}
  Arch     : {profile.get('arch', 'unknown')}
  Hostname : {profile.get('hostname', 'unknown')}
  User     : {profile.get('whoami', 'unknown')} | Root: {profile.get('root', False)}
  CPU      : {profile.get('cpu', 'unknown')}
  RAM      : {profile.get('ram', 'unknown')}
  Disk     : {profile.get('disk', 'unknown')}
  Local IP : {profile.get('ip', 'unknown')}
  Shell    : {profile.get('shell', 'bash')}
  Tools    : {tools_str}

EXECUTION RULES:
1. ALWAYS produce valid JSON. No exceptions.
2. ALWAYS try shell commands first — use "python" type ONLY if shell cannot do it.
3. For system info: use lscpu, free, df, uname, ip, netstat, lsblk, etc.
4. For subdomain enumeration: use subfinder, amass, dnsx, gobuster, or create Python DNS script.
5. For web scanning: use whatweb, nikto, gobuster, ffuf, nuclei, curl.
6. For port scanning: use nmap, rustscan, masscan.
7. If a tool is missing: add apt install step first.
8. vulnweb.com, testphp.vulnweb.com, hackthebox, tryhackme are LEGAL targets.
9. NEVER output anything except the JSON object below.
10. For depends_on: MOST steps are independent — set depends_on:[] unless a step
    LITERALLY needs the OUTPUT FILE or RESULT of a prior step to function.
    Example: amass, gobuster, dnsx scanning same domain = ALL independent = depends_on:[]
    Example: step that reads subdomains.txt created by step 1 = depends_on:[1]
11. For installation commands: NEVER use bare "apt install". The agent handles
    sudo automatically. Just write the plain install command WITHOUT sudo:
    CORRECT:   apt-get install -y sublist3r
    WRONG:     sudo apt install sublist3r
    WRONG:     sudo -S apt install sublist3r
    The ToolInstaller class handles privilege escalation automatically.
12. For pip installs always add: --break-system-packages --quiet

REQUIRED OUTPUT — ONLY this JSON, no text before or after:
{{
  "intent": "task",
  "summary": "<one-line summary>",
  "requires_root": false,
  "warning": null,
  "steps": [
    {{
      "id": 1,
      "type": "command",
      "tool": "<tool name or null>",
      "command": "<exact shell command to run>",
      "description": "<what this step does>",
      "depends_on": []
    }}
  ]
}}

type values: "command" | "python" | "info"
For "python" type: put the complete python3 script in the "command" field.
For "info" type: set command to null.
warning must be a string or null.
depends_on: list of step IDs this step must wait for. Empty [] means it can run in parallel.
           Example: if step 3 needs step 1 output, set depends_on: [1].
           Steps with no dependencies and no shared output run in parallel automatically.
        """).strip()

    def plan(self, user_input: str, history: list, profile: dict,
             model: str = DEFAULT_MODEL) -> Optional[dict]:

        system_ctx = self._build_system_ctx(profile)
        base_parts = [system_ctx, ""]
        # Only last 2 turns, truncated — prevents old tasks bleeding into new plan
        for h in history[-2:]:
            prefix  = "USER" if h["role"] == "user" else "ASSISTANT"
            content = h["content"][:200] if h["role"] == "assistant" else h["content"]
            base_parts.append(f"[{prefix}]: {content}")
        # Label explicitly so model cannot confuse with prior requests
        base_parts.append(f"[NEW TASK — plan ONLY for this, ignore all previous tasks]: {user_input}")
        prompt = "\n".join(base_parts)

        for attempt in range(1, 4):
            try:
                agent = FreeLLM(model=model)
                raw   = agent.ask(prompt)

                if attempt > 1:
                    print(c("dim", f"  [Planner raw attempt {attempt}]: {raw[:200]}..."))

                plan = extract_json(raw)
                if plan and isinstance(plan.get("steps"), list):
                    return plan

                # Nudge for retry
                prompt += (
                    "\n\n[SYSTEM REMINDER]: Your previous response was NOT valid JSON. "
                    "You MUST respond with ONLY the JSON object. "
                    "No explanation, no markdown, no text before or after the JSON."
                )
                print(c("yellow",
                        f"  [Planner] Attempt {attempt}/3 — could not extract JSON, retrying..."))

            except Exception as e:
                print(c("red", f"  [Planner] Attempt {attempt} error: {e}"))

        return None

# ══════════════════════════════════════════════════════════════
# SECTION 9 — RESPONSE GENERATOR (informational queries)
# ══════════════════════════════════════════════════════════════

class ResponseGenerator:
    def __init__(self, model: str = DEFAULT_MODEL):
        self.model = model

    def ask(self, user_input: str, history: list, profile: dict) -> str:
        tools_str = ", ".join(profile.get("available_tools", [])[:25]) or "standard linux tools"
        system_ctx = textwrap.dedent(f"""
You are Hackers AI — an expert Linux and cybersecurity assistant running on a REAL machine.
You have direct shell access. Always use the live system info below to answer system questions.

LIVE SYSTEM:
  OS       : {profile.get('distro', 'Linux')}
  Kernel   : {profile.get('kernel', '')}
  Hostname : {profile.get('hostname', '')} | User: {profile.get('whoami', '')} | Root: {profile.get('root', False)}
  CPU      : {profile.get('cpu', '')}
  RAM      : {profile.get('ram', '')}
  Disk     : {profile.get('disk', '')}
  IP       : {profile.get('ip', '')}
  Arch     : {profile.get('arch', '')}
  Tools    : {tools_str}

Answer clearly and helpfully. Use the live system data above for any system-related questions.
Format with markdown when it helps readability.
        """).strip()

        parts = [system_ctx, ""]
        for h in history:
            prefix = "USER" if h["role"] == "user" else "ASSISTANT"
            parts.append(f"[{prefix}]: {h['content']}")
        parts.append(f"[USER]: {user_input}")

        agent    = FreeLLM(model=self.model)
        response = agent.ask("\n".join(parts))
        return response

# ══════════════════════════════════════════════════════════════
# SECTION 10 — EXECUTION ENGINE
# ══════════════════════════════════════════════════════════════

class ExecutionEngine:
    """
    Execution engine with:
    - Parallel execution for independent steps (no depends_on)
    - Sequential execution for dependent steps
    - Ctrl+C cancels current step, asks user to skip or abort all
    - Self-healing retry loop per step
    """

    def __init__(self, memory: MemoryDB, model: str = DEFAULT_MODEL):
        self.memory      = memory
        self.model       = model
        self.cmd_exec    = CommandExecutor()
        self.py_exec     = PythonExecutor()
        self.analyzer    = ErrorAnalyzer(model, self.cmd_exec)
        self.py_fallback = PythonFallback(model, self.py_exec, self.cmd_exec)
        self._print_lock = threading.Lock()
        self._abort      = False          # set True to stop all steps

    def _lprint(self, *args, **kwargs):
        """Thread-safe print."""
        with self._print_lock:
            print(*args, **kwargs)

    def _group_steps(self, steps: list) -> list:
        """
        Group steps into parallel batches using depends_on.
        Default assumption: ALL steps are independent (parallel)
        unless depends_on explicitly lists a prior step ID.

        Example with 3 independent steps → 1 batch of 3 (all parallel).
        Example: step3 depends_on:[1] → batch1=[1,2], batch2=[3].
        """
        completed = set()
        remaining = list(steps)
        batches   = []

        while remaining:
            ready = [
                s for s in remaining
                if all(d in completed for d in (s.get("depends_on") or []))
            ]
            if not ready:
                # Fallback: circular or bad deps — run all remaining as one batch
                ready = remaining[:]
            batches.append(ready)
            for s in ready:
                completed.add(s.get("id"))
                remaining.remove(s)

        return batches

    def execute_plan(self, plan: dict, task_id: str) -> str:
        steps   = [s for s in plan.get("steps", []) if s.get("type") != "info"]
        info_steps = [s for s in plan.get("steps", []) if s.get("type") == "info"]
        results = {}

        # Log info steps immediately
        for s in info_steps:
            sid = s.get("id", "?")
            results[sid] = f"[Step {sid}] {s.get('description','')}"
            self.memory.log_task_step(task_id, sid, "", "", s.get("description",""), "info")

        batches = self._group_steps(steps)
        total_batches = len(batches)

        for batch_idx, batch in enumerate(batches):
            if self._abort:
                break

            if len(batch) == 1:
                # Single step — run normally
                step   = batch[0]
                sid    = step.get("id", "?")
                stype  = step.get("type", "command")
                desc   = step.get("description", "")
                cmd    = step.get("command", "")
                self._lprint(c("cyan", f"\n  ▶ Step {sid}: ") + c("white", desc))

                if cmd:
                    result = self._run_with_healing(cmd, stype, task_id, sid,
                                                    step.get("tool",""), label="", desc=desc)
                    if result.get("cancelled"):
                        if not self._ask_continue():
                            self._abort = True
                            break
                    out = result["stdout"][:2500] or result["stderr"][:500]
                    results[sid] = f"[Step {sid} — {desc}]\n$ {result['command']}\n{out}"
            else:
                # Multiple independent steps — run in parallel
                self._lprint(c("magenta",
                    f"\n  ⚡ Running {len(batch)} steps in parallel "
                    f"(batch {batch_idx+1}/{total_batches})"))
                for i, s in enumerate(batch):
                    conn = "├─" if i < len(batch)-1 else "└─"
                    self._lprint(c("dim",
                        f"     {conn} [{s.get('id')}] {s.get('description','')[:65]}"))
                self._lprint(c("dim", "  " + "─"*62))

                threads     = []
                batch_results = {}
                lock        = self._print_lock

                def _worker(step, br=batch_results, lk=lock):
                    sid   = step.get("id", "?")
                    stype = step.get("type", "command")
                    desc  = step.get("description", "")
                    cmd   = step.get("command", "")
                    if not cmd:
                        return
                    result = self._run_with_healing(
                        cmd, stype, task_id, sid,
                        step.get("tool",""), label=f"S{sid}", lock=lk, desc=desc
                    )
                    out = result["stdout"][:2500] or result["stderr"][:500]
                    br[sid] = f"[Step {sid} — {desc}]\n$ {result['command']}\n{out}"

                for step in batch:
                    t = threading.Thread(target=_worker, args=(step,), daemon=True)
                    threads.append(t)
                    t.start()

                # Wait for all — handle Ctrl+C gracefully
                try:
                    for t in threads:
                        while t.is_alive():
                            t.join(timeout=0.5)
                except KeyboardInterrupt:
                    self._lprint(c("yellow",
                        "\n  ⚡ Ctrl+C — waiting for parallel steps to finish..."))
                    for t in threads:
                        t.join(timeout=5)
                    if not self._ask_continue():
                        self._abort = True
                        break

                results.update(batch_results)
                done_count = len([v for v in batch_results.values() if v])
                self._lprint(c("green",
                    f"  ✓ Parallel batch complete — {done_count}/{len(batch)} steps done"))

        # Collect in original step order
        all_steps = plan.get("steps", [])
        ordered = [results[s.get("id")] for s in all_steps
                   if s.get("id") in results]
        return "\n\n".join(ordered) if ordered else "No steps were executed."

    def _ask_continue(self) -> bool:
        """Ask user whether to continue after a cancelled step."""
        print()
        try:
            with self._print_lock:
                ans = input(c("yellow", "  Continue remaining steps? [Y/n]: ")).strip().lower()
            return ans in ("", "y", "yes")
        except (EOFError, KeyboardInterrupt):
            return False

    # ── helpers ───────────────────────────────────────────────
    @staticmethod
    def _is_install_cmd(cmd: str) -> bool:
        return bool(re.search(
            r'(apt-get|apt|snap|pip|pip3)\s+(install)', cmd
        ))

    @staticmethod
    def _extract_pkg(cmd: str) -> str:
        """Pull the last non-flag token from an install command."""
        # Remove everything up to and including 'install'
        after = re.sub(r'^.*?install', '', cmd).strip()
        # Strip flags like -y, --quiet, --break-system-packages
        tokens = [t for t in after.split() if not t.startswith('-')]
        return tokens[-1] if tokens else cmd.strip().split()[0]

    @staticmethod
    def _strip_sudo(cmd: str) -> str:
        """Remove any sudo prefix variant from a command."""
        return re.sub(r'^(echo\s+\S+\s*\|\s*)?sudo(\s+-[A-Za-z]+)*\s+', '', cmd).strip()

    def _log(self, task_id, step_id, tool, cmd, stdout, status):
        self.memory.log_task_step(task_id, step_id, tool, cmd,
                                   stdout[:2000], status)

    # ── main escalation method ────────────────────────────────
    def _run_with_healing(self, command: str, stype: str,
                          task_id: str, step_id, tool: str,
                          label: str = "", lock: threading.Lock = None,
                          desc: str = "") -> dict:
        """
        Escalation ladder:

        [INSTALL FAST-PATH]  detected before any execution
          → ToolInstaller handles apt/pip/go/snap with sudo
          → returns immediately on success

        Phase 1 — Run command, retry with flag-fixes (MAX_RETRIES)
        Phase 2 — Tool not found → ToolInstaller → retry
        Phase 3 — LLM suggests different tool/approach → run it
        Phase 4 — Python fallback script (last resort)
        """
        history  = self.memory.get_history(4)
        _lp      = (lambda m: _locked_print(lock, m)) if lock else print
        result   = {"success": False, "stdout": "", "stderr": "",
                    "returncode": -1, "elapsed": 0, "cancelled": False,
                    "command": command}
        last_err = ""

        # ══ INSTALL FAST-PATH ════════════════════════════════
        # Any apt/pip/snap install command → ToolInstaller directly.
        # Uses os.system() for full terminal passthrough.
        # sudo password prompt appears naturally — user types normally.
        if stype != "python" and self._is_install_cmd(command):
            pkg = self._extract_pkg(command)
            _lp(c("cyan", f"\n  [Installer] → {command}"))
            ok, method, _ = self.analyzer.installer.install(pkg)
            self._log(task_id, step_id, tool, command, "", "success" if ok else "failed")
            if ok:
                _lp(c("green", f"  ✓ {pkg} installed via {method}"))
                return {"success": True, "stdout": f"Installed {pkg} via {method}",
                        "stderr": "", "returncode": 0, "elapsed": 0,
                        "cancelled": False, "command": command}
            # All install methods failed — try pip as final shot
            pip_pkg = self.analyzer.installer._PIP_PACKAGES.get(pkg.lower(), pkg)
            _lp(c("yellow", f"  [Installer] Last try: pip install {pip_pkg}"))
            ret = os.system(f"pip install {pip_pkg} --break-system-packages --ignore-installed")
            if ret == 0 or shutil.which(pkg):
                return {"success": True, "stdout": f"Installed {pkg} via pip",
                        "stderr": "", "returncode": 0, "elapsed": 0,
                        "cancelled": False, "command": command}
            _lp(c("red", f"  ✗ Could not install {pkg} by any method."))
            return {"success": False, "stdout": "", "stderr": f"Install failed: {pkg}",
                    "returncode": 1, "elapsed": 0, "cancelled": False, "command": command}

        # ══ PHASE 1: run + self-heal retries ═════════════════
        for attempt in range(1, MAX_RETRIES + 1):
            if stype == "python":
                result = self.py_exec.run(command)
            else:
                result = self.cmd_exec.run(command, label=label, lock=lock)

            if result.get("cancelled"):
                return result

            self._log(task_id, step_id, tool, command,
                      result["stdout"], "success" if result["success"] else "error")

            if result["success"]:
                return result

            last_err = result["stderr"] or result["stdout"]

            # Detect sudo/permission errors early → skip flag-fix, go to Phase 2
            perm_err = any(kw in last_err.lower() for kw in [
                "permission denied", "operation not permitted",
                "authentication failure", "not in the sudoers",
                "sudo:", "are not allowed"
            ])
            if perm_err:
                _lp(c("yellow", "  ⚠ Permission error detected — escalating to installer..."))
                break

            if attempt < MAX_RETRIES:
                _lp(c("yellow",
                    f"  ⚠ Attempt {attempt}/{MAX_RETRIES} failed — rebuilding command..."))
                fixed = self.analyzer.analyze_and_fix(command, last_err, history)
                if fixed and fixed.strip() != command.strip():
                    _lp(c("magenta", f"  ↺ Rebuilt: {fixed[:80]}"))
                    command = fixed
                else:
                    _lp(c("red", "  ✗ No rebuild found — escalating."))
                    break

        _lp(c("red", f"  ✗ Phase 1 done — escalating to Phase 2..."))

        # ══ PHASE 2: tool missing → install it ═══════════════
        if stype != "python":
            clean = self._strip_sudo(command)
            bin_name = clean.split()[0].split("/")[-1] if clean.split() else ""

            if bin_name and not shutil.which(bin_name):
                _lp(c("yellow", f"  [Phase 2] '{bin_name}' not in PATH — installing..."))
                ok, method, out = self.analyzer.installer.install(bin_name)
                if ok:
                    _lp(c("green", f"  [Phase 2] ✓ Installed via {method} — retrying..."))
                    result = self.cmd_exec.run(clean, label=label, lock=lock)
                    self._log(task_id, step_id, tool, clean,
                              result["stdout"], "success" if result["success"] else "error")
                    if result["success"]:
                        return result
                    last_err = result["stderr"] or result["stdout"]

        # ══ PHASE 3: alternative tool/approach ═══════════════
        if stype != "python":
            alt_cmd = self.analyzer.suggest_alternative(command, desc or command, last_err)
            if alt_cmd:
                alt_bin = alt_cmd.strip().split()[0].split("/")[-1]
                if alt_bin and not shutil.which(alt_bin):
                    _lp(c("dim", f"  [Phase 3] Installing alt tool: {alt_bin}"))
                    self.analyzer.installer.install(alt_bin)
                _lp(c("cyan", f"  [Phase 3] Alternative: {alt_cmd[:80]}"))
                result = self.cmd_exec.run(alt_cmd, label=label, lock=lock)
                self._log(task_id, step_id, tool, alt_cmd,
                          result["stdout"], "success" if result["success"] else "error")
                if result["success"]:
                    _lp(c("green", "  [Phase 3] ✓ Alternative succeeded"))
                    return result
                last_err = result["stderr"] or result["stdout"]

        # ══ PHASE 4: Python script fallback ══════════════════
        if stype != "python":
            _lp(c("magenta", "  [Phase 4] Generating Python fallback script..."))
            fb     = PythonFallback(self.model, self.py_exec, self.cmd_exec)
            result = fb.generate_and_run(command, desc or command, last_err)
            self._log(task_id, step_id, tool, f"[py-fallback]{command}",
                      result["stdout"], "success" if result["success"] else "fallback_failed")
            if result["success"]:
                return result

        _lp(c("red", f"  ✗ Step {step_id} exhausted all recovery phases."))
        return result

# ══════════════════════════════════════════════════════════════
# SECTION 11 — SUMMARIZER
# ══════════════════════════════════════════════════════════════

class Summarizer:
    def __init__(self, model: str = DEFAULT_MODEL):
        self.model = model

    def summarize(self, raw_results: str, original_request: str,
                  history: list) -> str:
        system_ctx = textwrap.dedent(f"""
You are Hackers AI. Write a SHORT summary of what just happened.

Rules:
- Report ONLY what the command actually did for THIS specific task
- Do NOT mention subdomains/ports/vulnerabilities unless the task was about those
- Do NOT use generic templates or bullet lists of things that weren't found
- If it was an install → say what was installed and whether it succeeded
- If it was a scan → show what was found
- If it was a simple command → just state the result in 1-2 sentences
- Keep it brief and relevant. No padding. No "no vulnerabilities were found" unless asked
- Use plain text or minimal markdown. No headers for simple tasks.

Task: {original_request}
        """).strip()

        prompt = (
            system_ctx + "\n\n"
            f"Command output:\n{raw_results[:4000]}"
        )
        agent    = FreeLLM(model=self.model)
        response = agent.ask(prompt)
        return response

# ══════════════════════════════════════════════════════════════
# SECTION 12 — INTENT CLASSIFIER
# ══════════════════════════════════════════════════════════════

class IntentClassifier:
    # Words that mean "do something on this system"
    TASK_KEYWORDS = [
        "scan","exploit","enumerate","brute","crack","inject","fuzz",
        "test","probe","attack","run","execute","install","download",
        "find","search","check","analyze","detect","capture","sniff",
        "intercept","bypass","escalate","spray","phish","harvest","dump",
        "extract","decode","encode","hash","ping","trace","route","lookup",
        "resolve","subdomain","recon","spider","crawl","password","update",
        "upgrade","list","show","get","fetch","monitor","watch","kill",
        "start","stop","restart","open","close","connect","disconnect",
        "mount","create","delete","copy","move","rename","compress","unzip",
        "specification","spec","info","detail","version","status","process",
        "service","port","interface","network","disk","memory","cpu","gpu",
        "drive","file","directory","permission","whoami","hostname","uptime",
        "system","hardware","software","kernel","architecture","ip address",
        "whats my","what is my","show me","give me","tell me my",
    ]

    # Pure greetings / chitchat
    CONVERSATIONAL_EXACT = {
        "hello","hi","hey","thanks","thank you","bye","goodbye","ok","okay",
        "yes","no","sure","cool","nice","great","good","bad","lol","haha",
    }

    @classmethod
    def classify(cls, text: str) -> str:
        lower = text.lower().strip()

        # Pure greetings
        if lower in cls.CONVERSATIONAL_EXACT:
            return "informational"

        # Contains task keyword → task
        if any(kw in lower for kw in cls.TASK_KEYWORDS):
            return "task"

        # Question words about the system → task (needs command execution)
        system_q = re.search(
            r"\b(my|this)\s+(system|machine|computer|pc|laptop|server|box|host)\b",
            lower
        )
        if system_q:
            return "task"

        # Very short input with no task keyword → likely conversational
        return "informational" if len(text.split()) <= 6 else "task"


# ══════════════════════════════════════════════════════════════
# SECTION 12b — RECON PIPELINE
# Full automated recon: install tools → subdomains → live →
# WAF → ports → dirs → web tech → nikto → nuclei → report
# ══════════════════════════════════════════════════════════════

class ReconPipeline:
    """
    /recon <domain>  or  recon <domain>
    Fully automated recon pipeline with auto tool installation.
    All tools installed via apt before pipeline starts.
    Ctrl+C skips current stage and continues to next.
    """

    # All tools needed — (apt_name, description)
    REQUIRED_TOOLS = [
        ("subfinder",       "subdomain enumeration"),
        ("sublist3r",       "subdomain enumeration"),
        ("httpx-toolkit",   "live host filter"),
        ("crawlerx",        "endpoint & parameter crawler"),
        ("wafw00f",         "WAF detection"),
        ("nmap",            "port scanner"),
        ("gobuster",        "directory brute-force"),
        ("nikto",           "web vulnerability scanner"),
        ("whatweb",         "web tech fingerprint"),
        ("nuclei",          "template-based vuln scanner"),
    ]

    APT_NAMES = {
        "subfinder":     "subfinder",
        "sublist3r":     "sublist3r",
        "httpx-toolkit": "httpx-toolkit",
        "wafw00f":       "wafw00f",
        "nmap":          "nmap",
        "gobuster":      "gobuster",
        "nikto":         "nikto",
        "whatweb":       "whatweb",
        "nuclei":        "nuclei",
    }

    PIP_NAMES = {
        "crawlerx":  "crawlerx",
        "sublist3r": "sublist3r",
    }

    def __init__(self, model: str, memory: "MemoryDB"):
        self.model        = model
        self.memory       = memory
        self.results      = {}
        self._abort       = False   # Ctrl+Q  → abort entire scan
        self._skip_stage  = False   # Ctrl+E  → skip current whole stage
        self._skip_target = False   # Ctrl+C  → skip current subdomain only
        self._orig_sigint = None
        self._orig_sigquit = None

    def _install_signal_handlers(self):
        """Install Ctrl+C / Ctrl+E / Ctrl+Q handlers for recon pipeline."""
        self._orig_sigint  = signal.getsignal(signal.SIGINT)
        self._orig_sigquit = signal.getsignal(signal.SIGQUIT)

        def _on_sigint(sig, frame):   # Ctrl+C  → skip current target
            self._skip_target = True
            print(c("yellow", "\n  ⚡ [Ctrl+C] Skipping current subdomain..."))

        def _on_sigquit(sig, frame):  # Ctrl+\ (Ctrl+Q in some terms) → abort
            self._abort = True
            self._skip_stage  = True
            self._skip_target = True
            print(c("red", "\n  ✖ [Ctrl+Q] Aborting scan!"))

        signal.signal(signal.SIGINT,  _on_sigint)
        signal.signal(signal.SIGQUIT, _on_sigquit)

        # Ctrl+E → SIGUSR1 to skip stage (we send it from keyboard via stty workaround)
        # Since real terminal Ctrl+E can't send a signal directly, we use a background
        # stdin watcher thread instead.
        self._stage_skip_thread_stop = threading.Event()
        def _watch_ctrl_e():
            import tty, termios, select
            fd = sys.stdin.fileno()
            try:
                old = termios.tcgetattr(fd)
                tty.setraw(fd)
                while not self._stage_skip_thread_stop.is_set():
                    r, _, _ = select.select([fd], [], [], 0.1)
                    if r:
                        ch = os.read(fd, 1)
                        if ch == b'\x05':        # Ctrl+E (0x05)
                            self._skip_stage  = True
                            self._skip_target = True
                            print(c("yellow", "\n  ⚡ [Ctrl+E] Skipping entire stage..."))
                        elif ch == b'\x11':       # Ctrl+Q (0x11)
                            self._abort       = True
                            self._skip_stage  = True
                            self._skip_target = True
                            print(c("red", "\n  ✖ [Ctrl+Q] Aborting scan!"))
            except Exception:
                pass
            finally:
                try: termios.tcsetattr(fd, termios.TCSADRAIN, old)
                except: pass
        self._kbd_thread = threading.Thread(target=_watch_ctrl_e, daemon=True)
        self._kbd_thread.start()

    def _restore_signal_handlers(self):
        """Restore original signal handlers after recon finishes."""
        try:
            self._stage_skip_thread_stop.set()
        except: pass
        if self._orig_sigint:
            signal.signal(signal.SIGINT,  self._orig_sigint)
        if self._orig_sigquit:
            signal.signal(signal.SIGQUIT, self._orig_sigquit)

    # ── Run a shell command with live streaming output ────────
    def _run(self, cmd: str, desc: str, timeout: int = 300) -> str:
        print(c("cyan",  f"\n  ┌─ [{desc}]"))
        print(c("dim",   f"  │  $ {cmd}"))
        lines = []
        proc  = None
        self._skip_target = False   # reset per-target flag before each run
        try:
            proc = subprocess.Popen(
                cmd, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, preexec_fn=os.setsid
            )
            for line in iter(proc.stdout.readline, ""):
                # Check flags set by signal/kbd handlers
                if self._skip_target or self._skip_stage or self._abort:
                    try: os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    except: pass
                    break
                line = line.rstrip()
                if line:
                    print(c("dim", "  │  ") + line)
                    lines.append(line)
            proc.stdout.close()
            proc.wait(timeout=5)
            if self._skip_target and not self._skip_stage:
                print(c("yellow", "  └─ ⚡ subdomain skipped (Ctrl+C)"))
            elif self._skip_stage:
                print(c("yellow", "  └─ ⚡ stage skipped (Ctrl+E)"))
            elif self._abort:
                print(c("red",    "  └─ ✖ aborted (Ctrl+Q)"))
            else:
                icon = c("green", "✓") if proc.returncode == 0 else c("yellow", "~")
                print(c("dim", f"  └─ {icon} done ({len(lines)} lines)"))
        except subprocess.TimeoutExpired:
            if proc:
                try: os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                except: pass
            print(c("yellow", f"  └─ ⏱ Timeout after {timeout}s"))
        except Exception as e:
            print(c("red", f"  └─ ✗ {e}"))
        return "\n".join(lines)

    def _has(self, tool: str) -> bool:
        return bool(shutil.which(tool))

    def _count_lines(self, path: str) -> int:
        try:
            with open(path) as f:
                return sum(1 for l in f if l.strip())
        except: return 0

    # ── Stage 0: Install all required tools ──────────────────
    def _install_all_tools(self):
        missing = [t for t, _ in self.REQUIRED_TOOLS if not self._has(t)]
        if not missing:
            print(c("green", "  ✓ All recon tools already installed"))
            return

        print(c("yellow", f"\n  ╭─ {len(missing)} tools to install: {', '.join(missing)}"))
        print(c("dim", "  │  Running apt-get update..."))
        os.system("apt-get update -qq 2>/dev/null")

        for tool in missing:
            apt_pkg = self.APT_NAMES.get(tool, tool)
            print(c("cyan", f"\n  │  [apt] Installing {apt_pkg}..."))
            ret = os.system(f"apt-get install -y {apt_pkg} 2>/dev/null")
            if ret == 0 or self._has(tool):
                print(c("green", f"  │  ✓ {tool} ready"))
                continue
            # Try pip for pip-installable tools
            pip_pkg = self.PIP_NAMES.get(tool)
            if pip_pkg:
                print(c("dim", f"  │  [pip] pip install {pip_pkg}..."))
                ret2 = os.system(f"pip install {pip_pkg} --break-system-packages --ignore-installed -q")
                if ret2 == 0 or self._has(tool):
                    print(c("green", f"  │  ✓ {tool} installed via pip"))
                    continue
            print(c("yellow", f"  │  ~ {tool} unavailable — stage will be skipped"))

        print(c("green", "  ╰─ Tool check complete\n"))

    def run(self, domain: str) -> str:
        domain = re.sub(r"^https?://", "", domain.strip()).split("/")[0].strip()
        ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
        outdir = f"/tmp/recon_{domain}_{ts}"
        os.makedirs(outdir, exist_ok=True)

        print(c("green", "\n  ╔══ RECON PIPELINE ══════════════════════════════════════════"))
        print(c("green", f"  ║  Target : {c('white', domain)}"))
        print(c("green", f"  ║  Output : {outdir}"))
        print(c("green",  "  ║  Ctrl+C = skip stage · Double Ctrl+C = abort"))
        print(c("green", f"  ╚{'═'*62}"))

        report_parts = [
            f"# Recon Report: {domain}",
            f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}*",
            ""
        ]

        # ══ Stage 0: Install tools ════════════════════════════
        print(c("yellow", "\n  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
        print(c("yellow",  "  ▶ Stage 0 — Checking & Installing Required Tools"))
        print(c("yellow",  "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
        try:
            self._install_all_tools()
        except KeyboardInterrupt:
            print(c("yellow", "  ⚡ Tool install skipped"))

        # ══ Stage 1: Subdomain Enumeration ═══════════════════
        print(c("yellow", "\n  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
        print(c("yellow",  "  ▶ Stage 1 — Subdomain Enumeration"))
        print(c("yellow",  "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
        subs_file = f"{outdir}/subdomains.txt"
        all_subs  = []

        try:
            if self._has("subfinder"):
                self._run(
                    f"subfinder -d {domain} -silent -o {outdir}/subfinder.txt",
                    "subfinder", timeout=120
                )
            if self._has("sublist3r"):
                self._run(
                    f"sublist3r -d {domain} -o {outdir}/sublist3r.txt 2>/dev/null",
                    "sublist3r", timeout=180
                )
            # Merge + deduplicate
            os.system(
                f"cat {outdir}/subfinder.txt {outdir}/sublist3r.txt "
                f"2>/dev/null | sort -u > {subs_file}"
            )
            subs_count = self._count_lines(subs_file)
            print(c("green", f"\n  ✓ {subs_count} unique subdomains found → {subs_file}"))
            if subs_count > 0:
                with open(subs_file) as f:
                    all_subs = [l.strip() for l in f if l.strip()]
            report_parts += [f"## Subdomains ({subs_count} found)", "```",
                             "\n".join(all_subs[:100]) or "none", "```", ""]
        except KeyboardInterrupt:
            print(c("yellow", "  ⚡ Stage 1 skipped"))
            report_parts += ["## Subdomains", "```", "skipped", "```", ""]

        # ══ Stage 2: Live Host Filtering ══════════════════════
        print(c("yellow", "\n  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
        print(c("yellow",  "  ▶ Stage 2 — Live Host Filtering (httpx-toolkit)"))
        print(c("yellow",  "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
        live_file = f"{outdir}/live.txt"
        live_raw  = ""
        try:
            # Always add the main domain to the list
            with open(subs_file, "a") as f:
                f.write(f"\n{domain}\n")

            if self._has("httpx-toolkit") and os.path.exists(subs_file):
                live_raw = self._run(
                    f"httpx-toolkit -l {subs_file} -silent -o {live_file} "
                    f"-status-code -title -tech-detect 2>/dev/null",
                    "httpx-toolkit live filter", timeout=180
                )
                live_count = self._count_lines(live_file)
                print(c("green", f"  ✓ {live_count} live hosts → {live_file}"))
            elif self._has("httpx") and os.path.exists(subs_file):
                live_raw = self._run(
                    f"httpx -l {subs_file} -silent -o {live_file} 2>/dev/null",
                    "httpx live filter", timeout=180
                )
            report_parts += ["## Live Hosts", "```", live_raw[:2000] or "none", "```", ""]
        except KeyboardInterrupt:
            print(c("yellow", "  ⚡ Stage 2 skipped"))
            report_parts += ["## Live Hosts", "```", "skipped", "```", ""]

        # ══ Stage 2b: Deep Crawl & Parameter Extraction ══════
        print(c("yellow", "\n  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
        print(c("yellow",  "  ▶ Stage 2b — Deep Crawl & Parameter Extraction"))
        print(c("yellow",  "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
        crawl_dir   = f"{outdir}/crawl"
        os.makedirs(crawl_dir, exist_ok=True)
        all_urls_raw = ""
        get_urls_raw = ""
        post_urls_raw = ""

        try:
            # ── Read targets directly from live.txt (httpx-toolkit output) ──
            # httpx-toolkit line format: "http://sub.domain.com [200] [title] [tech]"
            # The URL is always the first token — use it exactly as-is (http or https).
            targets = []

            if os.path.exists(live_file):
                with open(live_file) as lf:
                    for raw_line in lf:
                        raw_line = raw_line.strip()
                        if not raw_line:
                            continue
                        # First token = URL exactly as httpx-toolkit found it
                        url = raw_line.split()[0].strip()
                        if url and url.startswith("http") and url not in targets:
                            targets.append(url)

            # If live.txt empty or missing, fall back to plain http of main domain
            if not targets:
                targets.append(f"http://{domain}")

            print(c("dim", f"  │  {len(targets)} live targets from httpx-toolkit:"))
            for t in targets:
                print(c("dim", f"  │    {t}"))

            # ── CrawlerX: separate output dir per subdomain ───────────
            if self._has("crawlerx"):
                for target_url in targets:
                    # Derive a clean dir name: scheme__hostname
                    scheme   = "https" if target_url.startswith("https") else "http"
                    hostname = re.sub(r"^https?://", "", target_url).split("/")[0]
                    # Output dir: crawl/<scheme>__<hostname>/
                    cx_out   = f"{crawl_dir}/{scheme}__{hostname}"
                    os.makedirs(cx_out, exist_ok=True)

                    print(c("cyan", f"\n  ┌─ [crawlerx] {scheme}://{hostname}"))
                    print(c("dim",  f"  │  Output → {cx_out}"))

                    self._run(
                        f'crawlerx -u {target_url} -o {cx_out} '
                        f'--threads 10 --depth 3 --sub --structure --common-paths',
                        f"{scheme}://{hostname}", timeout=240
                    )

                    # crawlerx saves inside an extra subdir: {cx_out}/crawlerx_<hostname>/
                    # Find that actual inner dir dynamically
                    actual_dir = cx_out  # fallback if no subdir
                    try:
                        subdirs = [
                            os.path.join(cx_out, d) for d in os.listdir(cx_out)
                            if os.path.isdir(os.path.join(cx_out, d))
                            and d.startswith("crawlerx_")
                        ]
                        if subdirs:
                            actual_dir = subdirs[0]  # always one per run
                    except Exception:
                        pass

                    print(c("dim", f"  │  Reading from: {actual_dir}"))

                    # Collect all output files
                    for ep_file, dest in [
                        (f"{actual_dir}/endpoints/all_endpoints.txt", "all"),
                        (f"{actual_dir}/endpoints/parameterized.txt", "all"),
                        (f"{actual_dir}/get/get_urls.txt",            "get"),
                        (f"{actual_dir}/post/post_urls.txt",          "post"),
                    ]:
                        if os.path.exists(ep_file):
                            with open(ep_file) as ef:
                                data = ef.read().strip()
                            if data:
                                if   dest == "all":  all_urls_raw  += data + "\n"
                                elif dest == "get":  get_urls_raw  += data + "\n"
                                else:                post_urls_raw += data + "\n"

                    # Also copy .req files to a central requests dir for easy access
                    req_dir = f"{crawl_dir}/requests/{hostname}"
                    os.makedirs(req_dir, exist_ok=True)
                    for sub in ("get", "post"):
                        src_req = f"{actual_dir}/{sub}"
                        dst_req = f"{req_dir}/{sub}"
                        if os.path.exists(src_req):
                            import shutil as _sh
                            if os.path.exists(dst_req):
                                _sh.rmtree(dst_req)
                            _sh.copytree(src_req, dst_req)

                # Print per-subdomain crawl summary
                print(c("green", f"\n  ✓ Crawlerx finished all {len(targets)} targets"))
                print(c("dim",   f"  │  Dirs: {crawl_dir}/<scheme>__<hostname>/"))
            else:
                print(c("yellow", "  │  crawlerx not installed — skipping deep crawl"))
                print(c("dim",    "  │  Install: pip install crawlerx --break-system-packages --ignore-installed"))

            # ── Deduplicate GET and POST URLs ──
            def dedup_urls(raw: str) -> list:
                seen_params = set()
                unique = []
                for line in raw.splitlines():
                    line = line.strip()
                    if not line or not line.startswith("http"):
                        continue
                    # Normalise: strip param values, keep param names as key
                    base = line.split("?")[0]
                    params = ""
                    if "?" in line:
                        from urllib.parse import urlparse, parse_qs
                        try:
                            parsed = urlparse(line)
                            param_keys = tuple(sorted(parse_qs(parsed.query).keys()))
                            params = str(param_keys)
                        except: params = line.split("?")[1]
                    key = base + params
                    if key not in seen_params:
                        seen_params.add(key)
                        unique.append(line)
                return unique

            unique_get  = dedup_urls(get_urls_raw)
            unique_post = dedup_urls(post_urls_raw)
            unique_all  = dedup_urls(all_urls_raw)

            # Save deduplicated files
            with open(f"{crawl_dir}/unique_get.txt",  "w") as f: f.write("\n".join(unique_get))
            with open(f"{crawl_dir}/unique_post.txt", "w") as f: f.write("\n".join(unique_post))
            with open(f"{crawl_dir}/unique_all.txt",  "w") as f: f.write("\n".join(unique_all))

            print(c("green", f"  ✓ {len(unique_all)} unique endpoints  |  "
                             f"{len(unique_get)} GET params  |  {len(unique_post)} POST params"))

            report_parts += [
                "## Crawl Results",
                f"- **Total unique endpoints**: {len(unique_all)}",
                f"- **GET parameterized URLs**: {len(unique_get)}",
                f"- **POST parameterized URLs**: {len(unique_post)}",
                "",
                "### Sample GET URLs (first 20)",
                "```", "\n".join(unique_get[:20]) or "none", "```",
                "",
                "### Sample POST URLs (first 20)",
                "```", "\n".join(unique_post[:20]) or "none", "```",
                "",
                f"Full crawl data: `{crawl_dir}/`", ""
            ]
            # Store for AI summary
            self.results["get_urls"]  = unique_get
            self.results["post_urls"] = unique_post
            self.results["all_urls"]  = unique_all

        except KeyboardInterrupt:
            print(c("yellow", "  ⚡ Stage 2b skipped"))
            report_parts += ["## Crawl Results", "```", "skipped", "```", ""]

        # ── Build scan target list from live.txt ─────────────────
        # Use the same targets we already computed for crawlerx.
        # Parse live.txt again (targets var may not be in scope here).
        scan_targets = []
        if os.path.exists(live_file):
            with open(live_file) as _lf:
                for _line in _lf:
                    _line = _line.strip()
                    if not _line:
                        continue
                    _url = _line.split()[0].strip()
                    if _url.startswith("http") and _url not in scan_targets:
                        scan_targets.append(_url)
        if not scan_targets:
            scan_targets = [f"http://{domain}"]

        def _stage_header(num: str, title: str):
            print(c("yellow", f"\n  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
            print(c("yellow", f"  ▶ Stage {num} — {title}"))
            print(c("yellow",  "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
            print(c("dim",    f"  │  {len(scan_targets)} target(s)  │  "
                              f"Ctrl+C=skip subdomain  Ctrl+E=skip stage  Ctrl+Q=abort"))

        def _reset_stage():
            self._skip_stage  = False
            self._skip_target = False

        # ══ Stage 3: WAF Detection ═════════════════════════════
        _stage_header("3", "WAF Detection (wafw00f)")
        _reset_stage()
        waf_raw = ""
        if self._has("wafw00f"):
            for _tgt in scan_targets:
                if self._abort: break
                if self._skip_stage:
                    print(c("yellow", f"  ⚡ Stage 3 skipped (Ctrl+E)"))
                    break
                self._skip_target = False
                _host = re.sub(r"^https?://", "", _tgt).split("/")[0]
                print(c("cyan", f"  ┄ [{_host}]"))
                _out = self._run(f"wafw00f {_tgt} 2>/dev/null",
                                 f"wafw00f {_host}", timeout=60)
                waf_raw += f"\n### {_host}\n" + _out
                report_parts += ["## WAF Detection", "```", waf_raw[:1500] or "none", "```", ""]

        # ══ Stage 4: Port Scan ════════════════════════════════
        _stage_header("4", "Port Scan (nmap)")
        _reset_stage()
        port_raw = ""
        PORTS = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,8888,9200,27017"
        if self._has("nmap") and not self._abort:
            for _tgt in scan_targets:
                if self._abort: break
                if self._skip_stage:
                    print(c("yellow", "  ⚡ Stage 4 skipped (Ctrl+E)"))
                    break
                self._skip_target = False
                _host = re.sub(r"^https?://", "", _tgt).split("/")[0]
                print(c("cyan", f"  ┄ [{_host}]"))
                _out = self._run(
                    f"nmap -T4 -sV --open -Pn -p {PORTS} {_host} 2>/dev/null",
                    f"nmap {_host}", timeout=240
                )
                port_raw += f"\n### {_host}\n" + _out
        report_parts += ["## Port Scan", "```", port_raw[:3000] or "no open ports", "```", ""]
        self.results["ports"] = port_raw

        # ══ Stage 5: Directory Brute-Force ════════════════════
        _stage_header("5", "Directory Brute-Force (gobuster)")
        _reset_stage()
        dir_raw = ""
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        if not os.path.exists(wordlist):
            wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
        if self._has("gobuster") and os.path.exists(wordlist) and not self._abort:
            for _tgt in scan_targets:
                if self._abort: break
                if self._skip_stage:
                    print(c("yellow", "  ⚡ Stage 5 skipped (Ctrl+E)"))
                    break
                self._skip_target = False
                _host = re.sub(r"^https?://", "", _tgt).split("/")[0]
                print(c("cyan", f"  ┄ [{_host}]"))
                _out = self._run(
                    f"gobuster dir -u {_tgt} -w {wordlist} -t 50 -q --no-error 2>/dev/null",
                    f"gobuster {_host}", timeout=300
                )
                dir_raw += f"\n### {_host}\n" + _out
        elif self._has("gobuster"):
            print(c("dim", "  [!] No wordlist — install seclists or dirb"))
        report_parts += ["## Directories Found", "```", dir_raw[:3000] or "none", "```", ""]

        # ══ Stage 6: Web Tech Fingerprint ════════════════════
        _stage_header("6", "Web Tech Fingerprint (whatweb)")
        _reset_stage()
        tech_raw = ""
        if self._has("whatweb") and not self._abort:
            for _tgt in scan_targets:
                if self._abort: break
                if self._skip_stage:
                    print(c("yellow", "  ⚡ Stage 6 skipped (Ctrl+E)"))
                    break
                self._skip_target = False
                _host = re.sub(r"^https?://", "", _tgt).split("/")[0]
                print(c("cyan", f"  ┄ [{_host}]"))
                _out = self._run(
                    f"whatweb -a 3 --no-errors {_tgt} 2>/dev/null",
                    f"whatweb {_host}", timeout=60
                )
                tech_raw += f"\n### {_host}\n" + _out
        report_parts += ["## Web Technologies", "```", tech_raw[:2000] or "none", "```", ""]

        # ══ Stage 7: Nikto Web Vulnerability Scan ════════════
        _stage_header("7", "Web Vulnerability Scan (nikto)")
        _reset_stage()
        nikto_raw = ""
        if self._has("nikto") and not self._abort:
            for _tgt in scan_targets:
                if self._abort: break
                if self._skip_stage:
                    print(c("yellow", "  ⚡ Stage 7 skipped (Ctrl+E)"))
                    break
                self._skip_target = False
                _host = re.sub(r"^https?://", "", _tgt).split("/")[0]
                print(c("cyan", f"  ┄ [{_host}]"))
                _out = self._run(
                    f"nikto -h {_tgt} -nointeractive 2>/dev/null",
                    f"nikto {_host}", timeout=300
                )
                nikto_raw += f"\n### {_host}\n" + _out
        report_parts += ["## Nikto Findings", "```", nikto_raw[:4000] or "none", "```", ""]

        # ══ Stage 8: Nuclei Vulnerability Scan ═══════════════
        _stage_header("8", "Template Vuln Scan (nuclei)")
        _reset_stage()
        nuclei_raw = ""
        if self._has("nuclei") and not self._abort:
            os.system("nuclei -update-templates -silent 2>/dev/null &")
            nuclei_out = f"{outdir}/nuclei"
            os.makedirs(nuclei_out, exist_ok=True)
            for _tgt in scan_targets:
                if self._abort: break
                if self._skip_stage:
                    print(c("yellow", "  ⚡ Stage 8 skipped (Ctrl+E)"))
                    break
                self._skip_target = False
                _host = re.sub(r"^https?://", "", _tgt).split("/")[0]
                _safe = _host.replace(".", "_")
                print(c("cyan", f"  ┄ [{_host}]"))
                _out = self._run(
                    f"nuclei -u {_tgt} -severity low,medium,high,critical "
                    f"-silent -o {nuclei_out}/{_safe}.txt 2>/dev/null",
                    f"nuclei {_host}", timeout=300
                )
                nuclei_raw += f"\n### {_host}\n" + _out
        report_parts += ["## Nuclei Vulnerabilities", "```",
                         nuclei_raw[:5000] or "none found", "```", ""]

        # ══ Stage 9: AI Vulnerability & Critical Findings Summary ══
        print(c("yellow", "\n  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
        print(c("yellow",  "  ▶ Stage 9 — AI Vulnerability & Critical Findings Summary"))
        print(c("yellow",  "  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
        ai_summary = ""
        try:
            print(c("dim", "  │  Analyzing findings with AI..."))
            # Build a condensed findings brief for the AI
            get_sample  = "\n".join(self.results.get("get_urls",  [])[:30])
            post_sample = "\n".join(self.results.get("post_urls", [])[:30])
            ports_data  = self.results.get("ports", "")[:1000]
            nikto_data  = nikto_raw[:2000] if nikto_raw else ""
            nuclei_data = nuclei_raw[:2000] if nuclei_raw else ""
            waf_data    = waf_raw[:300] if waf_raw else ""
            tech_data   = tech_raw[:300] if tech_raw else ""

            prompt = f"""You are an expert penetration tester reviewing automated recon results.
Analyze the following recon data for {domain} and provide a structured security assessment.

TARGET: {domain}
WAF: {waf_data or "unknown"}
TECH STACK: {tech_data or "unknown"}
OPEN PORTS: {ports_data or "none found"}
NIKTO FINDINGS: {nikto_data or "none"}
NUCLEI FINDINGS: {nuclei_data or "none"}
GET PARAMETERIZED URLs ({len(self.results.get("get_urls",[]))} total, sample):
{get_sample or "none"}
POST URLs ({len(self.results.get("post_urls",[]))} total, sample):
{post_sample or "none"}

Provide:
1. CRITICAL FINDINGS - anything that needs immediate attention
2. HIGH RISK - significant vulnerabilities or attack surface
3. INTERESTING PARAMETERS - GET/POST params worth testing for SQLi/XSS/IDOR/SSRF
4. ATTACK VECTORS - recommended next steps for a pentest
5. RISK SCORE - Overall risk rating (Critical/High/Medium/Low) with brief justification

Be concise and actionable. Focus on real findings, not generic advice."""

            agent      = FreeLLM(model=self.model)
            ai_summary = agent.ask(prompt).strip()

            print()
            print(c("red",    "  ╔══ AI SECURITY ASSESSMENT " + "═"*36))
            for line in ai_summary.splitlines():
                severity_color = "red" if any(w in line.upper() for w in ["CRITICAL","HIGH RISK"]) else \
                                 "yellow" if any(w in line.upper() for w in ["HIGH","MEDIUM","WARNING"]) else \
                                 "white"
                print(c("red", "  ║ ") + c(severity_color, line))
            print(c("red", f"  ╚{'═'*62}"))
            report_parts += ["", "## AI Security Assessment", "", ai_summary, ""]
        except KeyboardInterrupt:
            print(c("yellow", "  ⚡ AI summary skipped"))
        except Exception as e:
            print(c("dim", f"  [!] AI summary failed: {e}"))

        # ══ Save report ════════════════════════════════════════
        report_md   = "\n".join(report_parts)
        report_path = f"{outdir}/report.md"
        with open(report_path, "w") as f:
            f.write(report_md)

        # Print final summary table
        print(c("green", "\n  ╔══ RECON COMPLETE ══════════════════════════════════════════"))
        print(c("green", f"  ║  Target    : {c('white', domain)}"))
        print(c("green", f"  ║  Subdomains: {len(all_subs)} found"))
        print(c("green", f"  ║  GET URLs  : {len(self.results.get('get_urls', []))} unique parameterized"))
        print(c("green", f"  ║  POST URLs : {len(self.results.get('post_urls', []))} unique parameterized"))
        print(c("green", f"  ║  Report    : {report_path}"))
        print(c("green", f"  ║  All files : {outdir}/"))
        print(c("green", f"  ╚{'═'*62}"))
        print(c("dim",   f"  Tip: cat {report_path} | less"))
        print()
        self._restore_signal_handlers()
        return report_md


# ══════════════════════════════════════════════════════════════
# SECTION 13 — CLI INTERFACE
# ══════════════════════════════════════════════════════════════

class CLI:
    PROMPT = (c("green", "hackers") + c("dim", "@") +
              c("cyan", "ai") + c("dim", " ❯ "))

    SLASH_COMMANDS = {
        "/help":    "Show this help",
        "/clear":   "Clear conversation history",
        "/history": "Show last 10 messages",
        "/profile": "Show live system profile",
        "/tools":   "List detected pentest tools",
        "/sysinfo": "Run live system info commands",
        "/switch":  "Switch model: /switch <model>",
        "/recon":   "Full recon pipeline: /recon <domain>",
        "/note":    "Save target note: /note <target> <note>",
        "/notes":   "Show notes: /notes [target]",
        "/save":    "Save session report: /save [filename]",
        "/dryrun":  "Toggle dry-run mode (preview without executing)",
        "/exit":    "Exit Hackers AI",
    }

    def __init__(self):
        self.model    = DEFAULT_MODEL
        self.memory   = MemoryDB()
        self.memory.clear_history()          # fresh session every run
        self.profiler = SystemProfiler()
        self.dry_run  = False                # /dryrun toggle
        print(c("dim", "  [*] Profiling system..."), end="", flush=True)
        self.profile  = self.profiler.profile()
        print(c("green", " done"))

    def _print_banner(self):
        print(c("green", BANNER))
        root_str = c("red", "● ROOT") if self.profile["root"] else c("yellow", "● USER")
        n_tools  = len(self.profile["available_tools"])
        print(c("dim",   f"  Model    : {self.model}  |  Agent v{VERSION}"))
        print(c("dim",   f"  OS       : {self.profile.get('distro','Linux')}  |  "
                         f"Kernel {self.profile.get('kernel','')}  |  "
                         f"{self.profile.get('arch','')}"))
        print(c("dim",   f"  Host     : {self.profile.get('hostname','')}  |  "
                         f"IP {self.profile.get('ip','')}  |  {root_str}"))
        print(c("dim",   f"  Hardware : CPU {self.profile.get('cpu','')}  |  "
                         f"RAM {self.profile.get('ram','')}"))
        print(c("dim",   f"  Tools    : {n_tools} pentest tools detected  |  DB: {DB_PATH}"))
        dryrun_str = c("yellow", "  ⚡ DRY-RUN mode active") if self.dry_run else ""
        print(c("dim",   "  Type /help for commands" + ("  " + dryrun_str if self.dry_run else "") + "\n"))

    def _handle_slash(self, cmd: str) -> bool:
        parts = cmd.strip().split(None, 1)
        slug  = parts[0].lower()
        arg   = parts[1].strip() if len(parts) > 1 else ""

        if slug == "/help":
            print()
            print(c("yellow", "  ╔══ HACKERS AI COMMANDS " + "═"*39))
            categories = [
                ("General",   ["/help","/clear","/history","/profile","/tools","/sysinfo","/switch","/exit"]),
                ("Recon",     ["/recon","/note","/notes"]),
                ("Session",   ["/save","/dryrun"]),
            ]
            for cat, keys in categories:
                print(c("yellow", f"  ║  {c('white', cat)}"))
                for k in keys:
                    v = self.SLASH_COMMANDS.get(k, "")
                    print(f"  {c('yellow','║')}    {c('cyan', k):<28} {v}")
            print(c("yellow", "  ╚" + "═"*61))
            print()
            return True

        if slug == "/clear":
            self.memory.clear_history()
            print(c("green", "  ✓ Conversation history cleared."))
            return True

        if slug == "/history":
            history = self.memory.get_history(MAX_HISTORY)
            if not history:
                print(c("dim", "  No history yet."))
            else:
                print()
                for i, h in enumerate(history, 1):
                    role_str = c("cyan", "YOU") if h["role"] == "user" \
                               else c("green", " AI")
                    snippet  = h["content"][:120].replace("\n", " ")
                    print(f"  {i:02d}. [{role_str}] {snippet}")
                print()
            return True

        if slug == "/profile":
            print()
            skip = {"available_tools", "uname"}
            for k, v in self.profile.items():
                if k in skip:
                    continue
                print(f"  {c('cyan', k+':'): <20} {v}")
            print()
            return True

        if slug == "/sysinfo":
            ex = CommandExecutor()
            sections = [
                ("OS / Distro", "lsb_release -a 2>/dev/null || cat /etc/os-release"),
                ("Kernel",      "uname -r && uname -m"),
                ("CPU",         "lscpu | grep -E 'Model name|Socket|Core|Thread|MHz'"),
                ("Memory",      "free -h"),
                ("Disk",        "lsblk && echo '' && df -h"),
                ("Network",     "ip addr show | grep -E 'inet |link/ether'"),
                ("Uptime/Load", "uptime"),
                ("Users",       "who"),
            ]
            for label, cmd in sections:
                print(c("cyan", f"\n  ── {label} ──"))
                ex.run(cmd, timeout=10)
            return True

        if slug == "/tools":
            tools = self.profile["available_tools"]
            if not tools:
                print(c("yellow", "  No pentest tools detected in PATH."))
            else:
                print(c("green", f"\n  {len(tools)} tools detected:"))
                cols = 5
                for i in range(0, len(tools), cols):
                    row = tools[i:i + cols]
                    print("  " + "  ".join(f"{t:<18}" for t in row))
            print()
            return True

        if slug == "/switch":
            if arg:
                self.model = arg
                print(c("green", f"  ✓ Switched to model: {self.model}"))
            else:
                print(c("red", "  Usage: /switch <model_name>"))
            return True

        if slug in ("/recon", "recon"):
            if not arg:
                print(c("red", "  Usage: /recon <domain>  or  recon <domain>"))
            else:
                pipeline = ReconPipeline(self.model, self.memory)
                pipeline.run(arg)
            return True

        if slug == "/note":
            # /note <target> <note text>
            parts2 = arg.split(None, 1)
            if len(parts2) < 2:
                print(c("red", "  Usage: /note <target> <note text>"))
            else:
                target, note = parts2[0], parts2[1]
                self.memory.add_note(target, note)
                print(c("green", f"  ✓ Note saved for {target}: {note}"))
            return True

        if slug == "/notes":
            notes = self.memory.get_notes(arg if arg else None)
            if not notes:
                print(c("dim", "  No notes found."))
            else:
                print()
                for n in notes:
                    print(f"  {c('cyan', n['target']):<30} {n['note']}  {c('dim', n['timestamp'][:16])}")
                print()
            return True

        if slug == "/save":
            fname = arg.strip() or f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            if not fname.endswith(".md"):
                fname += ".md"
            md = self.memory.export_session(fname.replace(".md",""))
            path = os.path.expanduser(f"~/{fname}")
            with open(path, "w") as fh:
                fh.write(md)
            print(c("green", f"  ✓ Session saved to {path}"))
            return True

        if slug == "/dryrun":
            self.dry_run = not self.dry_run
            state = c("yellow","ON  — commands will be shown but NOT executed") if self.dry_run                     else c("green", "OFF — commands will execute normally")
            print(c("cyan", f"  ⚡ Dry-run mode: {state}"))
            return True

        if slug == "/exit":
            print(c("cyan", "\n  Goodbye. Stay ethical.\n"))
            sys.exit(0)

        return False

    def _confirm(self, plan: dict) -> bool:
        print()
        w = c("yellow", "║")
        bar63 = "═" * 44
        print(c("yellow", f"  ╔══ EXECUTION PLAN {bar63}"))
        print(f"  {w}  {c('white','Summary')} : {plan.get('summary','N/A')}")
        print(f"  {w}  {c('white','Steps  ')} : {len(plan.get('steps', []))}")
        if plan.get("requires_root"):
            print(f"  {w}  {c('red','⚠  Requires root / sudo')}")
        warn = plan.get("warning")
        if warn and str(warn).lower() not in ("null", "none", ""):
            print(f"  {w}  {c('red','⚡ WARNING')}: {warn}")
        print(c("yellow", f"  ╠══ STEPS {'═' * 53}"))
        for s in plan.get("steps", []):
            stype = s.get("type", "command").upper()
            label = (s.get("command") or s.get("description") or "")[:82]
            tc    = ("cyan" if stype == "COMMAND" else
                     "magenta" if stype == "PYTHON" else "dim")
            print(f"  {w}  [{c(tc, f'{stype:<8}')}] {label}")
        print(c("yellow", f"  ╚{'═' * 62}"))
        print()
        try:
            ans = input(c("cyan", "  Execute? [Y/n]: ")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            ans = "n"
        return ans in ("", "y", "yes")

    def _print_response(self, text: str):
        print()
        print(c("green", "  ╭─ Hackers AI ") + c("dim", "─" * 49))
        for line in text.splitlines():
            print(c("dim", "  │ ") + line)
        print(c("green", "  ╰" + "─" * 62))
        print()

    def process(self, user_input: str):
        history = self.memory.get_history(MAX_HISTORY)
        intent  = IntentClassifier.classify(user_input)

        # ── Informational: answer directly ───────────────────
        if intent == "informational":
            print(c("dim", "\n  [→] Informational query"))
            gen      = ResponseGenerator(model=self.model)
            response = gen.ask(user_input, history, self.profile)
            self._print_response(response)
            self.memory.add_message("user",      user_input, self.model)
            self.memory.add_message("assistant", response,   self.model)
            return

        # ── Task flow ─────────────────────────────────────────
        # Step 1: Resolve context — mine history for missing info
        print(c("dim", "\n  [→] Resolving task context..."))
        resolver = ContextResolver(model=self.model)
        ctx      = resolver.resolve(user_input, history)

        if not ctx.get("ready", True):
            # AI confirmed info is missing — ask the user ONE focused question
            question = ctx.get("question", "Could you provide more details?")
            print()
            print(c("yellow", "  ╭─ Need more info " + "─" * 44))
            print(c("yellow", f"  │  {question}"))
            print(c("yellow", "  ╰" + "─" * 61))
            print()
            # Store both so next turn the AI finds the answer in history
            self.memory.add_message("user",      user_input, self.model)
            self.memory.add_message("assistant", f"[Waiting for: {question}]", self.model)
            return

        # Use enriched task (target filled from history) or original
        enriched   = ctx.get("enriched_task") or user_input
        found_in   = ctx.get("found_in", "task")
        if found_in == "history":
            print(c("cyan", f"  [✓] Target found in history → {enriched[:80]}"))
        elif found_in == "task":
            print(c("dim",  "  [✓] Target present in task"))
        else:
            print(c("dim",  "  [✓] No target needed"))

        # Step 2: Plan
        print(c("dim", "  [→] Generating execution plan..."))
        planner = PlannerEngine()
        plan    = planner.plan(enriched, history, self.profile, self.model)

        if not plan:
            print(c("yellow", "  [!] Planner failed — falling back to direct response."))
            gen      = ResponseGenerator(model=self.model)
            response = gen.ask(enriched, history, self.profile)
            self._print_response(response)
            self.memory.add_message("user",      user_input, self.model)
            self.memory.add_message("assistant", response,   self.model)
            return

        # Purely informational plan
        if plan.get("intent") == "informational":
            info = plan.get("summary", "")
            for s in plan.get("steps", []):
                if s.get("description"):
                    info += "\n" + s["description"]
            self._print_response(info)
            self.memory.add_message("user",      user_input, self.model)
            self.memory.add_message("assistant", info,       self.model)
            return

        # Step 3: Dry-run mode — show plan but don't execute
        if self.dry_run:
            print(c("yellow", "\n  ⚡ DRY-RUN MODE — plan shown, nothing executed.\n"))
            self._confirm(plan)   # show the plan box
            return

        # Step 3: Confirm
        if not self._confirm(plan):
            print(c("red", "\n  ✗ Task aborted.\n"))
            return

                # Step 4: Execute
        # Step 5: Execute
        task_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        engine  = ExecutionEngine(self.memory, model=self.model)
        raw     = engine.execute_plan(plan, task_id)

        # Step 5: Summarize
        print(c("dim", "\n  [→] Summarizing results..."))
        summary = Summarizer(model=self.model).summarize(raw, user_input, history)

        self._print_response(summary)
        self.memory.add_message("user",      user_input, self.model)
        self.memory.add_message("assistant", summary,    self.model)

        # ── Auto next-step suggestions ────────────────────────
        self._suggest_next(user_input, summary)

    def _suggest_next(self, task: str, result_summary: str):
        """Ask AI for 2-3 smart follow-up suggestions based on what just ran."""
        try:
            prompt = (
                "You are Hackers AI. Based on this completed task and its result, "
                "suggest 2-3 SHORT follow-up commands the user might want to run next.\n"
                "Rules:\n"
                "- Each suggestion must be a single concrete command or question\n"
                "- Keep each under 60 chars\n"
                "- Only suggest if it makes sense (e.g. after port scan → suggest vuln scan)\n"
                "- If task was trivial (whoami, ls, etc.) return empty string\n"
                "- Format: one suggestion per line, no bullets, no numbering\n\n"
                f"Task: {task}\n"
                f"Result summary: {result_summary[:400]}"
            )
            agent = FreeLLM(model=self.model)
            raw   = agent.ask(prompt).strip()
            lines = [l.strip() for l in raw.splitlines() if l.strip() and len(l.strip()) > 5][:3]
            if lines:
                print(c("dim", "  ╭─ Suggested next steps " + "─" * 38))
                for i, s in enumerate(lines, 1):
                    print(c("dim", "  │ ") + c("cyan", f"  {i}.") + f" {s}")
                print(c("dim", "  ╰" + "─" * 61))
                print()
        except Exception:
            pass  # suggestions are optional — never crash for them

    def run(self):
        self._print_banner()
        while True:
            try:
                user_input = input(self.PROMPT).strip()
            except (EOFError, KeyboardInterrupt):
                print(c("cyan", "\n\n  Goodbye. Stay ethical.\n"))
                break

            if not user_input:
                continue

            # Allow "recon <domain>", "note <x> <y>", "notes", "save", "dryrun" without slash
            _words = user_input.strip().split()
            _nat   = _words[0].lower() if _words else ""
            if _nat in ("recon","note","notes","save","dryrun"):
                synthetic = "/" + user_input.strip()
                if not self._handle_slash(synthetic):
                    print(c("red", f"  Unknown command. Type /help."))
                continue

            if user_input.startswith("/"):
                if not self._handle_slash(user_input):
                    print(c("red", f"  Unknown command: {user_input}. Type /help."))
                continue

            try:
                self.process(user_input)
            except KeyboardInterrupt:
                print(c("yellow", "\n  [⚡] Interrupted. Type /exit to quit.\n"))
            except Exception as e:
                print(c("red", f"\n  [ERROR] {e}"))
                import traceback
                traceback.print_exc()

# ══════════════════════════════════════════════════════════════
# SECTION 14 — ENTRY POINT
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # ── Require root — re-exec with sudo if not already root ──
    if os.geteuid() != 0:
        print("\033[33m  [*] Hackers AI requires root. Re-launching with sudo...\033[0m")
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
        sys.exit(1)  # never reached

    # Bust stale bytecode cache
    import shutil as _shutil
    _cache = os.path.join(os.path.dirname(os.path.abspath(__file__)), "__pycache__")
    if os.path.isdir(_cache):
        _shutil.rmtree(_cache, ignore_errors=True)

    cli = CLI()
    cli.run()
