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

class ErrorAnalyzer:
    def __init__(self, model: str, executor: CommandExecutor):
        self.model    = model
        self.executor = executor

    def _get_tool_help(self, tool: str) -> str:
        r = self.executor.run(f"{tool} --help 2>&1 || {tool} -h 2>&1", timeout=8)
        return (r["stdout"] + r["stderr"])[:1500]

    def analyze_and_fix(self, failed_cmd: str, error_output: str,
                        history: list) -> Optional[str]:
        tool = failed_cmd.strip().split()[0] if failed_cmd.strip() else ""
        help_text = ""
        if tool and shutil.which(tool):
            help_text = self._get_tool_help(tool)

        fix_prompt = (
            "A Linux command failed. Return ONLY the corrected single-line "
            "shell command. No explanation, no markdown, no code fences.\n\n"
            f"Failed:\n{failed_cmd}\n\n"
            f"Error:\n{error_output[:800]}\n"
            + (f"\nTool help:\n{help_text}\n" if help_text else "")
        )

        parts = []
        for h in history[-4:]:
            parts.append(f"[{h['role'].upper()}]: {h['content']}")
        parts.append(f"[USER]: {fix_prompt}")

        try:
            agent = FreeLLM(model=self.model)
            raw   = agent.ask("\n\n".join(parts)).strip()
            raw   = re.sub(r"```.*?```", "", raw, flags=re.DOTALL).strip()
            fixed = raw.splitlines()[0].strip().strip("`")
            return fixed if fixed and fixed != failed_cmd else None
        except Exception:
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
                                                    step.get("tool",""), label="")
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
                        step.get("tool",""), label=f"S{sid}", lock=lk
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

    def _run_with_healing(self, command: str, stype: str,
                          task_id: str, step_id, tool: str,
                          label: str = "", lock: threading.Lock = None) -> dict:
        history = self.memory.get_history(4)
        result  = {}
        for attempt in range(1, MAX_RETRIES + 1):
            if stype == "python":
                result = self.py_exec.run(command)
            else:
                result = self.cmd_exec.run(command, label=label, lock=lock)

            # Cancelled by user — don't retry, just return
            if result.get("cancelled"):
                return result

            status = "success" if result["success"] else "error"
            self.memory.log_task_step(
                task_id, step_id, tool, command,
                result["stdout"][:2000], status
            )

            if result["success"]:
                return result

            if attempt < MAX_RETRIES:
                _lp = (lambda m: _locked_print(lock, m)) if lock else print
                _lp(c("yellow",
                    f"  ⚠ Step {step_id} attempt {attempt}/{MAX_RETRIES} failed — self-healing..."))
                error_text = result["stderr"] or result["stdout"]
                fixed = self.analyzer.analyze_and_fix(command, error_text, history)
                if fixed and fixed.strip() != command.strip():
                    _lp(c("magenta", f"  ↺ Rebuilt: {fixed}"))
                    command = fixed
                else:
                    _lp(c("red", "  ✗ No fix found, moving on."))
                    break
            else:
                (lambda m: _locked_print(lock, m) if lock else print(m))(
                    c("red", f"  ✗ Step {step_id} failed after {MAX_RETRIES} attempts."))

        return result

# ══════════════════════════════════════════════════════════════
# SECTION 11 — SUMMARIZER
# ══════════════════════════════════════════════════════════════

class Summarizer:
    def __init__(self, model: str = DEFAULT_MODEL):
        self.model = model

    def summarize(self, raw_results: str, original_request: str,
                  history: list) -> str:
        system_ctx = (
            "You are Hackers AI. Produce a clear, concise report from the command output below.\n"
            "Highlight: subdomains found, open ports, vulnerabilities, errors, important data.\n"
            "Use markdown. Be direct. Do not repeat raw output verbatim."
        )
        parts = [system_ctx, ""]
        for h in history[-3:]:
            prefix = "USER" if h["role"] == "user" else "ASSISTANT"
            parts.append(f"[{prefix}]: {h['content']}")
        parts.append(f"[ORIGINAL REQUEST]: {original_request}")
        parts.append(f"[EXECUTION OUTPUT]:\n{raw_results[:5000]}")

        agent    = FreeLLM(model=self.model)
        response = agent.ask("\n".join(parts))
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
        "/sysinfo": "Run live system info commands now",
        "/switch":  "Switch model: /switch <model_name>",
        "/exit":    "Exit Hackers AI",
    }

    def __init__(self):
        self.model    = DEFAULT_MODEL
        self.memory   = MemoryDB()
        self.memory.clear_history()          # fresh session every run
        self.profiler = SystemProfiler()
        print(c("dim", "  [*] Profiling system..."), end="", flush=True)
        self.profile  = self.profiler.profile()
        print(c("green", " done"))

    def _print_banner(self):
        print(c("green", BANNER))
        root_str = c("red", "● ROOT") if self.profile["root"] else c("yellow", "● USER")
        n_tools  = len(self.profile["available_tools"])
        print(c("dim",   f"  Model    : {self.model}"))
        print(c("dim",   f"  OS       : {self.profile.get('distro','Linux')}  |  "
                         f"Kernel {self.profile.get('kernel','')}  |  "
                         f"{self.profile.get('arch','')}"))
        print(c("dim",   f"  Host     : {self.profile.get('hostname','')}  |  "
                         f"IP {self.profile.get('ip','')}  |  {root_str}"))
        print(c("dim",   f"  Hardware : CPU {self.profile.get('cpu','')}  |  "
                         f"RAM {self.profile.get('ram','')}"))
        print(c("dim",   f"  Tools    : {n_tools} pentest tools detected  |  DB: {DB_PATH}"))
        print(c("dim",   "  Type /help for commands\n"))

    def _handle_slash(self, cmd: str) -> bool:
        parts = cmd.strip().split(None, 1)
        slug  = parts[0].lower()
        arg   = parts[1].strip() if len(parts) > 1 else ""

        if slug == "/help":
            print()
            for k, v in self.SLASH_COMMANDS.items():
                print(f"  {c('cyan', k):<32} {v}")
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

        # Step 3: Confirm
        if not self._confirm(plan):
            print(c("red", "\n  ✗ Task aborted.\n"))
            return

        # Step 4: Execute
        task_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        engine  = ExecutionEngine(self.memory, model=self.model)
        raw     = engine.execute_plan(plan, task_id)

        # Step 5: Summarize
        print(c("dim", "\n  [→] Summarizing results..."))
        summary = Summarizer(model=self.model).summarize(raw, user_input, history)

        self._print_response(summary)
        self.memory.add_message("user",      user_input, self.model)
        self.memory.add_message("assistant", summary,    self.model)

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

            if user_input.startswith("/"):
                if not self._handle_slash(user_input):
                    print(c("red", f"  Unknown command: {user_input}. Type /help."))
                continue

            try:
                self.process(user_input)
            except Exception as e:
                print(c("red", f"\n  [ERROR] {e}"))
                import traceback
                traceback.print_exc()

# ══════════════════════════════════════════════════════════════
# SECTION 14 — ENTRY POINT
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    cli = CLI()
    cli.run()
