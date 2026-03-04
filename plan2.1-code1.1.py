#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║              H A C K E R S   A I  v1.0              ║
║         Ultimate Linux AI Pentesting Assistant       ║
╚══════════════════════════════════════════════════════╝
"""

# ─── SUDO GATE (must be first) ──────────────────────────────────────────────────
import os, sys
if os.geteuid() != 0:
    print("\033[91m\n[!] Hackers AI requires root privileges.\n    Run: sudo python3 hackers_ai.py\033[0m\n")
    sys.exit(1)

# ─── AUTO-INSTALL DEPENDENCIES ─────────────────────────────────────────────────
import subprocess

def _pip(pkg):
    subprocess.run([sys.executable, "-m", "pip", "install", pkg,
                    "--break-system-packages", "-q"], capture_output=True)

try:
    from freellm import FreeLLM
except ImportError:
    print("[*] Installing freellm..."); _pip("freellm")
    from freellm import FreeLLM

# ─── STDLIB IMPORTS ────────────────────────────────────────────────────────────
import json, re, tempfile, shutil, platform
from pathlib import Path
from datetime import datetime

# ─── ANSI COLORS ───────────────────────────────────────────────────────────────
class C:
    R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"
    M="\033[95m"; CY="\033[96m"; W="\033[97m"; D="\033[2m"
    BD="\033[1m"; RST="\033[0m"; UL="\033[4m"
    def red(s):    return f"{C.R}{s}{C.RST}"
    def green(s):  return f"{C.G}{s}{C.RST}"
    def yellow(s): return f"{C.Y}{s}{C.RST}"
    def cyan(s):   return f"{C.CY}{s}{C.RST}"
    def bold(s):   return f"{C.BD}{s}{C.RST}"
    def dim(s):    return f"{C.D}{s}{C.RST}"
    def mag(s):    return f"{C.M}{s}{C.RST}"

# ─── PATHS & CONSTANTS ─────────────────────────────────────────────────────────
AI_DIR       = Path("/root/.hackers_ai")
OS_INFO_FILE = AI_DIR / "os_info.json"
MAX_HISTORY  = 20          # 10 exchanges × 2
MAX_RETRIES  = 3           # error-retry per step
CMD_TIMEOUT  = 180         # seconds

AI_DIR.mkdir(parents=True, exist_ok=True)

# ─── BANNER ────────────────────────────────────────────────────────────────────
BANNER = f"""{C.R}{C.BD}
 ██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗ ███████╗     █████╗ ██╗
 ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗██╔════╝    ██╔══██╗██║
 ███████║███████║██║     █████╔╝ █████╗  ██████╔╝███████╗    ███████║██║
 ██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗╚════██║    ██╔══██║██║
 ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║███████║    ██║  ██║██║
 ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝    ╚═╝  ╚═╝╚═╝
{C.RST}{C.CY}                      Ultimate Linux AI Assistant{C.RST}
{C.D}            /clear  /exit  /switch "<model>"  /help{C.RST}
"""

# ─── OS INFO GATHERING ─────────────────────────────────────────────────────────
def _run_silent(cmd, timeout=5):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL,
                                       timeout=timeout).decode().strip()
    except:
        return "unknown"

def gather_os_info():
    if OS_INFO_FILE.exists():
        try:
            with open(OS_INFO_FILE) as f:
                return json.load(f)
        except:
            pass
    print(C.cyan("[*] First run — gathering system fingerprint..."))
    info = {
        "os_release":    _run_silent("cat /etc/os-release | head -8"),
        "kernel":        _run_silent("uname -r"),
        "arch":          _run_silent("uname -m"),
        "hostname":      _run_silent("hostname"),
        "python_bin":    sys.executable,
        "python_ver":    _run_silent(f"{sys.executable} --version"),
        "shell":         os.environ.get("SHELL", "/bin/bash"),
        "home":          str(Path.home()),
        "cpu":           _run_silent("grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2").strip(),
        "ram_total":     _run_silent("grep MemTotal /proc/meminfo | awk '{print $2,$3}'"),
        "disk_root":     _run_silent("df -h / | tail -1 | awk '{print $2\" total, \"$4\" free\"}'"),
        "interfaces":    _run_silent("ip -o link show | awk -F': ' '{print $2}' | tr '\\n' ','"),
        "default_iface": _run_silent("ip route | grep default | awk '{print $5}' | head -1") or "eth0",
        "wireless_iface":_run_silent("iw dev 2>/dev/null | grep Interface | awk '{print $2}' | head -1") or "wlan0",
        "public_ip":     _run_silent("curl -s --max-time 4 https://api.ipify.org"),
        "local_ip":      _run_silent("ip route get 1 2>/dev/null | awk '{print $7;exit}'"),
        "pkg_manager":   _run_silent("which apt || which dnf || which pacman | head -1"),
        "snap_avail":    "yes" if shutil.which("snap") else "no",
        "git_avail":     "yes" if shutil.which("git") else "no",
        "gathered_at":   datetime.now().isoformat(),
    }
    with open(OS_INFO_FILE, "w") as f:
        json.dump(info, f, indent=2)
    print(C.green("[✓] System fingerprint saved.\n"))
    return info

# ─── SYSTEM PROMPT BUILDER ─────────────────────────────────────────────────────
def build_system_prompt(info):
    return f"""You are HACKERS AI — an elite AI assistant for Linux penetration testing, cybersecurity, and system administration running on Kali Linux.

SYSTEM FINGERPRINT:
{json.dumps(info, indent=2)}

████████████████████████████████████████████████████████████
ABSOLUTE OUTPUT RULE — VIOLATIONS BREAK THE PROGRAM
████████████████████████████████████████████████████████████

YOUR ENTIRE RESPONSE MUST BE A SINGLE RAW JSON OBJECT.
- First character: {{
- Last character: }}
- NO text before the opening brace
- NO text after the closing brace
- NO markdown, NO code fences (```), NO explanations outside JSON
- ALL string values must use proper JSON escaping (\\n \\t \\" \\\\)

████████████████████████████████████████████████████████████
RESPONSE SCHEMAS — USE EXACTLY ONE PER RESPONSE
████████████████████████████████████████████████████████████

SCHEMA A — Pure information / greeting / question with no execution needed:
{{"type":"chat","message":"your concise plain-text answer here"}}

SCHEMA B — Task that requires running commands or python:
{{"type":"task","message":"one sentence describing what you will do","plan":["Step 1 description","Step 2 description"],"steps":[{{"desc":"short step label","action":"command","content":"full shell command ready to run"}},{{"desc":"short step label","action":"python","content":"#!/usr/bin/env python3\\nimport os\\n# full self-contained script"}}]}}

SCHEMA C — Error fix response:
{{"type":"fix","action":"command","content":"corrected command","explanation":"what was wrong and what changed"}}

████████████████████████████████████████████████████████████
DECISION RULES
████████████████████████████████████████████████████████████
- Use SCHEMA A when: greetings, general questions, explanations, theory ("what is hacking", "who are hackers")
- Use SCHEMA B when: ANY task needs shell execution or file creation/analysis ("scan this IP", "is X running", "check my system", "test this URL")
- Use SCHEMA C only when explicitly asked to fix a failed command

SCHEMA B RULES:
- COMMAND ALWAYS FIRST. Use "action":"python" ONLY when the task genuinely cannot be done with curl/grep/awk/sed (e.g. PDF generation, complex binary file parsing).
- ALWAYS SHELL: process checks, port scans, ALL web requests, file listing, network info, ping, service status, package checks, disk/memory, user info, ANY vuln testing doable with curl.
- PROCESS CHECKS: Use `pgrep -a <name> && echo "Running" || echo "Not running"` — always exits 0.

WEB VULNERABILITY TESTING — CURL ONLY, NEVER PYTHON:
- ALL web testing (XSS, SQLi, LFI, SSRF, etc.) uses curl commands only. Never use python/requests for web requests.
- CURL SYNTAX: Always space between curl and URL. Use -s (silent) to hide progress. Use --get --data-urlencode "param=PAYLOAD" for special chars.
- XSS STEPS — start basic, escalate to advanced, each a separate curl command:
  Step 1 basic:   curl -s --get --data-urlencode "q=<script>alert(1)</script>" http://HOST/PATH | grep -i "<script>"
  Step 2 img:     curl -s --get --data-urlencode "q=<img src=x onerror=alert(1)>" http://HOST/PATH | grep -i "onerror"
  Step 3 svg:     curl -s --get --data-urlencode 'q="><svg/onload=alert(1)>' http://HOST/PATH | grep -i "svg"
  Step 4 bypass:  curl -s --get --data-urlencode "q=<ScRiPt>alert(1)</ScRiPt>" http://HOST/PATH | grep -i "script"
  Step 5 dom:     curl -s --get --data-urlencode "q=javascript:alert(document.cookie)" http://HOST/PATH | grep -i "javascript"
- VERDICT: raw payload unencoded in response = VULNERABLE. &lt; &gt; encoded = server escaping (report as: encoding found, not directly vulnerable to reflected XSS).

PYTHON CODE IN JSON — CRITICAL INDENTATION RULES:
- Use \n for newlines. Use \" for quotes inside strings. NEVER triple-quotes.
- EVERY line inside an if/for/while/else/def body MUST start with 4 spaces after \n.
- CORRECT: "if x:\n    print(\"yes\")\nelse:\n    print(\"no\")"
- WRONG:   "if x:\nprint(\"yes\")"   ← IndentationError — missing 4 spaces

████████████████████████████████████████████████████████████
FILE OPERATIONS — ALWAYS USE PYTHON TEMP SCRIPT
████████████████████████████████████████████████████████████

ANY task involving creating, writing, reading, analysing, editing, or converting a file
MUST use "action":"python" steps. This includes: .pdf .txt .csv .json .xml .html .py .c
.docx .xlsx .mp3 .mp4 .pcap .zip .png .jpg and ALL other file types.

NEVER use shell commands (echo/cat/tee/touch) to CREATE file content — always python.
Shell is only allowed to: list files (ls), move/copy (mv/cp), delete (rm), check existence.

FILE OPERATION PYTHON TEMPLATE:
Step 1 — always install needed library first (if not stdlib):
  content: "#!/usr/bin/env python3\nimport subprocess\nsubprocess.run(['pip','install','LIBNAME','--break-system-packages','-q'],capture_output=True)"

Step 2 — create/write/modify the file:
  content: "#!/usr/bin/env python3\n# all imports\n# all logic\n# write file"

PDF SPECIFICALLY — use reportlab:
  "#!/usr/bin/env python3\nimport subprocess\nsubprocess.run(['pip','install','reportlab','--break-system-packages','-q'],capture_output=True)\nfrom reportlab.lib.pagesizes import letter\nfrom reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer\nfrom reportlab.lib.styles import getSampleStyleSheet\ndoc = SimpleDocTemplate('FILENAME.pdf', pagesize=letter)\nstyles = getSampleStyleSheet()\nelements = [Paragraph('YOUR TEXT HERE', styles['BodyText'])]\ndoc.build(elements)\nprint('PDF created: FILENAME.pdf')"

TASK UNDERSTANDING RULE:
- "create a pdf named X" → Step 1: install reportlab, Step 2: python script that WRITES the pdf
- "write a story in a pdf" → same — python script creates the file with the story content
- DO NOT plan steps that only verify or open a file without first creating it
- If the task says "create" or "write", the FIRST real step must produce the file

- Every command complete as-is. No placeholders.
- Install missing tools with apt before using them.
- Default iface: {info.get('default_iface','eth0')} | Wireless: {info.get('wireless_iface','wlan0')}
- Python scripts must be fully self-contained.
REMINDER: Output ONLY the JSON object. Not a single character outside it.
WRONG:  Here is the task: {{"type":"task",...}}
CORRECT: {{"type":"task",...}}

ANTI-HALLUCINATION RULES:
- History shows PAST completed tasks. Each new USER message is a NEW independent request.
- NEVER assume a task is already done because something similar appears in history.
- "write a story.pdf" = create a NEW file RIGHT NOW, not reference a previous one.
- If user asks to CREATE/WRITE/GENERATE anything → always produce a task with python steps.
- NEVER respond to a creation request with a chat message saying it was already done.
"""

# ─── COMMAND SANITISER ─────────────────────────────────────────────────────────
# Fixes common AI-generated shell mistakes BEFORE execution so they never
# reach the error-retry loop.

def _sanitise_command(cmd):
    """Auto-fix well-known AI shell generation mistakes."""
    original = cmd

    # ── 1. Missing space after long flags before quote ──────────────────────
    # --data-urlencode'foo' → --data-urlencode 'foo'
    # --data-urlencode"foo" → --data-urlencode "foo"
    cmd = re.sub(r"(--[\w-]+)(['\"])", r"\1 \2", cmd)

    # ── 2. Missing space between curl short flags and their value ────────────
    # -H'Host: ...' → -H 'Host: ...'
    cmd = re.sub(r"(\bcurl\b.*?)(-[a-zA-Z])(['\"])", r"\1\2 \3", cmd)

    # ── 3. Missing space after grep -i / -E / -v / -n before pattern ─────────
    # grep -i'pattern' → grep -i 'pattern'
    # grep -iE'pattern' → grep -iE 'pattern'
    cmd = re.sub(r"(grep\s+-[a-zA-Z]+)(['\"])", r"\1 \2", cmd)

    # ── 4. Missing space between command name and its first argument ──────────
    # curl'url' → curl 'url'
    cmd = re.sub(r"(\b(?:curl|wget|nmap|ping|nc|ncat|ssh|scp)\b)(['\"])",
                 r"\1 \2", cmd)

    # ── 5. grep rc=1 false-fail: append || true so no-match isn't an error ───
    # Only when grep is the last command in a pipeline
    if re.search(r'\|\s*grep\b', cmd) and not cmd.rstrip().endswith(("|| true", "|| :")):
        cmd = cmd.rstrip() + " || true"

    if cmd != original:
        print(C.dim(f"  [auto-fix] {original}"))
        print(C.dim(f"         → {cmd}"))

    return cmd

# ─── REAL-TIME COMMAND RUNNER ──────────────────────────────────────────────────
def run_command(cmd, timeout=CMD_TIMEOUT):
    cmd = _sanitise_command(cmd)
    print(f"\n{C.D}{'─'*64}{C.RST}")
    print(f"  {C.CY}⚡ CMD{C.RST}  {cmd}")
    print(f"{C.D}{'─'*64}{C.RST}")
    lines = []
    rc = 0
    try:
        proc = subprocess.Popen(
            cmd, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
            preexec_fn=os.setsid
        )
        for line in iter(proc.stdout.readline, ""):
            sys.stdout.write(f"  {line}")
            sys.stdout.flush()
            lines.append(line)
            if len(lines) > 800:          # cap memory
                lines = lines[-800:]
        proc.wait(timeout=timeout)
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        try: os.killpg(os.getpgid(proc.pid), 9)
        except: pass
        msg = "\n[TIMEOUT] Command exceeded time limit\n"
        print(C.yellow(msg)); lines.append(msg); rc = -1
    except KeyboardInterrupt:
        try: os.killpg(os.getpgid(proc.pid), 9)
        except: pass
        msg = "\n[INTERRUPTED] Stopped by user\n"
        print(C.yellow(msg)); lines.append(msg); rc = -2
    except Exception as e:
        msg = f"\n[EXEC ERROR] {e}\n"
        print(C.red(msg)); lines.append(msg); rc = -1
    print(f"{C.D}{'─'*64}{C.RST}")
    return "".join(lines), rc

# ─── PYTHON CODE REPAIR ────────────────────────────────────────────────────────
def _repair_python_indent(code):
    """
    Fix the most common AI indentation mistake: after a colon-terminated
    line (if/for/while/else/elif/try/except/with/def/class), the next
    line has no indentation at all.

    Strategy: parse with ast first; if OK return as-is. If IndentationError,
    use a line-by-line reindenter that tracks expected indent level.
    """
    # Fast path — already valid
    try:
        compile(code, "<string>", "exec")
        return code
    except IndentationError:
        pass
    except SyntaxError:
        return code  # not an indent problem, return as-is

    lines = code.splitlines()
    fixed = []
    indent = 0
    INDENT_SIZE = 4
    COLON_HEADS = re.compile(
        r'^\s*(if |elif |else:|for |while |def |class |try:|except|finally:|with )'
    )

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            fixed.append("")
            continue

        # Detect dedent keywords
        if stripped.startswith(("else:", "elif ", "except", "except:", "finally:")):
            indent = max(0, indent - INDENT_SIZE)

        fixed.append(" " * indent + stripped)

        # Increase indent after colon-ended lines
        if stripped.endswith(":") and not stripped.startswith("#"):
            indent += INDENT_SIZE

    result = "\n".join(fixed)
    # Final check
    try:
        compile(result, "<string>", "exec")
        return result
    except SyntaxError:
        return code  # give up, return original


# ─── PYTHON TEMP FILE RUNNER ───────────────────────────────────────────────────
def run_python_temp(code, timeout=CMD_TIMEOUT):
    tmp_path = None
    try:
        # Auto-repair indentation before writing
        repaired = _repair_python_indent(code)

        with tempfile.NamedTemporaryFile(suffix=".py", delete=False,
                                         mode="w", dir="/tmp") as tmp:
            tmp.write(repaired)
            tmp_path = tmp.name
        print(f"\n{C.D}{'─'*64}{C.RST}")
        print(f"  {C.M}🐍 PY {C.RST}  {tmp_path}")
        print(f"{C.D}{'─'*64}{C.RST}")
        output, rc = run_command(f"{sys.executable} {tmp_path}", timeout=timeout)
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try: os.unlink(tmp_path)
            except: pass
    return output, rc

# ─── JSON REPAIR & PARSER ──────────────────────────────────────────────────────

def _fix_json_strings(raw):
    """
    Repair AI-generated JSON that has:
    1. Literal newlines / tabs / carriage-returns inside string values
    2. Un-escaped control chars
    Works by tracking quote depth properly (handles \" escapes correctly).
    """
    out = []
    in_str = False
    i = 0
    while i < len(raw):
        ch = raw[i]
        if in_str:
            if ch == '\\':                  # escape sequence — copy verbatim
                out.append(ch)
                i += 1
                if i < len(raw):
                    out.append(raw[i])      # copy the escaped char unchanged
                    i += 1
                continue
            elif ch == '"':                 # end of JSON string
                in_str = False
                out.append(ch)
            elif ch == '\n':               # literal newline INSIDE string → fix
                out.append('\\n')
            elif ch == '\r':
                out.append('\\r')
            elif ch == '\t':
                out.append('\\t')
            else:
                out.append(ch)
        else:
            if ch == '"':
                in_str = True
                out.append(ch)
            else:
                out.append(ch)
        i += 1
    return "".join(out)


def _dirty_parse(raw):
    """
    Last-resort extractor: regex-grab type/message/plan/steps from
    badly broken JSON that survives no standard parser.
    Returns a dict or None.
    """
    # type
    m_type = re.search(r'"type"\s*:\s*"(\w+)"', raw)
    if not m_type:
        return None
    rtype = m_type.group(1)

    # message
    msg = ""
    m_msg = re.search(r'"message"\s*:\s*"((?:[^"\\]|\\.)*)"', raw, re.DOTALL)
    if m_msg:
        msg = m_msg.group(1)

    if rtype == "chat":
        return {"type": "chat", "message": msg}

    # plan — extract list of strings
    plan = re.findall(r'"([^"]{5,})"', raw[raw.find('"plan"'):raw.find('"steps"')] if '"plan"' in raw else "")

    # steps — extract each step block between { }
    steps = []
    steps_section = raw[raw.find('"steps"'):] if '"steps"' in raw else ""
    for block in re.finditer(r'\{([^{}]+)\}', steps_section):
        blk = block.group(0)
        m_desc   = re.search(r'"desc"\s*:\s*"((?:[^"\\]|\\.)*)"',   blk)
        m_action = re.search(r'"action"\s*:\s*"(\w+)"',              blk)
        m_cont   = re.search(r'"content"\s*:\s*"((?:[^"\\]|\\.)*)"', blk, re.DOTALL)
        if m_desc and m_action and m_cont:
            content = m_cont.group(1)
            # decode JSON escape sequences back to real chars for execution
            try:
                content = bytes(content, "utf-8").decode("unicode_escape")
            except Exception:
                content = content.replace("\\n", "\n").replace("\\t", "\t")
            steps.append({
                "desc":    m_desc.group(1),
                "action":  m_action.group(1),
                "content": content,
            })

    if steps:
        return {"type": "task", "message": msg, "plan": plan, "steps": steps}

    if rtype == "fix":
        m_act  = re.search(r'"action"\s*:\s*"(\w+)"', raw)
        m_cont = re.search(r'"content"\s*:\s*"((?:[^"\\]|\\.)*)"', raw, re.DOTALL)
        m_expl = re.search(r'"explanation"\s*:\s*"((?:[^"\\]|\\.)*)"', raw)
        if m_cont:
            return {
                "type":        "fix",
                "action":      m_act.group(1) if m_act else "command",
                "content":     m_cont.group(1),
                "explanation": m_expl.group(1) if m_expl else "",
            }
    return None


def _extract_json_objects(text):
    """Extract ALL syntactically balanced top-level JSON objects from text."""
    objects = []
    depth = 0
    start = None
    in_str = False
    i = 0
    while i < len(text):
        ch = text[i]
        if in_str:
            if ch == '\\':
                i += 2          # skip escape pair
                continue
            elif ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch == '{':
                if depth == 0:
                    start = i
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0 and start is not None:
                    candidate = text[start:i+1]
                    obj = _try_parse(candidate)
                    if isinstance(obj, dict):
                        objects.append(obj)
                    start = None
        i += 1
    return objects


def _try_parse(s):
    """Try json.loads, return dict or None."""
    try:
        result = json.loads(s)
        return result if isinstance(result, dict) else None
    except Exception:
        return None


def _promote(obj):
    """
    If we got a chat wrapper whose 'message' IS a task JSON blob
    (escaped or literal), unwrap and return the inner task object.
    """
    if not isinstance(obj, dict) or obj.get("type") not in ("chat", None, ""):
        return obj
    msg = obj.get("message", "")
    if not isinstance(msg, str):
        return obj
    inner = _try_parse(msg.strip())
    if isinstance(inner, dict) and inner.get("type") in ("task", "fix"):
        return inner
    candidates = _extract_json_objects(msg)
    for c in candidates:
        if c.get("type") in ("task", "fix"):
            return c
    return obj


def parse_ai_json(raw):
    raw = raw.strip()

    # Strip markdown fences
    raw = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.IGNORECASE)
    raw = re.sub(r"\s*```\s*$",       "", raw.strip())

    # ── Pass 1: direct parse (valid JSON) ─────────────────────────────────────
    obj = _try_parse(raw)
    if obj:
        return _promote(obj)

    # ── Pass 2: fix literal newlines/tabs inside strings, retry ───────────────
    fixed = _fix_json_strings(raw)
    obj = _try_parse(fixed)
    if obj:
        return _promote(obj)

    # ── Pass 3: extract any valid JSON sub-objects from fixed text ─────────────
    all_objs = _extract_json_objects(fixed)
    if all_objs:
        priority = {"task": 3, "fix": 2, "chat": 1}
        best = max(all_objs, key=lambda o: (
            priority.get(o.get("type", ""), 0),
            1 if "steps" in o else 0,
            1 if "message" in o else 0,
        ))
        return _promote(best)

    # ── Pass 4: dirty regex extraction (last resort) ──────────────────────────
    dirty = _dirty_parse(raw)
    if dirty:
        return dirty

    # ── Pass 5: give up — wrap raw text as chat ───────────────────────────────
    return {"type": "chat", "message": raw.strip()}

# ─── ASK AI ────────────────────────────────────────────────────────────────────
def _trim_history_for_context(history):
    """
    Build a clean conversation block from history.
    - User messages: kept in full
    - Assistant task JSON (large blobs): replaced with a compact summary line
      so the AI knows WHAT was done but doesn't get confused by the raw JSON
    - Assistant chat messages: kept (truncated to 300 chars)
    This prevents "I already did this" hallucinations from prior similar tasks.
    """
    lines = []
    for m in history[-MAX_HISTORY:]:
        role = "USER" if m["role"] == "user" else "ASSISTANT"
        content = m["content"]

        if role == "ASSISTANT":
            # Try to parse as JSON to detect task/summary responses
            obj = _try_parse(content.strip()) or {}
            if obj.get("type") == "task":
                # Summarise: just say what was planned, not the full JSON
                msg = obj.get("message", "")
                plan = "; ".join(obj.get("plan", []))[:120]
                content = f'[TASK EXECUTED: {msg}. Plan: {plan}]'
            elif obj.get("type") == "chat":
                # Keep chat responses but trim long ones
                content = obj.get("message", content)[:300]
            else:
                # Raw non-JSON or other — truncate hard
                content = content[:200]

        lines.append(f"{role}: {content}")
    return "\n".join(lines)


def ask_ai(bot, history, user_msg, sys_prompt):
    """Send message with proper context, return parsed JSON response."""
    history.append({"role": "user", "content": user_msg})

    # Build clean conversation block (bulky task JSONs are summarised)
    conv_block = _trim_history_for_context(history)

    # System prompt is always a clean prefix — NOT mixed into conversation history
    full_prompt = (
        f"{sys_prompt}\n"
        f"{'═'*60}\n"
        f"CONVERSATION HISTORY (for context only — do NOT repeat completed tasks):\n"
        f"{conv_block}\n"
        f"{'═'*60}\n"
        f"CURRENT REQUEST: {user_msg}\n"
        f"ASSISTANT (respond with ONLY a JSON object for THIS request):"
    )

    try:
        raw = bot.ask(full_prompt)
    except Exception as e:
        raw = json.dumps({"type": "chat", "message": f"[AI Error] {e}"})

    # Store raw reply in history
    history.append({"role": "assistant", "content": raw})
    if len(history) > MAX_HISTORY:
        history[:] = history[-MAX_HISTORY:]

    return parse_ai_json(raw), history

# Commands where rc=1 means "not found / no match" — NOT an error
_RC1_OK_PREFIXES = (
    "pgrep", "grep", "find", "locate", "which", "whereis",
    "dpkg -l", "apt list", "systemctl is-active", "systemctl is-enabled",
)

def _is_expected_rc(cmd, rc):
    """Return True if rc is a normal/expected non-error exit for this command."""
    if rc == 0:
        return True
    if rc == 1:
        cmd_stripped = cmd.strip().lstrip("sudo").strip()
        for prefix in _RC1_OK_PREFIXES:
            if cmd_stripped.startswith(prefix):
                return True
    return False

# ─── STEP EXECUTOR WITH ERROR LOOP ─────────────────────────────────────────────
def execute_step(bot, step, history, sys_prompt, step_log):
    action  = step.get("action", "command")
    content = step.get("content", "")
    desc    = step.get("desc", "")

    for attempt in range(1, MAX_RETRIES + 1):
        if attempt > 1:
            print(C.yellow(f"\n  [↻] Retry attempt {attempt}/{MAX_RETRIES}…"))

        # Run it
        if action == "command":
            output, rc = run_command(content)
        else:
            output, rc = run_python_temp(content)

        step_log.append({
            "desc": desc, "action": action, "content": content,
            "output": output[-2000:], "rc": rc, "attempt": attempt
        })

        # Success, user-interrupted, or expected non-zero (e.g. pgrep/grep no-match)
        if rc == -2:
            return output, rc, history
        if action == "command" and _is_expected_rc(content, rc):
            if rc != 0:
                print(C.cyan(f"  [i] rc={rc} is normal for this command (no match / not found)"))
            return output, rc, history
        if rc == 0:
            return output, rc, history

        # ── Error recovery ────────────────────────────────────────────────────
        err_snippet = output[-1200:]
        print(C.red(f"\n  [!] Step failed (rc={rc}). Asking AI to fix…"))

        tool_name = content.split()[0] if content.strip() else ""
        help_context = ""

        # Pre-fetch tool help for flag/syntax errors — but NOT for file-not-found
        is_file_not_found = ("no such file" in output.lower() or
                              "cannot access" in output.lower())
        if action == "command" and not is_file_not_found and (
                "invalid option" in output.lower() or
                "unrecognized" in output.lower() or
                "unknown" in output.lower() or
                "not found" in output.lower() or
                rc in (2, 127)):
            help_out, _ = run_command(
                f"{tool_name} -h 2>&1 || {tool_name} --help 2>&1 | head -60",
                timeout=10)
            help_context = f"\nTool help output:\n{help_out[:800]}"

        # Build targeted fix prompt with explicit constraints
        fix_prompt = (
            f"FIX REQUIRED. The following {'shell command' if action=='command' else 'python script'} FAILED.\n\n"
            f"FAILED CONTENT:\n{content}\n\n"
            f"ERROR OUTPUT:\n{err_snippet}\n"
            f"EXIT CODE: {rc}{help_context}\n\n"
            f"COMMON MISTAKES TO CHECK:\n"
            f"- Missing space between command and its arguments (e.g. curl'url' → curl 'url')\n"
            f"- Special chars in URLs/args need URL-encoding (< > {{}} spaces -> %3C %3E %7B %7D %20)\n"
            f"- For curl with special chars in URL: use --data-urlencode or pre-encode the value\n"
            f"- Wrong flags or missing required arguments\n"
            f"- Python indentation errors or missing imports\n\n"
            f"Return ONLY this exact JSON (no other text):\n"
            f'{{"type":"fix","action":"{action}","content":"THE_CORRECTED_CONTENT_HERE","explanation":"one line: what was wrong and what you changed"}}\n\n'
            f"CRITICAL: The content field MUST be different from the failed content above."
        )

        fix_resp, history = ask_ai(bot, history, fix_prompt, sys_prompt)

        new_content = fix_resp.get("content", "").strip()

        # Reject fix if: wrong type, empty, or identical to what just failed
        if (fix_resp.get("type") == "fix"
                and new_content
                and new_content != content.strip()):
            content = new_content
            print(C.cyan(f"  [✓] Fix applied: {fix_resp.get('explanation','')[:120]}"))
        else:
            if new_content == content.strip():
                print(C.yellow("  [~] Fix was identical to original — skipping."))
            else:
                print(C.yellow("  [~] No valid fix received — retrying original…"))

    print(C.red(f"  [✗] Step failed after {MAX_RETRIES} attempts."))
    return output, rc, history

# ─── SLASH COMMAND HANDLER ─────────────────────────────────────────────────────
def handle_slash(cmd, history, bot, sys_prompt, current_model):
    cmd_lower = cmd.strip().lower()

    if cmd_lower == "/clear":
        history.clear()
        print(C.green("[✓] Conversation history cleared."))
        return history, bot, current_model, True

    if cmd_lower == "/exit":
        print(C.cyan("[*] Goodbye, hacker. Stay legal."))
        sys.exit(0)

    if cmd_lower == "/help":
        print(f"""
{C.BD}SLASH COMMANDS{C.RST}
  {C.CY}/clear{C.RST}              Clear conversation memory
  {C.CY}/exit{C.RST}               Quit Hackers AI
  {C.CY}/switch "model"{C.RST}     Switch AI model
  {C.CY}/help{C.RST}               Show this help

{C.BD}AVAILABLE MODELS{C.RST}
  gpt · deepseek · google · claude
""")
        return history, bot, current_model, True

    m = re.match(r'/switch\s+"?([^"]+)"?', cmd, re.IGNORECASE)
    if m:
        new_model = m.group(1).strip()
        try:
            bot = FreeLLM(model=new_model)
            current_model = new_model
            print(C.green(f"[✓] Switched to model: {current_model}"))
        except Exception as e:
            print(C.red(f"[!] Switch failed: {e}"))
        return history, bot, current_model, True

    print(C.red(f"[!] Unknown command: {cmd}"))
    print(C.dim("    Type /help for available commands."))
    return history, bot, current_model, True

# ─── MAIN LOOP ─────────────────────────────────────────────────────────────────
def main():
    print(BANNER)

    # Gather OS fingerprint
    os_info = gather_os_info()
    sys_prompt = build_system_prompt(os_info)

    # Display quick system summary
    os_line = next((l for l in os_info.get("os_release", "").splitlines()
                    if l.startswith("PRETTY_NAME")), "")
    os_name = os_line.split("=")[-1].strip('"') if os_line else "Linux"
    print(f"  {C.G}●{C.RST} OS      : {os_name}")
    print(f"  {C.G}●{C.RST} Kernel  : {os_info.get('kernel','?')}")
    print(f"  {C.G}●{C.RST} Iface   : {os_info.get('default_iface','eth0')}  "
          f"Wireless: {os_info.get('wireless_iface','wlan0')}")
    print(f"  {C.G}●{C.RST} Local IP: {os_info.get('local_ip','?')}  "
          f"Public: {os_info.get('public_ip','?')}\n")

    # Init AI
    current_model = "claude"
    try:
        bot = FreeLLM(model=current_model)
        print(C.green(f"[✓] Model: {current_model}  |  Ready.\n"))
    except Exception as e:
        print(C.red(f"[!] Failed to init FreeLLM: {e}")); sys.exit(1)

    history = []  # cleared fresh each run (per spec)

    print(C.dim("─" * 64))
    print(C.dim("  Tip: describe any task, ask questions, or use /help"))
    print(C.dim("─" * 64) + "\n")

    # ── REPL ────────────────────────────────────────────────────────────────────
    while True:
        # Prompt
        try:
            user_input = input(f"{C.R}{C.BD}hackers-ai{C.RST} {C.D}({current_model}){C.RST}"
                               f"{C.W}>{C.RST} ").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{C.Y}[!] Use /exit to quit.{C.RST}")
            continue

        if not user_input:
            continue

        # ── Slash commands ────────────────────────────────────────────────────
        if user_input.startswith("/"):
            history, bot, current_model, _ = handle_slash(
                user_input, history, bot, sys_prompt, current_model)
            continue

        # ── Ask AI ────────────────────────────────────────────────────────────
        print(C.dim("\n  [~] Thinking…"), end="", flush=True)
        response, history = ask_ai(bot, history, user_input, sys_prompt)
        print(f"\r{' '*24}\r", end="")

        rtype   = response.get("type", "chat")
        message = response.get("message", "")
        plan    = response.get("plan", [])
        steps   = response.get("steps", [])

        # ── Last-resort re-promotion at display time ──────────────────────────
        # If we still got type=chat and message looks like raw JSON, try once more
        if rtype == "chat" and isinstance(message, str) and message.lstrip().startswith("{"):
            rescued = _try_parse(message.strip())
            if isinstance(rescued, dict) and rescued.get("type") in ("task", "fix"):
                response = rescued
                rtype   = response.get("type", "chat")
                message = response.get("message", "")
                plan    = response.get("plan", [])
                steps   = response.get("steps", [])

        # Sanitise message: collapse excessive whitespace, strip stray JSON blobs
        if isinstance(message, str):
            # Remove any embedded {"type":...} blobs (nested or flat)
            for _ in range(3):  # up to 3 nesting levels
                message = re.sub(r'\{[^{}]*"type"\s*:[^{}]*\}', '', message, flags=re.DOTALL)
            message = re.sub(r'\n{3,}', '\n\n', message).strip()

        # ── Chat / informational ───────────────────────────────────────────────
        if rtype == "chat" or not steps:
            print(f"\n{C.G}[AI]{C.RST} {message}\n")
            continue

        # ── Task response ──────────────────────────────────────────────────────
        print(f"\n{C.G}[AI]{C.RST} {message}\n")

        if plan:
            print(C.bold(C.yellow("  PLAN")))
            for i, p in enumerate(plan, 1):
                print(f"   {C.CY}{i}.{C.RST} {p}")

        print(f"\n{C.bold(C.yellow('  STEPS'))}")
        for i, s in enumerate(steps, 1):
            icon  = "🐍" if s.get("action") == "python" else "⚡"
            badge = C.mag("[PY] ") if s.get("action") == "python" else C.CY + "[CMD]" + C.RST + " "
            print(f"   {icon} {C.BD}{i}.{C.RST} {badge}{s.get('desc','')}")
            preview = s.get("content", "")[:90]
            if preview:
                print(f"      {C.D}{preview}{'…' if len(s.get('content',''))>90 else ''}{C.RST}")

        # ── Plan validator: catch hallucinated plans that skip the actual work ──
        FILE_CREATE_KEYWORDS = re.compile(
            r'\b(creat|writ|generat|build|mak|produc|save|output|stor)', re.I)
        FILE_EXT_KEYWORDS = re.compile(
            r'\b\w+\.(pdf|txt|csv|json|xml|html|docx|xlsx|py|c|cpp|png|jpg|mp3|mp4|pcap|zip)\b', re.I)

        # Detect if user asked to CREATE a file
        user_wants_file = (FILE_CREATE_KEYWORDS.search(user_input) and
                           FILE_EXT_KEYWORDS.search(user_input))

        # Check if ANY step actually writes/creates (python action or file-write shell cmd)
        has_write_step = any(
            s.get("action") == "python" or
            any(w in s.get("content","").lower()
                for w in ["open(", "write(", "doc.build", "to_csv", "to_json",
                           "savefig", "reportlab", ">", "tee "])
            for s in steps
        )

        if user_wants_file and not has_write_step:
            print(C.yellow(
                "\n  [⚠] Plan looks wrong — task asks to CREATE a file but no "
                "write step found.\n  [~] Asking AI to regenerate the correct plan…\n"
            ))
            regen_prompt = (
                f"Your previous plan was WRONG. The user asked: '{user_input}'\n"
                f"But your plan only had verification/open steps — it never CREATED the file.\n\n"
                f"Generate a CORRECT plan that:\n"
                f"1. Installs any needed library (reportlab for PDF, etc.) as a python step\n"
                f"2. Has a python step that WRITES/CREATES the actual file with full content\n"
                f"3. Optionally verifies with ls -l FILENAME at the end\n\n"
                f"Return the corrected task JSON now."
            )
            response, history = ask_ai(bot, history, regen_prompt, sys_prompt)
            rtype  = response.get("type", "chat")
            message = response.get("message", "")
            plan   = response.get("plan", [])
            steps  = response.get("steps", [])

            if not steps or rtype != "task":
                print(C.red("  [!] Could not regenerate plan. Please retry your request.\n"))
                continue

            # Show the corrected plan
            print(f"\n{C.G}[AI — CORRECTED]{C.RST} {message}\n")
            if plan:
                print(C.bold(C.yellow("  PLAN")))
                for i, p in enumerate(plan, 1):
                    print(f"   {C.CY}{i}.{C.RST} {p}")
            print(f"\n{C.bold(C.yellow('  STEPS'))}")
            for i, s in enumerate(steps, 1):
                icon  = "🐍" if s.get("action") == "python" else "⚡"
                badge = C.mag("[PY] ") if s.get("action") == "python" else C.CY + "[CMD]" + C.RST + " "
                print(f"   {icon} {C.BD}{i}.{C.RST} {badge}{s.get('desc','')}")
                preview = s.get("content", "")[:90]
                if preview:
                    print(f"      {C.D}{preview}{'…' if len(s.get('content',''))>90 else ''}{C.RST}")

            print(f"\n{C.Y}  Execute corrected plan? [{C.G}Y{C.Y}/{C.R}n{C.Y}] (default: Y): {C.RST}", end="")
            try:
                confirm2 = input().strip().lower()
            except (KeyboardInterrupt, EOFError):
                print(C.red("\n  [!] Cancelled.\n")); continue
            if confirm2 == "n":
                print(C.red("  [!] Execution cancelled.\n")); continue

        # ── Confirm execution ──────────────────────────────────────────────────
        print(f"\n{C.Y}  Execute plan? [{C.G}Y{C.Y}/{C.R}n{C.Y}] (default: Y): {C.RST}", end="")
        try:
            confirm = input().strip().lower()
        except (KeyboardInterrupt, EOFError):
            print(C.red("\n  [!] Cancelled.\n")); continue

        if confirm == "n":
            print(C.red("  [!] Execution cancelled.\n")); continue

        # ── Run each step ──────────────────────────────────────────────────────
        step_log   = []
        all_results = []
        aborted    = False

        for idx, step in enumerate(steps, 1):
            print(f"\n{C.BD}{C.Y}{'═'*64}{C.RST}")
            print(f"{C.BD}{C.Y}  STEP {idx}/{len(steps)}: {step.get('desc','')}{C.RST}")
            print(f"{C.BD}{C.Y}{'═'*64}{C.RST}")

            output, rc, history = execute_step(
                bot, step, history, sys_prompt, step_log)

            all_results.append({"step": idx, "rc": rc,
                                 "output_tail": output[-800:]})

            if rc == -2:          # user interrupted
                aborted = True
                print(C.yellow("\n  [!] Task aborted by user.\n"))
                break

            status = C.green("✓ OK") if rc == 0 else C.red(f"✗ rc={rc}")
            print(f"\n  Step {idx} status: {status}")

        # ── Post-task summary ──────────────────────────────────────────────────
        if not aborted and all_results:
            print(C.dim(f"\n  [~] Generating summary…"), end="", flush=True)
            steps_summary = "\n".join([
                f"Step {r['step']} (rc={r['rc']}):\n{r['output_tail'][:600]}"
                for r in all_results
            ])
            summary_prompt = (
                f"All steps finished. Analyze the actual output below and give a clear security/technical verdict.\n\n"
                f"STEP OUTPUTS:\n{steps_summary[:3500]}\n\n"
                f"Write 3-5 sentences covering:\n"
                f"1. What was found / confirmed (specific facts from output, not generic statements)\n"
                f"2. Verdict: vulnerable / not vulnerable / partial / needs more testing\n"
                f"3. Next recommended action if relevant\n"
                f"Do NOT just repeat the task title. Be specific to the actual output.\n"
                f'Return: {{"type":"chat","message":"your analysis here"}}'
            )
            summary_resp, history = ask_ai(bot, history, summary_prompt, sys_prompt)
            print(f"\r{' '*30}\r", end="")
            print(f"\n{C.G}{C.BD}[SUMMARY]{C.RST} {summary_resp.get('message','Task complete.')}\n")

# ─── ENTRY POINT ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()
