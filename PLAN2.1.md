Here is your **combined production-ready documentation**
(README + Architecture + GitHub Doc + Roadmap)
Text meaning unchanged — only structured and professional formatting added.

---

# 🚀 Hackers AI

### Ultimate Linux AI Assistant / Autonomous Agent

---

## 📌 Overview

**Hackers AI** is an AI-powered Linux assistant/agent designed to operate as an ultimate computer assistant.

It has:

* Deep awareness of Linux built-in tools
* Knowledge of important system files
* Understanding of additional tools (especially Kali tools)
* Ability to execute commands and automate tasks intelligently

> Tool uses are not mandatory because each tool has `-h` flags for usage reference.

---

# 🎯 Core Objective

Build an AI agent that:

* Executes Linux commands autonomously
* Creates temporary Python scripts when required
* Analyzes errors and self-corrects
* Tests vulnerabilities
* Operates with structured execution planning

---

# ⚙️ Execution Methods

The system works using **2 primary methods**:

1. **Direct Command Execution**
2. **Temporary Python File Execution**

   * Create `.py` file
   * Execute
   * Delete after completion

> Python file is created **only when task cannot be completed directly via command**.

---

# 🧠 Core Capabilities

---

## 📂 File Operations

Can:

* Analyze
* Generate
* Create
* Update
* Delete

File types include:

```
txt, pdf, .py, .c, mp3, mp4, pcap, csv, json, etc
```

---

## 💬 Conversational Intelligence

* General conversation ability
* Memory of previous conversations (example: last 10 messages)
* Smart summarized responses

---

## 🛠 Linux Tool Execution Engine

Supports tools like:

```
ping
top
neofetch
curl
wget
nmap
hydra
wireshark
tshark
metasploit
ettercap
bettercap
```

And all tools from:

🔗 [https://www.kali.org/tools](https://www.kali.org/tools)

---

### 🔁 Self-Healing Command System

If an error occurs:

1. Error is captured
2. Error fed back to AI
3. AI crafts corrected command
4. Re-executes

#### Example:

If AI generates:

```
ping -x 123.123.123
```

And `-x` is invalid:

* Tool help checked using `-h`
* Output analyzed
* Command rebuilt
* Re-run automatically

---

## 🔐 Vulnerability Testing Module

### 🌐 Web Vulnerabilities

```
xss
sqli
dir_brute
subdomain_enum
domain_info
brute_forcing
lfi
command_injection
csrf
ssrf
file upload
```

---

### 📡 Wireless Attacks

```
scanning_for_networks
wps
wpa
evil_tween
deauth
fake/evil_ap
wifiphishing
multiple_ap
```

And more.

---

## 🖥 System Profiling (First Run)

On first execution:

* Detect OS name
* Store key system information
* Identify default paths
* Detect installed applications

This allows intelligent path and tool usage later.

---

# 🤖 AI Model

Uses free AI from:

`freellm`

Documentation:

🔗 [https://pypi.org/project/freellm](https://pypi.org/project/freellm)

---

# 🔑 Security & Execution Rules

* Must run with `sudo`
* If not → show message and exit
* Can auto-install required:

  * Python libraries
  * Linux tools via:

    ```
    apt
    snapd
    git
    pypi
    ```

---

# 🧹 Memory Management

* Clear past memory on restart
* Maintain:

  * Global conversation memory
  * Separate task execution memory

---

# 🎮 Slash Commands

```
/clear             → clear previous conversation memory
/exit              → exit the tool
/switch "<model>"  → switch AI model
```

---

# 📺 Real-Time Output

* Shows command output in terminal in real time
* Except tools that do not print terminal output

---

# 🔄 Working Procedure

---

## 1️⃣ AI Response Structure

* Strong system prompt
* AI responses structured (example: JSON format)
* Python parser reads and executes

---

## 2️⃣ Request Classification

AI first determines if input is:

| Type                 | Description                |
| -------------------- | -------------------------- |
| Informational        | No execution needed        |
| Task                 | Requires command or Python |
| Informational + Task | Both                       |

---

### Examples

| Input                                                                   | Classification          |
| ----------------------------------------------------------------------- | ----------------------- |
| `tell me about my system`                                               | Informational + Command |
| `what is hacking`                                                       | Informational           |
| `is this url https://example.com/search?quary=books vulnareble to xss?` | Task                    |

---

## 3️⃣ Plan Generation Phase

If execution needed:

1. Generate detailed plan
2. Show steps
3. Ask user confirmation:

```
Press y → continue
Press n → stop
```

---

## 4️⃣ Execution Phase

If user presses `y`:

* Execute step-by-step
* Capture output
* Store output in task memory
* Feed output back to AI
* Continue next step dynamically

---

# 🏗 Software Architecture

---

## 🔹 High-Level Components

```
User Input
     ↓
Command Classifier
     ↓
Planner Engine
     ↓
Execution Engine
     ↓
Output Analyzer
     ↓
Memory Manager
     ↓
Response Generator
```

---

## 🔹 Core Modules

### 1. Input Processor

* Classifies request type

### 2. Planner Engine

* Generates structured plan
* Outputs JSON-like structured instruction

### 3. Command Execution Engine

* Runs Linux commands
* Captures stdout & stderr
* Handles retry logic

### 4. Python Execution Engine

* Creates temp file
* Executes
* Deletes file

### 5. Error Analyzer

* Reads tool errors
* Uses `-h` if needed
* Regenerates command

### 6. Vulnerability Testing Module

* Web scanning logic
* Wireless scanning logic
* Tool orchestration

### 7. Memory Manager

* Global memory
* Task memory
* Reset on restart

---

# 🛣 Development Roadmap

---

## 🧩 Phase 1 – Core Engine

* [ ] Command execution wrapper
* [ ] Error capturing
* [ ] Structured JSON output parsing
* [ ] Temporary Python executor

---

## 🧠 Phase 2 – Intelligence Layer

* [ ] Request classification system
* [ ] Plan generator
* [ ] Error self-correction loop
* [ ] Help flag reader (`-h` parser)

---

## 🔐 Phase 3 – Security & Vuln Modules

* [ ] Web vuln automation
* [ ] Wireless scanning framework
* [ ] Tool orchestration logic

---

## 🖥 Phase 4 – System Awareness

* [ ] OS fingerprinting
* [ ] Path detection
* [ ] Default installation mapping

---

## ⚡ Phase 5 – Advanced Features

* [ ] Multi-model switching
* [ ] Persistent mode presets
* [ ] Performance optimization
* [ ] Smart output summarization

---

# 📌 Project Philosophy

Hackers AI is:

* Autonomous
* Self-correcting
* Tool-aware
* Execution-focused
* Minimal manual intervention required

---
