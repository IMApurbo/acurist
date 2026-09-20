<div align="center">

# Acurist

**The Autonomous Terminal AI Agent for Offensive Security & Penetration Testing.**

*A high-performance, vendor-agnostic AI agent interface designed for bug bounty hunters, red teams, and security researchers.*

[![npm version](https://img.shields.io/npm/v/acurist?color=crimson&style=flat-square)](https://www.npmjs.com/package/acurist)
[![License](https://img.shields.io/npm/l/acurist?style=flat-square)](./LICENSE)
[![Node.js Version](https://img.shields.io/node/v/acurist?style=flat-square)](https://nodejs.org)

[Quick Start](#quick-start) • [Features](#key-capabilities) • [Architecture](#architecture) • [Documentation](#command-reference)

</div>

---

> ⚠️ **Legal Disclaimer:** *Acurist is developed for authorized penetration testing, vulnerability assessment, and educational research. Unauthorized testing against target infrastructure is illegal. Users are solely responsible for ensuring compliance with applicable laws.*

---

## Overview

**Acurist** is a terminal-native, autonomous AI agent built specifically for offensive security workflows, reconnaissance, exploit development, and security auditing. It delivers a streamlined, Claude Code–style interface—featuring scrolling transcripts, live tool execution tracking, automatic process backgrounding, and human-in-the-loop controls—without vendor lock-in.

Connect Acurist to any local or remote OpenAI/Anthropic-compatible endpoint (Ollama, LM Studio, vLLM, DeepSeek, or custom proxies) to conduct fully offline, air-gapped security assessments or automated web security scans.

---

## Key Capabilities

- **Autonomous Tool Execution:** Parse complex multi-step instructions, run security binaries (`nmap`, `ffuf`, `httpx`, `subfinder`), and dynamically process structured JSON or raw output.
- **Process Management & Backgrounding:** Automatically detaches long-running listeners (`nc`, `msfconsole`), staging servers, and long scans without blocking the interactive thread.
- **Air-Gapped & Offline Ready:** Full support for local models via Ollama, LM Studio, or custom inference servers—guaranteeing zero data exfiltration during sensitive audits.
- **Extensible via MCP:** Native support for the [Model Context Protocol](https://modelcontextprotocol.io) (MCP) to plug into custom threat intelligence APIs, vulnerability databases, and external tools.
- **Remote C2 Operations:** Integrates with Telegram to create a secure bridge for remote command execution, monitoring long scans, and receiving real-time finding alerts on the go.
- **Custom Security Personas:** Configure targeted agent profiles (e.g., *Active Directory Auditor*, *Web Application Specialist*, *Reverse Engineer*) with distinct system prompts and tool access.

---

## Screenshot

![acurist in action](./docs/screenshot.png)

## Feature Comparison

| Feature / Capability | Acurist | Claude Code | Cursor | GitHub Copilot |
| :--- | :---: | :---: | :---: | :---: |
| **Autonomous Security Command Execution** | ✅ | ✅ | ❌ | ❌ |
| **Automatic Backgrounding (Listeners / Servers)** | ✅ | ❌ | ❌ | ❌ |
| **Fully Offline / Air-Gapped Operation** | ✅ | ❌ | ❌ | ❌ |
| **Vendor Agnostic (Ollama / Local Proxies)** | ✅ | ❌ | ❌ | ❌ |
| **Model Context Protocol (MCP) Integration** | ✅ | ✅ | ❌ | ❌ |
| **Remote Bridge (Telegram C2 Integration)** | ✅ | ❌ | ❌ | ❌ |
| **Custom Agent Personas** | ✅ | ❌ | ❌ | ❌ |
| **Plugin Marketplace** | ✅ | ❌ | ❌ | ❌ |
| **Session State Persistence** | ✅ | ❌ | ❌ | ❌ |
| **Open Source** | ✅ | ❌ | ❌ | ❌ |

---

## System Requirements

- **Node.js**: `v22.0.0` or higher
- **Inference Backend**: Any OpenAI/Anthropic-compatible API endpoint (Default: `http://localhost:8765`)
  - *Includes built-in support for [deeptunnel](https://github.com/IMApurbo/deeptunnel) to access DeepSeek V3/R1 reasoning for free.*

---

## Quick Start

### 1. Installation

Install globally via `npm`:

```bash
npm install -g acurist

```

### 2. Launching with Free DeepSeek Reasoning

Acurist includes automated integration with `deeptunnel` to route requests to DeepSeek's web chat without paid API credits.

```bash
# Install the tunnel proxy
pip install deeptunnel

# Set your token and launch
export DEEPSEEK_TOKEN="your-bearer-token"
acurist

```

### 3. Model Configuration Flags

| Flag | Model Option | Target Use Case |
| --- | --- | --- |
| *(Default)* | DeepSeek V3 | Fast command generation, recon, and log parsing |
| `--ds-model expert` | DeepSeek R1 | In-depth logic analysis & complex exploit synthesis |
| `--ds-think` | Enabled | Chain-of-thought reasoning mode |
| `--ds-no-search` | Disabled | Offline / stealth operation mode |

*Example:*

```bash
acurist --ds-model expert --ds-think

```

---

## Advanced Execution Modes

Launch Acurist tuned for specific target environments or local setups:

```bash
# Connect to a local Ollama instance running a coding model
ACURIST_PROXY=http://localhost:11434 ACURIST_MODEL=qwen2.5-coder:32b acurist

# Force interactive human-in-the-loop confirmation before running shell commands
acurist --mode manual

# Start with a pre-configured security persona
acurist --agent web-app-sec

```

---

## Process & Tool Handling

Acurist monitors background processes natively. Network listeners, file watchers, and long-running security scanners are automatically detected, detached, and managed with non-blocking execution logs.

```
⏺ run_shell   nmap -sC -sV -p- 192.168.1.100 -oA initial_scan
  ⎿ Background process started.
      Job ID:  bg_1720000000_abc12
      PID:     31337
      Log:     /tmp/bg_1720000000_abc12.log

    Initial Output (3s):
    Starting Nmap 7.94 ( [https://nmap.org](https://nmap.org) ) at 2026-09-20 ...

```

### Managing Background Jobs

```
run_shell background:true settle_seconds:10   # Force backgrounding with execution pause
read_bg_log job_id:"bg_…" tail_lines:100      # Inspect process log output
read_bg_log job_id:"bg_…" kill:true          # Terminate running process

```

---

## Command Reference

Acurist supports slash (`/`) commands to adjust environment parameters dynamically without restarting the agent session.

### Core Commands

| Command | Description |
| --- | --- |
| `/help` | Display current keybindings and documentation |
| `/clear` | Clear active terminal transcript and agent memory |
| `/undo` | Revert the last execution turn |
| `/exit` | Gracefully exit the application |

### Model & Proxy Configuration

| Command | Description |
| --- | --- |
| `/model` | View active model alias and proxy resolution |
| `/model <name>` | Switch active model alias or proxy model ID |
| `/model list` | List available system and backend models |
| `/proxy <url>` | Update proxy endpoint base URL |

### Permissions & Control

| Command | Description |
| --- | --- |
| `/mode auto|manual` | Toggle global shell execution safety mode |
| `/perm <tool> auto|manual` | Configure granular per-tool execution privileges |

### Sessions & Engagement Logs

| Command | Description |
| --- | --- |
| `/save [name]` | Persist active engagement session state |
| `/load <name>` | Restore a saved assessment session |
| `/export [file]` | Export complete audit transcript to Markdown |

---

## Architecture

```
┌───────────────────────────────────────────────────────────┐
│                 Acurist CLI Interface                     │
│  ├─ Ink / React Terminal Renderer                         │
│  ├─ Real-Time Tool Execution Cards                        │
│  ├─ Non-Blocking Process Manager & Listener Handler       │
│  └─ Dynamic Input Handler (Slash Commands & @Mentions)    │
└─────────────────────────────┬─────────────────────────────┘
                              │  OpenAI / Anthropic Protocol
                              ▼
┌───────────────────────────────────────────────────────────┐
│                 Inference Backend Layer                   │
│  (Ollama / LM Studio / vLLM / Local Reverse Proxies)      │
│  ├─ /v1/models   (Endpoint Health Checks)                 │
│  └─ /v1/messages (Interactive Inference Engine)           │
└─────────────────────────────┴─────────────────────────────┘

```

---

## Contributing

Contributions are welcome. Please read our contributing guidelines before submitting a pull request.

1. Fork the repository
2. Clone your fork: `git clone https://github.com/IMApurbo/acurist.git`
3. Install dependencies: `npm install`
4. Run dev mode: `npm run dev`
5. Test locally: `node dist/index.js`

---

## License

This project is licensed under the MIT License - see the [LICENSE](https://www.google.com/search?q=./LICENSE&utm_source=gemini) file for details.

© [IMApurbo](https://github.com/IMApurbo?utm_source=gemini)
