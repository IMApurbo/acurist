#!/usr/bin/env python3
"""
Advanced Autonomous AI Assistant - FreeLLM
Bug Bounty & Penetration Testing Edition
Ethical Hacking & Security Research Assistant
"""

import os
import sys
import json
import subprocess
import re
import hashlib
import requests
import socket
import threading
import sqlite3
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from freellm import FreeLLM
from prompt_toolkit import PromptSession
from prompt_toolkit.styles import Style
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import FileHistory
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.syntax import Syntax
from rich.tree import Tree
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.live import Live
import psutil

class SecurityScanner:
    """Bug Bounty & Penetration Testing Tools"""
    
    def __init__(self, console):
        self.console = console
        self.findings = []
        # FIX 1: Removed agent-state attributes that don't belong here.
        # recent_observations, task_active, current_goal, max_steps_per_request
        # are now correctly initialized in AutonomousAI.__init__

    def port_scan(self, target, ports="common"):
        """Scan ports on target"""
        self.console.print(f"\n[yellow]🔍 Scanning {target}...[/yellow]\n")
        
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
        
        if ports == "common":
            port_list = common_ports
        elif ports == "all":
            port_list = range(1, 1025)
        else:
            port_list = [int(p) for p in ports.split(',')]
        
        open_ports = []
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), console=self.console) as progress:
            task = progress.add_task(f"Scanning {len(port_list)} ports...", total=len(port_list))
            
            for port in port_list:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((target, port))
                
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                    
                    open_ports.append({'port': port, 'service': service})
                    self.console.print(f"[green]✓ Port {port} OPEN ({service})[/green]")
                
                sock.close()
                progress.update(task, advance=1)
        
        self.findings.append({
            'type': 'port_scan',
            'target': target,
            'open_ports': open_ports,
            'timestamp': datetime.now().isoformat()
        })
        
        return open_ports
    
    def subdomain_enum(self, domain):
        """Enumerate subdomains"""
        self.console.print(f"\n[yellow]🔍 Enumerating subdomains for {domain}...[/yellow]\n")
        
        common_subs = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk', 
                      'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'admin', 'api', 'dev', 
                      'staging', 'test', 'portal', 'blog', 'shop', 'app', 'mobile', 'vpn', 'remote']
        
        found_subdomains = []
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), console=self.console) as progress:
            task = progress.add_task(f"Checking {len(common_subs)} subdomains...", total=len(common_subs))
            
            for sub in common_subs:
                subdomain = f"{sub}.{domain}"
                try:
                    ip = socket.gethostbyname(subdomain)
                    found_subdomains.append({'subdomain': subdomain, 'ip': ip})
                    self.console.print(f"[green]✓ Found: {subdomain} → {ip}[/green]")
                except:
                    pass
                
                progress.update(task, advance=1)
        
        self.findings.append({
            'type': 'subdomain_enum',
            'domain': domain,
            'subdomains': found_subdomains,
            'timestamp': datetime.now().isoformat()
        })
        
        return found_subdomains
    
    def directory_bruteforce(self, url):
        """Bruteforce directories on web server"""
        self.console.print(f"\n[yellow]🔍 Bruteforcing directories on {url}...[/yellow]\n")
        
        common_dirs = ['admin', 'login', 'dashboard', 'api', 'backup', 'config', 'db', 'uploads', 
                      'images', 'js', 'css', 'includes', 'test', 'dev', 'staging', 'old', 'temp',
                      'phpMyAdmin', 'phpmyadmin', 'wordpress', 'wp-admin', 'wp-content', 'administrator']
        
        found_dirs = []
        
        with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), console=self.console) as progress:
            task = progress.add_task(f"Checking {len(common_dirs)} directories...", total=len(common_dirs))
            
            for directory in common_dirs:
                test_url = f"{url.rstrip('/')}/{directory}"
                try:
                    response = requests.get(test_url, timeout=3, allow_redirects=False)
                    if response.status_code in [200, 301, 302, 403]:
                        found_dirs.append({
                            'path': test_url, 
                            'status': response.status_code,
                            'size': len(response.content)
                        })
                        self.console.print(f"[green]✓ [{response.status_code}] {test_url}[/green]")
                except:
                    pass
                
                progress.update(task, advance=1)
        
        self.findings.append({
            'type': 'directory_bruteforce',
            'url': url,
            'directories': found_dirs,
            'timestamp': datetime.now().isoformat()
        })
        
        return found_dirs
    
    def sql_injection_test(self, url):
        """Test for SQL injection vulnerabilities"""
        self.console.print(f"\n[yellow]🔍 Testing for SQL injection on {url}...[/yellow]\n")
        
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "admin' #",
            "' UNION SELECT NULL--",
            "1' AND '1'='1",
            "' AND 1=1--",
        ]
        
        vulnerabilities = []
        
        for payload in payloads:
            try:
                test_url = f"{url}?id={payload}"
                response = requests.get(test_url, timeout=5)
                
                sql_errors = ['SQL syntax', 'mysql_fetch', 'Warning: mysql', 'SQLite', 
                             'PostgreSQL', 'ORA-', 'Microsoft SQL', 'syntax error']
                
                for error in sql_errors:
                    if error.lower() in response.text.lower():
                        vulnerabilities.append({
                            'payload': payload,
                            'error': error,
                            'url': test_url
                        })
                        self.console.print(f"[red]⚠ VULNERABLE: {payload} → {error}[/red]")
                        break
            except:
                pass
        
        self.findings.append({
            'type': 'sql_injection',
            'url': url,
            'vulnerabilities': vulnerabilities,
            'timestamp': datetime.now().isoformat()
        })
        
        return vulnerabilities
    
    def xss_test(self, url):
        """Test for XSS vulnerabilities"""
        self.console.print(f"\n[yellow]🔍 Testing for XSS on {url}...[/yellow]\n")
        
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src='javascript:alert(\"XSS\")'></iframe>",
            "<body onload=alert('XSS')>",
        ]
        
        vulnerabilities = []
        
        for payload in payloads:
            try:
                test_url = f"{url}?q={payload}"
                response = requests.get(test_url, timeout=5)
                
                if payload in response.text:
                    vulnerabilities.append({
                        'payload': payload,
                        'url': test_url,
                        'reflected': True
                    })
                    self.console.print(f"[red]⚠ VULNERABLE: Payload reflected - {payload[:50]}[/red]")
            except:
                pass
        
        self.findings.append({
            'type': 'xss',
            'url': url,
            'vulnerabilities': vulnerabilities,
            'timestamp': datetime.now().isoformat()
        })
        
        return vulnerabilities
    
    def generate_report(self, output_file="security_report.md"):
        """Generate security assessment report"""
        self.console.print(f"\n[cyan]📝 Generating security report...[/cyan]\n")
        
        report = f"""# Security Assessment Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Executive Summary
Total Findings: {len(self.findings)}

"""
        
        for finding in self.findings:
            report += f"\n## {finding['type'].upper().replace('_', ' ')}\n"
            report += f"Timestamp: {finding['timestamp']}\n\n"
            
            if finding['type'] == 'port_scan':
                report += f"Target: {finding['target']}\n"
                report += f"Open Ports: {len(finding['open_ports'])}\n\n"
                for port in finding['open_ports']:
                    report += f"- Port {port['port']}: {port['service']}\n"
            
            elif finding['type'] == 'subdomain_enum':
                report += f"Domain: {finding['domain']}\n"
                report += f"Subdomains Found: {len(finding['subdomains'])}\n\n"
                for sub in finding['subdomains']:
                    report += f"- {sub['subdomain']} → {sub['ip']}\n"
            
            elif finding['type'] == 'directory_bruteforce':
                report += f"URL: {finding['url']}\n"
                report += f"Directories Found: {len(finding['directories'])}\n\n"
                for dir in finding['directories']:
                    report += f"- [{dir['status']}] {dir['path']}\n"
            
            elif finding['type'] == 'sql_injection':
                report += f"URL: {finding['url']}\n"
                report += f"Vulnerabilities: {len(finding['vulnerabilities'])}\n\n"
                for vuln in finding['vulnerabilities']:
                    report += f"- Payload: `{vuln['payload']}`\n"
                    report += f"  Error: {vuln['error']}\n"
            
            elif finding['type'] == 'xss':
                report += f"URL: {finding['url']}\n"
                report += f"Vulnerabilities: {len(finding['vulnerabilities'])}\n\n"
                for vuln in finding['vulnerabilities']:
                    report += f"- Payload: `{vuln['payload']}`\n"
            
            report += "\n---\n"
        
        with open(output_file, 'w') as f:
            f.write(report)
        
        self.console.print(f"[green]✓ Report saved to {output_file}[/green]")
        return report

class CodeAnalyzer:
    """AI-Powered Code Review & Analysis"""
    
    def __init__(self, bot, console):
        self.bot = bot
        self.console = console
    
    def analyze_security(self, filepath, content):
        """Analyze code for security vulnerabilities"""
        self.console.print(f"\n[yellow]🔒 Analyzing security for {filepath}...[/yellow]\n")
        
        prompt = f"""Analyze this code for security vulnerabilities:

File: {filepath}
```
{content[:3000]}
```

Identify:
1. SQL Injection risks
2. XSS vulnerabilities
3. CSRF issues
4. Authentication/Authorization flaws
5. Hardcoded credentials
6. Insecure deserialization
7. Path traversal risks
8. Command injection

For each issue found, provide:
- Severity (Critical/High/Medium/Low)
- Line number (if possible)
- Description
- Fix suggestion

Be concise and specific."""

        analysis = self.bot.ask(prompt)
        
        md = Markdown(analysis)
        self.console.print(Panel(
            md,
            title="[red]🔒 Security Analysis[/red]",
            border_style="red"
        ))
        
        return analysis
    
    def analyze_quality(self, filepath, content):
        """Analyze code quality"""
        self.console.print(f"\n[yellow]📊 Analyzing code quality for {filepath}...[/yellow]\n")
        
        prompt = f"""Analyze this code for quality issues:

File: {filepath}
```
{content[:3000]}
```

Check for:
1. Code smells
2. Duplicate code
3. Complex functions (too long/nested)
4. Poor naming conventions
5. Missing error handling
6. Inefficient algorithms
7. Memory leaks
8. Best practice violations

Rate overall quality: A/B/C/D/F
Provide specific improvements."""

        analysis = self.bot.ask(prompt)
        
        md = Markdown(analysis)
        self.console.print(Panel(
            md,
            title="[cyan]📊 Code Quality Analysis[/cyan]",
            border_style="cyan"
        ))
        
        return analysis
    
    def suggest_optimizations(self, filepath, content):
        """Suggest performance optimizations"""
        self.console.print(f"\n[yellow]⚡ Analyzing performance for {filepath}...[/yellow]\n")
        
        prompt = f"""Analyze this code for performance optimizations:

File: {filepath}
```
{content[:3000]}
```

Suggest:
1. Algorithm improvements
2. Database query optimization
3. Caching opportunities
4. Async/parallel processing
5. Memory optimization
6. Network optimization

Provide before/after code examples."""

        analysis = self.bot.ask(prompt)
        
        md = Markdown(analysis)
        self.console.print(Panel(
            md,
            title="[green]⚡ Performance Optimization[/green]",
            border_style="green"
        ))
        
        return analysis

class ProjectManager:
    """Multi-File Project Management"""
    
    def __init__(self, bot, console, workspace):
        self.bot = bot
        self.console = console
        self.workspace = workspace
    
    def create_project_structure(self, project_type, project_name):
        """Create complete project structure"""
        self.console.print(f"\n[cyan]📁 Creating {project_type} project: {project_name}...[/cyan]\n")
        
        prompt = f"""Generate a complete project structure for a {project_type} project named '{project_name}'.

Provide a JSON structure with:
- directories to create
- files to create with their content
- dependencies/requirements
- README content

Project types: flask, fastapi, django, react, vue, express, etc.

Output ONLY valid JSON in this format:
{{
  "directories": ["dir1", "dir2/subdir"],
  "files": [
    {{"path": "file.py", "content": "code here"}},
    {{"path": "README.md", "content": "readme content"}}
  ],
  "dependencies": ["package1", "package2"]
}}"""

        response = self.bot.ask(prompt)
        
        try:
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                structure = json.loads(json_match.group())
            else:
                structure = json.loads(response)
            
            project_path = self.workspace / project_name
            project_path.mkdir(exist_ok=True)
            
            for dir_path in structure.get('directories', []):
                (project_path / dir_path).mkdir(parents=True, exist_ok=True)
                self.console.print(f"[green]✓ Created directory: {dir_path}[/green]")
            
            for file_info in structure.get('files', []):
                file_path = project_path / file_info['path']
                file_path.parent.mkdir(parents=True, exist_ok=True)
                
                with open(file_path, 'w') as f:
                    f.write(file_info['content'])
                
                self.console.print(f"[green]✓ Created file: {file_info['path']}[/green]")
            
            if structure.get('dependencies'):
                self.console.print(f"\n[yellow]📦 Dependencies:[/yellow]")
                for dep in structure['dependencies']:
                    self.console.print(f"  - {dep}")
            
            self.console.print(f"\n[green]✅ Project '{project_name}' created successfully![/green]")
            
            return project_path
            
        except Exception as e:
            self.console.print(f"[red]Error creating project: {e}[/red]")
            return None
    
    def visualize_structure(self, path=None):
        """Visualize project structure as tree"""
        if path is None:
            path = self.workspace
        
        tree = Tree(f"[bold cyan]📁 {path.name}[/bold cyan]")
        
        def add_to_tree(directory, parent_tree):
            try:
                items = sorted(directory.iterdir(), key=lambda x: (not x.is_dir(), x.name))
                
                for item in items:
                    if item.name.startswith('.'):
                        continue
                    
                    if item.is_dir():
                        branch = parent_tree.add(f"[cyan]📁 {item.name}[/cyan]")
                        if len(list(item.iterdir())) < 50:
                            add_to_tree(item, branch)
                    else:
                        size = item.stat().st_size
                        size_str = f"{size:,} bytes" if size < 1024 else f"{size/1024:.1f} KB"
                        parent_tree.add(f"[green]📄 {item.name}[/green] [dim]({size_str})[/dim]")
            except PermissionError:
                parent_tree.add("[red]❌ Permission Denied[/red]")
        
        add_to_tree(Path(path), tree)
        self.console.print(tree)

class DebugAssistant:
    """Intelligent Debugging Assistant"""
    
    def __init__(self, bot, console):
        self.bot = bot
        self.console = console
    
    def analyze_error(self, error_message, code_context=""):
        """Analyze error and suggest fixes"""
        self.console.print(f"\n[yellow]🐛 Analyzing error...[/yellow]\n")
        
        prompt = f"""Analyze this error and provide a fix:

Error Message:
```
{error_message}
```

Code Context:
```
{code_context}
```

Provide:
1. Root cause explanation
2. Step-by-step fix
3. Corrected code
4. Prevention tips

Be specific and practical."""

        analysis = self.bot.ask(prompt)
        
        md = Markdown(analysis)
        self.console.print(Panel(
            md,
            title="[red]🐛 Debug Analysis[/red]",
            border_style="red"
        ))
        
        return analysis
    
    def suggest_breakpoints(self, filepath, content):
        """Suggest strategic breakpoint locations"""
        self.console.print(f"\n[yellow]🎯 Suggesting breakpoints for {filepath}...[/yellow]\n")
        
        prompt = f"""Analyze this code and suggest strategic breakpoint locations for debugging:

```
{content[:2000]}
```

For each breakpoint, provide:
- Line number (approximate)
- Reason (what to inspect)
- Variables to watch

List top 5 most useful breakpoints."""

        suggestions = self.bot.ask(prompt)
        
        md = Markdown(suggestions)
        self.console.print(Panel(
            md,
            title="[yellow]🎯 Breakpoint Suggestions[/yellow]",
            border_style="yellow"
        ))
        
        return suggestions

class AutonomousAI:
    def __init__(self):
        self.console = Console()
        self.bot = FreeLLM(model="claude")
        self.workspace = Path.cwd()
        self.conversation_context = []
        self.current_files = {}
        self.current_user = os.getenv('USER', 'user')
        self.is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False

        # FIX 2: Agent-state attributes now correctly live here in AutonomousAI
        self.recent_observations: list = []
        self.task_active: bool = False
        self.current_goal: Optional[str] = None
        self.max_steps_per_request: int = 12
        self.conversation_history: list = []   # rolling last 10 exchanges

        # Initialize advanced modules
        self.security_scanner = SecurityScanner(self.console)
        self.code_analyzer = CodeAnalyzer(self.bot, self.console)
        self.project_manager = ProjectManager(self.bot, self.console, self.workspace)
        self.debug_assistant = DebugAssistant(self.bot, self.console)
        
        # Session memory
        self.session_memory = {
            'current_task': None,
            'completed_steps': [],
            'next_steps': [],
            'context_summary': '',
            'pending_info': None,
            'original_request': None
        }
        
        # Command history database
        self.init_history_db()
        
        # Create history
        history_dir = Path.home() / '.ai_assistant'
        history_dir.mkdir(exist_ok=True)
        self.history_file = history_dir / 'history'
        
        self.session = PromptSession(
            history=FileHistory(str(self.history_file))
        )
        
        self.prompt_style = Style.from_dict({
            'username': '#ff0000 bold' if self.is_root else '#00aaff bold',
            'symbol': '#ffaa00 bold',
            'path': '#00ff00',
        })
    
    def init_history_db(self):
        """Initialize command history database"""
        db_path = Path.home() / '.ai_assistant' / 'history.db'
        db_path.parent.mkdir(exist_ok=True)
        
        self.db_conn = sqlite3.connect(str(db_path))
        cursor = self.db_conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                command TEXT NOT NULL,
                success BOOLEAN,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                execution_time REAL,
                output_size INTEGER
            )
        ''')
        
        self.db_conn.commit()
    
    def log_command(self, command, success, exec_time, output_size):
        """Log command to history database"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            INSERT INTO command_history (command, success, execution_time, output_size)
            VALUES (?, ?, ?, ?)
        ''', (command, success, exec_time, output_size))
        self.db_conn.commit()
    
    def get_command_suggestions(self):
        """Get frequently used commands"""
        cursor = self.db_conn.cursor()
        cursor.execute('''
            SELECT command, COUNT(*) as count 
            FROM command_history 
            WHERE success = 1 
            GROUP BY command 
            ORDER BY count DESC 
            LIMIT 10
        ''')
        return cursor.fetchall()
    
    def fix_command_spacing(self, command):
        """Fix common spacing issues in commands"""
        patterns = [
            (r'^nmap(\d)', r'nmap \1'),
            (r'^ping(\d)', r'ping \1'),
            (r'^curl(http)', r'curl \1'),
            (r'^wget(http)', r'wget \1'),
            (r'^ssh(\w)', r'ssh \1'),
            (r'^scp(\w)', r'scp \1'),
            (r'^cat(\w)', r'cat \1'),
            (r'^grep(\w)', r'grep \1'),
            (r'^find(\w)', r'find \1'),
            (r'^ps(\w)', r'ps \1'),
            (r'^kill(\d)', r'kill \1'),
            (r'^chmod(\d)', r'chmod \1'),
            (r'^chown(\w)', r'chown \1'),
            (r'^rm([^\s])', r'rm \1'),
            (r'^cp([^\s])', r'cp \1'),
            (r'^mv([^\s])', r'mv \1'),
            (r'^mkdir([^\s])', r'mkdir \1'),
            (r'^touch([^\s])', r'touch \1'),
            (r'^whois([^\s])', r'whois \1'),
        ]
        
        fixed_command = command
        for pattern, replacement in patterns:
            fixed_command = re.sub(pattern, replacement, fixed_command)
        
        return fixed_command
    
    def get_prompt(self):
        """Generate dynamic prompt based on user and permissions"""
        username = self.current_user
        
        if self.is_root:
            symbol = "💀>"
        else:
            symbol = "🔥>"
        
        return HTML(f'<username>{username}</username><symbol>{symbol}</symbol> ')
    
    def update_user_info(self):
        """Update current user information"""
        try:
            self.current_user = os.getenv('USER', 'user')
            self.is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
            
            self.prompt_style = Style.from_dict({
                'username': '#ff0000 bold' if self.is_root else '#00aaff bold',
                'symbol': '#ffaa00 bold',
                'path': '#00ff00',
            })
        except:
            pass
    
    def execute_command(self, command):
        """Execute shell command with live output"""
        import time
        start_time = time.time()
        
        command = self.fix_command_spacing(command)
        
        if command.strip().startswith('cd '):
            path = command.strip()[3:].strip()
            return self.change_directory(path)
        
        if command.strip() in ['sudo su', 'su', 'sudo -i', 'sudo -s']:
            return self.switch_to_root()
        
        if command.strip() == 'exit' and self.is_root:
            return self.exit_root()
        
        # Handle close/kill application commands
        if command.strip().startswith(('close ', 'kill ')):
            app_name = command.strip().split()[1]
            return self.close_application(app_name)
        
        # GUI apps that must run in background (fire-and-forget)
        background_commands = [
            'firefox', 'chromium', 'google-chrome', 'mousepad', 'gedit', 'code', 'gimp',
            'libreoffice', 'vlc', 'evince', 'xdg-open', 'gnome-open', 'thunar', 'nautilus',
            'php -S', 'python -m http.server', 'python -m SimpleHTTPServer',
            'npm start', 'npm run dev', 'flask run', 'django runserver',
            'node server', 'serve', 'http-server', 'live-server',
            'wireshark', 'burpsuite', 'zaproxy',
            'ssh -D', 'ssh -L',
        ]

        # Long-running CLI tools that stream output — run foreground with live output
        foreground_stream_commands = [
            'gobuster', 'nmap', 'nikto', 'sqlmap', 'hydra', 'john', 'hashcat',
            'wfuzz', 'ffuf', 'dirb', 'dirbuster', 'medusa', 'crackmapexec',
            'dalfox', 'subfinder', 'amass', 'dnsx', 'feroxbuster', 'ssh-audit',
            'enum4linux', 'smbclient', 'dig', 'whois', 'theHarvester',
            'ping', 'top', 'htop', 'tail -f', 'watch',
            'tcpdump', 'nc -l', 'netcat -l', 'socat',
            # pre-flight / verification — must show output
            'ls', 'find', 'which', 'cat', 'file', 'locate', 'curl', 'wget',
        ]
        
        # Check which category the command falls into
        should_background = any(cmd in command for cmd in background_commands)
        cmd_first_word = command.strip().split()[0] if command.strip() else ''
        should_stream = not should_background and (
            any(cmd in command for cmd in foreground_stream_commands if ' ' in cmd) or
            any(cmd_first_word == cmd for cmd in foreground_stream_commands if ' ' not in cmd)
        )

        if should_stream:
            try:
                self.console.print(f"\n[cyan]⚡ Running:[/cyan] {command}\n")
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    cwd=self.workspace
                )
                output_lines = []
                for line in process.stdout:
                    line = line.rstrip()
                    if line:
                        self.console.print(line)
                        output_lines.append(line)
                process.wait()
                elapsed = time.time() - start_time
                stdout = '\n'.join(output_lines)
                self.log_command(command, process.returncode == 0, elapsed, len(stdout))
                return {
                    'stdout': stdout,
                    'stderr': '',
                    'returncode': process.returncode,
                    'success': process.returncode == 0
                }
            except Exception as e:
                self.console.print(f"[red]Error: {e}[/red]")
                return {'stdout': '', 'stderr': str(e), 'returncode': -1, 'success': False}
        
        if should_background:
            try:
                self.console.print(f"\n[cyan]🚀 Starting in background:[/cyan] {command}")
                
                process = subprocess.Popen(
                    f"nohup {command} > /dev/null 2>&1 &",
                    shell=True,
                    cwd=self.workspace,
                    start_new_session=True
                )
                
                time.sleep(0.5)
                
                self.console.print(f"[green]✓ Process started successfully[/green]")
                
                if 'php -S' in command:
                    parts = command.split()
                    server_addr = 'localhost:8000'
                    for i, part in enumerate(parts):
                        if 'localhost' in part or '127.0.0.1' in part:
                            server_addr = part
                            break
                    self.console.print(f"[cyan bold]🌐 Server running at: http://{server_addr}[/cyan bold]")
                    self.console.print(f"[dim]Access your files at the URL above[/dim]")
                
                elif 'http.server' in command or 'SimpleHTTPServer' in command:
                    port = '8000'
                    if '-m http.server' in command:
                        parts = command.split()
                        if len(parts) > 3:
                            port = parts[-1]
                    self.console.print(f"[cyan bold]🌐 Server running at: http://localhost:{port}[/cyan bold]")
                
                elif 'firefox' in command or 'chrome' in command or 'chromium' in command:
                    url_match = re.search(r'https?://[^\s]+', command)
                    if url_match:
                        url = url_match.group()
                        self.console.print(f"[cyan bold]🌐 Opening: {url}[/cyan bold]")
                    else:
                        self.console.print(f"[cyan]🌐 Browser opened[/cyan]")
                
                elif 'npm start' in command or 'npm run' in command:
                    self.console.print(f"[cyan]📦 NPM process running[/cyan]")
                
                elif 'flask run' in command or 'django runserver' in command:
                    port = '5000' if 'flask' in command else '8000'
                    self.console.print(f"[cyan bold]🌐 Server running at: http://localhost:{port}[/cyan bold]")
                
                if 'php -S' in command:
                    self.console.print(f"[dim]To stop: pkill -f 'php -S'[/dim]")
                elif 'firefox' in command:
                    self.console.print(f"[dim]To close: pkill firefox[/dim]")
                
                self.console.print()
                
                self.log_command(command, True, 0.5, 0)
                
                return {
                    'stdout': f'Started in background: {command}',
                    'stderr': '',
                    'returncode': 0,
                    'success': True
                }
                    
            except Exception as e:
                self.console.print(f"[red]✗ Error starting background process: {e}[/red]\n")
                import traceback
                traceback.print_exc()
                return {
                    'stdout': '',
                    'stderr': str(e),
                    'returncode': -1,
                    'success': False
                }
        
        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=self.workspace
            )
            
            stdout, stderr = process.communicate()
            returncode = process.returncode
            elapsed = time.time() - start_time
            
            if stdout:
                self.console.print(stdout.rstrip())
            if stderr and returncode != 0:
                self.console.print(f"[red]{stderr.rstrip()}[/red]")
            
            self.log_command(command, returncode == 0, elapsed, len(stdout))
            
            return {
                'stdout': stdout,
                'stderr': stderr,
                'returncode': returncode,
                'success': returncode == 0
            }
            
        except Exception as e:
            self.console.print(f"[red]Error: {e}[/red]")
            return {
                'stdout': '',
                'stderr': str(e),
                'returncode': -1,
                'success': False
            }
    
    def close_application(self, app_name):
        """Close/kill an application"""
        try:
            result = subprocess.run(['pkill', '-f', app_name], capture_output=True)
            
            if result.returncode == 0:
                self.console.print(f"\n[green]✓ Closed {app_name}[/green]")
                return {'stdout': f'Closed {app_name}', 'stderr': '', 'returncode': 0, 'success': True}
            else:
                result = subprocess.run(['killall', app_name], capture_output=True)
                if result.returncode == 0:
                    self.console.print(f"\n[green]✓ Closed {app_name}[/green]")
                    return {'stdout': f'Closed {app_name}', 'stderr': '', 'returncode': 0, 'success': True}
                else:
                    self.console.print(f"\n[yellow]Process '{app_name}' not found or already closed[/yellow]")
                    return {'stdout': '', 'stderr': 'Process not found', 'returncode': 1, 'success': False}
        except Exception as e:
            self.console.print(f"\n[red]Error closing {app_name}: {e}[/red]")
            return {'stdout': '', 'stderr': str(e), 'returncode': -1, 'success': False}
    
    def switch_to_root(self):
        """Switch to root user"""
        if self.is_root:
            self.console.print("\n[yellow]Already running as root[/yellow]")
            return {'stdout': 'Already root', 'stderr': '', 'returncode': 0, 'success': True}
        
        self.console.print("\n[yellow]⚠️  Switching to root user...[/yellow]")
        self.is_root = True
        self.current_user = "root"
        self.update_user_info()
        self.console.print(f"\n[red bold]root💀>[/red bold] [green]Elevated to root privileges[/green]")
        
        return {'stdout': 'Switched to root', 'stderr': '', 'returncode': 0, 'success': True}
    
    def exit_root(self):
        """Exit root and return to normal user"""
        if not self.is_root:
            self.console.print("\n[yellow]Not running as root[/yellow]")
            return {'stdout': 'Not root', 'stderr': '', 'returncode': 0, 'success': True}
        
        original_user = os.getenv('SUDO_USER') or os.getenv('USER', 'user')
        self.is_root = False
        self.current_user = original_user
        self.update_user_info()
        self.console.print(f"\n[cyan bold]{self.current_user}🔥>[/cyan bold] [green]Returned to normal user[/green]")
        
        return {'stdout': 'Exited root', 'stderr': '', 'returncode': 0, 'success': True}
    
    def change_directory(self, path):
        """Change working directory"""
        try:
            if path.startswith('~'):
                path = str(Path.home()) + path[1:]
            
            new_path = Path(path)
            if not new_path.is_absolute():
                new_path = self.workspace / new_path
            
            new_path = new_path.resolve()
            
            if new_path.exists() and new_path.is_dir():
                self.workspace = new_path
                self.console.print(f"\n[green]✓ Changed directory to:[/green] {self.workspace}")
                return {'stdout': str(self.workspace), 'stderr': '', 'returncode': 0, 'success': True}
            else:
                self.console.print(f"\n[red]✗ Directory not found:[/red] {path}")
                return {'stdout': '', 'stderr': f'Directory not found: {path}', 'returncode': 1, 'success': False}
        except Exception as e:
            self.console.print(f"\n[red]✗ Error:[/red] {e}")
            return {'stdout': '', 'stderr': str(e), 'returncode': 1, 'success': False}
    
    def detect_file_language(self, filepath):
        """Detect programming language from file extension"""
        ext_map = {
            '.py': 'python', '.js': 'javascript', '.html': 'html', '.css': 'css',
            '.java': 'java', '.cpp': 'cpp', '.c': 'c', '.sh': 'bash',
            '.json': 'json', '.xml': 'xml', '.yaml': 'yaml', '.yml': 'yaml',
            '.md': 'markdown', '.sql': 'sql', '.php': 'php', '.rb': 'ruby',
            '.go': 'go', '.rs': 'rust', '.ts': 'typescript', '.jsx': 'jsx', '.tsx': 'tsx',
        }
        
        ext = Path(filepath).suffix.lower()
        return ext_map.get(ext, 'text')
    
    def read_file(self, filepath):
        """Read file content with syntax highlighting"""
        try:
            path = Path(filepath)
            if not path.is_absolute():
                path = self.workspace / path
            
            with open(path, 'r') as f:
                content = f.read()
            
            self.current_files[str(path)] = content
            
            self.console.print(f"\n[green]✓ Loaded file:[/green] {path}")
            self.console.print(f"[dim]Size: {len(content)} bytes, Lines: {len(content.splitlines())}[/dim]\n")
            
            language = self.detect_file_language(str(path))
            
            if len(content) > 2000:
                preview = '\n'.join(content.splitlines()[:50])
                syntax = Syntax(preview, language, theme="monokai", line_numbers=True)
                self.console.print(Panel(
                    syntax, 
                    title=f"[cyan]Preview of {path.name} (first 50 lines)[/cyan]",
                    border_style="cyan"
                ))
                self.console.print(f"[dim]... {len(content.splitlines()) - 50} more lines ...[/dim]\n")
            else:
                syntax = Syntax(content, language, theme="monokai", line_numbers=True)
                self.console.print(Panel(
                    syntax, 
                    title=f"[cyan]{path.name}[/cyan]",
                    border_style="cyan"
                ))
            
            return content, None
        except Exception as e:
            self.console.print(f"\n[red]✗ Error reading file:[/red] {e}")
            return None, str(e)
    
    def write_file(self, filepath, content):
        """Write content to file with confirmation"""
        try:
            path = Path(filepath)
            if not path.is_absolute():
                path = self.workspace / path
            
            path.parent.mkdir(parents=True, exist_ok=True)
            
            file_exists = path.exists()
            
            with open(path, 'w') as f:
                f.write(content)
            
            action = "Updated" if file_exists else "Created"
            self.console.print(f"\n[green]✓ {action} file:[/green] {path}")
            self.console.print(f"[dim]Size: {len(content)} bytes, Lines: {len(content.splitlines())}[/dim]\n")
            
            language = self.detect_file_language(str(path))
            syntax = Syntax(content, language, theme="monokai", line_numbers=True)
            self.console.print(Panel(
                syntax, 
                title=f"[cyan]{path.name}[/cyan]",
                border_style="green"
            ))
            
            self.current_files[str(path)] = content
            
            return True, None
        except Exception as e:
            self.console.print(f"\n[red]✗ Error writing file:[/red] {e}")
            return False, str(e)
    
    def edit_file(self, filepath, instructions):
        """Intelligently edit a file based on instructions using AI"""
        try:
            self.console.print(f"\n[cyan]📖 Reading file:[/cyan] {filepath}")
            content, error = self.read_file(filepath)
            
            if error:
                return {'success': False, 'error': error}
            
            self.console.print(f"\n[yellow]🤖 AI is analyzing and modifying the code...[/yellow]\n")
            
            edit_prompt = f"""You are a code editor AI. Your task is to modify the following file according to the user's instructions.

FILE: {filepath}
CURRENT CONTENT:
```
{content}
```

USER INSTRUCTIONS: {instructions}

IMPORTANT RULES:
1. Read and understand the current code structure
2. Make ONLY the changes requested by the user
3. Preserve the existing code style and formatting
4. Do NOT rewrite the entire file unless explicitly asked
5. Add comments where you made changes
6. Output ONLY the complete modified file content
7. Do NOT include any explanations, markdown formatting, or code fences
8. Output the raw code directly

Modified file content:"""

            with self.console.status("[cyan]AI is editing the file...", spinner="dots"):
                modified_content = self.bot.ask(edit_prompt)
            
            modified_content = modified_content.strip()
            if modified_content.startswith('```'):
                lines = modified_content.split('\n')
                if lines[0].startswith('```'):
                    lines = lines[1:]
                if lines and lines[-1].startswith('```'):
                    lines = lines[:-1]
                modified_content = '\n'.join(lines)
            
            self.console.print("\n[yellow]Changes made:[/yellow]")
            original_lines = content.splitlines()
            modified_lines = modified_content.splitlines()
            
            changes_count = 0
            for i, (orig, mod) in enumerate(zip(original_lines, modified_lines), 1):
                if orig != mod:
                    changes_count += 1
                    if changes_count <= 10:
                        self.console.print(f"\n[dim]Line {i}:[/dim]")
                        self.console.print(f"[red]- {orig}[/red]")
                        self.console.print(f"[green]+ {mod}[/green]")
            
            if changes_count > 10:
                self.console.print(f"\n[dim]... and {changes_count - 10} more changes ...[/dim]")
            
            success, error = self.write_file(filepath, modified_content)
            
            if success:
                return {
                    'success': True,
                    'changes': changes_count,
                    'original_size': len(content),
                    'new_size': len(modified_content)
                }
            else:
                return {'success': False, 'error': error}
            
        except Exception as e:
            self.console.print(f"\n[red]Error editing file: {e}[/red]")
            return {'success': False, 'error': str(e)}
    
    def create_file_with_ai(self, filepath, description):
        """Create a new file with AI-generated content"""
        try:
            self.console.print(f"\n[cyan]📝 Creating file:[/cyan] {filepath}")
            self.console.print(f"[dim]Description: {description}[/dim]\n")
            
            language = self.detect_file_language(filepath)
            
            creation_prompt = f"""You are a code generation AI. Create a file based on the user's description.

FILE TO CREATE: {filepath}
FILE TYPE: {language}
USER DESCRIPTION: {description}

REQUIREMENTS:
1. Generate complete, working code
2. Follow best practices for {language}
3. Include helpful comments
4. Make it production-ready
5. Output ONLY the file content
6. Do NOT include explanations or markdown formatting
7. Do NOT use code fences (```)

Generate the complete file content:"""

            with self.console.status(f"[cyan]AI is generating {language} code...", spinner="dots"):
                content = self.bot.ask(creation_prompt)
            
            content = content.strip()
            if content.startswith('```'):
                lines = content.split('\n')
                if lines[0].startswith('```'):
                    lines = lines[1:]
                if lines and lines[-1].startswith('```'):
                    lines = lines[:-1]
                content = '\n'.join(lines)
            
            success, error = self.write_file(filepath, content)
            
            if success:
                return {
                    'success': True,
                    'size': len(content),
                    'lines': len(content.splitlines())
                }
            else:
                return {'success': False, 'error': error}
            
        except Exception as e:
            self.console.print(f"\n[red]Error creating file: {e}[/red]")
            return {'success': False, 'error': str(e)}
    
    def get_system_context(self):
        """Get current system context"""
        context = {
            'workspace': str(self.workspace),
            'files_in_workspace': [],
            'system_info': {}
        }
        
        try:
            for item in self.workspace.iterdir():
                if not item.name.startswith('.'):
                    context['files_in_workspace'].append({
                        'name': item.name,
                        'type': 'dir' if item.is_dir() else 'file',
                        'size': item.stat().st_size if item.is_file() else 0
                    })
        except:
            pass
        
        try:
            context['system_info'] = {
                'cpu_percent': psutil.cpu_percent(interval=0.1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent
            }
        except:
            pass
        
        return context
    
    def parse_ai_response(self, response):
        """Parse AI response to extract actions"""
        actions = []
        
        action_pattern = r'<action>(.*?)</action>'
        matches = re.findall(action_pattern, response, re.DOTALL)
        
        for match in matches:
            try:
                action_data = json.loads(match.strip())
                actions.append(action_data)
            except:
                lines = match.strip().split('\n')
                for line in lines:
                    if line.strip():
                        try:
                            action_data = json.loads(line.strip())
                            actions.append(action_data)
                        except:
                            pass
        
        return actions

    def extract_reply(self, response):
        """Extract plain text reply from <reply> tag or text outside control tags"""
        # Prefer explicit <reply> tag
        reply_match = re.search(r'<reply>(.*?)</reply>', response, re.DOTALL)
        if reply_match:
            return reply_match.group(1).strip()
        # Fall back: strip all known tags and return remaining text
        plain = re.sub(r'<(action|done|thought|question|reply)>.*?</\1>', '', response, flags=re.DOTALL)
        plain = plain.strip()
        return plain if len(plain) > 5 else None
    
    def execute_action(self, action):
        """Execute a parsed action"""
        action_type = action.get('type')
        
        try:
            if action_type == 'command':
                cmd = action.get('command')
                result = self.execute_command(cmd)
                return result
            
            elif action_type == 'read_file':
                filepath = action.get('path')
                content, error = self.read_file(filepath)
                if error:
                    return {'success': False, 'error': error}
                else:
                    return {'success': True, 'content': content}
            
            elif action_type == 'write_file':
                filepath = action.get('path')
                content = action.get('content')
                success, error = self.write_file(filepath, content)
                if error:
                    return {'success': False, 'error': error}
                else:
                    return {'success': True}
            
            elif action_type == 'edit_file':
                filepath = action.get('path')
                instructions = action.get('instructions')
                return self.edit_file(filepath, instructions)
            
            elif action_type == 'create_file':
                filepath = action.get('path')
                description = action.get('description', '')
                return self.create_file_with_ai(filepath, description)
            
            elif action_type == 'port_scan':
                target = action.get('target')
                ports = action.get('ports', 'common')
                result = self.security_scanner.port_scan(target, ports)
                return {'success': True, 'open_ports': result}
            
            elif action_type == 'subdomain_enum':
                domain = action.get('domain')
                result = self.security_scanner.subdomain_enum(domain)
                return {'success': True, 'subdomains': result}
            
            elif action_type == 'dir_bruteforce':
                url = action.get('url')
                result = self.security_scanner.directory_bruteforce(url)
                return {'success': True, 'directories': result}
            
            elif action_type == 'sql_injection_test':
                url = action.get('url')
                result = self.security_scanner.sql_injection_test(url)
                return {'success': True, 'vulnerabilities': result}
            
            elif action_type == 'xss_test':
                url = action.get('url')
                result = self.security_scanner.xss_test(url)
                return {'success': True, 'vulnerabilities': result}
            
            elif action_type == 'security_report':
                output_file = action.get('output', 'security_report.md')
                report = self.security_scanner.generate_report(output_file)
                return {'success': True, 'report': report}
            
            elif action_type == 'analyze_security':
                filepath = action.get('path')
                content, error = self.read_file(filepath)
                if error:
                    return {'success': False, 'error': error}
                result = self.code_analyzer.analyze_security(filepath, content)
                return {'success': True, 'analysis': result}
            
            elif action_type == 'analyze_quality':
                filepath = action.get('path')
                content, error = self.read_file(filepath)
                if error:
                    return {'success': False, 'error': error}
                result = self.code_analyzer.analyze_quality(filepath, content)
                return {'success': True, 'analysis': result}
            
            elif action_type == 'optimize_performance':
                filepath = action.get('path')
                content, error = self.read_file(filepath)
                if error:
                    return {'success': False, 'error': error}
                result = self.code_analyzer.suggest_optimizations(filepath, content)
                return {'success': True, 'suggestions': result}
            
            elif action_type == 'create_project':
                project_type = action.get('project_type')
                project_name = action.get('name')
                result = self.project_manager.create_project_structure(project_type, project_name)
                return {'success': result is not None, 'path': str(result) if result else None}
            
            elif action_type == 'visualize_structure':
                path = action.get('path', None)
                self.project_manager.visualize_structure(path)
                return {'success': True}
            
            elif action_type == 'analyze_error':
                error_msg = action.get('error')
                context = action.get('context', '')
                result = self.debug_assistant.analyze_error(error_msg, context)
                return {'success': True, 'analysis': result}
            
            elif action_type == 'suggest_breakpoints':
                filepath = action.get('path')
                content, error = self.read_file(filepath)
                if error:
                    return {'success': False, 'error': error}
                result = self.debug_assistant.suggest_breakpoints(filepath, content)
                return {'success': True, 'suggestions': result}
            
            elif action_type == 'analyze':
                target = action.get('target')
                self.console.print(f"\n[cyan]Analyzing:[/cyan] {target}")
                
                if target == 'system':
                    cpu = psutil.cpu_percent(interval=1)
                    mem = psutil.virtual_memory()
                    disk = psutil.disk_usage('/')
                    
                    info = f"""CPU: {cpu}%
Memory: {mem.percent}% ({mem.used // (1024**3)}GB / {mem.total // (1024**3)}GB)
Disk: {disk.percent}% ({disk.used // (1024**3)}GB / {disk.total // (1024**3)}GB)"""
                    
                    self.console.print(Panel(info, title="System Status"))
                    return {'success': True, 'data': info}
            
            return {'success': False, 'error': 'Unknown action type'}
            
        except Exception as e:
            self.console.print(f"\n[red]Error in execute_action: {e}[/red]")
            import traceback
            traceback.print_exc()
            return {'success': False, 'error': str(e)}
    
    def is_command_or_chat(self, user_input):
        """Use AI to determine if input is a command request or casual chat"""
        
        educational_patterns = [
            r'\bhow\s+(can|do|does)\s+\w+\s+(hack|exploit|attack|breach)',
            r'\bwhat\s+are\s+\w+\s+(vulnerabilities|exploits|attacks)',
            r'\bhow\s+to\s+(hack|exploit|attack)',
            r'\btell\s+me\s+about\s+(hacking|pentesting|security)',
        ]
        
        for pattern in educational_patterns:
            if re.search(pattern, user_input.lower()):
                return 'educational'
        
        classification_prompt = f"""Classify this user input as "CHAT", "TASK", or "EDUCATIONAL":

User: "{user_input}"

CHAT = casual conversation (greetings, how are you, small talk)
TASK = user wants you to DO something (run commands, scan, test, create files)
EDUCATIONAL = user asking how something works (how to hack, how vulnerabilities work, learning about security)

Examples:
"hi" -> CHAT
"scan example.com" -> TASK
"how can hackers hack a website" -> EDUCATIONAL
"test for SQL injection" -> TASK
"what are common web vulnerabilities" -> EDUCATIONAL

Respond with ONLY: CHAT, TASK, or EDUCATIONAL"""

        try:
            response = self.bot.ask(classification_prompt).strip().upper()
            
            if 'CHAT' in response:
                return 'chat'
            elif 'EDUCATIONAL' in response:
                return 'educational'
            else:
                return 'task'
        except:
            return 'chat' if len(user_input.strip()) < 15 else 'task'
    
    def handle_educational(self, user_input):
        """Handle educational questions about hacking/security"""
        try:
            educational_prompt = f"""You are a cybersecurity educator and ethical hacking instructor. The user is asking an educational question about security.

CONTEXT: You are an educational assistant in a Kali Linux penetration testing environment. The user is learning about ethical hacking and security research.

User Question: {user_input}

Provide an educational response that:
1. Explains the concept clearly for learning purposes
2. Focuses on defensive security and understanding vulnerabilities
3. Emphasizes ethical hacking and responsible disclosure
4. Provides practical examples where appropriate
5. Mentions how these techniques are used in bug bounty programs and penetration testing

Be informative and educational. This is for security research and learning purposes.

Keep response concise (3-5 paragraphs)."""

            response = self.bot.ask(educational_prompt)
            
            self.console.print(f"\n[bold cyan]🎓 Security Education:[/bold cyan]\n")
            md = Markdown(response)
            self.console.print(Panel(
                md,
                title="[cyan]📚 Educational Response[/cyan]",
                border_style="cyan",
                padding=(1, 2)
            ))
            print()
            
            self.conversation_context.append({
                'user': user_input,
                'ai': response,
                'type': 'educational'
            })
        except Exception as e:
            self.console.print(f"[red]Error: {e}[/red]")
    
    def handle_chat(self, user_input):
        """Handle casual conversation"""
        try:
            chat_prompt = f"""You are a helpful AI assistant in a penetration testing environment having a casual conversation.

User: {user_input}

Respond naturally and friendly. Keep it brief (2-3 sentences max)."""

            response = self.bot.ask(chat_prompt)
            
            self.console.print(f"\n[bold cyan]AI:[/bold cyan] {response}\n")
            
            self.conversation_context.append({
                'user': user_input,
                'ai': response,
                'type': 'chat'
            })
        except Exception as e:
            self.console.print(f"[red]Error: {e}[/red]")
    
    def update_session_memory(self, step_description, is_complete=False):
        """Update AI's memory of current session"""
        
        memory_prompt = f"""Update the session memory based on this new information.

Current Memory:
- Task: {self.session_memory['current_task'] or 'None'}
- Completed: {', '.join(self.session_memory['completed_steps'][-3:]) if self.session_memory['completed_steps'] else 'Nothing yet'}
- Context: {self.session_memory['context_summary']}

New Event: {step_description}
Task Complete: {is_complete}

Provide updated memory in this format:
TASK: [brief description of overall task]
COMPLETED: [list of completed steps, comma separated]
NEXT: [what should happen next]
CONTEXT: [brief 1-2 sentence summary of current situation]

Keep it very brief and focused."""

        try:
            response = self.bot.ask(memory_prompt)
            
            lines = response.strip().split('\n')
            for line in lines:
                if line.startswith('TASK:'):
                    self.session_memory['current_task'] = line.replace('TASK:', '').strip()
                elif line.startswith('COMPLETED:'):
                    completed = line.replace('COMPLETED:', '').strip()
                    self.session_memory['completed_steps'] = [s.strip() for s in completed.split(',') if s.strip()]
                elif line.startswith('NEXT:'):
                    next_steps = line.replace('NEXT:', '').strip()
                    self.session_memory['next_steps'] = [s.strip() for s in next_steps.split(',') if s.strip()]
                elif line.startswith('CONTEXT:'):
                    self.session_memory['context_summary'] = line.replace('CONTEXT:', '').strip()
            
            if is_complete:
                self.session_memory['current_task'] = None
                self.session_memory['next_steps'] = []
                
        except Exception as e:
            pass
    
    def get_memory_context(self):
        """Get formatted memory context for AI"""
        if not self.session_memory['current_task']:
            return ""
        
        memory_text = f"""
SESSION MEMORY:
Current Task: {self.session_memory['current_task']}
Completed Steps: {', '.join(self.session_memory['completed_steps'])}
Next Steps: {', '.join(self.session_memory['next_steps'])}
Context: {self.session_memory['context_summary']}
"""
        return memory_text

    # FIX 3: Moved _get_action_list_prompt INSIDE the class with correct indentation
    def _summarise_last_turn(self):
        """Build a brief summary of the last completed turn for conversation history"""
        if not self.recent_observations:
            return "No actions taken."
        lines = []
        for obs in self.recent_observations[-3:]:  # last 3 actions of the turn
            cmd = obs.get('action', {}).get('command', obs.get('action', {}).get('type', '?'))
            stdout = str(obs.get('result', {}).get('stdout', ''))[:300].strip()
            status = '✓' if obs.get('success') else '✗'
            lines.append(f"  {status} {cmd}")
            if stdout:
                lines.append(f"    Output: {stdout[:200]}")
        return '\n'.join(lines)

    def _format_conversation_history(self):
        """Format last 10 turns for injection into prompt"""
        if not self.conversation_history:
            return ""
        lines = ["CONVERSATION HISTORY (last exchanges for context):"]
        for i, turn in enumerate(self.conversation_history, 1):
            lines.append(f"  [{i}] User: {turn['user']}")
            lines.append(f"      Result: {turn['summary']}")
        return '\n'.join(lines)

    def _get_action_list_prompt(self):
        """Return the list of available internal actions for the agent prompt"""
        return """
<action>{"type": "command", "command": "ls -la"}</action>
<action>{"type": "read_file", "path": "file.py"}</action>
<action>{"type": "write_file", "path": "file.py", "content": "..."}</action>
<action>{"type": "edit_file", "path": "file.py", "instructions": "..."}</action>
<action>{"type": "create_file", "path": "file.py", "description": "..."}</action>
<action>{"type": "port_scan", "target": "192.168.1.1", "ports": "common"}</action>
<action>{"type": "subdomain_enum", "domain": "example.com"}</action>
<action>{"type": "dir_bruteforce", "url": "http://example.com"}</action>
<action>{"type": "sql_injection_test", "url": "http://example.com/page"}</action>
<action>{"type": "xss_test", "url": "http://example.com/page"}</action>
<action>{"type": "security_report", "output": "report.md"}</action>
<action>{"type": "analyze_security", "path": "file.py"}</action>
<action>{"type": "analyze_quality", "path": "file.py"}</action>
<action>{"type": "optimize_performance", "path": "file.py"}</action>
<action>{"type": "create_project", "project_type": "flask", "name": "myapp"}</action>
<action>{"type": "visualize_structure"}</action>
<action>{"type": "analyze_error", "error": "...", "context": "..."}</action>
<action>{"type": "suggest_breakpoints", "path": "file.py"}</action>
<action>{"type": "analyze", "target": "system"}</action>
"""

    def think_and_act(self, user_input):
        """Improved agent loop: think → act → observe → repeat until done or limit reached"""
        if not user_input.strip():
            return

        # Reset per-request observations
        self.recent_observations = []

        # Initial goal from user
        self.current_goal = user_input
        self.task_active = True

        step_count = 0
        last_response = ""
        hard_limit = 30  # safety ceiling only — AI should <done> long before this

        while self.task_active and step_count < hard_limit:
            step_count += 1
            self.console.print(f"\n[bold blue]Step {step_count}[/bold blue]")

            # Build rich context for the model
            context = self.get_system_context()
            memory_str = self.get_memory_context()
            obs_json = json.dumps(self.recent_observations[-5:], indent=2, default=str) if self.recent_observations else "No observations yet."

            # FIX 4: Removed inline comment from inside the f-string (caused SyntaxError)
            action_list = self._get_action_list_prompt()

            # Highlight last failure prominently so AI can't miss it
            last_obs = self.recent_observations[-1] if self.recent_observations else None
            last_error_banner = ""
            if last_obs and not last_obs.get("success"):
                failed_cmd = last_obs.get("action", {}).get("command", "unknown")
                failed_out = str(last_obs.get("result", {}).get("stdout", ""))[:600]
                last_error_banner = f"""
⚠ LAST ACTION FAILED — YOU MUST FIX THIS, DO NOT EMIT <done>:
  Command: {failed_cmd}
  Output:  {failed_out}
Fix the error, consult --help if needed, and retry with the correct command.
"""
            conv_history = self._format_conversation_history()

            prompt = f"""You are an expert penetration tester and bug bounty hunter operating inside Kali Linux.
Your name is Acurist, developed by @IMApurbo.
You have deep knowledge of all Kali tools, their flags, wordlists, and real-world usage.

CURRENT GOAL: {self.current_goal}
{last_error_banner}
{conv_history}

SYSTEM CONTEXT:
Workspace: {context['workspace']}
Files: {json.dumps(context.get('files_in_workspace', []), indent=2)}

SESSION MEMORY:
{memory_str}

RECENT OBSERVATIONS (most recent last):
{obs_json}

LAST RESPONSE:
{last_response[:800] if last_response else "First pass"}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
KALI LINUX KNOWLEDGE BASE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

WORDLISTS (pre-installed on Kali — ALWAYS verify with ls before use):
  # Check what's available first:
  #   ls /usr/share/wordlists/
  #   ls /usr/share/wordlists/dirbuster/
  #   ls /usr/share/wordlists/SecLists/Discovery/Web-Content/ 2>/dev/null

  COMMON PATHS (use ls to confirm before passing to tools):
  /usr/share/wordlists/rockyou.txt                                          # passwords
  /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt             # web dirs
  /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt              # web dirs (fast)
  /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt   # web dirs
  /usr/share/wordlists/dirb/common.txt                                      # dirb default
  /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
  /usr/share/wordlists/SecLists/Discovery/Web-Content/big.txt
  /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt
  /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
  /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
  /usr/share/wordlists/SecLists/Fuzzing/SQLi/Generic-SQLi.txt
  /usr/share/wordlists/SecLists/Fuzzing/XSS/XSS-Jhaddix.txt
  /usr/share/wordlists/SecLists/Passwords/Common-Credentials/top-passwords-shortlist.txt
  /usr/share/metasploit-framework/data/wordlists/

  SMART FALLBACK: if SecLists not installed → use dirbuster lists; if dirbuster missing → use dirb/common.txt

TOOL KNOWLEDGE & EXAMPLE COMMANDS:

[WAF / FIREWALL DETECTION]
  wafw00f https://target.com                          # detect WAF/firewall
  wafw00f https://target.com -a                       # try all WAF fingerprints
  wafw00f -l                                          # list all known WAFs
  nmap --script http-waf-detect -p 80,443 target.com
  nmap --script http-waf-fingerprint target.com

[RECON & OSINT]
  nmap -sV -sC -oN out.txt <target>
  nmap -p- --min-rate 5000 -T4 <target>
  nmap -sU --top-ports 100 <target>
  nmap -sV --script vuln <target>
  whois <domain>
  dig <domain> ANY
  dig axfr @<nameserver> <domain>                     # DNS zone transfer
  theHarvester -d <domain> -b all
  amass enum -d <domain>
  subfinder -d <domain> -o subs.txt
  dnsx -l subs.txt -resp -o resolved.txt
  fierce --domain <domain>
  dnsrecon -d <domain> -t std
  maltego                                             # GUI OSINT tool

[WEB FINGERPRINTING]
  whatweb https://target.com
  whatweb -a 3 https://target.com                    # aggressive mode
  wapiti -u https://target.com                       # web app scanner
  nikto -h https://target.com
  nikto -h https://target.com -ssl -port 443
  webtech -u https://target.com
  curl -sI https://target.com | grep -i "server\|x-powered\|x-aspnet"

[WEB DIRECTORY & FILE ENUM]
  gobuster dir -u <url> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt,js -t 50
  gobuster dns -d <domain> -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
  gobuster vhost -u <url> -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt --append-domain
  ffuf -u <url>/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -mc 200,301,302,403 -t 50
  ffuf -u <url>?FUZZ=test -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt
  feroxbuster -u <url> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
  dirb <url> /usr/share/wordlists/dirb/common.txt

[SSL/TLS]
  sslscan <target>
  sslyze <target>
  testssl.sh <target>
  nmap --script ssl-enum-ciphers -p 443 <target>
  nmap --script ssl-heartbleed -p 443 <target>

[SQL INJECTION]
  # Manual via curl:
  curl -s "<url>?id=1'" | grep -i "error\|sql\|syntax\|warning"
  curl -s "<url>?id=1 OR 1=1--"
  curl -s "<url>?id=1' AND SLEEP(5)--" -w "%{{time_total}}"   # time-based blind
  # Automated:
  sqlmap -u "<url>?id=1" --dbs --batch
  sqlmap -u "<url>?id=1" -D <db> --tables --batch
  sqlmap -u "<url>?id=1" -D <db> -T <table> --dump --batch
  sqlmap -r request.txt --level=5 --risk=3 --batch
  sqlmap -u "<url>" --forms --crawl=2 --batch
  sqlmap -u "<url>" --tamper=space2comment --waf-bypass --batch

[XSS]
  curl -s "<url>?q=<script>alert(1)</script>" | grep -i "script"
  curl -s "<url>?name=<img src=x onerror=alert(1)>" | grep -i "onerror"
  ffuf -u "<url>?q=FUZZ" -w /usr/share/wordlists/SecLists/Fuzzing/XSS/XSS-Jhaddix.txt -mr "<script"
  dalfox url "<url>?q=test"
  dalfox url "<url>?q=test" --waf-bypass
  xsser -u "<url>?q=XSS"

[IDOR / ACCESS CONTROL]
  curl -s -H "Cookie: session=<token>" "<url>/api/user/1"
  curl -s -H "Cookie: session=<token>" "<url>/api/user/2"
  curl -X PUT -H "Authorization: Bearer <token>" "<url>/api/resource/id" -d '{{"role":"admin"}}'

[SSRF]
  curl -s "<url>?url=http://127.0.0.1/"
  curl -s "<url>?url=http://169.254.169.254/latest/meta-data/"
  curl -s "<url>?url=file:///etc/passwd"

[LFI / PATH TRAVERSAL]
  curl -s "<url>?page=../../../../etc/passwd"
  curl -s "<url>?page=php://filter/convert.base64-encode/resource=index.php"
  ffuf -u "<url>?page=FUZZ" -w /usr/share/wordlists/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt
  kadimus -u "<url>?page=test"

[OPEN REDIRECT]
  curl -I "<url>?redirect=https://evil.com"
  ffuf -u "<url>?url=FUZZ" -w /usr/share/wordlists/SecLists/Fuzzing/open-redirects.txt -mr "evil.com"

[RACE CONDITION]
  seq 1 20 | xargs -P 20 -I{{}} curl -s -X POST "<url>/redeem" -d "code=PROMO" -H "Cookie: session=<tok>"

[BUSINESS LOGIC]
  curl -s -X POST "<url>/cart" -d "item=1&qty=-1&price=-99.99" -H "Cookie: session=<token>"

[AUTH & BRUTE FORCE]
  hydra -L users.txt -P /usr/share/wordlists/rockyou.txt <target> http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"
  hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://<target>
  medusa -h <target> -U users.txt -P /usr/share/wordlists/rockyou.txt -M http
  patator http_fuzz url=<url> method=POST body='user=FILE0&pass=FILE1' 0=users.txt 1=passwords.txt
  # JWT:
  echo "<jwt>" | python3 -c "import sys,base64,json; p=sys.stdin.read().split('.'); print(base64.b64decode(p[1]+'==').decode())"
  jwt_tool <token> -T                                 # tamper JWT

[SERVICES & NETWORK]
  enum4linux -a <target>
  smbclient -L //<target> -N
  crackmapexec smb <target> -u users.txt -p passwords.txt
  crackmapexec ssh <target> -u users.txt -p passwords.txt
  ssh-audit <target>
  snmpwalk -v2c -c public <target>
  onesixtyone -c /usr/share/wordlists/SecLists/Discovery/SNMP/common-snmp-community-strings.txt <target>
  ftp <target>                                        # try anonymous login
  nc -nv <target> <port>

[CMS SCANNERS]
  wpscan --url https://target.com --enumerate u,p,t  # WordPress
  wpscan --url https://target.com -P /usr/share/wordlists/rockyou.txt --usernames admin
  joomscan -u https://target.com                     # Joomla
  droopescan scan drupal -u https://target.com       # Drupal
  cmseek -u https://target.com                       # auto-detect CMS

[VULNERABILITY SCANNERS]
  nuclei -u https://target.com                       # template-based scanner
  nuclei -u https://target.com -t cves/              # CVE templates
  nuclei -u https://target.com -t vulnerabilities/
  nuclei -l urls.txt -t technologies/
  openvas                                             # full VA scanner (GUI)

[EXPLOITATION]
  msfconsole                                          # Metasploit framework
  searchsploit <keyword>                              # search exploits
  searchsploit -x <exploit_id>                       # read exploit
  python3 exploit.py <target>

[PASSWORD CRACKING]
  hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt       # MD5
  hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt    # NTLM
  hashcat -m 1800 hash.txt /usr/share/wordlists/rockyou.txt    # sha512crypt
  john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
  hash-identifier <hash>                             # identify hash type

[TRAFFIC ANALYSIS]
  tcpdump -i eth0 -w capture.pcap
  wireshark                                          # GUI
  tshark -r capture.pcap -Y "http"

[REPORTING]
  nmap ... -oN report.txt -oX report.xml
  gobuster ... | tee gobuster_out.txt
  sqlmap ... | tee sqlmap_out.txt
  nuclei ... -o nuclei_results.txt

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DECISION RULES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

0. PRE-FLIGHT CHECKS — only for security/tool tasks, NEVER for chat or capability questions:
   - "what can you do", "help", "who are you", "what are you" → skip directly to Rule 3 (informational)
   - Only run ls/which checks when you are ABOUT TO USE a specific tool or wordlist
   - If a wordlist path or tool availability is already confirmed in RECENT OBSERVATIONS, skip pre-flight and proceed directly
   - Only run ls/which if you don't already know the path is valid from a previous step

1. MISSING INFO → Ask ONLY if you genuinely cannot extract it from the message:
   - If the user says "scan testphp.vulnweb.com" → target is testphp.vulnweb.com, DO NOT ask
   - If the user says "find dirs on example.com via gobuster" → target is example.com, DO NOT ask
   - If the user says "test xss on http://site.com/page?q=1" → URL is there, DO NOT ask
   - ONLY ask if the message contains zero extractable target/URL/domain/IP, e.g. just "test xss" alone
   - Always try to infer: domain names, IPs, URLs, even partial ones like "testphp.vulnweb.com" are valid targets
   - Prepend http:// automatically if scheme is missing
   - Use: <question>single specific question</question> — ONE question only

2. INFO AVAILABLE → Act immediately with correct tools:
   - Treat investigative questions as tasks — "is there a firewall on X" = run wafw00f on X
   - "is there a WAF/firewall" → wafw00f <url>
   - "what tech is running on X" → whatweb <url>, nikto, nmap --script
   - "is X vulnerable to SQLi" → sqlmap
   - "does X have open ports" → nmap
   - "check SSL/TLS on X" → sslscan / testssl.sh
   - "scan X for vulns" → nuclei -u <url>
   - Always use the most specific/appropriate Kali tool for the question
   - Prefer real Kali tools over internal actions (port_scan, dir_bruteforce etc. = last resort)

3. INFORMATIONAL / CHAT — answer immediately with <reply>, NO actions, NO pre-flight:
   - "what is X", "tell me about X", "explain X", "how does X work" → expert knowledge answer
   - "who are you", "what is your name", "who made you", "who developed you" → <reply>I'm Acurist, an AI-powered penetration testing and bug bounty assistant developed by @IMApurbo. I run inside Kali Linux and I'm here to help you with security assessments.</reply>
   - "what can you do", "what are your capabilities", "help me", "how can you help" → describe capabilities: recon, WAF detection (wafw00f), web fingerprinting (whatweb, nikto), directory brute-forcing (gobuster, ffuf), vulnerability scanning (nuclei, nmap), SQLi (sqlmap), XSS (dalfox), SSL analysis (sslscan), CMS scanning (wpscan, joomscan), password cracking (hashcat, john), and much more
   - greetings, small talk → brief friendly reply as Acurist
   - Then emit <done>

4. SIMPLE ONE-SHOT ("open firefox", "check my ip"):
   - ONE action, then <done>

5. ERROR RECOVERY — when an action fails, NEVER emit <done>:
   a. Read the error output carefully from RECENT OBSERVATIONS
   b. If wrong flags/syntax → check the help menu first:
      <action>{{"type": "command", "command": "gobuster dir --help 2>&1 | head -60"}}</action>
      then retry with corrected command
   c. If tool not found → try alternative tool or install it:
      <action>{{"type": "command", "command": "apt-get install -y <tool> 2>&1"}}</action>
   d. If wordlist not found → ls to find correct path then retry
   e. If connection refused / timeout → verify target is reachable:
      <action>{{"type": "command", "command": "curl -Is http://target --max-time 5"}}</action>
   f. Keep retrying with fixes until success or truly impossible
   g. COMMON FLAG FIXES:
      - gobuster: `-t 50` needs a space+value, never `-t` alone
      - nmap: use `-T4` not `-T 4`
      - sqlmap: always include `--batch` to avoid interactive prompts
      - ffuf: `-mc 200,301,302,403` not just `-mc`

6. MULTI-STEP TASK:
   - Plan mentally, execute step by step, use observations to adapt
   - After each step check if it succeeded before moving on

FORMAT:
  <action>{{"type": "command", "command": "the_actual_command"}}</action>
  <reply>ALWAYS include this after actions — interpret the results, explain what was found, give your expert analysis</reply>
  <question>specific question for missing info</question>
  <done>brief reason</done>
  RULES:
  - ALWAYS add a <reply> after running tools — never leave the user with just raw output
  - Never emit the same tool/command twice in one response — one wafw00f call is enough
  - <reply> should explain: what the tool found, what it means, recommended next steps
  - If you want both basic and aggressive mode of a tool, pick ONE for the first run

AVAILABLE INTERNAL ACTIONS (fallback only):
{action_list}"""

            with self.console.status("[bold cyan]Thinking...[/bold cyan]", spinner="dots"):
                try:
                    response = self.bot.ask(prompt)
                    last_response = response
                except Exception as e:
                    self.console.print(f"[red]LLM error: {e}[/red]")
                    break

            # ── 1. Parse and execute actions FIRST ───────────────────────
            actions = self.parse_ai_response(response)
            reply_text = self.extract_reply(response)

            # Deduplicate: only one command per unique tool per step
            seen_tools = set()
            unique_actions = []
            for a in actions:
                if a.get('type') == 'command':
                    tool = a.get('command', '').strip().split()[0] if a.get('command', '').strip() else ''
                    if tool in seen_tools:
                        continue
                    seen_tools.add(tool)
                else:
                    key = (a.get('type'), a.get('path', ''), a.get('domain', ''), a.get('url', ''))
                    if key in seen_tools:
                        continue
                    seen_tools.add(key)
                unique_actions.append(a)
            actions = unique_actions

            # Pure informational reply — no actions needed
            if reply_text and not actions:
                md = Markdown(reply_text)
                self.console.print(Panel(md, title="[bold cyan]Acurist[/bold cyan]", border_style="cyan"))
                self.task_active = False
                break

            if actions:
                self.console.print(f"\n[yellow]Executing {len(actions)} action(s)[/yellow]")
                for idx, action in enumerate(actions, 1):
                    self.console.print(f"  → Action {idx}: {action.get('type', 'unknown')}")
                    result = self.execute_action(action)

                    raw_out = str(result.get('stdout', '') or '') + str(result.get('stderr', '') or '')
                    is_syntax_error = any(x in raw_out.lower() for x in [
                        'flag needs an argument', 'incorrect usage', 'command not found',
                        'no such file', 'permission denied', 'invalid option',
                        'unrecognized option', 'error: unknown flag',
                    ])
                    true_failure = is_syntax_error or result.get('returncode', 0) == -1

                    obs = {
                        "step": step_count,
                        "action": action,
                        "result": result,
                        "success": not true_failure,
                        "time": datetime.now().isoformat()
                    }
                    self.recent_observations.append(obs)
                    if true_failure:
                        self.console.print("[red]↑ Action failed — model will fix in next step[/red]")

                if len(actions) > 2:
                    import time
                    time.sleep(0.6)

            # ── Print summary AFTER tool output ───────────────────────────
            if reply_text and actions:
                self.console.print(f"\n[bold cyan]💬 Acurist:[/bold cyan] {reply_text}\n")

            # ── 2. Check control tags AFTER execution ─────────────────────
            if "<done>" in response:
                # Block done if the most recent observation was a failure — force fix
                last_obs = self.recent_observations[-1] if self.recent_observations else None
                if last_obs and not last_obs["success"]:
                    self.console.print("[yellow]⚠ Last action failed — AI must fix and retry before finishing[/yellow]")
                    # Don't break — loop continues so AI sees the failure in next observation
                else:
                    self.console.print("\n[green bold]✓ Done[/green bold]")
                    self.task_active = False
                    break

            question_match = re.search(r'<question>(.*?)</question>', response, re.DOTALL)
            if question_match:
                question = question_match.group(1).strip()
                self.console.print(f"\n[bold yellow]❓ Clarification needed:[/bold yellow]\n{question}\n")
                self.session_memory['pending_info'] = question
                self.session_memory['original_request'] = user_input
                self.task_active = False
                break

            # ── 3. No actions and no done = plain text chat reply ─────────
            if not actions:
                plain = re.sub(r'<thought>.*?</thought>', '', response, flags=re.DOTALL).strip()
                if plain:
                    self.console.print(f"\n[bold cyan]AI:[/bold cyan] {plain}\n")
                self.task_active = False
                break

        if step_count >= hard_limit:
            self.console.print(f"\n[orange1]Safety limit of {hard_limit} steps reached. Stopping.[/orange1]")

        self.task_active = False
        self.current_goal = None
    
    def show_welcome(self):
        """Show welcome message with ASCII gradient logo"""
        
        logo = """
[bold cyan]                            _____       _____ [/bold cyan]
[cyan]______ __________  ___________([/cyan][blue]_)________  /_[/blue]
[blue]_  __ `/  ___/  / / /_  ___/_[/blue][bold blue]  /__  ___/  __/[/bold blue]
[bold blue]/ /_/ // /__ / /_/ /_  /   _[/bold blue][bold magenta]  / _(__  )/ /_  [/bold magenta]
[bold magenta]\\__,_/ \\___/ \\__,_/ /_/    /_/[/bold magenta][magenta]  /____/ \\__/[/magenta]
        """
        
        welcome = "🔒 AI-Powered Pentesting & Bug Bounty Assistant"
        
        self.console.print(logo)
        self.console.print("[dim]                           Author: @IMApurbo[/dim]\n")
        self.console.print(welcome, style="cyan")
        self.console.print(f"\n[yellow]Workspace:[/yellow] {self.workspace}\n")
    
    def run(self):
        """Main loop"""
        os.system('clear' if os.name != 'nt' else 'cls')
        self.show_welcome()
        
        while True:
            try:
                user_input = self.session.prompt(
                    self.get_prompt(),
                    style=self.prompt_style
                ).strip()
                
                if not user_input:
                    continue
                
                if user_input.lower() in ['quit', 'exit', 'bye'] and not self.is_root:
                    self.console.print("\n[cyan]Goodbye! 👋[/cyan]\n")
                    break
                
                if user_input.lower() == 'exit' and self.is_root:
                    self.exit_root()
                    continue
                
                if user_input.lower() == 'clear':
                    os.system('clear' if os.name != 'nt' else 'cls')
                    self.show_welcome()
                    continue
                
                if user_input.lower() == 'help':
                    self.show_welcome()
                    continue
                
                # No keyword detection — AI decides everything
                # If AI previously asked a question, inject the answer into the original task
                if self.session_memory.get('pending_info') and self.session_memory.get('original_request'):
                    original = self.session_memory['original_request']
                    question = self.session_memory['pending_info']
                    combined = f"{original}\n[User answered '{question}' with: {user_input}]"
                    self.session_memory['pending_info'] = None
                    self.session_memory['original_request'] = None
                    self.think_and_act(combined)
                else:
                    self.think_and_act(user_input)

                # Record turn in conversation history (keep last 10)
                summary = self._summarise_last_turn()
                self.conversation_history.append({
                    'user': user_input,
                    'summary': summary
                })
                self.conversation_history = self.conversation_history[-10:]
                
                print()
                
            except KeyboardInterrupt:
                self.console.print("\n\n[yellow]Use 'exit' or 'quit' to leave[/yellow]\n")
                continue
            except EOFError:
                break
            except Exception as e:
                self.console.print(f"\n[red]Error: {e}[/red]\n")
                import traceback
                traceback.print_exc()


def main():
    try:
        ai = AutonomousAI()
        ai.run()
    except Exception as e:
        print(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()

"""fixed previous chats remember issue, showing output after execution, qstn answer from ai"""
