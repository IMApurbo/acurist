#!/usr/bin/env python3
"""
Autonomous AI Assistant - Powered by FreeLLM
An intelligent assistant that understands natural language and autonomously executes tasks
Enhanced with intelligent file operations
"""

import os
import sys
import json
import subprocess
import re
from pathlib import Path
from datetime import datetime
from freellm import FreeLLM
from prompt_toolkit import PromptSession
from prompt_toolkit.styles import Style
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.history import FileHistory
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.syntax import Syntax
from rich.live import Live
from rich.spinner import Spinner
from rich.text import Text
from rich.table import Table
from rich.layout import Layout
import psutil

class AutonomousAI:
    def __init__(self):
        self.console = Console()
        self.bot = FreeLLM(model="claude")
        self.workspace = Path.cwd()
        self.conversation_context = []
        self.current_files = {}  # Store loaded files in memory
        self.current_user = os.getenv('USER', 'user')
        self.is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
        
        # Session memory - AI's running summary of what it's doing
        self.session_memory = {
            'current_task': None,
            'completed_steps': [],
            'next_steps': [],
            'context_summary': '',
            'pending_info': None,
            'original_request': None
        }
        
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
            username_color = "red"
        else:
            symbol = "🔥>"
            username_color = "cyan"
        
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
        """Execute shell command with live output in bordered panel"""
        command = self.fix_command_spacing(command)
        
        if command.strip().startswith('cd '):
            path = command.strip()[3:].strip()
            return self.change_directory(path)
        
        if command.strip() in ['sudo su', 'su', 'sudo -i', 'sudo -s']:
            return self.switch_to_root()
        
        if command.strip() == 'exit' and self.is_root:
            return self.exit_root()
        
        gui_commands = ['firefox', 'chromium', 'google-chrome', 'mousepad', 'gedit', 'code', 'gimp', 
                       'libreoffice', 'vlc', 'evince', 'xdg-open', 'gnome-open']
        
        is_gui_command = any(command.strip().startswith(cmd) for cmd in gui_commands)
        
        if is_gui_command:
            try:
                subprocess.Popen(
                    command + ' &',
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    cwd=self.workspace
                )
                self.console.print(f"\n[green]✓ Launched:[/green] {command}")
                self.console.print("[dim]Application opened in background[/dim]\n")
                return {
                    'stdout': f'Launched: {command}',
                    'stderr': '',
                    'returncode': 0,
                    'success': True
                }
            except Exception as e:
                return {
                    'stdout': '',
                    'stderr': str(e),
                    'returncode': -1,
                    'success': False
                }
        
        infinite_commands = ['ping', 'top', 'htop', 'tail -f', 'watch', 'tcpdump', 'wireshark']
        needs_ctrl_c = any(cmd in command for cmd in infinite_commands)
        
        verbose_commands = {
            'nmap': '-v',
            'curl': '-v',
            'wget': '-v',
            'rsync': '-v',
            'apt': '-V',
            'pip': '-v'
        }
        
        cmd_parts = command.split()
        if cmd_parts:
            base_cmd = cmd_parts[0]
            for cmd_name, verbose_flag in verbose_commands.items():
                if cmd_name in base_cmd and verbose_flag not in command:
                    cmd_parts.insert(1, verbose_flag)
                    command = ' '.join(cmd_parts)
                    break
        
        try:
            import time
            
            stdout_lines = []
            stderr_lines = []
            start_time = time.time()
            user_interrupted = False
            
            simple_commands = ['ls', 'pwd', 'whoami', 'id', 'date', 'echo']
            is_simple = any(command.strip().startswith(cmd) for cmd in simple_commands)
            
            if is_simple:
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
                
                stdout_lines = stdout.split('\n') if stdout else []
                stderr_lines = stderr.split('\n') if stderr else []
                
                if returncode == 0 and stdout:
                    self.show_ai_analysis_only(command, stdout_lines, elapsed)
                
                return {
                    'stdout': stdout,
                    'stderr': stderr,
                    'returncode': returncode,
                    'success': returncode == 0
                }
            
            output_lines = []
            
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=self.workspace,
                bufsize=1,
                universal_newlines=True,
                preexec_fn=os.setsid if hasattr(os, 'setsid') else None
            )
            
            if needs_ctrl_c:
                self.console.print(f"\n[yellow]ℹ️  Press Ctrl+C to stop and see analysis[/yellow]\n")
            
            with self.console.status(f"[cyan]Running: {command[:60]}...", spinner="dots"):
                try:
                    import select
                    
                    while True:
                        reads = [process.stdout.fileno(), process.stderr.fileno()]
                        ret = select.select(reads, [], [], 0.1)
                        
                        for fd in ret[0]:
                            if fd == process.stdout.fileno():
                                line = process.stdout.readline()
                                if line:
                                    stdout_lines.append(line)
                                    self.console.print(line.rstrip(), style="green")
                            
                            if fd == process.stderr.fileno():
                                line = process.stderr.readline()
                                if line:
                                    stderr_lines.append(line)
                                    self.console.print(line.rstrip(), style="yellow")
                        
                        if process.poll() is not None:
                            remaining_stdout = process.stdout.read()
                            remaining_stderr = process.stderr.read()
                            
                            if remaining_stdout:
                                for line in remaining_stdout.split('\n'):
                                    if line:
                                        stdout_lines.append(line + '\n')
                                        self.console.print(line, style="green")
                            
                            if remaining_stderr:
                                for line in remaining_stderr.split('\n'):
                                    if line:
                                        stderr_lines.append(line + '\n')
                                        self.console.print(line, style="yellow")
                            
                            break
                
                except KeyboardInterrupt:
                    user_interrupted = True
                    self.console.print("\n\n[yellow]⏸️  Interrupted by user[/yellow]")
                    
                    try:
                        if hasattr(os, 'killpg'):
                            os.killpg(os.getpgid(process.pid), subprocess.signal.SIGTERM)
                        else:
                            process.terminate()
                        
                        time.sleep(0.5)
                        
                        if process.poll() is None:
                            process.kill()
                        
                        try:
                            remaining_stdout = process.stdout.read()
                            remaining_stderr = process.stderr.read()
                            
                            if remaining_stdout:
                                for line in remaining_stdout.split('\n'):
                                    if line:
                                        stdout_lines.append(line + '\n')
                            
                            if remaining_stderr:
                                for line in remaining_stderr.split('\n'):
                                    if line:
                                        stderr_lines.append(line + '\n')
                        except:
                            pass
                            
                    except Exception as e:
                        pass
            
            returncode = process.poll() if process.poll() is not None else -1
            elapsed = time.time() - start_time
            
            if (returncode == 0 or user_interrupted) and stdout_lines:
                ai_summary = self.show_ai_analysis_only(command, stdout_lines, elapsed, user_interrupted)
                
                if '>' in command and ai_summary:
                    parts = command.split('>')
                    if len(parts) > 1:
                        filename = parts[-1].strip().split()[0]
                        try:
                            with open(filename, 'a') as f:
                                f.write("\n\n" + "="*50 + "\n")
                                f.write("AI ANALYSIS SUMMARY\n")
                                f.write("="*50 + "\n\n")
                                f.write(ai_summary)
                                f.write("\n")
                            self.console.print(f"\n[green]✓ AI summary also written to {filename}[/green]\n")
                        except Exception as e:
                            self.console.print(f"\n[yellow]Note: Could not append summary to file: {e}[/yellow]\n")
            elif returncode != 0 and stderr_lines:
                self.console.print("\n[yellow]⚠️  Command failed. Attempting to fix and retry...[/yellow]")
                
                fix_prompt = f"""The command failed with this error:
Command: {command}
Error: {''.join(stderr_lines[:5])}

Provide ONLY the corrected command, nothing else."""

                try:
                    with self.console.status("[cyan]AI is fixing the command...", spinner="dots"):
                        fixed_cmd = self.bot.ask(fix_prompt).strip()
                        fixed_cmd = fixed_cmd.strip('`').strip('"').strip("'")
                        if fixed_cmd.startswith('bash') or fixed_cmd.startswith('sh'):
                            fixed_cmd = ' '.join(fixed_cmd.split()[1:])
                    
                    self.console.print(f"\n[cyan]Retrying with:[/cyan] {fixed_cmd}\n")
                    
                    return self.execute_command(fixed_cmd)
                except:
                    self.console.print("\n[red]Could not auto-fix command[/red]\n")
            
            return {
                'stdout': ''.join(stdout_lines),
                'stderr': ''.join(stderr_lines),
                'returncode': returncode,
                'success': returncode == 0 or user_interrupted
            }
            
        except Exception as e:
            self.console.print(f"[red]Error: {e}[/red]")
            return {
                'stdout': '',
                'stderr': str(e),
                'returncode': -1,
                'success': False
            }
    
    def show_ai_analysis_only(self, command, stdout_lines, elapsed, user_interrupted=False):
        """Show only AI analysis with rich formatting and return the summary text"""
        
        try:
            with self.console.status("[cyan]🤖 AI is analyzing...", spinner="dots"):
                full_output = ''.join(stdout_lines)
                
                if len(full_output) > 5000:
                    output_for_ai = full_output[:2500] + "\n...(truncated)...\n" + full_output[-2500:]
                else:
                    output_for_ai = full_output
                
                interrupt_note = "\nNote: Command was interrupted by user before completion." if user_interrupted else ""
                
                analysis_prompt = f"""Analyze this command output briefly and clearly.

Command: {command}
Time: {elapsed:.2f}s{interrupt_note}

Output:
```
{output_for_ai}
```

Provide a concise analysis:
- What was found/done
- Key results
- Important insights

Be brief and practical."""

                analysis = self.bot.ask(analysis_prompt)
                md = Markdown(analysis)
                self.console.print("\n")
                self.console.print(Panel(
                    md, 
                    title="[bold cyan]🤖 AI Analysis[/bold cyan]",
                    border_style="cyan",
                    padding=(1, 2)
                ))
                self.console.print()
                
                return analysis
        except Exception as e:
            self.console.print(f"\n[dim yellow]Could not generate AI analysis: {e}[/dim yellow]\n")
            return None
    
    def switch_to_root(self):
        """Switch to root user"""
        if self.is_root:
            self.console.print("\n[yellow]Already running as root[/yellow]")
            return {
                'stdout': 'Already root',
                'stderr': '',
                'returncode': 0,
                'success': True
            }
        
        self.console.print("\n[yellow]⚠️  Switching to root user...[/yellow]")
        self.console.print("[dim]Note: This is a simulated root environment in the AI assistant[/dim]")
        
        self.is_root = True
        self.current_user = "root"
        self.update_user_info()
        
        self.console.print(f"\n[red bold]root💀>[/red bold] [green]Elevated to root privileges[/green]")
        
        return {
            'stdout': 'Switched to root',
            'stderr': '',
            'returncode': 0,
            'success': True
        }
    
    def exit_root(self):
        """Exit root and return to normal user"""
        if not self.is_root:
            self.console.print("\n[yellow]Not running as root[/yellow]")
            return {
                'stdout': 'Not root',
                'stderr': '',
                'returncode': 0,
                'success': True
            }
        
        original_user = os.getenv('SUDO_USER') or os.getenv('USER', 'user')
        
        self.is_root = False
        self.current_user = original_user
        self.update_user_info()
        
        self.console.print(f"\n[cyan bold]{self.current_user}🔥>[/cyan bold] [green]Returned to normal user[/green]")
        
        return {
            'stdout': 'Exited root',
            'stderr': '',
            'returncode': 0,
            'success': True
        }
    
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
                return {
                    'stdout': str(self.workspace),
                    'stderr': '',
                    'returncode': 0,
                    'success': True
                }
            else:
                self.console.print(f"\n[red]✗ Directory not found:[/red] {path}")
                return {
                    'stdout': '',
                    'stderr': f'Directory not found: {path}',
                    'returncode': 1,
                    'success': False
                }
        except Exception as e:
            self.console.print(f"\n[red]✗ Error:[/red] {e}")
            return {
                'stdout': '',
                'stderr': str(e),
                'returncode': 1,
                'success': False
            }
    
    def detect_file_language(self, filepath):
        """Detect programming language from file extension"""
        ext_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.html': 'html',
            '.css': 'css',
            '.java': 'java',
            '.cpp': 'cpp',
            '.c': 'c',
            '.sh': 'bash',
            '.json': 'json',
            '.xml': 'xml',
            '.yaml': 'yaml',
            '.yml': 'yaml',
            '.md': 'markdown',
            '.sql': 'sql',
            '.php': 'php',
            '.rb': 'ruby',
            '.go': 'go',
            '.rs': 'rust',
            '.ts': 'typescript',
            '.jsx': 'jsx',
            '.tsx': 'tsx',
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
            
            # Store in memory
            self.current_files[str(path)] = content
            
            # Show file info
            self.console.print(f"\n[green]✓ Loaded file:[/green] {path}")
            self.console.print(f"[dim]Size: {len(content)} bytes, Lines: {len(content.splitlines())}[/dim]\n")
            
            # Show syntax highlighted preview
            language = self.detect_file_language(str(path))
            
            if len(content) > 2000:
                # Show first 50 lines for large files
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
            
            # Check if file exists
            file_exists = path.exists()
            
            with open(path, 'w') as f:
                f.write(content)
            
            # Show success message
            action = "Updated" if file_exists else "Created"
            self.console.print(f"\n[green]✓ {action} file:[/green] {path}")
            self.console.print(f"[dim]Size: {len(content)} bytes, Lines: {len(content.splitlines())}[/dim]\n")
            
            # Show syntax highlighted content
            language = self.detect_file_language(str(path))
            syntax = Syntax(content, language, theme="monokai", line_numbers=True)
            self.console.print(Panel(
                syntax, 
                title=f"[cyan]{path.name}[/cyan]",
                border_style="green"
            ))
            
            # Store in memory
            self.current_files[str(path)] = content
            
            return True, None
        except Exception as e:
            self.console.print(f"\n[red]✗ Error writing file:[/red] {e}")
            return False, str(e)
    
    def edit_file(self, filepath, instructions):
        """Intelligently edit a file based on instructions using AI"""
        try:
            # First, read the file
            self.console.print(f"\n[cyan]📖 Reading file:[/cyan] {filepath}")
            content, error = self.read_file(filepath)
            
            if error:
                return {'success': False, 'error': error}
            
            # Use AI to understand and modify the code
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
            
            # Clean up the response (remove any markdown if present)
            modified_content = modified_content.strip()
            if modified_content.startswith('```'):
                # Remove code fences
                lines = modified_content.split('\n')
                if lines[0].startswith('```'):
                    lines = lines[1:]
                if lines and lines[-1].startswith('```'):
                    lines = lines[:-1]
                modified_content = '\n'.join(lines)
            
            # Show what changed
            self.console.print("\n[yellow]Changes made:[/yellow]")
            original_lines = content.splitlines()
            modified_lines = modified_content.splitlines()
            
            changes_count = 0
            for i, (orig, mod) in enumerate(zip(original_lines, modified_lines), 1):
                if orig != mod:
                    changes_count += 1
                    if changes_count <= 10:  # Show first 10 changes
                        self.console.print(f"\n[dim]Line {i}:[/dim]")
                        self.console.print(f"[red]- {orig}[/red]")
                        self.console.print(f"[green]+ {mod}[/green]")
            
            if changes_count > 10:
                self.console.print(f"\n[dim]... and {changes_count - 10} more changes ...[/dim]")
            
            # Write the modified content
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
            
            # Detect file type
            language = self.detect_file_language(filepath)
            
            # Generate content with AI
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
            
            # Clean up response
            content = content.strip()
            if content.startswith('```'):
                lines = content.split('\n')
                if lines[0].startswith('```'):
                    lines = lines[1:]
                if lines and lines[-1].startswith('```'):
                    lines = lines[:-1]
                content = '\n'.join(lines)
            
            # Write the file
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
        
        classification_prompt = f"""Classify this user input as either "CHAT" or "TASK":

User: "{user_input}"

CHAT = casual conversation (greetings, how are you, small talk, questions about yourself)
TASK = user wants you to DO something (run commands, create files, analyze data, edit files, etc.)

Examples:
"hi" -> CHAT
"how are you?" -> CHAT
"what can you do" -> CHAT
"thanks" -> CHAT
"find python files" -> TASK
"show disk usage" -> TASK
"create a script" -> TASK
"edit the login page" -> TASK
"modify index.html" -> TASK

Respond with ONLY: CHAT or TASK"""

        try:
            response = self.bot.ask(classification_prompt).strip().upper()
            
            if 'CHAT' in response:
                return 'chat'
            else:
                return 'task'
        except:
            return 'chat' if len(user_input.strip()) < 15 else 'task'
    
    def handle_chat(self, user_input):
        """Handle casual conversation"""
        try:
            chat_prompt = f"""You are a helpful AI assistant having a casual conversation.

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
    
    def think_and_act(self, user_input):
        """AI thinks about what to do and executes actions"""
        
        if self.session_memory['pending_info']:
            self.console.print(f"\n[green]✓ Got it! Continuing with the task...[/green]\n")
            
            user_answer = user_input
            original_request = self.session_memory['original_request']
            question_asked = self.session_memory['pending_info']
            
            self.session_memory['pending_info'] = None
            self.session_memory['original_request'] = None
            
            context = self.get_system_context()
            memory_context = self.get_memory_context()
            
            execute_prompt = f"""You now have all the information needed to complete the task.

ORIGINAL REQUEST: {original_request}
QUESTION ASKED: {question_asked}
USER'S ANSWER: {user_answer}

Current Context:
- Workspace: {context['workspace']}
- Files: {json.dumps(context['files_in_workspace'][:5], indent=2)}

{memory_context}

Now execute the task using the provided information. Output <action> tags immediately.

Available actions:
<action>{{"type": "command", "command": "your command here"}}</action>
<action>{{"type": "read_file", "path": "filename"}}</action>
<action>{{"type": "write_file", "path": "filename", "content": "content"}}</action>
<action>{{"type": "edit_file", "path": "filename", "instructions": "what to change"}}</action>
<action>{{"type": "create_file", "path": "filename", "description": "what to create"}}</action>

IMPORTANT:
- Do NOT ask any more questions
- Use the information provided: {user_answer}
- Output <action> tags to complete the task

Execute now:"""

            with self.console.status("[bold cyan]Processing...", spinner="dots"):
                try:
                    response = self.bot.ask(execute_prompt)
                except Exception as e:
                    self.console.print(f"[red]AI Error: {e}[/red]")
                    return
            
            actions = self.parse_ai_response(response)
            
            if not actions:
                self.console.print("[yellow]No actions generated. Let me try a different approach...[/yellow]\n")
                
                direct_prompt = f"""Generate the exact shell command to: {original_request}

Target/Info: {user_answer}

Respond with ONLY the command, nothing else."""

                try:
                    cmd = self.bot.ask(direct_prompt).strip()
                    cmd = cmd.strip('`').strip('"').strip("'")
                    
                    self.console.print(f"[cyan]Executing:[/cyan] {cmd}\n")
                    result = self.execute_command(cmd)
                    
                    step_desc = f"Executed: {cmd}"
                    self.update_session_memory(step_desc, is_complete=True)
                    return
                except Exception as e:
                    self.console.print(f"[red]Error: {e}[/red]")
                    return
            
            self.console.print(f"\n[yellow]📋 Executing {len(actions)} step(s)...[/yellow]\n")
            
            for i, action in enumerate(actions, 1):
                self.console.print(f"[bold cyan]→ Step {i}/{len(actions)}:[/bold cyan]")
                result = self.execute_action(action)
                
                step_desc = f"Executed: {action.get('command', action.get('type', 'unknown'))}"
                is_last_step = (i == len(actions))
                self.update_session_memory(step_desc, is_complete=is_last_step)
            
            return
        
        context = self.get_system_context()
        memory_context = self.get_memory_context()
        
        recent_context = self.conversation_context[-3:] if len(self.conversation_context) > 3 else self.conversation_context
        context_str = "\n".join([f"User: {c['user']}\nAI: {c.get('ai', '')}" for c in recent_context])
        
        system_prompt = f"""You are an autonomous AI assistant with the ability to understand user intent and take actions.

Current Context:
- Workspace: {context['workspace']}
- Files in workspace: {json.dumps(context['files_in_workspace'][:10], indent=2)}
- System: CPU {context['system_info'].get('cpu_percent', 0)}%, Memory {context['system_info'].get('memory_percent', 0)}%

{memory_context}

Recent conversation:
{context_str}

You can perform these actions by outputting JSON inside <action></action> tags:

1. Execute shell commands:
<action>{{"type": "command", "command": "ls -la"}}</action>

2. Read files (will show syntax-highlighted content):
<action>{{"type": "read_file", "path": "example.py"}}</action>

3. Write/create new files:
<action>{{"type": "write_file", "path": "example.py", "content": "print('hello')"}}</action>

4. Edit existing files intelligently (AI will read, understand, and modify):
<action>{{"type": "edit_file", "path": "index.html", "instructions": "add login functionality"}}</action>

5. Create new files with AI-generated content:
<action>{{"type": "create_file", "path": "login.html", "description": "create a login page with username and password fields"}}</action>

6. Analyze system:
<action>{{"type": "analyze", "target": "system"}}</action>

7. ASK FOR CLARIFICATION (if info is missing):
<question>What is the target IP address you want to scan?</question>

USER REQUEST: {user_input}

CRITICAL FILE OPERATION RULES:

1. EDITING FILES:
   - When user says "modify", "edit", "change", "update", "add to" an existing file
   - Use "edit_file" action - DO NOT write full code
   - AI will automatically read the file, understand it, and make targeted changes
   - Example: "modify index.html and add login functionality"
     → <action>{{"type": "edit_file", "path": "index.html", "instructions": "add login functionality"}}</action>

2. CREATING NEW FILES:
   - When user says "create", "make", "generate" a NEW file
   - Use "create_file" action with description
   - AI will generate complete code
   - Example: "create a login page in HTML"
     → <action>{{"type": "create_file", "path": "login.html", "description": "login page with username and password fields"}}</action>

3. READING FILES:
   - When user says "show", "read", "display" a file
   - Use "read_file" action
   - File will be displayed with syntax highlighting

ANALYZE THE REQUEST: "{user_input}"

Does it involve:
- Editing an EXISTING file? → Use edit_file
- Creating a NEW file? → Use create_file
- Reading a file? → Use read_file
- Missing information? → Ask a question
- Has all info? → Execute actions

Respond now:"""

        with self.console.status("[bold cyan]Thinking...", spinner="dots"):
            try:
                response = self.bot.ask(system_prompt)
            except Exception as e:
                self.console.print(f"[red]AI Error: {e}[/red]")
                return
        
        question_match = re.search(r'<question>(.*?)</question>', response, re.DOTALL)
        
        if question_match:
            question = question_match.group(1).strip()
            
            self.console.print("\n[bold yellow]❓ AI needs more information:[/bold yellow]")
            self.console.print(f"\n[cyan]{question}[/cyan]\n")
            
            self.session_memory['pending_info'] = question
            self.session_memory['original_request'] = user_input
            
            self.update_session_memory(f"Asked user: {question}", is_complete=False)
            
            return
        
        explanation_parts = re.split(r'<action>.*?</action>', response, flags=re.DOTALL)
        full_explanation = ''.join(explanation_parts).strip()
        
        if full_explanation:
            self.console.print("\n[bold cyan]AI:[/bold cyan]")
            md = Markdown(full_explanation)
            self.console.print(md)
        
        actions = self.parse_ai_response(response)
        
        if actions:
            self.console.print(f"\n[yellow]📋 Executing {len(actions)} step(s)...[/yellow]\n")
            
            action_results = []
            for i, action in enumerate(actions, 1):
                self.console.print(f"[bold cyan]→ Step {i}/{len(actions)}:[/bold cyan]")
                result = self.execute_action(action)
                action_results.append(result)
                
                step_desc = f"Executed: {action.get('command', action.get('type', 'unknown'))}"
                is_last_step = (i == len(actions))
                self.update_session_memory(step_desc, is_complete=is_last_step)
        
        self.conversation_context.append({
            'user': user_input,
            'ai': full_explanation,
            'actions': actions if actions else [],
            'type': 'task'
        })
    
    def show_welcome(self):
        """Show welcome message"""
        welcome = """
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║          🤖 Autonomous AI Assistant - FreeLLM Enhanced         ║
║                                                                ║
║  I understand natural language and can:                        ║
║  • Write and execute code                                      ║
║  • Create files with AI-generated content                      ║
║  • Read and display files with syntax highlighting             ║
║  • Intelligently edit existing files (no full rewrites!)       ║
║  • Manage files and directories                                ║
║  • Execute system commands                                     ║
║  • Analyze logs and data                                       ║
║  • Monitor system resources                                    ║
║                                                                ║
║  Just tell me what you want in plain English!                  ║
║                                                                ║
║  File Operation Examples:                                      ║
║  • "create a login page in HTML"                               ║
║  • "modify index.html and add a navigation bar"                ║
║  • "edit config.py and change the database settings"           ║
║  • "show me the contents of app.js"                            ║
║  • "create a Python script that sorts files by size"           ║
║                                                                ║
║  Other Examples:                                               ║
║  • "show me what's using the most CPU"                         ║
║  • "find all python files modified today"                      ║
║  • "analyze the system logs for errors"                        ║
║                                                                ║
║  Type 'exit' or 'quit' to leave                                ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
        """
        self.console.print(welcome, style="cyan bold")
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
                
                if user_input.lower() in ['quit', 'bye'] and not self.is_root:
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
                
                command_indicators = ['ls ', 'cd ', 'pwd', 'cat ', 'grep ', 'ps ', 'top', 
                                     'sudo ', 'apt ', 'nano ', 'vim ', 'mkdir ', 'rm ', 'cp ', 'mv ',
                                     'chmod ', 'chown ', 'ping ', 'nmap ', 'netstat ', 'ss ', 'wget ',
                                     'curl ', 'git ', 'docker ', 'systemctl ', 'service ', 'kill ',
                                     'echo ', 'touch ', 'head ', 'tail ', 'less ', 'more ', 'python ',
                                     'whoami', 'id', 'date', 'uptime', 'free', 'df', 'du']
                
                is_direct_command = (
                    any(user_input.startswith(cmd) or user_input == cmd.strip() for cmd in command_indicators) or
                    user_input.startswith('./') or
                    user_input.startswith('/')
                )
                
                if is_direct_command:
                    action = {'type': 'command', 'command': user_input}
                    self.execute_action(action)
                else:
                    input_type = self.is_command_or_chat(user_input)
                    
                    if input_type == 'chat':
                        self.handle_chat(user_input)
                    else:
                        self.think_and_act(user_input)
                
                print()
                
            except KeyboardInterrupt:
                self.console.print("\n\n[yellow]Use 'exit' or 'quit' to leave[/yellow]\n")
                continue
            except EOFError:
                break
            except Exception as e:
                self.console.print(f"\n[red]Error: {e}[/red]\n")

def main():
    try:
        ai = AutonomousAI()
        ai.run()
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
