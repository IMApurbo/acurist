#!/usr/bin/env python3
"""
Autonomous AI Assistant - Powered by FreeLLM
An intelligent assistant that understands natural language and autonomously executes tasks
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
        self.current_files = {}
        self.current_user = os.getenv('USER', 'user')
        self.is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
        
        # Session memory - AI's running summary of what it's doing
        self.session_memory = {
            'current_task': None,
            'completed_steps': [],
            'next_steps': [],
            'context_summary': '',
            'pending_info': None,  # Information AI is waiting for
            'original_request': None  # Original user request before asking question
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
        # Fix commands with no space after command name
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
            
            # Update prompt style
            self.prompt_style = Style.from_dict({
                'username': '#ff0000 bold' if self.is_root else '#00aaff bold',
                'symbol': '#ffaa00 bold',
                'path': '#00ff00',
            })
        except:
            pass
    
    def execute_command(self, command):
        """Execute shell command with live output in bordered panel"""
        # Fix spacing issues
        command = self.fix_command_spacing(command)
        
        # Handle cd command specially
        if command.strip().startswith('cd '):
            path = command.strip()[3:].strip()
            return self.change_directory(path)
        
        # Handle sudo su or su commands (permission switch)
        if command.strip() in ['sudo su', 'su', 'sudo -i', 'sudo -s']:
            return self.switch_to_root()
        
        if command.strip() == 'exit' and self.is_root:
            return self.exit_root()
        
        # Detect commands that open GUI tools or browsers (run in background)
        gui_commands = ['firefox', 'chromium', 'google-chrome', 'mousepad', 'gedit', 'code', 'gimp', 
                       'libreoffice', 'vlc', 'evince', 'xdg-open', 'gnome-open']
        
        is_gui_command = any(command.strip().startswith(cmd) for cmd in gui_commands)
        
        if is_gui_command:
            # Run GUI commands in background and return immediately
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
        
        # Commands that typically run indefinitely
        infinite_commands = ['ping', 'top', 'htop', 'tail -f', 'watch', 'tcpdump', 'wireshark']
        needs_ctrl_c = any(cmd in command for cmd in infinite_commands)
        
        # Add verbose flags if supported
        verbose_commands = {
            'nmap': '-v',
            'curl': '-v',
            'wget': '-v',
            'rsync': '-v',
            'apt': '-V',
            'pip': '-v'
        }
        
        # Add verbose flag if command supports it
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
            
            # For simple fast commands, just run directly
            simple_commands = ['ls', 'pwd', 'whoami', 'id', 'date', 'echo']
            is_simple = any(command.strip().startswith(cmd) for cmd in simple_commands)
            
            if is_simple:
                # Run simple commands without fancy UI
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
                
                # Show output directly
                if stdout:
                    self.console.print(stdout.rstrip())
                if stderr and returncode != 0:
                    self.console.print(f"[red]{stderr.rstrip()}[/red]")
                
                stdout_lines = stdout.split('\n') if stdout else []
                stderr_lines = stderr.split('\n') if stderr else []
                
                # Only show AI analysis, no summary
                if returncode == 0 and stdout:
                    self.show_ai_analysis_only(command, stdout_lines, elapsed)
                
                return {
                    'stdout': stdout,
                    'stderr': stderr,
                    'returncode': returncode,
                    'success': returncode == 0
                }
            
            # For longer commands, show live output
            output_lines = []
            
            # Start process
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
            
            # Create a simple progress indicator
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
                        
                        # Check if process is done
                        if process.poll() is not None:
                            # Read remaining output
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
                    # User pressed Ctrl+C
                    user_interrupted = True
                    self.console.print("\n\n[yellow]⏸️  Interrupted by user[/yellow]")
                    
                    # Terminate the process
                    try:
                        if hasattr(os, 'killpg'):
                            os.killpg(os.getpgid(process.pid), subprocess.signal.SIGTERM)
                        else:
                            process.terminate()
                        
                        time.sleep(0.5)
                        
                        if process.poll() is None:
                            process.kill()
                        
                        # Read any remaining output
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
            
            # Only show AI analysis
            if (returncode == 0 or user_interrupted) and stdout_lines:
                ai_summary = self.show_ai_analysis_only(command, stdout_lines, elapsed, user_interrupted)
                
                # Check if command was a redirect to file (contains >)
                if '>' in command and ai_summary:
                    # Extract filename
                    parts = command.split('>')
                    if len(parts) > 1:
                        filename = parts[-1].strip().split()[0]
                        try:
                            # Append AI summary to the file
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
                # Command failed - try to fix and retry
                self.console.print("\n[yellow]⚠️  Command failed. Attempting to fix and retry...[/yellow]")
                
                # Ask AI to fix the command
                fix_prompt = f"""The command failed with this error:
Command: {command}
Error: {''.join(stderr_lines[:5])}

Provide ONLY the corrected command, nothing else."""

                try:
                    with self.console.status("[cyan]AI is fixing the command...", spinner="dots"):
                        fixed_cmd = self.bot.ask(fix_prompt).strip()
                        # Clean up any markdown or quotes
                        fixed_cmd = fixed_cmd.strip('`').strip('"').strip("'")
                        if fixed_cmd.startswith('bash') or fixed_cmd.startswith('sh'):
                            fixed_cmd = ' '.join(fixed_cmd.split()[1:])
                    
                    self.console.print(f"\n[cyan]Retrying with:[/cyan] {fixed_cmd}\n")
                    
                    # Retry with fixed command
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
                # Prepare output for AI
                full_output = ''.join(stdout_lines)
                
                # Limit output size for AI
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
                
                # Return plain text for file writing
                return analysis
        except Exception as e:
            self.console.print(f"\n[dim yellow]Could not generate AI analysis: {e}[/dim yellow]\n")
            return None
        
        if is_gui_command:
            # Run GUI commands in background and return immediately
            try:
                subprocess.Popen(
                    command + ' &',
                    shell=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    cwd=self.workspace
                )
                self.console.print(f"\n[green]✓ Launched:[/green] {command}")
                self.console.print("[dim]Application opened in background[/dim]")
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
        
        # Commands that typically run indefinitely
        infinite_commands = ['ping', 'top', 'htop', 'tail -f', 'watch', 'tcpdump', 'wireshark']
        needs_ctrl_c = any(cmd in command for cmd in infinite_commands)
        
        # Add verbose flags if supported
        verbose_commands = {
            'nmap': '-v',
            'curl': '-v',
            'wget': '-v',
            'rsync': '-v',
            'apt': '-V',
            'pip': '-v'
        }
        
        # Add verbose flag if command supports it
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
            
            # Create layout
            layout = Layout()
            layout.split_column(
                Layout(name="output", ratio=8),
                Layout(name="status", size=3)
            )
            
            output_lines = []
            stdout_lines = []
            stderr_lines = []
            start_time = time.time()
            user_interrupted = False
            
            # Start process
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
                self.console.print(f"\n[yellow]ℹ️  This command runs continuously. Press Ctrl+C to stop and see summary.[/yellow]\n")
            
            try:
                with Live(layout, refresh_per_second=4, console=self.console) as live:
                    import select
                    
                    while True:
                        reads = [process.stdout.fileno(), process.stderr.fileno()]
                        ret = select.select(reads, [], [], 0.1)
                        
                        for fd in ret[0]:
                            if fd == process.stdout.fileno():
                                line = process.stdout.readline()
                                if line:
                                    stdout_lines.append(line)
                                    output_lines.append(('stdout', line.rstrip()))
                            
                            if fd == process.stderr.fileno():
                                line = process.stderr.readline()
                                if line:
                                    stderr_lines.append(line)
                                    output_lines.append(('stderr', line.rstrip()))
                        
                        # Check if process is done
                        if process.poll() is not None:
                            # Read remaining output
                            remaining_stdout = process.stdout.read()
                            remaining_stderr = process.stderr.read()
                            
                            if remaining_stdout:
                                for line in remaining_stdout.split('\n'):
                                    if line:
                                        stdout_lines.append(line + '\n')
                                        output_lines.append(('stdout', line))
                            
                            if remaining_stderr:
                                for line in remaining_stderr.split('\n'):
                                    if line:
                                        stderr_lines.append(line + '\n')
                                        output_lines.append(('stderr', line))
                            
                            break
                        
                        # Update output panel
                        output_text = Text()
                        # Show last 30 lines
                        for line_type, line_content in output_lines[-30:]:
                            if line_type == 'stdout':
                                output_text.append(line_content + '\n', style="green")
                            else:
                                output_text.append(line_content + '\n', style="yellow")
                        
                        layout["output"].update(
                            Panel(
                                output_text,
                                title=f"[bold cyan]Command: {command[:50]}...[/bold cyan]" if len(command) > 50 else f"[bold cyan]Command: {command}[/bold cyan]",
                                border_style="cyan"
                            )
                        )
                        
                        # Update status panel with spinner
                        elapsed = time.time() - start_time
                        status_table = Table.grid(padding=(0, 2))
                        status_table.add_column(style="cyan", justify="left")
                        status_table.add_column(style="magenta", justify="right")
                        
                        status_info = "🔄 Running..." if not needs_ctrl_c else "🔄 Running (Ctrl+C to stop)..."
                        status_table.add_row(
                            f"{status_info} {Spinner('dots', style='cyan').render(time.time())}",
                            f"⏱️  Elapsed: {elapsed:.1f}s"
                        )
                        status_table.add_row(
                            f"📊 Lines: {len(output_lines)}",
                            f"💾 Working Dir: {self.workspace.name}"
                        )
                        
                        layout["status"].update(
                            Panel(status_table, border_style="green")
                        )
            
            except KeyboardInterrupt:
                # User pressed Ctrl+C
                user_interrupted = True
                self.console.print("\n\n[yellow]⏸️  Interrupted by user (Ctrl+C)[/yellow]")
                
                # Terminate the process
                try:
                    if hasattr(os, 'killpg'):
                        os.killpg(os.getpgid(process.pid), subprocess.signal.SIGTERM)
                    else:
                        process.terminate()
                    
                    # Wait a bit for graceful termination
                    time.sleep(0.5)
                    
                    # Force kill if still running
                    if process.poll() is None:
                        process.kill()
                    
                    # Read any remaining output
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
                    self.console.print(f"[dim]Note: {e}[/dim]")
            
            returncode = process.poll() if process.poll() is not None else -1
            elapsed = time.time() - start_time
            
            # Show final summary
            self.show_command_summary(command, returncode, stdout_lines, stderr_lines, elapsed, user_interrupted)
            
            return {
                'stdout': ''.join(stdout_lines),
                'stderr': ''.join(stderr_lines),
                'returncode': returncode,
                'success': returncode == 0 or user_interrupted
            }
            
        except Exception as e:
            self.console.print(f"[red]Error executing command: {e}[/red]")
            import traceback
            traceback.print_exc()
            return {
                'stdout': '',
                'stderr': str(e),
                'returncode': -1,
                'success': False
            }
    
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
        
        # Get original user
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
    
    def show_command_summary(self, command, returncode, stdout_lines, stderr_lines, elapsed, user_interrupted=False):
        """This method is no longer used - keeping for compatibility"""
        pass
    
    def read_file(self, filepath):
        """Read file content"""
        try:
            path = Path(filepath)
            if not path.is_absolute():
                path = self.workspace / path
            
            with open(path, 'r') as f:
                content = f.read()
            return content, None
        except Exception as e:
            return None, str(e)
    
    def write_file(self, filepath, content):
        """Write content to file"""
        try:
            path = Path(filepath)
            if not path.is_absolute():
                path = self.workspace / path
            
            path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(path, 'w') as f:
                f.write(content)
            return True, None
        except Exception as e:
            return False, str(e)
    
    def get_system_context(self):
        """Get current system context"""
        context = {
            'workspace': str(self.workspace),
            'files_in_workspace': [],
            'system_info': {}
        }
        
        # List files in workspace
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
        
        # System info
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
        
        # Look for <action> tags in response
        action_pattern = r'<action>(.*?)</action>'
        matches = re.findall(action_pattern, response, re.DOTALL)
        
        for match in matches:
            try:
                action_data = json.loads(match.strip())
                actions.append(action_data)
            except:
                # Try to parse as individual lines
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
                self.console.print(f"\n[cyan]Reading file:[/cyan] {filepath}")
                content, error = self.read_file(filepath)
                
                if error:
                    self.console.print(f"[red]✗ Error: {error}[/red]")
                    return {'success': False, 'error': error}
                else:
                    self.current_files[filepath] = content
                    self.console.print(f"[green]✓ File loaded ({len(content)} bytes)[/green]")
                    
                    # Show preview
                    if len(content) < 500:
                        syntax = Syntax(content, "python", theme="monokai")
                        self.console.print(syntax)
                    
                    return {'success': True, 'content': content}
            
            elif action_type == 'write_file':
                filepath = action.get('path')
                content = action.get('content')
                self.console.print(f"\n[cyan]Writing file:[/cyan] {filepath}")
                success, error = self.write_file(filepath, content)
                
                if error:
                    self.console.print(f"[red]✗ Error: {error}[/red]")
                    return {'success': False, 'error': error}
                else:
                    self.console.print("[green]✓ File saved[/green]")
                    
                    # Show the code
                    syntax = Syntax(content, "python", theme="monokai", line_numbers=True)
                    self.console.print(Panel(syntax, title=filepath))
                    
                    return {'success': True}
            
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
TASK = user wants you to DO something (run commands, create files, analyze data, etc.)

Examples:
"hi" -> CHAT
"how are you?" -> CHAT
"what can you do" -> CHAT
"thanks" -> CHAT
"find python files" -> TASK
"show disk usage" -> TASK
"create a script" -> TASK

Respond with ONLY: CHAT or TASK"""

        try:
            response = self.bot.ask(classification_prompt).strip().upper()
            
            if 'CHAT' in response:
                return 'chat'
            else:
                return 'task'
        except:
            # Default to chat for very short inputs, task otherwise
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
            
            # Parse response
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
            pass  # Silent fail - memory is optional
    
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
        
        # Check if AI was waiting for information
        if self.session_memory['pending_info']:
            # AI was waiting for answer, now continue with original task
            self.console.print(f"\n[green]✓ Got it! Continuing with the task...[/green]\n")
            
            # Store the answer
            user_answer = user_input
            original_request = self.session_memory['original_request']
            question_asked = self.session_memory['pending_info']
            
            # Clear pending state BEFORE processing
            self.session_memory['pending_info'] = None
            self.session_memory['original_request'] = None
            
            # Get system context
            context = self.get_system_context()
            memory_context = self.get_memory_context()
            
            # Create focused prompt with the provided information
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

IMPORTANT:
- Do NOT ask any more questions
- Use the information provided: {user_answer}
- Output <action> tags to complete the task
- Use proper spacing in all commands

Execute now:"""

            with self.console.status("[bold cyan]Processing...", spinner="dots"):
                try:
                    response = self.bot.ask(execute_prompt)
                except Exception as e:
                    self.console.print(f"[red]AI Error: {e}[/red]")
                    return
            
            # Parse and execute actions directly
            actions = self.parse_ai_response(response)
            
            if not actions:
                self.console.print("[yellow]No actions generated. Let me try a different approach...[/yellow]\n")
                
                # Fallback: Generate command directly
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
            
            # Execute the actions
            self.console.print(f"\n[yellow]📋 Executing {len(actions)} step(s)...[/yellow]\n")
            
            for i, action in enumerate(actions, 1):
                self.console.print(f"[bold cyan]→ Step {i}/{len(actions)}:[/bold cyan]")
                result = self.execute_action(action)
                
                step_desc = f"Executed: {action.get('command', action.get('type', 'unknown'))}"
                is_last_step = (i == len(actions))
                self.update_session_memory(step_desc, is_complete=is_last_step)
            
            return
        
        # Get system context
        context = self.get_system_context()
        
        # Get memory context
        memory_context = self.get_memory_context()
        
        # Build conversation context
        recent_context = self.conversation_context[-3:] if len(self.conversation_context) > 3 else self.conversation_context
        context_str = "\n".join([f"User: {c['user']}\nAI: {c.get('ai', '')}" for c in recent_context])
        
        # Create the thinking prompt
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

2. Read files:
<action>{{"type": "read_file", "path": "example.py"}}</action>

3. Write/create files:
<action>{{"type": "write_file", "path": "example.py", "content": "print('hello')"}}</action>

4. Analyze system:
<action>{{"type": "analyze", "target": "system"}}</action>

5. ASK FOR CLARIFICATION (if info is missing):
<question>What is the target IP address you want to scan?</question>

USER REQUEST: {user_input}

CRITICAL: Analyze the request carefully!

Step 1: Does the request have ALL required information?

Requests MISSING information (YOU MUST ASK):
- "scan the server" → MISSING: Which server? What IP?
- "scan for open ports" → MISSING: What target?
- "backup the files" → MISSING: Which files?
- "connect to database" → MISSING: Connection details?
- "download the file" → MISSING: Which file? From where?

Requests WITH complete information (EXECUTE):
- "scan 192.168.1.1 for open ports" → Has IP → Execute
- "scan localhost" or "scan 127.0.0.1" → Has target → Execute
- "list files in current directory" → Complete → Execute
- "check disk usage" → Complete → Execute

Step 2: Decision Rules:
- If the request mentions "the server", "the database", "the file" without specifying WHICH ONE → ASK
- If scanning/connecting but NO IP/hostname/target specified → ASK
- If backing up but NO path specified → ASK
- If downloading but NO URL/path specified → ASK

Step 3: Output Decision:
- Missing info? → Output ONLY <question>...</question> (NO actions!)
- Have all info? → Output <action>...</action> tags

ANALYZE THE REQUEST: "{user_input}"

Does it have all required information to execute? If NO, ask a question. If YES, execute actions."""

        # Show thinking animation
        with self.console.status("[bold cyan]Thinking...", spinner="dots"):
            try:
                response = self.bot.ask(system_prompt)
            except Exception as e:
                self.console.print(f"[red]AI Error: {e}[/red]")
                return
        
        # Check if AI is asking a question
        question_match = re.search(r'<question>(.*?)</question>', response, re.DOTALL)
        
        if question_match:
            question = question_match.group(1).strip()
            
            # AI needs more information - enter waiting mode
            self.console.print("\n[bold yellow]❓ AI needs more information:[/bold yellow]")
            self.console.print(f"\n[cyan]{question}[/cyan]\n")
            
            # Store state
            self.session_memory['pending_info'] = question
            self.session_memory['original_request'] = user_input
            
            # Update memory
            self.update_session_memory(f"Asked user: {question}", is_complete=False)
            
            return  # Wait for user response
        
        # Display AI's explanation (non-action parts)
        explanation_parts = re.split(r'<action>.*?</action>', response, flags=re.DOTALL)
        full_explanation = ''.join(explanation_parts).strip()
        
        if full_explanation:
            self.console.print("\n[bold cyan]AI:[/bold cyan]")
            md = Markdown(full_explanation)
            self.console.print(md)
        
        # Parse and execute actions
        actions = self.parse_ai_response(response)
        
        if actions:
            self.console.print(f"\n[yellow]📋 Executing {len(actions)} step(s)...[/yellow]\n")
            
            action_results = []
            for i, action in enumerate(actions, 1):
                self.console.print(f"[bold cyan]→ Step {i}/{len(actions)}:[/bold cyan]")
                result = self.execute_action(action)
                action_results.append(result)
                
                # Update memory after each step
                step_desc = f"Executed: {action.get('command', action.get('type', 'unknown'))}"
                is_last_step = (i == len(actions))
                self.update_session_memory(step_desc, is_complete=is_last_step)
        
        # Add to conversation history
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
║          🤖 Autonomous AI Assistant - FreeLLM                  ║
║                                                                ║
║  I understand natural language and can:                        ║
║  • Write and execute code                                      ║
║  • Manage files and directories                                ║
║  • Execute system commands                                     ║
║  • Analyze logs and data                                       ║
║  • Monitor system resources                                    ║
║  • And much more...                                            ║
║                                                                ║
║  Just tell me what you want in plain English!                  ║
║                                                                ║
║  Examples:                                                     ║
║  • "create a python script that sorts files by size"           ║
║  • "show me what's using the most CPU"                         ║
║  • "find all python files modified today"                      ║
║  • "analyze the system logs for errors"                        ║
║  • "write a web scraper for news articles"                     ║
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
                # Get user input with dynamic prompt
                user_input = self.session.prompt(
                    self.get_prompt(),
                    style=self.prompt_style
                ).strip()
                
                if not user_input:
                    continue
                
                # Check for exit
                if user_input.lower() in ['quit', 'bye'] and not self.is_root:
                    self.console.print("\n[cyan]Goodbye! 👋[/cyan]\n")
                    break
                
                # If user types 'exit' and is root, drop privileges
                if user_input.lower() == 'exit' and self.is_root:
                    self.exit_root()
                    continue
                
                # Check for special commands
                if user_input.lower() == 'clear':
                    os.system('clear' if os.name != 'nt' else 'cls')
                    self.show_welcome()
                    continue
                
                if user_input.lower() == 'help':
                    self.show_welcome()
                    continue
                
                # Check if user is directly typing commands (starts with specific commands or contains |, &&, etc)
                command_indicators = ['ls ', 'cd ', 'pwd', 'cat ', 'grep ', 'ps ', 'top', 
                                     'sudo ', 'apt ', 'nano ', 'vim ', 'mkdir ', 'rm ', 'cp ', 'mv ',
                                     'chmod ', 'chown ', 'ping ', 'nmap ', 'netstat ', 'ss ', 'wget ',
                                     'curl ', 'git ', 'docker ', 'systemctl ', 'service ', 'kill ',
                                     'echo ', 'touch ', 'head ', 'tail ', 'less ', 'more ', 'python ',
                                     'whoami', 'id', 'date', 'uptime', 'free', 'df', 'du']
                
                # Only treat as direct command if it starts exactly with a command (with space or at end)
                is_direct_command = (
                    any(user_input.startswith(cmd) or user_input == cmd.strip() for cmd in command_indicators) or
                    user_input.startswith('./') or
                    user_input.startswith('/')
                )
                
                if is_direct_command:
                    # Execute command directly
                    action = {'type': 'command', 'command': user_input}
                    self.execute_action(action)
                else:
                    # Determine if it's a task or chat
                    input_type = self.is_command_or_chat(user_input)
                    
                    if input_type == 'chat':
                        # Handle as casual conversation
                        self.handle_chat(user_input)
                    else:
                        # Let AI think and act on the task
                        self.think_and_act(user_input)
                
                print()  # Spacing
                
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
