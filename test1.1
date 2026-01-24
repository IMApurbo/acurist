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
        
        # Create history
        history_dir = Path.home() / '.ai_assistant'
        history_dir.mkdir(exist_ok=True)
        self.history_file = history_dir / 'history'
        
        self.session = PromptSession(
            history=FileHistory(str(self.history_file))
        )
        
        self.prompt_style = Style.from_dict({
            'prompt': '#00aa00 bold',
        })
        
    def fix_command_spacing(self, command):
        """Fix common spacing issues in commands"""
        # Fix commands with no space after command name
        patterns = [
            (r'nmap(\d)', r'nmap \1'),
            (r'ping(\d)', r'ping \1'),
            (r'curl(http)', r'curl \1'),
            (r'wget(http)', r'wget \1'),
            (r'ssh(\w)', r'ssh \1'),
            (r'scp(\w)', r'scp \1'),
            (r'cat(\w)', r'cat \1'),
            (r'grep(\w)', r'grep \1'),
            (r'find(\w)', r'find \1'),
            (r'ps(\w)', r'ps \1'),
            (r'kill(\d)', r'kill \1'),
            (r'chmod(\d)', r'chmod \1'),
            (r'chown(\w)', r'chown \1'),
        ]
        
        fixed_command = command
        for pattern, replacement in patterns:
            fixed_command = re.sub(pattern, replacement, fixed_command)
        
        return fixed_command
    
    def execute_command(self, command):
        """Execute shell command with live output in bordered panel"""
        # Fix spacing issues
        command = self.fix_command_spacing(command)
        
        # Handle cd command specially
        if command.strip().startswith('cd '):
            path = command.strip()[3:].strip()
            return self.change_directory(path)
        
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
        """Show a summary of command execution with AI analysis"""
        
        # Create summary table
        summary = Table(title="📋 Command Execution Summary", show_header=True, header_style="bold magenta")
        summary.add_column("Property", style="cyan", width=20)
        summary.add_column("Value", style="green")
        
        # Status
        if user_interrupted:
            status = "⏸️  Interrupted by User"
            status_style = "yellow"
        else:
            status = "✅ Success" if returncode == 0 else f"❌ Failed (Exit Code: {returncode})"
            status_style = "green" if returncode == 0 else "red"
        
        summary.add_row("Command", command[:60] + "..." if len(command) > 60 else command)
        summary.add_row("Status", f"[{status_style}]{status}[/{status_style}]")
        summary.add_row("Execution Time", f"{elapsed:.2f} seconds")
        summary.add_row("Output Lines", str(len(stdout_lines)))
        summary.add_row("Error Lines", str(len(stderr_lines)))
        summary.add_row("Working Directory", str(self.workspace))
        
        # Show summary in a panel
        self.console.print("\n")
        self.console.print(Panel(summary, border_style="magenta", padding=(1, 2)))
        
        # Show errors if any
        if stderr_lines and returncode != 0 and not user_interrupted:
            self.console.print("\n[bold red]Errors:[/bold red]")
            error_text = Text()
            for line in stderr_lines[-10:]:  # Last 10 error lines
                error_text.append(line, style="red")
            self.console.print(Panel(error_text, border_style="red", title="Error Messages"))
        
        # AI Analysis of output
        if (returncode == 0 or user_interrupted) and stdout_lines:
            self.console.print("\n[bold cyan]🤖 AI Analysis:[/bold cyan]")
            
            with self.console.status("[cyan]AI is analyzing the output...", spinner="dots"):
                # Prepare output for AI
                full_output = ''.join(stdout_lines)
                
                # Limit output size for AI
                if len(full_output) > 5000:
                    output_for_ai = full_output[:2500] + "\n...(truncated)...\n" + full_output[-2500:]
                else:
                    output_for_ai = full_output
                
                interrupt_note = "\nNote: This command was interrupted by the user (Ctrl+C) before completion." if user_interrupted else ""
                
                analysis_prompt = f"""Analyze this command output and provide a concise, helpful summary.

Command executed: {command}
Execution time: {elapsed:.2f} seconds{interrupt_note}

Output:
```
{output_for_ai}
```

Please provide:
1. What the command did
2. Key findings or important results
3. Any notable patterns or insights
4. Practical interpretation of the results

Keep your response clear, concise, and focused on what matters most to the user."""

                try:
                    analysis = self.bot.ask(analysis_prompt)
                    md = Markdown(analysis)
                    self.console.print(Panel(md, border_style="cyan", title="🤖 AI Summary", padding=(1, 2)))
                except Exception as e:
                    self.console.print(f"[yellow]Could not generate AI analysis: {e}[/yellow]")
    
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
        
        if action_type == 'command':
            cmd = action.get('command')
            self.console.print(f"\n[bold cyan]Executing Command:[/bold cyan]")
            result = self.execute_command(cmd)
            
            if result['success']:
                self.console.print("\n[green]✓ Command completed successfully[/green]")
            else:
                self.console.print(f"\n[red]✗ Command failed (exit code: {result['returncode']})[/red]")
            
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
    
    def think_and_act(self, user_input):
        """AI thinks about what to do and executes actions"""
        
        # Get system context
        context = self.get_system_context()
        
        # Build conversation context
        recent_context = self.conversation_context[-5:] if len(self.conversation_context) > 5 else self.conversation_context
        context_str = "\n".join([f"User: {c['user']}\nAI: {c['ai']}" for c in recent_context])
        
        # Create the thinking prompt
        system_prompt = f"""You are an autonomous AI assistant with the ability to understand user intent and take actions.

Current Context:
- Workspace: {context['workspace']}
- Files in workspace: {json.dumps(context['files_in_workspace'][:10], indent=2)}
- System: CPU {context['system_info'].get('cpu_percent', 0)}%, Memory {context['system_info'].get('memory_percent', 0)}%

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

USER REQUEST: {user_input}

Think step by step about what the user wants, then:
1. First, explain what you understand and what you'll do
2. Then output the necessary <action> tags to accomplish the task
3. You can output multiple actions in sequence
4. After actions, provide a friendly summary

CRITICAL RULES FOR COMMANDS:
- Always include proper spacing in commands (e.g., "nmap 192.168.0.1" NOT "nmap192.168.0.1")
- Use proper shell syntax with spaces between command and arguments
- Double-check all IP addresses, file paths, and arguments have proper spacing
- For port scanning: "nmap -p- 192.168.0.1" or "nmap 192.168.0.1"
- For file operations: "cat file.txt" NOT "catfile.txt"
- For network: "ping 8.8.8.8" NOT "ping8.8.8.8"

Remember:
- For coding tasks, write the complete code in a file
- For system tasks, use appropriate shell commands with PROPER SPACING
- For analysis, gather information first then explain
- Always be helpful and autonomous"""

        # Show thinking animation
        with self.console.status("[bold cyan]Thinking...", spinner="dots"):
            try:
                response = self.bot.ask(system_prompt)
            except Exception as e:
                self.console.print(f"[red]AI Error: {e}[/red]")
                return
        
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
            self.console.print(f"\n[yellow]Executing {len(actions)} action(s)...[/yellow]")
            
            action_results = []
            for i, action in enumerate(actions, 1):
                self.console.print(f"\n[bold]Action {i}/{len(actions)}:[/bold]")
                result = self.execute_action(action)
                action_results.append(result)
                
            # If there were actions, ask AI to summarize results
            if any(not r.get('success', False) for r in action_results):
                self.console.print("\n[yellow]Some actions failed. AI is analyzing...[/yellow]")
        
        # Add to conversation history
        self.conversation_context.append({
            'user': user_input,
            'ai': full_explanation,
            'actions': actions if actions else []
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
                # Get user input
                user_input = self.session.prompt(
                    HTML('<prompt>You: </prompt>'),
                    style=self.prompt_style
                ).strip()
                
                if not user_input:
                    continue
                
                # Check for exit
                if user_input.lower() in ['exit', 'quit', 'bye']:
                    self.console.print("\n[cyan]Goodbye! 👋[/cyan]\n")
                    break
                
                # Check for special commands
                if user_input.lower() == 'clear':
                    os.system('clear' if os.name != 'nt' else 'cls')
                    self.show_welcome()
                    continue
                
                if user_input.lower() == 'help':
                    self.show_welcome()
                    continue
                
                # Let AI think and act
                self.think_and_act(user_input)
                
                print()  # Spacing
                
            except KeyboardInterrupt:
                self.console.print("\n\n[yellow]Use 'exit' to quit[/yellow]\n")
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
