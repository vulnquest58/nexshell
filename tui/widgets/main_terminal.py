"""
Main Terminal Widget — Provides an interactive terminal within the TUI.
Handles command input, output display, and history navigation.
"""

from textual.widget import Widget
from textual.widgets import Static, Input
from textual.containers import Vertical, Horizontal
from textual.reactive import reactive
from textual.message import Message
from collections import deque
from datetime import datetime
import os


class MainTerminal(Widget):
    """Interactive terminal widget with history and output display."""

    DEFAULT_CSS = """
    MainTerminal {
        height: 1fr;
        width: 1fr;
    }
    """

    class CommandSubmitted(Message):
        def __init__(self, command: str, session_id: str):
            self.command    = command
            self.session_id = session_id
            super().__init__()

    def __init__(self, session_id: str = "tab-1", port: int = 4444, **kwargs):
        super().__init__(**kwargs)
        self.session_id  = session_id
        self.port        = port
        self._history    = deque(maxlen=200)
        self._hist_idx   = -1
        self._output_buf = []

    def compose(self):
        with Vertical():
            yield Static(
                id="terminal-output",
                markup=False,
            )
            with Horizontal(id="terminal-input-row"):
                yield Static(
                    f"[NexShell :{self.port}]$ ",
                    id="terminal-prompt",
                )
                yield Input(
                    placeholder="Enter command...",
                    id="terminal-input",
                )

    def on_mount(self):
        self._banner()
        self.query_one("#terminal-input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted):
        cmd = event.value.strip()
        if not cmd:
            return
        event.input.clear()
        self._history.appendleft(cmd)
        self._hist_idx = -1
        self.write_output(f"[NexShell :{self.port}]$ {cmd}")
        self.post_message(self.CommandSubmitted(cmd, self.session_id))

    def on_key(self, event):
        """Handle history navigation with arrow keys."""
        inp = self.query_one("#terminal-input", Input)
        if event.key == "up":
            if self._hist_idx < len(self._history) - 1:
                self._hist_idx += 1
                inp.value = self._history[self._hist_idx]
                inp.cursor_position = len(inp.value)
        elif event.key == "down":
            if self._hist_idx > 0:
                self._hist_idx -= 1
                inp.value = self._history[self._hist_idx]
                inp.cursor_position = len(inp.value)
            elif self._hist_idx == 0:
                self._hist_idx = -1
                inp.value = ""

    def write_output(self, text: str):
        """Append text to terminal output."""
        self._output_buf.append(text)
        # Keep last 500 lines
        if len(self._output_buf) > 500:
            self._output_buf = self._output_buf[-500:]
        output_widget = self.query_one("#terminal-output", Static)
        output_widget.update("\n".join(self._output_buf))
        # Scroll to bottom
        try:
            output_widget.scroll_end(animate=False)
        except Exception:
            pass

    def execute_command(self, command: str):
        """Write command to input field and submit."""
        inp = self.query_one("#terminal-input", Input)
        inp.value = command
        self.on_input_submitted(Input.Submitted(inp, command))

    def clear(self):
        self._output_buf.clear()
        self.query_one("#terminal-output", Static).update("")

    def _banner(self):
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        self.write_output(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        self.write_output(f"  NexShell TUI v2.0 — Session: {self.session_id}")
        self.write_output(f"  Listening on port: {self.port}  |  {ts}")
        self.write_output(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        self.write_output(f"  Type 'help' for NexShell commands.")
        self.write_output(f"  Ctrl+T: New Tab  |  Ctrl+W: Close Tab")
        self.write_output("")
