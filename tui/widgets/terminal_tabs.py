"""
Terminal Tabs Widget — Multi-tab terminal with per-tab port allocation.
"""

from textual.widget import Widget
from textual.widgets import TabbedContent, TabPane, Button, Static
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.message import Message
from typing import Dict, Optional

from tui.widgets.main_terminal import MainTerminal


class TerminalTabs(Widget):
    """Multi-tab terminal interface — each tab gets its own port."""

    DEFAULT_CSS = """
    TerminalTabs {
        width: 1fr;
        height: 1fr;
    }
    #tab-header {
        height: 3;
        background: #161b22;
        padding: 0 1;
        border-bottom: solid #30363d;
    }
    #tab-header-title {
        width: 1fr;
        content-align: left middle;
        color: #58a6ff;
        text-style: bold;
    }
    #new-tab-btn {
        width: auto;
        min-width: 14;
        background: #21262d;
        border: solid #30363d;
        color: #3fb950;
    }
    #new-tab-btn:hover {
        background: #30363d;
        border: solid #58a6ff;
    }
    """

    active_tab = reactive("")
    tab_count  = reactive(0)

    class TabCreated(Message):
        def __init__(self, tab_id: str, port: int):
            self.tab_id = tab_id
            self.port   = port
            super().__init__()

    class TabClosed(Message):
        def __init__(self, tab_id: str):
            self.tab_id = tab_id
            super().__init__()

    class TerminalCommand(Message):
        """Forwarded from child MainTerminal.CommandSubmitted."""
        def __init__(self, command: str, session_id: str):
            self.command    = command
            self.session_id = session_id
            super().__init__()

    def __init__(self, port_allocator, session_manager, **kwargs):
        super().__init__(**kwargs)
        self.port_allocator  = port_allocator
        self.session_manager = session_manager
        self.tabs: Dict[str, MainTerminal] = {}
        self.tab_ports: Dict[str, int]     = {}
        self._tab_counter = 0

    def compose(self):
        with Vertical():
            with Horizontal(id="tab-header"):
                yield Static("🖥  Terminal Sessions", id="tab-header-title")
                yield Button("➕ New Tab", id="new-tab-btn")
            yield TabbedContent(id="terminal-tabs-content")

    def on_mount(self):
        self.create_new_tab()

    # ── Event handlers ────────────────────────────────────────────────────

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "new-tab-btn":
            self.create_new_tab()

    def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated):
        if event.tab:
            self.active_tab = str(event.tab.id)

    def on_main_terminal_command_submitted(self, event: MainTerminal.CommandSubmitted):
        """Bubble terminal commands up to the app."""
        self.post_message(self.TerminalCommand(event.command, event.session_id))

    # ── Tab management ────────────────────────────────────────────────────

    def create_new_tab(self):
        port = self.port_allocator.allocate_session_port()
        if not port:
            return

        self._tab_counter += 1
        tab_id    = f"tab-{self._tab_counter}"
        tab_title = f"Session {self._tab_counter}  :{port}"

        terminal = MainTerminal(
            session_id=tab_id,
            port=port,
            id=f"terminal-{tab_id}",
        )

        tc = self.query_one("#terminal-tabs-content", TabbedContent)
        tc.add_pane(TabPane(tab_title, terminal, id=tab_id))

        self.tabs[tab_id]      = terminal
        self.tab_ports[tab_id] = port
        self.tab_count         = len(self.tabs)

        # Create a session record
        self.session_manager.create_session(
            target_ip="0.0.0.0",
            target_port=0,
            local_port=port,
        )

        self.post_message(self.TabCreated(tab_id, port))
        tc.active = tab_id

    def close_tab(self, tab_id: str):
        if tab_id not in self.tabs:
            return
        port = self.tab_ports.pop(tab_id, None)
        if port:
            self.port_allocator.release_port(port)
        self.tabs.pop(tab_id)
        tc = self.query_one("#terminal-tabs-content", TabbedContent)
        tc.remove_pane(tab_id)
        self.tab_count = len(self.tabs)
        self.post_message(self.TabClosed(tab_id))

    # ── Terminal helpers ──────────────────────────────────────────────────

    def get_active_terminal(self) -> Optional[MainTerminal]:
        return self.tabs.get(self.active_tab)

    def get_terminal(self, tab_id: str) -> Optional[MainTerminal]:
        return self.tabs.get(tab_id)

    def write_to_active(self, text: str):
        t = self.get_active_terminal()
        if t:
            t.write_output(text)

    def execute_in_active(self, command: str):
        t = self.get_active_terminal()
        if t:
            t.execute_command(command)

    def get_tab_count(self) -> int:
        return len(self.tabs)
