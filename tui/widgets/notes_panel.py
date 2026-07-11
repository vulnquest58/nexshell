"""
Notes Panel Widget — Persistent sticky notes for operation context.
"""

from textual.widget import Widget
from textual.widgets import Static, TextArea
from textual.containers import Vertical


class NotesPanel(Widget):
    """Quick-notes panel stored in memory during session."""

    DEFAULT_CSS = """
    NotesPanel {
        height: 1fr;
        border: solid #8b949e;
        padding: 1;
        background: #161b22;
    }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._notes = ""

    def compose(self):
        with Vertical():
            yield Static("📝 Operation Notes", id="notes-title")
            yield TextArea(
                id="notes-area",
                language=None,
                theme="monokai",
            )

    def on_mount(self):
        self._load_default_hints()

    def _load_default_hints(self):
        hints = (
            "# Operation Notes\n"
            "# ─────────────────────────────────────────\n"
            "Target    : \n"
            "Scope     : \n"
            "LHOST     : \n"
            "LPORT     : \n"
            "TTY       : [ ] upgraded\n"
            "Persist   : [ ] installed\n"
            "Creds     : \n"
            "Flags     : \n"
            "# ─────────────────────────────────────────\n"
        )
        try:
            ta = self.query_one("#notes-area", TextArea)
            ta.load_text(hints)
        except Exception:
            pass

    def get_notes(self) -> str:
        try:
            return self.query_one("#notes-area", TextArea).text
        except Exception:
            return ""
