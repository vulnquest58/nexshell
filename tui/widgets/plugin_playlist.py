"""
Plugin Playlist Widget — Checkbox list with smart Run button.
Validates connection/TTY requirements before enabling execution.
"""

import os
import importlib
from textual.widget import Widget
from textual.widgets import ListView, ListItem, Checkbox, Label, Static, Button
from textual.containers import Vertical, Horizontal
from textual.reactive import reactive
from textual.message import Message


# Plugins that DON'T need an active shell
_NO_CONN_REQUIRED = {
    "smart_tty_upgrade",
    "reverse_shell_generator",
    "command_queue",
    "cloud_integration",
}

# Plugins that need a TTY-upgraded shell
_TTY_REQUIRED = {
    "file_transfer_engine",
    "local_file_sharer",
    "port_sniffer",
}

_PLUGIN_COMMANDS = {
    "smart_tty_upgrade":       "plugins run smart-tty-upgrade --stage python",
    "file_transfer_engine":    "plugins run file-transfer-engine --detect",
    "persistence_engine":      "plugins run persistence-engine --list",
    "local_file_sharer":       "plugins run local-file-sharer --linux",
    "port_sniffer":            "plugins run port-sniffer --scan",
    "reverse_shell_generator": "plugins run reverse-shell-gen --list",
    "command_queue":           "plugins run command-queue --list",
    "cloud_integration":       "plugins run cloud-integration --test",
}


class PluginPlaylist(Widget):
    """Plugin playlist with condition-aware Run button."""

    DEFAULT_CSS = """
    PluginPlaylist {
        height: 1fr;
        border: solid #58a6ff;
        padding: 1;
        background: #161b22;
    }
    """

    connection_active = reactive(False)
    tty_upgraded      = reactive(False)

    class PluginExecute(Message):
        def __init__(self, plugin_name: str, command: str):
            self.plugin_name = plugin_name
            self.command     = command
            super().__init__()

    class PluginChainExecute(Message):
        def __init__(self, plugin_names: list):
            self.plugin_names = plugin_names
            super().__init__()

    def __init__(self, plugins_dir: str = "plugins",
                 plugin_executor=None, **kwargs):
        super().__init__(**kwargs)
        self.plugins_dir     = plugins_dir
        self.plugin_executor = plugin_executor
        self._selected: list = []

    def compose(self):
        with Vertical():
            yield Static("🔌 Plugin Playlist", id="playlist-title")
            with Horizontal(id="btn-row"):
                yield Button("▶ Run Selected", id="run-btn", variant="success")
                yield Button("⟳ Refresh",      id="refresh-btn")
            yield ListView(id="plugin-list")

    def on_mount(self):
        self._load_plugins()
        self._update_btn()

    # ── Event handlers ────────────────────────────────────────────────────

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "run-btn":
            self._run_selected()
        elif event.button.id == "refresh-btn":
            self._load_plugins()

    def on_checkbox_changed(self, event: Checkbox.Changed):
        name = str(event.checkbox.label)
        if event.value:
            if name not in self._selected:
                self._selected.append(name)
        else:
            if name in self._selected:
                self._selected.remove(name)
        self._update_btn()

    def watch_connection_active(self, _):
        self._update_btn()

    def watch_tty_upgraded(self, _):
        self._update_btn()

    # ── Logic ─────────────────────────────────────────────────────────────

    def _update_btn(self):
        try:
            btn = self.query_one("#run-btn", Button)
        except Exception:
            return

        if not self._selected:
            btn.disabled = True
            btn.label    = "▶ Select Plugin First"
            return

        needs_conn = any(p not in _NO_CONN_REQUIRED for p in self._selected)
        if needs_conn and not self.connection_active:
            btn.disabled = True
            btn.label    = "⚠ No Connection"
            return

        needs_tty = any(p in _TTY_REQUIRED for p in self._selected)
        if needs_tty and not self.tty_upgraded:
            btn.disabled = True
            btn.label    = "⚠ TTY Not Upgraded"
            return

        btn.disabled = False
        btn.label    = f"▶ Run ({len(self._selected)})"

    def _run_selected(self):
        if not self._selected:
            return
        if len(self._selected) == 1:
            name = self._selected[0]
            cmd  = _PLUGIN_COMMANDS.get(name, f"plugins run {name}")
            self.post_message(self.PluginExecute(name, cmd))
        else:
            self.post_message(self.PluginChainExecute(list(self._selected)))

    def _load_plugins(self):
        try:
            lv = self.query_one("#plugin-list", ListView)
            lv.clear()
        except Exception:
            return

        self._selected = []
        plugins_path   = self.plugins_dir

        if not os.path.isabs(plugins_path):
            root = os.path.dirname(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            )
            plugins_path = os.path.join(root, self.plugins_dir)

        if not os.path.exists(plugins_path):
            return

        for fname in sorted(os.listdir(plugins_path)):
            if not fname.endswith(".py") or fname.startswith("_"):
                continue
            pname = fname[:-3]
            try:
                mod = importlib.import_module(f"plugins.{pname}")
                # Find the plugin class
                cls = next(
                    (
                        getattr(mod, a)
                        for a in dir(mod)
                        if isinstance(getattr(mod, a), type)
                        and hasattr(getattr(mod, a), "name")
                        and getattr(mod, a).__module__ == mod.__name__
                    ),
                    None,
                )
                ver   = getattr(cls, "version", "?") if cls else "?"
                label = f"{pname}  v{ver}"
                lv.append(ListItem(Checkbox(label, id=f"cb-{pname}")))
            except Exception:
                # Still show it, just mark as not loaded
                lv.append(ListItem(Checkbox(f"{pname}  [err]", id=f"cb-{pname}")))

    # ── Public setters ────────────────────────────────────────────────────

    def set_connection_status(self, active: bool):
        self.connection_active = active

    def set_tty_status(self, upgraded: bool):
        self.tty_upgraded = upgraded

    def get_selected(self) -> list:
        return list(self._selected)
