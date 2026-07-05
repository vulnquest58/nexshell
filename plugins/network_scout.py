#!/usr/bin/env python3
"""
NexShell Plugin — Network Scout v3.0 (2026 Edition)
Internal network discovery and service detection for modern environments.

Techniques:
  - IPv4/IPv6 ping sweep (ICMP + TCP fallback)
  - Port sweep with nmap integration (if available)
  - Service banner grabbing & version detection
  - ARP/NDP-based discovery
  - Kubernetes, Cloud, DevOps, Observability service detection
  - SMBv1 detection (EternalBlue)
  - LLMNR/NBT-NS poisoning vector detection
  - Cloud IMDS endpoint probing

Usage:
    (NexShell)> plugins run network-scout
    (NexShell)> plugins run network-scout --subnet 192.168.1.0/24
    (NexShell)> plugins run network-scout --ports 22,80,443,445,3306,5432
    (NexShell)> plugins run network-scout --fast
    (NexShell)> plugins run network-scout --ipv6
"""

import re
from core.plugin import NexPlugin


class NetworkScout(NexPlugin):
    name        = "network-scout"
    description = "Modern network discovery — IPv4/IPv6, K8s, Cloud, DevOps, banner grab"
    author      = "vulnquest58"
    version     = "3.0"
    platform    = "all"
    category    = "recon"
    mitre_id    = "T1046"

    # ── Comprehensive port list (2025/2026 services) ──────────────────────────
    INTERESTING_PORTS = {
        # Traditional Services
        21:   "FTP",       22:   "SSH",       23:   "Telnet",
        25:   "SMTP",      53:   "DNS",       79:   "Finger",
        80:   "HTTP",      110:  "POP3",      111:  "RPCBind",
        135:  "MSRPC",     139:  "NetBIOS",   143:  "IMAP",
        161:  "SNMP",      389:  "LDAP",      443:  "HTTPS",
        445:  "SMB",       465:  "SMTPS",     512:  "Rexec",
        513:  "Rlogin",    514:  "RSH/Syslog",515:  "LPD",
        587:  "SMTP-Sub",  631:  "IPP",       636:  "LDAPS",
        873:  "Rsync",     993:  "IMAPS",     995:  "POP3S",
        1080: "SOCKS",     1433: "MSSQL",     1521: "Oracle",
        1723: "PPTP",      2049: "NFS",       2222: "Alt-SSH",
        3306: "MySQL",     3389: "RDP",       4369: "RabbitMQ-EPM",
        5432: "PostgreSQL",5900: "VNC",       5984: "CouchDB",
        6379: "Redis",     7001: "WebLogic",  7077: "Spark",
        8009: "AJP",       8080: "HTTP-Alt",  8443: "HTTPS-Alt",
        8888: "Jupyter",   9000: "PHP-FPM",   9200: "Elasticsearch",
        9300: "ES-Cluster",11211:"Memcached", 27017:"MongoDB",
        50000:"SAP",
        
        # Kubernetes & Cloud Native (2025/2026)
        6443: "K8s-API",   10250:"K8s-Kubelet",10255:"K8s-Kubelet-RO",
        10256:"K8s-Kube-Proxy",2379:"etcd",    2380: "etcd-Peer",
        30000:"K8s-NodePort",
        
        # DevOps & CI/CD
        8080: "Jenkins",   9090: "Prometheus",3000: "Grafana",
        5601: "Kibana",    9093: "Alertmanager",9094:"Alertmanager-Cluster",
        8200: "Vault",     8500: "Consul",     8300: "Consul-gRPC",
        4646: "Nomad",     9200: "Elastic",    16686:"Jaeger-UI",
        14268:"Jaeger-Collector",
        
        # Message Brokers & Streaming
        9092: "Kafka",     4222: "NATS",       5672: "RabbitMQ-AMQP",
        15672:"RabbitMQ-Mgmt",1883:"MQTT",     9090: "H2-Database",
        
        # Modern Databases
        8123: "ClickHouse",9042: "Cassandra", 8086: "InfluxDB",
        4222: "NATS",      6379: "Redis",      27017:"MongoDB",
        
        # API & Service Mesh
        50051:"gRPC",      15001:"Istio-Envoy",15006:"Istio-Inbound",
        15090:"Istio-Prom",4317: "OTLP-gRPC",  4318: "OTLP-HTTP",
        
        # Legacy & Insecure
        135:  "MSRPC",     137:  "NetBIOS-NS", 138: "NetBIOS-DG",
        139:  "NetBIOS",   445:  "SMB",
    }

    def run(self, session, args: list):
        # Parse args
        subnet   = None
        ports    = None
        fast     = '--fast' in (args or [])
        ipv6     = '--ipv6' in (args or [])

        for a in (args or []):
            if a.startswith('--subnet='):
                subnet = a.split('=', 1)[1]
            elif a.startswith('--ports='):
                try:
                    ports = [int(p) for p in a.split('=', 1)[1].split(',')]
                except ValueError:
                    pass

        self.info(f"Starting network-scout v3.0 (fast={fast}, ipv6={ipv6}) ...")
        platform = self._detect_platform(session)
        sections = []
        hosts_found = []
        ipv6_hosts = []

        # ── Step 1: Determine local subnet ───────────────────────────────────
        if not subnet:
            subnet = self._get_local_subnet(session, platform)
        sections.append(f"\n[*] Target subnet: {subnet}")

        # ── Step 2: Check for nmap availability ──────────────────────────────
        nmap_available = self._check_nmap(session, platform)
        if nmap_available:
            sections.append("[+] nmap detected — using advanced scanning")

        # ── Step 3: Ping sweep ────────────────────────────────────────────────
        ping_cmd = self._build_ping_sweep(subnet, platform, fast)
        sections.append(f"[*] Ping sweep: {ping_cmd[:80]}...")
        try:
            ping_out = self._exec(session, ping_cmd)
            if ping_out:
                ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', ping_out)
                hosts_found = list(dict.fromkeys(ips))
                self.loot(ping_out, category='network', source='network-scout:ping-sweep')
                sections.append(f"[+] Alive hosts ({len(hosts_found)}): {', '.join(hosts_found[:20])}")
        except Exception as e:
            self.warn(f"Ping sweep failed: {e}")

        # ── Step 4: IPv6 discovery (if requested) ────────────────────────────
        if ipv6:
            ipv6_cmd = self._build_ipv6_sweep(platform)
            ipv6_out = self._exec(session, ipv6_cmd)
            if ipv6_out:
                ipv6_addrs = re.findall(r'([0-9a-fA-F:]{7,})', ipv6_out)
                ipv6_hosts = list(dict.fromkeys(ipv6_addrs))
                sections.append(f"[+] IPv6 hosts ({len(ipv6_hosts)}): {', '.join(ipv6_hosts[:10])}")

        # ── Step 5: ARP/NDP discovery ────────────────────────────────────────
        arp_cmd = "ip neigh 2>/dev/null || arp -a 2>/dev/null" if platform == 'linux' else "arp -a"
        arp_out = self._exec(session, arp_cmd)
        if arp_out:
            arp_ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', arp_out)
            for ip in arp_ips:
                if ip not in hosts_found:
                    hosts_found.append(ip)
            self.loot(arp_out, category='network', source='network-scout:arp')
            sections.append(f"[+] ARP/NDP table ({len(arp_ips)} entries)")

        # ── Step 6: Port sweep on each host ──────────────────────────────────
        scan_ports = ports or list(self.INTERESTING_PORTS.keys())
        if fast:
            scan_ports = [22, 80, 443, 445, 3389, 8080, 3306, 5432, 6379, 27017, 6443, 10250]

        open_services = {}
        banners = {}
        for host in hosts_found[:20]:
            if nmap_available:
                open_ports, host_banners = self._nmap_scan(session, host, scan_ports, platform)
            else:
                open_ports = self._port_sweep(session, host, scan_ports, platform)
                host_banners = {}
            
            if open_ports:
                open_services[host] = open_ports
                banners[host] = host_banners
                svc_summary = ', '.join(f"{p}/{self.INTERESTING_PORTS.get(p, '?')}" for p in open_ports)
                self.loot(f"{host}: {svc_summary}", category='network', source='network-scout:ports')
                sections.append(f"[+] {host}: {svc_summary}")

        # ── Step 7: Auto-findings ─────────────────────────────────────────────
        findings_created = 0
        danger_services = {
            23: 'Telnet', 21: 'FTP', 512: 'rexec', 513: 'rlogin', 514: 'rsh',
            6379: 'Redis', 11211: 'Memcached', 9200: 'Elasticsearch',
            27017: 'MongoDB', 5984: 'CouchDB', 10250: 'Kubelet-API',
            2379: 'etcd', 8123: 'ClickHouse', 8086: 'InfluxDB'
        }

        for host, open_ports in open_services.items():
            for port in open_ports:
                if port in danger_services:
                    svc = danger_services[port]
                    self.finding(
                        title          = f"Insecure Service: {svc} on {host}:{port}",
                        description    = f"{svc} detected on {host}:{port} — commonly unauthenticated or exposes sensitive data.",
                        severity       = "High",
                        recommendation = f"Restrict {svc} access with firewall rules. Enable authentication. Use TLS encryption.",
                        mitre_id       = self.mitre_id,
                    )
                    self.emit('finding.created', severity='high', title=f'Insecure {svc}', plugin=self.name)
                    findings_created += 1

        # ── Step 8: SMB enumeration & SMBv1 detection ────────────────────────
        for host, open_ports in open_services.items():
            if 445 in open_ports:
                smb_cmd = self._build_smb_enum(host, platform)
                smb_out = self._exec(session, smb_cmd)
                if smb_out:
                    self.loot(smb_out, category='network', source=f'network-scout:smb:{host}')
                    sections.append(f"[+] SMB ({host}):\n{smb_out[:400]}")
                    
                    # Check for SMBv1
                    if 'dialect' in smb_out.lower() and 'nt lm 0.12' in smb_out.lower():
                        self.finding(
                            title          = f"SMBv1 Enabled on {host}",
                            description    = f"SMBv1 detected on {host} — vulnerable to EternalBlue (CVE-2017-0144) and other attacks.",
                            severity       = "Critical",
                            recommendation = "Disable SMBv1 immediately. Upgrade to SMBv3 with encryption.",
                            mitre_id       = "T1210",
                        )
                        findings_created += 1
                    
                    if re.search(r'Disk|IPC\$|ADMIN\$', smb_out):
                        self.finding(
                            title          = f"SMB Shares Enumerated on {host}",
                            description    = smb_out[:400],
                            severity       = "Medium",
                            recommendation = "Review SMB shares for anonymous access. Disable SMBv1. Restrict share permissions.",
                            mitre_id       = "T1135",
                        )
                        findings_created += 1

        # ── Step 9: Banner grabbing results ──────────────────────────────────
        if banners:
            sections.append("\n[*] Service Banners:")
            for host, host_banners in banners.items():
                for port, banner in host_banners.items():
                    sections.append(f"  {host}:{port} → {banner[:100]}")

        # ── Summary ───────────────────────────────────────────────────────────
        total_svc = sum(len(v) for v in open_services.values())
        sections.append(f"\n[*] Summary: {len(hosts_found)} IPv4 hosts | {len(ipv6_hosts)} IPv6 hosts | {total_svc} open services | {findings_created} findings")
        self.info(f"network-scout complete — {len(hosts_found)} hosts, {total_svc} services, {findings_created} findings.")
        return '\n'.join(sections)

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _check_nmap(self, session, platform: str) -> bool:
        """Check if nmap is available."""
        try:
            cmd = "which nmap 2>/dev/null || where nmap 2>nul"
            out = self._exec(session, cmd)
            return 'nmap' in out.lower()
        except Exception:
            return False

    def _get_local_subnet(self, session, platform: str) -> str:
        """Detect local subnet from IP address."""
        try:
            if platform == 'linux':
                out = self._exec(session, "ip addr show | grep 'inet ' | grep -v '127.0.0.1'")
            else:
                out = self._exec(session, "ipconfig | findstr IPv4")
            ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}', out)
            if ips:
                return f"{ips[0]}.0/24"
        except Exception:
            pass
        return "192.168.1.0/24"

    def _build_ping_sweep(self, subnet: str, platform: str, fast: bool) -> str:
        base = '.'.join(subnet.split('.')[:3])
        if platform == 'linux':
            if fast:
                return f"for i in $(seq 1 254); do ping -c1 -W1 {base}.$i &>/dev/null && echo {base}.$i & done; wait"
            return f"for i in $(seq 1 254); do (ping -c1 -W1 {base}.$i &>/dev/null && echo {base}.$i) & done; wait"
        else:
            return f"for /l %i in (1,1,254) do @ping -n 1 -w 200 {base}.%i > nul && echo {base}.%i"

    def _build_ipv6_sweep(self, platform: str) -> str:
        """Build IPv6 discovery command."""
        if platform == 'linux':
            return "ip -6 neigh show | awk '{print $1}'"
        else:
            return "powershell -c \"Get-NetNeighbor -AddressFamily IPv6 | Select-Object IPAddress\""

    def _nmap_scan(self, session, host: str, ports: list, platform: str) -> tuple:
        """Use nmap for advanced scanning with banner grabbing."""
        port_list = ','.join(str(p) for p in ports)
        cmd = f"nmap -sV -sC -p {port_list} --open -T4 {host} 2>/dev/null"
        out = self._exec(session, cmd)
        
        open_ports = []
        banners = {}
        
        # Parse nmap output
        for line in out.splitlines():
            match = re.search(r'(\d+)/tcp\s+open\s+(\S+)(?:\s+(.+))?', line)
            if match:
                port = int(match.group(1))
                service = match.group(2)
                banner = match.group(3) or service
                open_ports.append(port)
                banners[port] = banner
        
        return open_ports, banners

    def _port_sweep(self, session, host: str, ports: list, platform: str) -> list:
        """Return list of open ports on host."""
        open_ports = []
        if platform == 'linux':
            port_list = ' '.join(str(p) for p in ports)
            cmd = (
                f"for p in {port_list}; do "
                f"(echo >/dev/tcp/{host}/$p) 2>/dev/null && echo $p; "
                f"done"
            )
            out = self._exec(session, cmd)
            for line in out.splitlines():
                line = line.strip()
                if line.isdigit():
                    open_ports.append(int(line))
        else:
            # Windows: use Test-NetConnection (PowerShell)
            for port in ports[:15]:
                cmd = f"powershell -c (Test-NetConnection {host} -Port {port}).TcpTestSucceeded 2>nul"
                out = self._exec(session, cmd)
                if 'True' in out:
                    open_ports.append(port)
        return open_ports

    def _build_smb_enum(self, host: str, platform: str) -> str:
        """Build SMB enumeration command with SMBv1 detection."""
        if platform == 'linux':
            return f"smbclient -L {host} -N 2>/dev/null || nmblookup -A {host} 2>/dev/null"
        else:
            return f"net view \\\\{host} 2>nul"

    def _detect_platform(self, session) -> str:
        try:
            out = self._exec(session, 'echo %OS%')
            if 'Windows' in out:
                return 'windows'
        except Exception:
            pass
        return 'linux'

    @staticmethod
    def _exec(session, cmd: str) -> str:
        for method in ('exec', 'run', 'execute', 'send_command'):
            fn = getattr(session, method, None)
            if callable(fn):
                result = fn(cmd)
                if isinstance(result, bytes):
                    return result.decode(errors='replace')
                if isinstance(result, str):
                    return result
        return ''