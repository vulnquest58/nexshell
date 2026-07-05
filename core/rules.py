#!/usr/bin/env python3
"""
NexShell — Rule Engine  (core/rules.py)
IF condition THEN action — auto-generates findings and recommendations.

Built-in rules fire automatically on events (session connected, loot found).
Users can add custom rules at runtime.

Usage:
    from core.rules import rule_engine

    # Rules evaluate automatically via EventBus
    # Manual check:
    rule_engine.evaluate_session(session_data)
"""

import logging
import datetime
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger('nexshell.rules')


# ══════════════════════════════════════════════════════════════════════════════
#  CONDITION / ACTION TYPES
# ══════════════════════════════════════════════════════════════════════════════

Condition = Callable[[Dict[str, Any]], bool]
Action    = Callable[[Dict[str, Any]], Optional[str]]


class Rule:
    """A single IF→THEN rule."""

    def __init__(self, name: str, condition: Condition, action: Action,
                 description: str = "", severity: str = "info",
                 mitre_id: str = "", enabled: bool = True):
        self.name        = name
        self.condition   = condition
        self.action      = action
        self.description = description
        self.severity    = severity    # info | low | medium | high | critical
        self.mitre_id    = mitre_id
        self.enabled     = enabled
        self._fired: List[str] = []   # timestamps when fired

    def evaluate(self, context: Dict[str, Any]) -> Optional[str]:
        """Evaluate condition; if True, execute action. Returns action output."""
        if not self.enabled:
            return None
        try:
            if self.condition(context):
                result = self.action(context)
                self._fired.append(datetime.datetime.utcnow().isoformat())
                return result
        except Exception as e:
            logger.debug(f"Rule '{self.name}' error: {e}")
        return None

    @property
    def fire_count(self) -> int:
        return len(self._fired)


# ══════════════════════════════════════════════════════════════════════════════
#  RULE ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class RuleEngine:
    """Evaluates all registered rules against a context dict."""

    def __init__(self):
        self._rules: List[Rule] = []
        self._findings_callback: Optional[Callable] = None
        self._load_builtin_rules()

    def register(self, rule: Rule):
        self._rules.append(rule)

    def set_findings_callback(self, cb: Callable):
        """Set callback(title, description, severity, mitre_id) for auto-findings."""
        self._findings_callback = cb

    def evaluate(self, context: Dict[str, Any]) -> List[str]:
        """
        Run all rules against context.
        context keys: host, os, user, is_root, shell_type, loot_category, etc.
        Returns list of triggered rule outputs.
        """
        triggered = []
        for rule in self._rules:
            result = rule.evaluate(context)
            if result:
                triggered.append(result)
                logger.info(f"Rule fired: [{rule.name}] → {result[:80]}")
                if self._findings_callback:
                    try:
                        self._findings_callback(
                            title=f"[Auto] {rule.name}",
                            description=result,
                            severity=rule.severity,
                            mitre_id=rule.mitre_id,
                            host=context.get('host', ''),
                            session_id=context.get('session_id', 0),
                        )
                    except Exception:
                        pass
        return triggered

    def evaluate_session(self, session_data: Dict[str, Any]) -> List[str]:
        """Convenience: evaluate rules against a session dict."""
        return self.evaluate(session_data)

    def list_rules(self) -> List[Dict[str, Any]]:
        return [
            {
                'name': r.name, 'description': r.description,
                'severity': r.severity, 'mitre_id': r.mitre_id,
                'enabled': r.enabled, 'fires': r.fire_count,
            }
            for r in self._rules
        ]

    def enable(self, name: str):
        for r in self._rules:
            if r.name == name:
                r.enabled = True

    def disable(self, name: str):
        for r in self._rules:
            if r.name == name:
                r.enabled = False

    # ── Built-in rules ────────────────────────────────────────────────────────

    def _load_builtin_rules(self):
        rules = [
            Rule(
                name        = "Windows Administrator Access",
                condition   = lambda ctx: ctx.get('os') == 'Windows' and ctx.get('is_root'),
                action      = lambda ctx: (
                    f"SYSTEM/Administrator access on Windows host {ctx.get('host', '?')}. "
                    f"Consider: credential extraction (mimikatz), DCSync, lateral movement."
                ),
                description = "Detects SYSTEM/Admin on Windows — high-value target",
                severity    = "critical",
                mitre_id    = "T1078",
            ),
            Rule(
                name        = "Linux Root Access",
                condition   = lambda ctx: ctx.get('os', '').lower() in ('linux', 'unix') and ctx.get('is_root'),
                action      = lambda ctx: (
                    f"Root access on Linux host {ctx.get('host', '?')}. "
                    f"Consider: persistence (crontab/systemd), credential harvest (/etc/shadow), lateral movement."
                ),
                description = "Detects root access on Linux — high-value target",
                severity    = "critical",
                mitre_id    = "T1078",
            ),
            Rule(
                name        = "Credentials in Loot",
                condition   = lambda ctx: ctx.get('loot_category') == 'credentials',
                action      = lambda ctx: (
                    f"Credentials found on {ctx.get('host', '?')}: {ctx.get('loot_preview', '')[:60]}. "
                    f"Recommend: password reuse check, lateral movement attempt."
                ),
                description = "Fires when credentials are found in loot",
                severity    = "high",
                mitre_id    = "T1552",
            ),
            Rule(
                name        = "AWS Keys Found",
                condition   = lambda ctx: ctx.get('loot_category') == 'api_tokens' and 'AKIA' in ctx.get('loot_preview', ''),
                action      = lambda ctx: (
                    f"AWS Access Key found on {ctx.get('host', '?')}. "
                    f"Recommend: enumerate AWS permissions (aws sts get-caller-identity), check S3 buckets."
                ),
                description = "Detects AWS access keys in loot",
                severity    = "critical",
                mitre_id    = "T1552.005",
            ),
            Rule(
                name        = "SSH Private Key Found",
                condition   = lambda ctx: ctx.get('loot_category') == 'private_keys',
                action      = lambda ctx: (
                    f"SSH private key found on {ctx.get('host', '?')}. "
                    f"Recommend: test key against all discovered hosts for lateral movement."
                ),
                description = "Detects SSH private keys in loot",
                severity    = "high",
                mitre_id    = "T1552.004",
            ),
            Rule(
                name        = "Hash Found - Cracking Opportunity",
                condition   = lambda ctx: ctx.get('loot_category') == 'hashes',
                action      = lambda ctx: (
                    f"Password hash found on {ctx.get('host', '?')}. "
                    f"Recommend: offline cracking (hashcat/john), pass-the-hash attack."
                ),
                description = "Detects password hashes — crack or PTH",
                severity    = "high",
                mitre_id    = "T1110.002",
            ),
            Rule(
                name        = "Dumb Shell Quality",
                condition   = lambda ctx: ctx.get('shell_type') == 'dumb',
                action      = lambda ctx: (
                    f"Session {ctx.get('session_id', '?')} on {ctx.get('host', '?')} has dumb shell. "
                    f"Recommend: run 'upgrade' to get PTY (python3/script/socat)."
                ),
                description = "Recommends shell upgrade for dumb shells",
                severity    = "info",
                mitre_id    = "",
            ),
            Rule(
                name        = "Container Environment Detected",
                condition   = lambda ctx: ctx.get('is_container', False),
                action      = lambda ctx: (
                    f"Container environment detected on {ctx.get('host', '?')}. "
                    f"Recommend: run 'container-auto' escape module, check for Docker socket."
                ),
                description = "Detects container environment — escape opportunity",
                severity    = "medium",
                mitre_id    = "T1611",
            ),
        ]
        for rule in rules:
            self.register(rule)


# ══════════════════════════════════════════════════════════════════════════════
#  GLOBAL ENGINE SINGLETON
# ══════════════════════════════════════════════════════════════════════════════

rule_engine = RuleEngine()
