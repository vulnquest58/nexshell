#!/usr/bin/env python3
"""
NexShell — Compatibility shim so old imports still work.
Copied from modules/transport.py — kept in sync.
"""
# Just re-export everything from the original transport module
try:
    import importlib.util, sys
    from pathlib import Path
    _orig = Path(__file__).parent / 'transport.py'
    spec  = importlib.util.spec_from_file_location('_transport_orig', str(_orig))
    mod   = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    TLSListener    = mod.TLSListener
    HTTPTunnel     = mod.HTTPTunnel
    DoHExfil       = mod.DoHExfil
    TRANSPORT_INFO = mod.TRANSPORT_INFO
    _generate_self_signed_cert = mod._generate_self_signed_cert
except Exception:
    TLSListener    = None
    HTTPTunnel     = None
    DoHExfil       = None
    TRANSPORT_INFO = {}
    _generate_self_signed_cert = None
