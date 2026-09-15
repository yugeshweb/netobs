#!/usr/bin/env python3
"""Features from TLS handshake metadata. No payload, no decryption.

Deliberately excludes TLS version and raw cipher identity: both drift with
time, and a model that leans on them learns the capture era rather than the
behaviour.
"""
import math
import re
from collections import Counter

TLS_FEATURE_NAMES = [
    "has_sni", "sni_is_ip", "sni_length", "sni_label_count",
    "sni_entropy", "sni_digit_ratio", "sni_hyphen", "sni_tld_common",
    "established", "resumed",
    "cert_self_signed", "cert_invalid", "cert_missing", "cert_ok",
    "subject_is_issuer", "subject_len", "issuer_len",
    "subject_has_org", "subject_generic_cn",
    "cipher_is_gcm", "cipher_is_cbc", "cipher_is_rc4", "cipher_fs",
    "curve_present", "alpn_present", "alpn_is_http2",
    "port_is_443", "port_high",
]

COMMON_TLDS = {"com", "net", "org", "io", "co", "edu", "gov", "uk", "de",
               "fr", "jp", "cn", "ru", "br", "in", "nl", "eu", "cz", "info"}

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
GENERIC_CN = re.compile(r"(localhost|example|test|default|internal|\blocal\b)", re.I)


def _s(v):
    v = (v or "").strip()
    return "" if v in ("-", "(empty)", "(unset)") else v


def shannon(s):
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((k / n) * math.log2(k / n) for k in c.values())


def tls_features(rec):
    """rec: dict of Zeek ssl.log fields (strings)."""
    sni = _s(rec.get("server_name")).lower()
    cipher = _s(rec.get("cipher")).upper()
    status = _s(rec.get("validation_status")).lower()
    subject = _s(rec.get("subject"))
    issuer = _s(rec.get("issuer"))
    alpn = _s(rec.get("next_protocol"))
    curve = _s(rec.get("curve"))

    labels = [l for l in sni.split(".") if l] if sni else []
    tld = labels[-1] if labels else ""
    digits = sum(c.isdigit() for c in sni)

    self_signed = "self signed" in status
    invalid = bool(status) and status != "ok" and not self_signed
    missing = not status
    ok = status == "ok"

    try:
        port = int(_s(rec.get("id.resp_p")) or 0)
    except ValueError:
        port = 0

    return [
        1.0 if sni else 0.0,
        1.0 if IP_RE.match(sni) else 0.0,
        float(len(sni)),
        float(len(labels)),
        shannon(sni),
        (digits / len(sni)) if sni else 0.0,
        1.0 if "-" in sni else 0.0,
        1.0 if tld in COMMON_TLDS else 0.0,

        1.0 if _s(rec.get("established")).upper().startswith("T") else 0.0,
        1.0 if _s(rec.get("resumed")).upper().startswith("T") else 0.0,

        1.0 if self_signed else 0.0,
        1.0 if invalid else 0.0,
        1.0 if missing else 0.0,
        1.0 if ok else 0.0,

        1.0 if (subject and subject == issuer) else 0.0,
        float(len(subject)),
        float(len(issuer)),
        1.0 if re.search(r"\bO=", subject) else 0.0,
        1.0 if GENERIC_CN.search(subject) else 0.0,

        1.0 if "GCM" in cipher else 0.0,
        1.0 if "CBC" in cipher else 0.0,
        1.0 if "RC4" in cipher else 0.0,
        1.0 if ("ECDHE" in cipher or "DHE" in cipher) else 0.0,

        1.0 if curve else 0.0,
        1.0 if alpn else 0.0,
        1.0 if alpn.startswith("h2") else 0.0,

        1.0 if port == 443 else 0.0,
        1.0 if port > 1024 and port != 8443 else 0.0,
    ]
