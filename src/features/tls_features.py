#!/usr/bin/env python3
"""Features from TLS handshake and certificate metadata. No payload, no
decryption, and deliberately no lexical analysis of the server name.

Excluded on purpose:
  - TLS version and raw cipher identity: both drift over time, and the
    malicious captures skew older than the benign ones.
  - Any text feature of the SNI (length, entropy, digit ratio). An earlier
    version leaned on these and became a domain-name classifier, duplicating
    the DGA detector and failing entirely on malware that contacts
    legitimate-looking hosts.

What remains describes how the session was set up and who vouched for it.
"""
import re

TLS_FEATURE_NAMES = [
    "has_sni", "sni_is_ip",
    "established", "resumed",
    "cert_self_signed", "cert_invalid", "cert_expired", "cert_not_yet_valid",
    "cert_unable_verify", "cert_missing", "cert_ok",
    "subject_is_issuer", "subject_len", "issuer_len",
    "subject_field_count", "issuer_field_count",
    "subject_has_org", "issuer_has_org", "subject_generic_cn",
    "issuer_is_known_ca", "client_cert_present",
    "cipher_is_gcm", "cipher_is_cbc", "cipher_is_rc4", "cipher_fs",
    "curve_present", "alpn_present", "alpn_is_http2",
    "port_is_443", "port_nonstandard",
]

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
GENERIC_CN = re.compile(r"(localhost|example|test|default|internal|\blocal\b|"
                        r"^CN=[A-Za-z0-9]{1,4}$)", re.I)
KNOWN_CA = re.compile(r"(let's encrypt|digicert|globalsign|comodo|sectigo|"
                      r"verisign|thawte|geotrust|godaddy|amazon|google trust|"
                      r"entrust|rapidssl|symantec|baltimore|usertrust)", re.I)
STD_TLS_PORTS = {443, 8443, 993, 995, 465, 587, 636, 989, 990, 5061}


def _s(v):
    v = (v or "").strip()
    return "" if v in ("-", "(empty)", "(unset)") else v


def tls_features(rec):
    sni = _s(rec.get("server_name")).lower()
    cipher = _s(rec.get("cipher")).upper()
    status = _s(rec.get("validation_status")).lower()
    subject = _s(rec.get("subject"))
    issuer = _s(rec.get("issuer"))
    client_cert = _s(rec.get("client_subject"))
    alpn = _s(rec.get("next_protocol"))
    curve = _s(rec.get("curve"))

    self_signed = "self signed" in status
    expired = "expired" in status or "has expired" in status
    not_yet = "not yet valid" in status
    unable = "unable to" in status or "unable_to" in status
    ok = status == "ok"
    missing = not status
    invalid = bool(status) and not ok and not any(
        (self_signed, expired, not_yet, unable))

    try:
        port = int(_s(rec.get("id.resp_p")) or 0)
    except ValueError:
        port = 0

    return [
        1.0 if sni else 0.0,
        1.0 if IP_RE.match(sni) else 0.0,

        1.0 if _s(rec.get("established")).upper().startswith("T") else 0.0,
        1.0 if _s(rec.get("resumed")).upper().startswith("T") else 0.0,

        1.0 if self_signed else 0.0,
        1.0 if invalid else 0.0,
        1.0 if expired else 0.0,
        1.0 if not_yet else 0.0,
        1.0 if unable else 0.0,
        1.0 if missing else 0.0,
        1.0 if ok else 0.0,

        1.0 if (subject and subject == issuer) else 0.0,
        float(len(subject)),
        float(len(issuer)),
        float(subject.count("=")),
        float(issuer.count("=")),
        1.0 if re.search(r"\bO=", subject) else 0.0,
        1.0 if re.search(r"\bO=", issuer) else 0.0,
        1.0 if GENERIC_CN.search(subject) else 0.0,
        1.0 if KNOWN_CA.search(issuer) else 0.0,
        1.0 if client_cert else 0.0,

        1.0 if "GCM" in cipher else 0.0,
        1.0 if "CBC" in cipher else 0.0,
        1.0 if "RC4" in cipher else 0.0,
        1.0 if ("ECDHE" in cipher or "DHE" in cipher) else 0.0,

        1.0 if curve else 0.0,
        1.0 if alpn else 0.0,
        1.0 if alpn.startswith("h2") else 0.0,

        1.0 if port == 443 else 0.0,
        1.0 if port and port not in STD_TLS_PORTS else 0.0,
    ]
