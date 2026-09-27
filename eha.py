#!/usr/bin/env python3
"""
Enterprise Hardening Auditor (EHA)
------------------------------------
A lightweight, dependency-minimal Infrastructure VAPT auditor for BFSI
environments. Checks target hosts for common CIS-benchmark-aligned
misconfigurations:

  * Deprecated SSL/TLS protocol support (Port 443)
  * Legacy/outdated SSH banners (Port 22)
  * SMB signing posture (Port 445)

Generates a standalone, offline-friendly HTML report.

Author: Enterprise Hardening Auditor Project
License: Internal / Authorized Security Testing Use Only

LEGAL NOTICE:
This tool performs active network probing (socket connections, TLS
handshakes, banner grabs, and optionally invokes nmap). Only run this
against systems you own or have explicit written authorization to test.
"""

import argparse
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from html import escape as html_escape
from typing import Optional


# --------------------------------------------------------------------------
# Data Models
# --------------------------------------------------------------------------

@dataclass
class Finding:
    port: int
    service: str
    vulnerability: str
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW | SECURE | INFO
    cvss: str
    description: str
    remediation: str
    evidence: str = ""


@dataclass
class ScanResult:
    target: str
    timestamp: str
    findings: list = field(default_factory=list)
    port_status: dict = field(default_factory=dict)  # port -> "open"/"closed"/"filtered"

    def add(self, finding: Finding):
        self.findings.append(finding)

    def severity_counts(self):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SECURE": 0, "INFO": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


# --------------------------------------------------------------------------
# Utility: Port reachability check
# --------------------------------------------------------------------------

def check_port_open(host: str, port: int, timeout: float) -> bool:
    """Return True if a TCP connection to host:port succeeds within timeout."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def resolve_host(host: str) -> Optional[str]:
    """Resolve hostname to an IP address, returning None on failure."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


# --------------------------------------------------------------------------
# Module 1: Cryptographic Strength Auditor (Port 443)
# --------------------------------------------------------------------------

class TLSAuditor:
    """
    Probes a target's TLS endpoint for support of deprecated protocol
    versions by attempting handshakes constrained to each protocol version
    via ssl.SSLContext, and records which ones the server accepts.
    """

    # Map of label -> (min_version, max_version) using ssl.TLSVersion where
    # supported by the running OpenSSL build. Some legacy protocols
    # (SSLv2/SSLv3) are compiled out of modern OpenSSL entirely, in which
    # case we report them as "Not supported by client library" rather than
    # falsely claiming the server rejected them.
    PROTOCOL_TESTS = [
        ("SSLv3", "SSLv3"),
        ("TLSv1.0", "TLSv1"),
        ("TLSv1.1", "TLSv1.1"),
        ("TLSv1.2", "TLSv1.2"),
        ("TLSv1.3", "TLSv1.3"),
    ]

    def __init__(self, host: str, port: int, timeout: float):
        self.host = host
        self.port = port
        self.timeout = timeout

    def _build_context_for_version(self, version_name: str):
        """
        Build an SSLContext locked to a single protocol version.
        Returns None if the local OpenSSL build does not support
        constraining to that legacy version at all (common for SSLv2/SSLv3
        on modern distros where they are compiled out).
        """
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            version_map = {
                "SSLv3": ssl.TLSVersion.SSLv3 if hasattr(ssl.TLSVersion, "SSLv3") else None,
                "TLSv1": ssl.TLSVersion.TLSv1 if hasattr(ssl.TLSVersion, "TLSv1") else None,
                "TLSv1.1": ssl.TLSVersion.TLSv1_1 if hasattr(ssl.TLSVersion, "TLSv1_1") else None,
                "TLSv1.2": ssl.TLSVersion.TLSv1_2,
                "TLSv1.3": ssl.TLSVersion.TLSv1_3,
            }

            target_version = version_map.get(version_name)
            if target_version is None:
                return None

            # Allow legacy protocols through the security policy layer
            # (OpenSSL 3.x sets a default @SECLEVEL that blocks old
            # protocols outright; we lower it purely for detection).
            try:
                context.set_ciphers("DEFAULT@SECLEVEL=0")
            except ssl.SSLError:
                pass

            context.minimum_version = target_version
            context.maximum_version = target_version
            return context
        except (ValueError, AttributeError):
            return None

    def test_protocol(self, label: str, version_key: str) -> str:
        """
        Attempt a handshake using only the specified protocol version.
        Returns one of: "ACCEPTED", "REJECTED", "UNSUPPORTED_BY_CLIENT",
        "CONNECTION_ERROR"
        """
        context = self._build_context_for_version(version_key)
        if context is None:
            return "UNSUPPORTED_BY_CLIENT"

        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as tls_sock:
                    negotiated = tls_sock.version()
                    if negotiated:
                        return "ACCEPTED"
                    return "REJECTED"
        except ssl.SSLError:
            return "REJECTED"
        except (socket.timeout, ConnectionResetError, ConnectionRefusedError, OSError):
            return "CONNECTION_ERROR"

    def run(self) -> list:
        findings = []
        results = {}

        for label, version_key in self.PROTOCOL_TESTS:
            outcome = self.test_protocol(label, version_key)
            results[label] = outcome
            print(f"    [TLS] {label:<10} -> {outcome}")

        legacy_labels = ["SSLv3", "TLSv1.0", "TLSv1.1"]
        accepted_legacy = [l for l in legacy_labels if results.get(l) == "ACCEPTED"]

        if accepted_legacy:
            findings.append(Finding(
                port=443,
                service="SSL/TLS",
                vulnerability="Deprecated SSL/TLS Protocol Version Enabled",
                severity="HIGH",
                cvss="7.5",
                description=(
                    "The remote service accepts connections encrypted via legacy "
                    "cryptographic protocols (" + ", ".join(accepted_legacy) + "), which are "
                    "susceptible to man-in-the-middle (MITM) attacks such as POODLE or BEAST. "
                    "Legacy protocols use weak cipher suites and have known cryptographic "
                    "weaknesses that can allow an attacker to decrypt intercepted traffic."
                ),
                remediation=(
                    "Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 in the server configuration "
                    "(Apache: 'SSLProtocol -all +TLSv1.2 +TLSv1.3' in ssl.conf; Nginx: "
                    "'ssl_protocols TLSv1.2 TLSv1.3;' in the server block; IIS: disable via "
                    "registry keys under SCHANNEL Protocols, or use IIS Crypto). Enforce TLS "
                    "1.2 and TLS 1.3 only, then re-scan to confirm legacy protocols are rejected."
                ),
                evidence="Accepted legacy protocols: " + ", ".join(accepted_legacy),
            ))
        else:
            modern_accepted = [l for l in ["TLSv1.2", "TLSv1.3"] if results.get(l) == "ACCEPTED"]
            findings.append(Finding(
                port=443,
                service="SSL/TLS",
                vulnerability="No Deprecated SSL/TLS Protocols Detected",
                severity="SECURE",
                cvss="N/A",
                description=(
                    "The remote service correctly rejected legacy protocol handshake attempts. "
                    "Modern protocols supported: " + (", ".join(modern_accepted) if modern_accepted else "Unconfirmed") + "."
                ),
                remediation="No action required. Continue to monitor for future protocol deprecations.",
                evidence="Modern protocols accepted: " + (", ".join(modern_accepted) if modern_accepted else "None confirmed"),
            ))

        return findings


# --------------------------------------------------------------------------
# Module 2: SSH Banner & Configuration Auditor (Port 22)
# --------------------------------------------------------------------------

class SSHAuditor:
    """
    Connects to the target's SSH port and inspects the pre-authentication
    banner string to identify protocol version and software version,
    flagging known-risky configurations.
    """

    # Conservative "known outdated" threshold. RegreSSHion (CVE-2024-6387)
    # affected OpenSSH 8.5p1 through 9.7p1 on glibc-based Linux; versions
    # fixed at 9.8p1+ are not vulnerable. We flag anything below 9.8 for
    # review, and explicitly call out the CVE if in the known-affected range.
    REGRESSHION_VULNERABLE_MIN = (8, 5)
    REGRESSHION_FIXED_AT = (9, 8)

    def __init__(self, host: str, port: int, timeout: float):
        self.host = host
        self.port = port
        self.timeout = timeout

    def grab_banner(self) -> Optional[str]:
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                banner_bytes = sock.recv(1024)
                return banner_bytes.decode("utf-8", errors="replace").strip()
        except (socket.timeout, ConnectionResetError, ConnectionRefusedError, OSError):
            return None

    @staticmethod
    def parse_openssh_version(banner: str) -> Optional[tuple]:
        """
        Extract an (major, minor) numeric version from a banner like
        'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6'. Returns None if not
        an OpenSSH banner or unparseable.
        """
        if "OpenSSH_" not in banner:
            return None
        try:
            after = banner.split("OpenSSH_", 1)[1]
            version_str = ""
            for ch in after:
                if ch.isdigit() or ch == ".":
                    version_str += ch
                else:
                    break
            parts = version_str.split(".")
            if len(parts) >= 2:
                major = int(parts[0])
                minor_str = "".join(c for c in parts[1] if c.isdigit())
                minor = int(minor_str) if minor_str else 0
                return (major, minor)
        except (ValueError, IndexError):
            return None
        return None

    def run(self) -> list:
        findings = []
        banner = self.grab_banner()

        if banner is None:
            findings.append(Finding(
                port=22,
                service="SSH",
                vulnerability="SSH Banner Grab Failed",
                severity="INFO",
                cvss="N/A",
                description=(
                    "A TCP connection was established on port 22, but no banner was "
                    "received within the configured timeout, or the connection was reset. "
                    "This may indicate a TCP wrapper, fail2ban-style rate limiting, or a "
                    "non-SSH service on this port."
                ),
                remediation="Manually verify the service on this port using 'nc' or 'ssh -vvv' and re-run the audit with a higher timeout.",
            ))
            return findings

        print(f"    [SSH] Banner: {banner}")

        if "SSH-1.99" in banner or ("SSH-1." in banner and "SSH-1.99" not in banner):
            findings.append(Finding(
                port=22,
                service="SSH",
                vulnerability="Outdated SSH Service / Legacy SSHv1 Protocol Supported",
                severity="CRITICAL",
                cvss="9.8",
                description=(
                    "The SSH service advertises support for the legacy SSHv1 protocol "
                    "(banner: '" + banner + "'). SSHv1 has fundamental cryptographic design "
                    "flaws, including susceptibility to man-in-the-middle attacks and "
                    "insertion attacks, and is considered fully broken."
                ),
                remediation=(
                    "Update /etc/ssh/sshd_config to explicitly set 'Protocol 2' (or remove "
                    "the directive entirely on modern OpenSSH, where SSHv1 support has been "
                    "removed since 7.6+ and upgrade the daemon if this banner appears). "
                    "Disable weak MACs and ciphers, then restart the sshd service."
                ),
                evidence=banner,
            ))
            return findings

        version_tuple = self.parse_openssh_version(banner)
        if version_tuple:
            major, minor = version_tuple
            in_regresshion_range = (
                (major, minor) >= self.REGRESSHION_VULNERABLE_MIN
                and (major, minor) < self.REGRESSHION_FIXED_AT
            )
            is_legacy = (major, minor) < (7, 0)

            if in_regresshion_range:
                findings.append(Finding(
                    port=22,
                    service="SSH",
                    vulnerability="Outdated SSH Service (Potential RegreSSHion Exposure - CVE-2024-6387)",
                    severity="CRITICAL",
                    cvss="8.1",
                    description=(
                        f"The detected OpenSSH version ({major}.{minor}) falls within the range "
                        "affected by CVE-2024-6387 ('RegreSSHion'), a signal-handler race "
                        "condition in sshd that can lead to unauthenticated remote code "
                        "execution as root on affected glibc-based Linux systems. Exploitation "
                        "is probabilistic and may require many connection attempts, but the "
                        "impact is critical."
                    ),
                    remediation=(
                        "Upgrade OpenSSH to version 9.8p1 or later immediately. If an "
                        "immediate upgrade is not possible, apply the vendor-backported patch "
                        "for CVE-2024-6387, or mitigate by setting 'LoginGraceTime 0' in "
                        "sshd_config (note: this can enable a separate DoS condition, so "
                        "patching is strongly preferred over this workaround)."
                    ),
                    evidence=banner,
                ))
            elif is_legacy:
                findings.append(Finding(
                    port=22,
                    service="SSH",
                    vulnerability="Outdated SSH Service / Legacy OpenSSH Version",
                    severity="HIGH",
                    cvss="7.5",
                    description=(
                        f"The detected OpenSSH version ({major}.{minor}) is significantly "
                        "outdated and likely missing numerous security patches accumulated "
                        "over multiple release cycles, increasing exposure to known CVEs."
                    ),
                    remediation=(
                        "Upgrade the OpenSSH package to the latest stable release available "
                        "for the OS distribution. Update sshd_config to enforce 'Protocol 2' "
                        "and disable weak MAC/cipher/KEX algorithms per current CIS benchmarks."
                    ),
                    evidence=banner,
                ))
            else:
                findings.append(Finding(
                    port=22,
                    service="SSH",
                    vulnerability="SSH Service Version Current",
                    severity="SECURE",
                    cvss="N/A",
                    description=(
                        f"The detected OpenSSH version ({major}.{minor}) is not in the known "
                        "RegreSSHion-affected range and does not appear to be a legacy release. "
                        "Confirm patch level against the vendor's current advisories."
                    ),
                    remediation="No immediate action required. Maintain a regular patching cadence.",
                    evidence=banner,
                ))
        else:
            findings.append(Finding(
                port=22,
                service="SSH",
                vulnerability="Non-OpenSSH or Unparseable SSH Banner",
                severity="MEDIUM",
                cvss="N/A",
                description=(
                    "The SSH banner did not match the expected OpenSSH format "
                    "(banner: '" + banner + "'). This may be a commercial SSH implementation "
                    "(e.g., Tectia, Cisco IOS SSH) or a customized/obscured banner."
                ),
                remediation="Manually identify the SSH implementation and cross-reference its version against vendor security advisories.",
                evidence=banner,
            ))

        return findings


# --------------------------------------------------------------------------
# Module 3: SMB Signing & Exploit Auditor (Port 445)
# --------------------------------------------------------------------------

class SMBAuditor:
    """
    Assesses SMB signing posture on port 445. Primary method invokes nmap's
    smb-security-mode NSE script (if nmap is installed on the auditor's
    machine) and parses its text output. Falls back to a raw negotiate
    probe that reports connectivity only, with a manual-verification note,
    when nmap is unavailable.
    """

    def __init__(self, host: str, port: int, timeout: float):
        self.host = host
        self.port = port
        self.timeout = timeout

    def _run_nmap_smb_script(self) -> Optional[str]:
        nmap_path = shutil.which("nmap")
        if not nmap_path:
            return None

        try:
            completed = subprocess.run(
                [
                    nmap_path,
                    "-p", str(self.port),
                    "--script", "smb-security-mode",
                    "--host-timeout", f"{max(int(self.timeout * 4), 10)}s",
                    self.host,
                ],
                capture_output=True,
                text=True,
                timeout=max(self.timeout * 6, 30),
            )
            return completed.stdout
        except subprocess.TimeoutExpired:
            return None
        except (OSError, subprocess.SubprocessError):
            return None

    def _raw_negotiate_probe(self) -> bool:
        """
        Sends a minimal SMB negotiate request to confirm the service is a
        live SMB listener. This does NOT parse signing state -- full SMB1/2/3
        dialect negotiation and signing-flag parsing is out of scope for a
        dependency-free raw-socket implementation, so this is used only as
        a liveness/fallback check when nmap is not present.
        """
        negotiate_request = bytes.fromhex(
            "00000085ff534d4272000000001843c80000000000000000000000000000"
            "00fffe0000000000620002504332303001024c414e4d414e312e30000255"
            "34d80003004e5420"
        )
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                sock.sendall(negotiate_request)
                response = sock.recv(1024)
                return len(response) > 0
        except (socket.timeout, ConnectionResetError, ConnectionRefusedError, OSError):
            return False

    def run(self) -> list:
        findings = []
        nmap_output = self._run_nmap_smb_script()

        if nmap_output:
            print("    [SMB] nmap smb-security-mode output captured")
            lowered = nmap_output.lower()

            signing_disabled = "message signing disabled" in lowered
            signing_not_required = "message signing enabled but not required" in lowered
            signing_required = "message signing enabled and required" in lowered

            if signing_disabled or signing_not_required:
                status_text = "disabled" if signing_disabled else "enabled but not required"
                findings.append(Finding(
                    port=445,
                    service="SMB",
                    vulnerability="SMB Signing Disabled / Not Required",
                    severity="HIGH",
                    cvss="7.5",
                    description=(
                        f"SMB message signing is {status_text} on the target host. Unsigned "
                        "SMB traffic allows an attacker positioned on the same network segment "
                        "to intercept, modify, and relay authentication requests (NTLM Relay "
                        "Attack), potentially achieving administrative access on target systems "
                        "or pivoting further into the domain."
                    ),
                    remediation=(
                        "Enforce SMB Signing via Group Policy Object (GPO): navigate to "
                        "Computer Configuration > Windows Settings > Security Settings > Local "
                        "Policies > Security Options, and enable both 'Microsoft network "
                        "client: Digitally sign communications (always)' and 'Microsoft "
                        "network server: Digitally sign communications (always)'. For Samba, "
                        "set 'server signing = mandatory' in smb.conf."
                    ),
                    evidence=nmap_output.strip()[:500],
                ))
            elif signing_required:
                findings.append(Finding(
                    port=445,
                    service="SMB",
                    vulnerability="SMB Signing Properly Enforced",
                    severity="SECURE",
                    cvss="N/A",
                    description="SMB message signing is enabled and required on the target host, mitigating NTLM relay risk over SMB.",
                    remediation="No action required.",
                    evidence=nmap_output.strip()[:500],
                ))
            else:
                findings.append(Finding(
                    port=445,
                    service="SMB",
                    vulnerability="SMB Signing Status Undetermined",
                    severity="MEDIUM",
                    cvss="N/A",
                    description=(
                        "The nmap smb-security-mode script ran but its output did not match "
                        "any recognized signing-state pattern. Manual verification is "
                        "recommended."
                    ),
                    remediation="Manually run 'nmap -p445 --script smb-security-mode <target>' and review full output, or verify signing state via 'crackmapexec smb <target>' or Group Policy audit.",
                    evidence=nmap_output.strip()[:500],
                ))
        else:
            print("    [SMB] nmap not available or scan failed; falling back to liveness probe")
            is_alive = self._raw_negotiate_probe()
            if is_alive:
                findings.append(Finding(
                    port=445,
                    service="SMB",
                    vulnerability="SMB Signing Status Not Verified (nmap unavailable)",
                    severity="MEDIUM",
                    cvss="N/A",
                    description=(
                        "The SMB service on port 445 is reachable and responded to a negotiate "
                        "request, but signing status could not be determined because nmap is "
                        "not installed on the auditing machine. A raw-socket implementation of "
                        "full SMB dialect negotiation and signing-flag parsing was not used to "
                        "avoid an unreliable, protocol-incomplete result."
                    ),
                    remediation=(
                        "Install nmap on the auditing workstation and re-run this tool, or "
                        "manually verify signing state with 'nmap -p445 --script "
                        "smb-security-mode <target>' or 'crackmapexec smb <target>'."
                    ),
                    evidence="Raw negotiate probe received a response; nmap not found on PATH.",
                ))
            else:
                findings.append(Finding(
                    port=445,
                    service="SMB",
                    vulnerability="SMB Service Unreachable",
                    severity="INFO",
                    cvss="N/A",
                    description="Port 445 was reported open but did not respond to a negotiate probe within the timeout window.",
                    remediation="Verify manually; the service may be firewalled to specific source IPs or rate-limiting connections.",
                ))

        return findings


# --------------------------------------------------------------------------
# Module 4: Enterprise Reporting Engine
# --------------------------------------------------------------------------

class ReportGenerator:
    SEVERITY_COLORS = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#eab308",
        "LOW": "#3b82f6",
        "SECURE": "#6b7280",
        "INFO": "#6b7280",
    }

    def __init__(self, result: ScanResult):
        self.result = result

    def _badge(self, severity: str, count: int) -> str:
        color = self.SEVERITY_COLORS.get(severity, "#6b7280")
        return f"""
        <div class="metric-badge" style="border-top: 4px solid {color};">
            <div class="metric-count" style="color: {color};">{count}</div>
            <div class="metric-label">{html_escape(severity.title())}</div>
        </div>"""

    def _row(self, f: Finding) -> str:
        color = self.SEVERITY_COLORS.get(f.severity, "#6b7280")
        port_status = self.result.port_status.get(f.port, "unknown")
        evidence_html = f"<div class='evidence'>Evidence: {html_escape(f.evidence)}</div>" if f.evidence else ""
        return f"""
        <tr>
            <td><span class="port-tag">{f.port}</span><br><span class="service-tag">{html_escape(f.service)}</span></td>
            <td class="vuln-name">{html_escape(f.vulnerability)}{evidence_html}</td>
            <td><span class="sev-pill" style="background:{color};">{html_escape(f.severity)} {('(' + f.cvss + ')') if f.cvss and f.cvss != 'N/A' else ''}</span></td>
            <td>{html_escape(f.description)}</td>
            <td>{html_escape(f.remediation)}</td>
        </tr>"""

    def generate(self, output_path: str):
        counts = self.result.severity_counts()
        badges = "".join(
            self._badge(sev, counts.get(sev, 0))
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SECURE"]
        )
        rows = "".join(self._row(f) for f in self.result.findings) if self.result.findings else \
            "<tr><td colspan='5' style='text-align:center;padding:30px;color:#888;'>No findings recorded.</td></tr>"

        port_summary_items = "".join(
            f"<li><strong>Port {p}:</strong> {html_escape(status)}</li>"
            for p, status in sorted(self.result.port_status.items())
        )

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VAPT Hardening Report - {html_escape(self.result.target)}</title>
<style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
        font-family: 'Segoe UI', Roboto, Arial, sans-serif;
        background: #f4f5f7;
        color: #1f2430;
        line-height: 1.5;
    }}
    header.dark-header {{
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
        color: #f8fafc;
        padding: 40px 5%;
        border-bottom: 4px solid #3b82f6;
    }}
    header.dark-header h1 {{
        font-size: 28px;
        letter-spacing: 0.5px;
    }}
    header.dark-header p {{
        color: #94a3b8;
        margin-top: 6px;
        font-size: 14px;
    }}
    .container {{
        max-width: 1200px;
        margin: 0 auto;
        padding: 30px 5% 60px 5%;
    }}
    .exec-summary {{
        background: #ffffff;
        border-radius: 10px;
        padding: 25px 30px;
        box-shadow: 0 1px 4px rgba(0,0,0,0.08);
        margin-bottom: 30px;
    }}
    .exec-summary h2 {{
        font-size: 18px;
        margin-bottom: 15px;
        color: #0f172a;
        border-bottom: 2px solid #e2e8f0;
        padding-bottom: 10px;
    }}
    .exec-grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 15px;
        margin-bottom: 20px;
    }}
    .exec-item {{
        background: #f8fafc;
        border-radius: 8px;
        padding: 14px 16px;
    }}
    .exec-item .label {{
        font-size: 11px;
        text-transform: uppercase;
        color: #64748b;
        letter-spacing: 0.5px;
    }}
    .exec-item .value {{
        font-size: 16px;
        font-weight: 600;
        color: #0f172a;
        margin-top: 4px;
        word-break: break-all;
    }}
    .metrics-row {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
        gap: 15px;
        margin-top: 10px;
    }}
    .metric-badge {{
        background: #f8fafc;
        border-radius: 8px;
        padding: 16px;
        text-align: center;
    }}
    .metric-count {{
        font-size: 30px;
        font-weight: 700;
    }}
    .metric-label {{
        font-size: 12px;
        text-transform: uppercase;
        color: #64748b;
        margin-top: 4px;
        letter-spacing: 0.5px;
    }}
    .port-status-box {{
        background: #ffffff;
        border-radius: 10px;
        padding: 20px 25px;
        margin-bottom: 30px;
        box-shadow: 0 1px 4px rgba(0,0,0,0.08);
    }}
    .port-status-box h3 {{
        font-size: 15px;
        margin-bottom: 10px;
        color: #0f172a;
    }}
    .port-status-box ul {{
        list-style: none;
        display: flex;
        gap: 30px;
        flex-wrap: wrap;
    }}
    .port-status-box li {{
        font-size: 13px;
        color: #334155;
        background: #f1f5f9;
        padding: 6px 12px;
        border-radius: 6px;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
        background: #ffffff;
        border-radius: 10px;
        overflow: hidden;
        box-shadow: 0 1px 4px rgba(0,0,0,0.08);
    }}
    thead tr {{
        background: #0f172a;
        color: #f8fafc;
    }}
    th {{
        text-align: left;
        padding: 14px 16px;
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }}
    td {{
        padding: 14px 16px;
        border-bottom: 1px solid #e2e8f0;
        font-size: 13px;
        vertical-align: top;
    }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: #f8fafc; }}
    .port-tag {{
        font-weight: 700;
        font-size: 14px;
        color: #0f172a;
    }}
    .service-tag {{
        font-size: 11px;
        color: #64748b;
        text-transform: uppercase;
    }}
    .vuln-name {{
        font-weight: 600;
        color: #0f172a;
        min-width: 220px;
    }}
    .evidence {{
        margin-top: 6px;
        font-size: 11px;
        color: #64748b;
        font-family: 'Consolas', monospace;
        background: #f1f5f9;
        padding: 4px 8px;
        border-radius: 4px;
        word-break: break-all;
    }}
    .sev-pill {{
        display: inline-block;
        color: #fff;
        padding: 4px 10px;
        border-radius: 20px;
        font-size: 11px;
        font-weight: 700;
        white-space: nowrap;
    }}
    footer {{
        text-align: center;
        padding: 25px;
        color: #94a3b8;
        font-size: 12px;
    }}
</style>
</head>
<body>

<header class="dark-header">
    <h1>&#128274; Security Assessment Summary</h1>
    <p>Enterprise Hardening Auditor (EHA) &mdash; Infrastructure VAPT Report</p>
</header>

<div class="container">

    <div class="exec-summary">
        <h2>Executive Summary</h2>
        <div class="exec-grid">
            <div class="exec-item">
                <div class="label">Target</div>
                <div class="value">{html_escape(self.result.target)}</div>
            </div>
            <div class="exec-item">
                <div class="label">Scan Timestamp</div>
                <div class="value">{html_escape(self.result.timestamp)}</div>
            </div>
            <div class="exec-item">
                <div class="label">Total Findings</div>
                <div class="value">{len(self.result.findings)}</div>
            </div>
        </div>
        <div class="metrics-row">
            {badges}
        </div>
    </div>

    <div class="port-status-box">
        <h3>Port Reachability</h3>
        <ul>
            {port_summary_items if port_summary_items else '<li>No port data recorded.</li>'}
        </ul>
    </div>

    <table>
        <thead>
            <tr>
                <th>Port / Service</th>
                <th>Vulnerability Identified</th>
                <th>Severity Rating</th>
                <th>Technical Impact</th>
                <th>Remediation Guidelines</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>

</div>

<footer>
    Generated by Enterprise Hardening Auditor (EHA) &middot; For authorized security testing use only.<br>
    This report should be handled as CONFIDENTIAL and distributed only to authorized personnel.
</footer>

</body>
</html>"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)


# --------------------------------------------------------------------------
# Orchestrator
# --------------------------------------------------------------------------

class EnterpriseHardeningAuditor:
    PORTS = {
        22: "SSH",
        443: "SSL/TLS",
        445: "SMB",
    }

    def __init__(self, target: str, timeout: float, output_path: str, output_json: Optional[str]):
        self.target = target
        self.timeout = timeout
        self.output_path = output_path
        self.output_json = output_json

    def run(self) -> ScanResult:
        resolved_ip = resolve_host(self.target)
        if resolved_ip is None:
            print(f"[!] ERROR: Unable to resolve hostname '{self.target}'. Verify the target and DNS resolution.")
            sys.exit(1)

        print(f"[*] Enterprise Hardening Auditor (EHA)")
        print(f"[*] Target        : {self.target} ({resolved_ip})")
        print(f"[*] Timeout       : {self.timeout}s")
        print(f"[*] Scan started  : {datetime.now().isoformat(timespec='seconds')}")
        print("-" * 70)

        result = ScanResult(
            target=f"{self.target} ({resolved_ip})" if resolved_ip != self.target else self.target,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        print("[*] Probing target ports for reachability...")
        with ThreadPoolExecutor(max_workers=3) as executor:
            future_to_port = {
                executor.submit(check_port_open, self.target, port, self.timeout): port
                for port in self.PORTS
            }
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    is_open = future.result()
                except Exception:
                    is_open = False
                status = "open" if is_open else "closed/filtered"
                result.port_status[port] = status
                print(f"    Port {port:<5} ({self.PORTS[port]:<8}) -> {status}")

        print("-" * 70)

        if result.port_status.get(443) == "open":
            print("[*] Running Module 1: Cryptographic Strength Auditor (Port 443)")
            try:
                tls_findings = TLSAuditor(self.target, 443, self.timeout).run()
                result.findings.extend(tls_findings)
            except Exception as exc:
                print(f"    [!] TLS module encountered an error: {exc}")
                result.findings.append(Finding(
                    port=443, service="SSL/TLS",
                    vulnerability="TLS Audit Module Error", severity="INFO", cvss="N/A",
                    description=f"The TLS audit module raised an unexpected exception: {exc}",
                    remediation="Re-run the scan or manually verify TLS configuration with 'openssl s_client' or 'testssl.sh'.",
                ))
        else:
            print("[*] Module 1 (TLS) skipped: Port 443 is Not Applicable/Closed")
            result.findings.append(Finding(
                port=443, service="SSL/TLS",
                vulnerability="Port Closed / Filtered",
                severity="INFO", cvss="N/A",
                description="Port 443 did not respond to a TCP connection attempt within the timeout window.",
                remediation="Not Applicable — no HTTPS/TLS service detected on this port.",
            ))

        if result.port_status.get(22) == "open":
            print("[*] Running Module 2: SSH Banner & Configuration Auditor (Port 22)")
            try:
                ssh_findings = SSHAuditor(self.target, 22, self.timeout).run()
                result.findings.extend(ssh_findings)
            except Exception as exc:
                print(f"    [!] SSH module encountered an error: {exc}")
                result.findings.append(Finding(
                    port=22, service="SSH",
                    vulnerability="SSH Audit Module Error", severity="INFO", cvss="N/A",
                    description=f"The SSH audit module raised an unexpected exception: {exc}",
                    remediation="Re-run the scan or manually verify with 'ssh -vvv' against the target.",
                ))
        else:
            print("[*] Module 2 (SSH) skipped: Port 22 is Not Applicable/Closed")
            result.findings.append(Finding(
                port=22, service="SSH",
                vulnerability="Port Closed / Filtered",
                severity="INFO", cvss="N/A",
                description="Port 22 did not respond to a TCP connection attempt within the timeout window.",
                remediation="Not Applicable — no SSH service detected on this port.",
            ))

        if result.port_status.get(445) == "open":
            print("[*] Running Module 3: SMB Signing & Exploit Auditor (Port 445)")
            try:
                smb_findings = SMBAuditor(self.target, 445, self.timeout).run()
                result.findings.extend(smb_findings)
            except Exception as exc:
                print(f"    [!] SMB module encountered an error: {exc}")
                result.findings.append(Finding(
                    port=445, service="SMB",
                    vulnerability="SMB Audit Module Error", severity="INFO", cvss="N/A",
                    description=f"The SMB audit module raised an unexpected exception: {exc}",
                    remediation="Re-run the scan or manually verify with 'nmap --script smb-security-mode'.",
                ))
        else:
            print("[*] Module 3 (SMB) skipped: Port 445 is Not Applicable/Closed")
            result.findings.append(Finding(
                port=445, service="SMB",
                vulnerability="Port Closed / Filtered",
                severity="INFO", cvss="N/A",
                description="Port 445 did not respond to a TCP connection attempt within the timeout window.",
                remediation="Not Applicable — no SMB service detected on this port.",
            ))

        print("-" * 70)
        print("[*] Generating HTML report...")
        ReportGenerator(result).generate(self.output_path)
        print(f"[+] Report written to: {os.path.abspath(self.output_path)}")

        if self.output_json:
            self._write_json(result)
            print(f"[+] JSON export written to: {os.path.abspath(self.output_json)}")

        counts = result.severity_counts()
        print("-" * 70)
        print("[*] Scan Summary:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SECURE", "INFO"]:
            if counts.get(sev, 0) > 0:
                print(f"    {sev:<10}: {counts[sev]}")
        print("-" * 70)

        return result

    def _write_json(self, result: ScanResult):
        payload = {
            "target": result.target,
            "timestamp": result.timestamp,
            "port_status": {str(k): v for k, v in result.port_status.items()},
            "findings": [
                {
                    "port": f.port,
                    "service": f.service,
                    "vulnerability": f.vulnerability,
                    "severity": f.severity,
                    "cvss": f.cvss,
                    "description": f.description,
                    "remediation": f.remediation,
                    "evidence": f.evidence,
                }
                for f in result.findings
            ],
        }
        with open(self.output_json, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)


# --------------------------------------------------------------------------
# CLI Entry Point
# --------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="eha.py",
        description=(
            "Enterprise Hardening Auditor (EHA) - Infrastructure VAPT tool for "
            "auditing SSH, TLS, and SMB misconfigurations against CIS Benchmark "
            "principles. AUTHORIZED SECURITY TESTING USE ONLY."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "target",
        help="Target IP address or hostname to audit (e.g., 192.168.1.10 or host.example.com)",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=4.0,
        help="Socket/connection timeout in seconds for each probe",
    )
    parser.add_argument(
        "-o", "--output",
        default="VAPT_Hardening_Report.html",
        help="Output path for the generated HTML report",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        default=None,
        help="Optional path to also export findings as JSON",
    )
    return parser


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    print("=" * 70)
    print(" ENTERPRISE HARDENING AUDITOR (EHA)")
    print(" Infrastructure VAPT Tool - CIS Benchmark Aligned")
    print(" FOR AUTHORIZED SECURITY TESTING USE ONLY")
    print("=" * 70)

    auditor = EnterpriseHardeningAuditor(
        target=args.target,
        timeout=args.timeout,
        output_path=args.output,
        output_json=args.json_output,
    )

    try:
        auditor.run()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(130)


if __name__ == "__main__":
    main()
