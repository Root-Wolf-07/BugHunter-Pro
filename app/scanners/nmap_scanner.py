"""
Bug Hunter AI — Nmap Scanner Integration
Uses safe XML output and argument arrays. No shell injection.
"""
from __future__ import annotations

import logging
import tempfile
import os
from typing import Any, Dict, List, Optional, Tuple

import defusedxml.ElementTree as ET

from app.scanners.base import SecurityScanner

logger = logging.getLogger(__name__)


class NmapScanner(SecurityScanner):
    """Nmap network scanner integration."""

    name = "nmap"
    description = "Network mapper — host discovery, port scanning, service/version detection"
    category = "network"

    def scan(
        self,
        target: str,
        scan_id: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, Any]:
        """Run nmap and return (raw_xml, parsed_dict)."""
        opts = options or {}

        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tf:
            xml_path = tf.name

        try:
            # Build argument array — no shell concatenation
            args = [
                "nmap",
                "-sV",           # service/version detection
                "--open",        # only show open ports
                "-oX", xml_path, # XML output
                "--host-timeout", str(opts.get("host_timeout", "60s")),
            ]

            # Add any extra safe flags from options
            extra_flags = opts.get("extra_flags", [])
            if isinstance(extra_flags, list):
                args.extend(extra_flags)

            args.append(target)

            logger.info(f"Running nmap: {' '.join(args)}")
            stdout, stderr, rc = self._run_subprocess(args, timeout=300)

            # Read XML output
            raw_xml = ""
            if os.path.exists(xml_path):
                with open(xml_path, "r", encoding="utf-8", errors="replace") as f:
                    raw_xml = f.read()

            parsed = self.parse_results(raw_xml)
            return raw_xml, parsed

        finally:
            if os.path.exists(xml_path):
                os.unlink(xml_path)

    def parse_results(self, raw_output: str) -> List[Dict[str, Any]]:
        """Parse nmap XML output into a list of finding dicts."""
        findings: List[Dict[str, Any]] = []

        if not raw_output.strip():
            return findings

        try:
            root = ET.fromstring(raw_output)
        except ET.ParseError as exc:
            logger.warning(f"Nmap XML parse error: {exc}")
            return findings

        for host in root.findall("host"):
            # Get address
            addr_el = host.find("address")
            ip = addr_el.get("addr", "unknown") if addr_el is not None else "unknown"

            # Get hostname
            hostnames = host.find("hostnames")
            hostname = ""
            if hostnames is not None:
                hn = hostnames.find("hostname")
                if hn is not None:
                    hostname = hn.get("name", "")

            display = hostname or ip

            ports = host.find("ports")
            if ports is None:
                continue

            for port in ports.findall("port"):
                portid = port.get("portid", "?")
                protocol = port.get("protocol", "tcp")

                state_el = port.find("state")
                state = state_el.get("state", "unknown") if state_el is not None else "unknown"
                if state != "open":
                    continue

                service_el = port.find("service")
                service_name = ""
                service_version = ""
                if service_el is not None:
                    service_name = service_el.get("name", "")
                    product = service_el.get("product", "")
                    version = service_el.get("version", "")
                    service_version = f"{product} {version}".strip()

                # Determine basic severity for exposed services
                severity = _service_severity(service_name, portid)

                findings.append({
                    "title": f"Open Port {portid}/{protocol} — {service_name or 'unknown'}",
                    "category": "network_exposure",
                    "severity": severity,
                    "confidence": "CONFIRMED",
                    "affected_component": f"{display}:{portid}/{protocol}",
                    "description": (
                        f"Port {portid}/{protocol} is open on {display}. "
                        f"Service detected: {service_name} {service_version}".strip()
                    ),
                    "evidence": (
                        f"Nmap detected open port {portid}/{protocol} on {ip}. "
                        f"Service: {service_name} {service_version}".strip()
                    ),
                    "detected_by": "nmap",
                    "raw_finding": {
                        "ip": ip,
                        "hostname": hostname,
                        "port": portid,
                        "protocol": protocol,
                        "service": service_name,
                        "version": service_version,
                    },
                })

        return findings


def _service_severity(service: str, port: str) -> str:
    """Assign a base severity based on service type and port number."""
    high_risk_services = {"telnet", "ftp", "rsh", "rlogin", "rexec", "tftp", "finger"}
    medium_risk_services = {"http", "smtp", "pop3", "imap", "snmp", "rdp", "vnc"}
    high_risk_ports = {"23", "21", "512", "513", "514", "69", "79", "135", "445"}

    svc = service.lower()
    if svc in high_risk_services or port in high_risk_ports:
        return "HIGH"
    if svc in medium_risk_services:
        return "MEDIUM"
    if svc in {"ssh", "https", "tls"}:
        return "INFO"
    return "LOW"
