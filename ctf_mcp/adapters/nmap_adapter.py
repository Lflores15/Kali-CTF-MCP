"""
Nmap Adapter
Interface for nmap network scanning tool
"""

import os
import re
import tempfile
from typing import Any, Optional

from .base import ToolAdapter, AdapterResult
from ..utils.security import InputValidator, SecurityError, safe_xml_parse


class NmapAdapter(ToolAdapter):
    """
    Adapter for nmap network scanner.

    Provides:
    - Port scanning (TCP SYN/connect/UDP/ACK, all-ports)
    - Service and version detection
    - OS fingerprinting
    - Aggressive scan (-A)
    - Ping sweep / host discovery
    - Vulnerability scanning (NSE scripts)
    - Specific NSE script execution with structured output
    """

    @property
    def name(self) -> str:
        return "nmap"

    @property
    def tool_name(self) -> str:
        return "nmap"

    @property
    def description(self) -> str:
        return "Network exploration and security auditing tool"

    @property
    def min_version(self) -> Optional[str]:
        return "7.0"

    def _get_version(self) -> Optional[str]:
        result = self._run_command([self.tool_name, "--version"], timeout=10)
        if result.success:
            match = re.search(r'Nmap version (\d+\.\d+)', result.output)
            if match:
                return match.group(1)
        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_open_ports(output: str) -> list[dict]:
        """Parse nmap text output into a list of open-port dicts."""
        ports = []
        for line in output.splitlines():
            match = re.match(r'(\d+)/(\w+)\s+open\s+(\S+)\s*(.*)', line)
            if match:
                ports.append({
                    "port": int(match.group(1)),
                    "protocol": match.group(2),
                    "service": match.group(3),
                    "version": match.group(4).strip() or None,
                })
        return ports

    @staticmethod
    def _parse_nse_blocks(output: str) -> dict[str, list[str]]:
        """
        Parse NSE script output blocks into a dict keyed by script name.

        Handles both formats:
            Single-line:  |_http-title: Go ahead and ScanMe!
            Multi-line:   | ssh-hostkey:
                          |   2048 ab:cd:ef:... (RSA)
                          |_  256 aa:bb:cc:dd (ED25519)
        """
        scripts: dict[str, list[str]] = {}
        current: Optional[str] = None

        for line in output.splitlines():
            # Single-line NSE output: |_script-name: value on same line
            single = re.match(r'\|_\s*([\w\-]+):\s*(.*)', line)
            if single:
                scripts[single.group(1)] = [single.group(2).strip()]
                current = None
                continue

            # Multi-line header: | script-name:  (nothing after colon)
            header = re.match(r'\|\s*([\w\-]+):\s*$', line)
            if header:
                current = header.group(1)
                scripts[current] = []
                continue

            # Content lines belonging to current multi-line block
            if current and re.match(r'\|', line):
                content = re.sub(r'^\|_?\s*', '', line).strip()
                if content:
                    scripts[current].append(content)
            elif line and not line.startswith('|'):
                current = None

        return scripts

    # ------------------------------------------------------------------
    # Scan methods
    # ------------------------------------------------------------------

    def scan_ports(
        self,
        target: str,
        ports: str = "1-1000",
        scan_type: str = "connect",
        all_ports: bool = False,
        timeout: int = 300,
    ) -> AdapterResult:
        """
        Scan ports on a target host or network.

        Args:
            target: IP, hostname, CIDR (10.10.10.0/24), or range (10.10.10.1-50)
            ports: Port spec e.g. "1-1000", "80,443,8080" (ignored if all_ports=True)
            scan_type: syn | connect | udp | ack | fin
            all_ports: If True, scan all 65535 ports (-p-)
            timeout: Scan timeout in seconds
        """
        result = AdapterResult()

        try:
            target = InputValidator.validate_scan_target(target)
            if not all_ports:
                ports = InputValidator.validate_port_spec(ports)
        except SecurityError as e:
            result.error = str(e)
            return result

        scan_flags = {
            "syn": "-sS",
            "connect": "-sT",
            "udp": "-sU",
            "ack": "-sA",
            "fin": "-sF",
        }
        flag = scan_flags.get(scan_type, "-sT")

        port_arg = "-" if all_ports else ports

        args = [
            self.tool_name,
            flag,
            "-p", port_arg,
            "-T4",
            "--open",
            target,
        ]

        result = self._run_command(args, timeout=timeout)

        if result.success:
            open_ports = self._parse_open_ports(result.output)
            result.data = {
                "target": target,
                "scan_type": scan_type,
                "all_ports": all_ports,
                "open_ports": open_ports,
                "count": len(open_ports),
            }

        return result

    def service_scan(
        self,
        target: str,
        ports: Optional[str] = None,
        timeout: int = 300,
    ) -> AdapterResult:
        """
        Detect services and versions on target (-sV -sC).

        Args:
            target: IP, hostname, CIDR, or range
            ports: Port spec (None = nmap default top 1000)
            timeout: Scan timeout in seconds
        """
        result = AdapterResult()

        try:
            target = InputValidator.validate_scan_target(target)
            if ports:
                ports = InputValidator.validate_port_spec(ports)
        except SecurityError as e:
            result.error = str(e)
            return result

        args = [self.tool_name, "-sV", "-sC", "-T4", target]
        if ports:
            args.extend(["-p", ports])

        result = self._run_command(args, timeout=timeout)

        if result.success:
            services = self._parse_open_ports(result.output)
            nse_output = self._parse_nse_blocks(result.output)
            result.data = {
                "target": target,
                "services": services,
                "nse_output": nse_output,
            }

        return result

    def aggressive_scan(
        self,
        target: str,
        ports: Optional[str] = None,
        timeout: int = 300,
    ) -> AdapterResult:
        """
        Aggressive scan: OS detect + version + default scripts + traceroute (-A).
        This is the standard first scan for HTB/NCL boxes.

        Args:
            target: IP, hostname, CIDR, or range
            ports: Port spec (None = nmap default top 1000)
            timeout: Scan timeout in seconds
        """
        result = AdapterResult()

        try:
            target = InputValidator.validate_scan_target(target)
            if ports:
                ports = InputValidator.validate_port_spec(ports)
        except SecurityError as e:
            result.error = str(e)
            return result

        args = [self.tool_name, "-A", "-T4", target]
        if ports:
            args.extend(["-p", ports])

        result = self._run_command(args, timeout=timeout)

        if result.success:
            services = self._parse_open_ports(result.output)
            nse_output = self._parse_nse_blocks(result.output)

            # Extract OS guess
            os_matches = []
            for line in result.output.splitlines():
                if re.match(r'OS (details|guess|CPE):', line, re.IGNORECASE):
                    os_matches.append(line.strip())
                elif "Running:" in line:
                    os_matches.append(line.strip())

            result.data = {
                "target": target,
                "services": services,
                "os_matches": os_matches,
                "nse_output": nse_output,
            }

        return result

    def ping_sweep(
        self,
        target: str,
        timeout: int = 120,
    ) -> AdapterResult:
        """
        Host discovery without port scanning (-sn).
        Useful for finding live hosts on a subnet.

        Args:
            target: IP, hostname, CIDR (e.g. 10.10.10.0/24), or range
            timeout: Scan timeout in seconds
        """
        result = AdapterResult()

        try:
            target = InputValidator.validate_scan_target(target)
        except SecurityError as e:
            result.error = str(e)
            return result

        args = [self.tool_name, "-sn", "-T4", target]

        result = self._run_command(args, timeout=timeout)

        if result.success:
            live_hosts = []
            for line in result.output.splitlines():
                match = re.search(r'Nmap scan report for (.+)', line)
                if match:
                    live_hosts.append(match.group(1).strip())

            result.data = {
                "target": target,
                "live_hosts": live_hosts,
                "count": len(live_hosts),
            }

        return result

    def os_detect(
        self,
        target: str,
        timeout: int = 300,
    ) -> AdapterResult:
        """
        Detect operating system (-O).

        Args:
            target: IP or hostname (CIDR not useful for OS detect)
            timeout: Scan timeout in seconds
        """
        result = AdapterResult()

        try:
            target = InputValidator.validate_scan_target(target)
        except SecurityError as e:
            result.error = str(e)
            return result

        args = [self.tool_name, "-O", "-T4", target]

        result = self._run_command(args, timeout=timeout)

        if result.success:
            os_matches = []
            for line in result.output.splitlines():
                if re.match(r'(OS details|Running|OS CPE|Aggressive OS):', line, re.IGNORECASE):
                    os_matches.append(line.strip())

            result.data = {
                "target": target,
                "os_matches": os_matches,
            }

        return result

    def vuln_scan(
        self,
        target: str,
        ports: Optional[str] = None,
        timeout: int = 600,
    ) -> AdapterResult:
        """
        Scan for vulnerabilities using NSE vuln scripts.

        Args:
            target: IP, hostname, CIDR, or range
            ports: Port spec
            timeout: Scan timeout in seconds
        """
        result = AdapterResult()

        try:
            target = InputValidator.validate_scan_target(target)
            if ports:
                ports = InputValidator.validate_port_spec(ports)
        except SecurityError as e:
            result.error = str(e)
            return result

        args = [self.tool_name, "--script", "vuln", "-T4", target]
        if ports:
            args.extend(["-p", ports])

        result = self._run_command(args, timeout=timeout)

        if result.success:
            nse_output = self._parse_nse_blocks(result.output)

            # Pull out entries that mention VULNERABLE
            vulnerabilities = []
            current_vuln: Optional[dict] = None
            for line in result.output.splitlines():
                if "VULNERABLE" in line:
                    if current_vuln:
                        vulnerabilities.append(current_vuln)
                    current_vuln = {"title": line.strip(), "details": []}
                elif current_vuln and line.strip().startswith("|"):
                    info = re.sub(r'^\|_?\s*', '', line).strip()
                    if info:
                        current_vuln["details"].append(info)
                elif current_vuln and line and not line.startswith("|"):
                    current_vuln = None

            if current_vuln:
                vulnerabilities.append(current_vuln)

            result.data = {
                "target": target,
                "vulnerabilities": vulnerabilities,
                "vuln_count": len(vulnerabilities),
                "nse_output": nse_output,
            }

        return result

    def quick_scan(
        self,
        target: str,
        timeout: int = 120,
    ) -> AdapterResult:
        """
        Fast scan of top 100 ports (-F).

        Args:
            target: IP, hostname, CIDR, or range
            timeout: Scan timeout in seconds
        """
        result = AdapterResult()

        try:
            target = InputValidator.validate_scan_target(target)
        except SecurityError as e:
            result.error = str(e)
            return result

        args = [self.tool_name, "-F", "-T4", "--open", target]

        result = self._run_command(args, timeout=timeout)

        if result.success:
            open_ports = self._parse_open_ports(result.output)
            result.data = {
                "target": target,
                "open_ports": open_ports,
                "count": len(open_ports),
            }

        return result

    def script_scan(
        self,
        target: str,
        scripts: str,
        ports: Optional[str] = None,
        script_args: Optional[str] = None,
        timeout: int = 300,
    ) -> AdapterResult:
        """
        Run specific NSE scripts and return structured output.

        Args:
            target: IP, hostname, CIDR, or range
            scripts: Script names or category (e.g. "http-title,http-headers" or "safe")
            ports: Port spec
            script_args: Script arguments (e.g. "http.useragent=Mozilla")
            timeout: Scan timeout in seconds
        """
        result = AdapterResult()

        try:
            target = InputValidator.validate_scan_target(target)
            scripts = InputValidator.validate_nse_script(scripts)
            if ports:
                ports = InputValidator.validate_port_spec(ports)
            if script_args:
                if not re.match(r'^[\w\-.,=:/@]+$', script_args):
                    raise SecurityError(f"Invalid script arguments: {script_args}")
        except SecurityError as e:
            result.error = str(e)
            return result

        args = [self.tool_name, "--script", scripts, "-T4", target]
        if ports:
            args.extend(["-p", ports])
        if script_args:
            args.extend(["--script-args", script_args])

        result = self._run_command(args, timeout=timeout)

        if result.success:
            nse_output = self._parse_nse_blocks(result.output)
            result.data = {
                "target": target,
                "scripts": scripts,
                "nse_output": nse_output,
            }

        return result

    def scan_to_xml(
        self,
        target: str,
        ports: Optional[str] = None,
        timeout: int = 300,
    ) -> AdapterResult:
        """
        Run a service scan and return fully parsed XML data.

        Args:
            target: IP, hostname, CIDR, or range
            ports: Port spec
            timeout: Scan timeout in seconds
        """
        result = AdapterResult()

        try:
            target = InputValidator.validate_scan_target(target)
            if ports:
                ports = InputValidator.validate_port_spec(ports)
        except SecurityError as e:
            result.error = str(e)
            return result

        tmp = tempfile.NamedTemporaryFile(suffix='.xml', delete=False)
        tmp.close()

        try:
            args = [self.tool_name, "-sV", "-T4", "-oX", tmp.name, target]
            if ports:
                args.extend(["-p", ports])

            result = self._run_command(args, timeout=timeout)

            if result.success:
                try:
                    tree = safe_xml_parse(tmp.name)
                    root = tree.getroot()

                    hosts = []
                    for host in root.findall('host'):
                        host_data: dict[str, Any] = {
                            "addresses": [],
                            "hostnames": [],
                            "ports": [],
                            "os": None,
                        }

                        for addr in host.findall('address'):
                            host_data["addresses"].append({
                                "addr": addr.get('addr'),
                                "type": addr.get('addrtype'),
                            })

                        for hn in host.findall('.//hostname'):
                            host_data["hostnames"].append(hn.get('name'))

                        for port in host.findall('.//port'):
                            state = port.find('state')
                            if state is not None and state.get('state') != 'open':
                                continue
                            port_data: dict[str, Any] = {
                                "port": int(port.get('portid')),
                                "protocol": port.get('protocol'),
                                "state": state.get('state') if state is not None else None,
                            }
                            service = port.find('service')
                            if service is not None:
                                port_data["service"] = service.get('name')
                                port_data["product"] = service.get('product')
                                port_data["version"] = service.get('version')
                                port_data["extrainfo"] = service.get('extrainfo')

                            # NSE script output per port
                            port_scripts: dict[str, str] = {}
                            for script in port.findall('script'):
                                port_scripts[script.get('id', '')] = script.get('output', '')
                            if port_scripts:
                                port_data["scripts"] = port_scripts

                            host_data["ports"].append(port_data)

                        # OS detection
                        os_elem = host.find('.//osmatch')
                        if os_elem is not None:
                            host_data["os"] = {
                                "name": os_elem.get('name'),
                                "accuracy": os_elem.get('accuracy'),
                            }

                        hosts.append(host_data)

                    result.data = {"hosts": hosts}

                except Exception as e:
                    result.error = f"XML parse error: {e}"

        finally:
            # Always clean up the temp file
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

        return result
