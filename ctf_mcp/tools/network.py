"""
Network Tools Module for CTF-MCP
Nmap-based network scanning and enumeration tools for CTF challenges
"""

from ..adapters.nmap_adapter import NmapAdapter


class NetworkTools:
    """Network scanning and enumeration tools for CTF challenges"""

    def __init__(self):
        self._nmap = NmapAdapter()

    def _nmap_unavailable(self) -> str:
        return "nmap is not installed or not in PATH. Install with: sudo apt install nmap"

    def get_tools(self) -> dict[str, str]:
        """Return available tools and their descriptions"""
        return {
            "quick_scan": "Fast scan of top 100 ports on a target (-F). Good first look at a box.",
            "port_scan": "Scan a specific port range or all 65535 ports on a target.",
            "service_scan": "Detect service names and versions on open ports (-sV -sC).",
            "aggressive_scan": "Full aggressive scan: OS + versions + default scripts + traceroute (-A). Standard first scan for HTB/NCL.",
            "ping_sweep": "Discover live hosts on a subnet without port scanning (-sn). Accepts CIDR e.g. 10.10.10.0/24.",
            "os_detect": "Fingerprint the operating system of a target (-O).",
            "vuln_scan": "Run NSE vuln scripts to find known CVEs and misconfigs.",
            "script_scan": "Run specific NSE scripts against a target (e.g. http-title, smb-enum-shares).",
        }

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    def quick_scan(self, target: str, timeout: int = 120) -> str:
        """
        Fast scan of the top 100 most common ports.
        Good for a quick first look at what is running on a box.

        :param target: IP address, hostname, CIDR range (10.10.10.0/24), or IP range (10.10.10.1-50)
        :param timeout: Maximum scan time in seconds
        """
        if not self._nmap.is_available:
            return self._nmap_unavailable()

        result = self._nmap.quick_scan(target=target, timeout=timeout)

        if not result.success:
            return f"Scan failed: {result.error}\n\nRaw output:\n{result.output}"

        data = result.data
        lines = [
            f"Quick scan of {data['target']}",
            f"Open ports ({data['count']}):",
            "-" * 40,
        ]
        for p in data["open_ports"]:
            ver = f"  {p['version']}" if p.get("version") else ""
            lines.append(f"  {p['port']}/{p['protocol']}  {p['service']}{ver}")

        if not data["open_ports"]:
            lines.append("  No open ports found in top 100.")

        lines.append("")
        lines.append(result.output)
        return "\n".join(lines)

    def port_scan(
        self,
        target: str,
        ports: str = "1-1000",
        scan_type: str = "connect",
        all_ports: bool = False,
        timeout: int = 300,
    ) -> str:
        """
        Scan a port range on a target.

        :param target: IP address, hostname, CIDR range, or IP range
        :param ports: Port specification e.g. "1-1000", "80,443,8080" (ignored if all_ports=True)
        :param scan_type: Scan technique: connect (default), syn (needs root), udp, ack, fin
        :param all_ports: If true, scan all 65535 ports (-p-). Slow but thorough.
        :param timeout: Maximum scan time in seconds
        """
        if not self._nmap.is_available:
            return self._nmap_unavailable()

        result = self._nmap.scan_ports(
            target=target,
            ports=ports,
            scan_type=scan_type,
            all_ports=all_ports,
            timeout=timeout,
        )

        if not result.success:
            return f"Scan failed: {result.error}\n\nRaw output:\n{result.output}"

        data = result.data
        label = "all ports" if data["all_ports"] else ports
        lines = [
            f"Port scan of {data['target']} [{label}] ({data['scan_type']})",
            f"Open ports ({data['count']}):",
            "-" * 40,
        ]
        for p in data["open_ports"]:
            ver = f"  {p['version']}" if p.get("version") else ""
            lines.append(f"  {p['port']}/{p['protocol']}  {p['service']}{ver}")

        if not data["open_ports"]:
            lines.append("  No open ports found.")

        lines.append("")
        lines.append(result.output)
        return "\n".join(lines)

    def service_scan(
        self,
        target: str,
        ports: str = None,
        timeout: int = 300,
    ) -> str:
        """
        Detect service names and versions on open ports (-sV -sC).
        Also runs default NSE scripts (banner grab, HTTP title, SSH hostkey, etc.).

        :param target: IP address, hostname, CIDR range, or IP range
        :param ports: Port specification (default: nmap top 1000)
        :param timeout: Maximum scan time in seconds
        """
        if not self._nmap.is_available:
            return self._nmap_unavailable()

        result = self._nmap.service_scan(target=target, ports=ports, timeout=timeout)

        if not result.success:
            return f"Scan failed: {result.error}\n\nRaw output:\n{result.output}"

        data = result.data
        lines = [
            f"Service scan of {data['target']}",
            f"Services ({len(data['services'])}):",
            "-" * 40,
        ]
        for s in data["services"]:
            ver = f"  {s['version']}" if s.get("version") else ""
            lines.append(f"  {s['port']}/{s['protocol']}  {s['service']}{ver}")

        if data.get("nse_output"):
            lines.append("\nNSE Script Output:")
            lines.append("-" * 40)
            for script, output_lines in data["nse_output"].items():
                lines.append(f"  [{script}]")
                for ol in output_lines:
                    lines.append(f"    {ol}")

        lines.append("")
        lines.append(result.output)
        return "\n".join(lines)

    def aggressive_scan(
        self,
        target: str,
        ports: str = None,
        timeout: int = 300,
    ) -> str:
        """
        Aggressive scan combining OS detection, version detection, default NSE scripts,
        and traceroute (-A). This is the standard first scan for HTB and NCL boxes.

        :param target: IP address, hostname, CIDR range, or IP range
        :param ports: Port specification (default: nmap top 1000)
        :param timeout: Maximum scan time in seconds
        """
        if not self._nmap.is_available:
            return self._nmap_unavailable()

        result = self._nmap.aggressive_scan(target=target, ports=ports, timeout=timeout)

        if not result.success:
            return f"Scan failed: {result.error}\n\nRaw output:\n{result.output}"

        data = result.data
        lines = [
            f"Aggressive scan of {data['target']}",
            "-" * 40,
        ]

        if data.get("os_matches"):
            lines.append("OS Detection:")
            for os in data["os_matches"]:
                lines.append(f"  {os}")
            lines.append("")

        lines.append(f"Services ({len(data['services'])}):")
        for s in data["services"]:
            ver = f"  {s['version']}" if s.get("version") else ""
            lines.append(f"  {s['port']}/{s['protocol']}  {s['service']}{ver}")

        if data.get("nse_output"):
            lines.append("\nNSE Script Output:")
            lines.append("-" * 40)
            for script, output_lines in data["nse_output"].items():
                lines.append(f"  [{script}]")
                for ol in output_lines:
                    lines.append(f"    {ol}")

        lines.append("")
        lines.append(result.output)
        return "\n".join(lines)

    def ping_sweep(self, target: str, timeout: int = 120) -> str:
        """
        Discover live hosts on a network without port scanning (-sn).
        Accepts CIDR notation for subnet sweeps.

        :param target: IP address, hostname, CIDR range (e.g. 10.10.10.0/24), or IP range (e.g. 10.10.10.1-50)
        :param timeout: Maximum scan time in seconds
        """
        if not self._nmap.is_available:
            return self._nmap_unavailable()

        result = self._nmap.ping_sweep(target=target, timeout=timeout)

        if not result.success:
            return f"Sweep failed: {result.error}\n\nRaw output:\n{result.output}"

        data = result.data
        lines = [
            f"Ping sweep of {data['target']}",
            f"Live hosts ({data['count']}):",
            "-" * 40,
        ]
        for host in data["live_hosts"]:
            lines.append(f"  {host}")

        if not data["live_hosts"]:
            lines.append("  No live hosts found.")

        lines.append("")
        lines.append(result.output)
        return "\n".join(lines)

    def os_detect(self, target: str, timeout: int = 300) -> str:
        """
        Fingerprint the operating system of a target (-O).
        Requires root/sudo privileges for best results.

        :param target: IP address or hostname
        :param timeout: Maximum scan time in seconds
        """
        if not self._nmap.is_available:
            return self._nmap_unavailable()

        result = self._nmap.os_detect(target=target, timeout=timeout)

        if not result.success:
            return f"OS detection failed: {result.error}\n\nRaw output:\n{result.output}"

        data = result.data
        lines = [
            f"OS detection for {data['target']}",
            "-" * 40,
        ]
        for match in data.get("os_matches", []):
            lines.append(f"  {match}")

        if not data.get("os_matches"):
            lines.append("  OS could not be determined.")
            lines.append("  Tip: Run as root/sudo for better OS detection accuracy.")

        lines.append("")
        lines.append(result.output)
        return "\n".join(lines)

    def vuln_scan(
        self,
        target: str,
        ports: str = None,
        timeout: int = 600,
    ) -> str:
        """
        Run NSE vuln category scripts to find known CVEs and misconfigurations.

        :param target: IP address, hostname, CIDR range, or IP range
        :param ports: Port specification (default: nmap top 1000)
        :param timeout: Maximum scan time in seconds
        """
        if not self._nmap.is_available:
            return self._nmap_unavailable()

        result = self._nmap.vuln_scan(target=target, ports=ports, timeout=timeout)

        if not result.success:
            return f"Vuln scan failed: {result.error}\n\nRaw output:\n{result.output}"

        data = result.data
        lines = [
            f"Vulnerability scan of {data['target']}",
            f"Vulnerabilities found: {data['vuln_count']}",
            "-" * 40,
        ]

        for vuln in data.get("vulnerabilities", []):
            lines.append(f"  {vuln['title']}")
            for detail in vuln.get("details", []):
                lines.append(f"    {detail}")
            lines.append("")

        if data.get("nse_output"):
            lines.append("All NSE Output:")
            lines.append("-" * 40)
            for script, output_lines in data["nse_output"].items():
                lines.append(f"  [{script}]")
                for ol in output_lines:
                    lines.append(f"    {ol}")

        lines.append("")
        lines.append(result.output)
        return "\n".join(lines)

    def script_scan(
        self,
        target: str,
        scripts: str,
        ports: str = None,
        script_args: str = None,
        timeout: int = 300,
    ) -> str:
        """
        Run specific NSE scripts against a target and return structured output.
        Common scripts for HTB/NCL: http-title, smb-enum-shares, ftp-anon,
        ssh-auth-methods, http-robots.txt, dns-zone-transfer, smtp-commands.

        :param target: IP address, hostname, CIDR range, or IP range
        :param scripts: Script name(s) or category e.g. "http-title" or "http-title,http-headers" or "safe"
        :param ports: Port specification (default: nmap top 1000)
        :param script_args: Script arguments e.g. "http.useragent=Mozilla"
        :param timeout: Maximum scan time in seconds
        """
        if not self._nmap.is_available:
            return self._nmap_unavailable()

        result = self._nmap.script_scan(
            target=target,
            scripts=scripts,
            ports=ports,
            script_args=script_args,
            timeout=timeout,
        )

        if not result.success:
            return f"Script scan failed: {result.error}\n\nRaw output:\n{result.output}"

        data = result.data
        lines = [
            f"NSE script scan of {data['target']} (scripts: {data['scripts']})",
            "-" * 40,
        ]

        if data.get("nse_output"):
            for script, output_lines in data["nse_output"].items():
                lines.append(f"  [{script}]")
                for ol in output_lines:
                    lines.append(f"    {ol}")
                lines.append("")
        else:
            lines.append("  No NSE output parsed. See raw output below.")

        lines.append(result.output)
        return "\n".join(lines)
