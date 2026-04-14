"""
TShark Adapter
Interface for tshark (Wireshark CLI) for PCAP analysis
"""

import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Optional

from .base import ToolAdapter, AdapterResult
from ..utils.security import InputValidator, SecurityError


def _find_tshark_binary() -> str:
    """
    Locate the tshark binary.

    Search order:
    1. System PATH
    2. Wireshark macOS app bundle
    3. Common install locations
    """
    if shutil.which("tshark"):
        return "tshark"

    # macOS Wireshark app bundle
    mac_path = Path("/Applications/Wireshark.app/Contents/MacOS/tshark")
    if mac_path.is_file() and os.access(mac_path, os.X_OK):
        return str(mac_path)

    # Common Linux locations
    for candidate in ["/usr/bin/tshark", "/usr/local/bin/tshark", "/opt/wireshark/bin/tshark"]:
        p = Path(candidate)
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)

    return "tshark"


def _find_capinfos_binary() -> Optional[str]:
    """Locate capinfos, co-installed with tshark/wireshark."""
    if shutil.which("capinfos"):
        return "capinfos"

    mac_path = Path("/Applications/Wireshark.app/Contents/MacOS/capinfos")
    if mac_path.is_file() and os.access(mac_path, os.X_OK):
        return str(mac_path)

    return None


class TSharkAdapter(ToolAdapter):
    """
    Adapter for tshark (Wireshark CLI) PCAP analysis.

    Wraps tshark and capinfos to analyze packet capture files.
    Supports protocol hierarchy, stream following, field extraction,
    object export, and display filter queries.
    """

    def __init__(self):
        super().__init__()
        self._tshark = _find_tshark_binary()
        self._capinfos = _find_capinfos_binary()

    @property
    def name(self) -> str:
        return "tshark"

    @property
    def tool_name(self) -> str:
        return self._tshark

    @property
    def description(self) -> str:
        return "TShark Wireshark CLI PCAP analyzer"

    @property
    def min_version(self) -> Optional[str]:
        return None

    def _get_version(self) -> Optional[str]:
        result = self._run_command([self.tool_name, "--version"], timeout=10)
        if result.success or result.return_code == 0:
            match = re.search(r'TShark[^\d]+([\d.]+)', result.output)
            if match:
                return match.group(1)
        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _validate_file(self, file_path: str) -> str:
        try:
            return InputValidator.validate_file_path(
                file_path, must_exist=True, allow_absolute=True
            )
        except Exception as e:
            raise SecurityError(str(e))

    def _validate_display_filter(self, display_filter: str) -> str:
        """Validate tshark display filter — reject shell metacharacters."""
        if any(c in display_filter for c in InputValidator.SHELL_METACHARACTERS):
            raise SecurityError(f"Invalid characters in display filter: {display_filter}")
        return display_filter

    def _validate_stream_index(self, index: int) -> int:
        if not isinstance(index, int) or index < 0 or index > 100000:
            raise SecurityError(f"Invalid stream index: {index}")
        return index

    def _tshark_cmd(self, pcap_file: str, extra_args: list[str]) -> list[str]:
        return [self._tshark, "-r", pcap_file] + extra_args

    # ------------------------------------------------------------------
    # Plugin methods
    # ------------------------------------------------------------------

    def summary(self, pcap_file: str, timeout: int = 30) -> AdapterResult:
        """Get file summary: packet count, duration, file size, data rate."""
        result = AdapterResult()
        try:
            pcap_file = self._validate_file(pcap_file)
        except SecurityError as e:
            result.error = str(e)
            return result

        # Use capinfos if available for a richer summary
        if self._capinfos:
            r = self._run_command([self._capinfos, pcap_file], timeout=timeout)
            if r.success or r.return_code == 0:
                r.success = True
                r.data = {"source": "capinfos", "raw": r.output}
                return r

        # Fallback: tshark -q -z io,phs gives protocol counts
        r = self._run_command(
            self._tshark_cmd(pcap_file, ["-q", "-z", "io,phs"]),
            timeout=timeout,
        )
        if r.return_code == 0:
            r.success = True
        r.data = {"source": "tshark", "raw": r.output}
        return r

    def protocol_hierarchy(self, pcap_file: str, timeout: int = 60) -> AdapterResult:
        """Show protocol breakdown of the capture."""
        result = AdapterResult()
        try:
            pcap_file = self._validate_file(pcap_file)
        except SecurityError as e:
            result.error = str(e)
            return result

        r = self._run_command(
            self._tshark_cmd(pcap_file, ["-q", "-z", "io,phs"]),
            timeout=timeout,
        )
        if r.return_code == 0:
            r.success = True
        r.data = {"raw": r.output}
        return r

    def conversations(
        self,
        pcap_file: str,
        proto: str = "tcp",
        timeout: int = 60,
    ) -> AdapterResult:
        """List conversations (who talked to whom) for a protocol."""
        result = AdapterResult()
        try:
            pcap_file = self._validate_file(pcap_file)
        except SecurityError as e:
            result.error = str(e)
            return result

        allowed = {"tcp", "udp", "ip", "eth"}
        proto = proto.lower()
        if proto not in allowed:
            result.error = f"Protocol must be one of: {', '.join(sorted(allowed))}"
            return result

        r = self._run_command(
            self._tshark_cmd(pcap_file, ["-q", "-z", f"conv,{proto}"]),
            timeout=timeout,
        )
        if r.return_code == 0:
            r.success = True
        r.data = {"protocol": proto, "raw": r.output}
        return r

    def follow_stream(
        self,
        pcap_file: str,
        stream_index: int = 0,
        proto: str = "tcp",
        mode: str = "ascii",
        timeout: int = 60,
    ) -> AdapterResult:
        """Follow a TCP/UDP stream and return its contents."""
        result = AdapterResult()
        try:
            pcap_file = self._validate_file(pcap_file)
            stream_index = self._validate_stream_index(stream_index)
        except SecurityError as e:
            result.error = str(e)
            return result

        proto = proto.lower()
        if proto not in {"tcp", "udp", "http", "tls"}:
            result.error = "Protocol must be tcp, udp, http, or tls"
            return result

        mode = mode.lower()
        if mode not in {"ascii", "hex", "raw"}:
            result.error = "Mode must be ascii, hex, or raw"
            return result

        r = self._run_command(
            self._tshark_cmd(pcap_file, ["-q", "-z", f"follow,{proto},{mode},{stream_index}"]),
            timeout=timeout,
        )
        if r.return_code == 0:
            r.success = True
        r.data = {"proto": proto, "stream": stream_index, "mode": mode, "raw": r.output}
        return r

    def http_requests(self, pcap_file: str, timeout: int = 60) -> AdapterResult:
        """Extract HTTP requests: method, host, URI, response code."""
        result = AdapterResult()
        try:
            pcap_file = self._validate_file(pcap_file)
        except SecurityError as e:
            result.error = str(e)
            return result

        fields = [
            "frame.number", "ip.src", "ip.dst",
            "http.request.method", "http.host", "http.request.uri",
            "http.response.code",
        ]
        args = ["-Y", "http", "-T", "fields"]
        for f in fields:
            args += ["-e", f]
        args += ["-E", "separator=|", "-E", "header=y"]

        r = self._run_command(self._tshark_cmd(pcap_file, args), timeout=timeout)
        if r.return_code == 0:
            r.success = True
            r.data = {"requests": self._parse_fields(r.output, fields)}
        return r

    def dns_queries(self, pcap_file: str, timeout: int = 60) -> AdapterResult:
        """Extract DNS queries and responses."""
        result = AdapterResult()
        try:
            pcap_file = self._validate_file(pcap_file)
        except SecurityError as e:
            result.error = str(e)
            return result

        fields = ["frame.number", "ip.src", "dns.qry.name", "dns.resp.name", "dns.a", "dns.aaaa"]
        args = ["-Y", "dns", "-T", "fields"]
        for f in fields:
            args += ["-e", f]
        args += ["-E", "separator=|", "-E", "header=y"]

        r = self._run_command(self._tshark_cmd(pcap_file, args), timeout=timeout)
        if r.return_code == 0:
            r.success = True
            r.data = {"queries": self._parse_fields(r.output, fields)}
        return r

    def credentials(self, pcap_file: str, timeout: int = 60) -> AdapterResult:
        """Extract credentials: FTP user/pass, HTTP Basic auth, Telnet."""
        result = AdapterResult()
        try:
            pcap_file = self._validate_file(pcap_file)
        except SecurityError as e:
            result.error = str(e)
            return result

        creds = []
        found_output = []

        # FTP credentials
        ftp_filter = 'ftp.request.command == "USER" || ftp.request.command == "PASS"'
        ftp_fields = ["frame.number", "ip.src", "ftp.request.command", "ftp.request.arg"]
        args = ["-Y", ftp_filter, "-T", "fields"]
        for f in ftp_fields:
            args += ["-e", f]
        args += ["-E", "separator=|"]
        r = self._run_command(self._tshark_cmd(pcap_file, args), timeout=timeout)
        if r.return_code == 0 and r.output.strip():
            found_output.append("=== FTP ===\n" + r.output)
            for line in r.output.strip().splitlines():
                parts = line.split("|")
                if len(parts) >= 4:
                    creds.append({"proto": "FTP", "frame": parts[0], "src": parts[1],
                                  "command": parts[2], "value": parts[3]})

        # HTTP Basic auth
        http_fields = ["frame.number", "ip.src", "http.host", "http.authbasic"]
        args = ["-Y", "http.authbasic", "-T", "fields"]
        for f in http_fields:
            args += ["-e", f]
        args += ["-E", "separator=|"]
        r = self._run_command(self._tshark_cmd(pcap_file, args), timeout=timeout)
        if r.return_code == 0 and r.output.strip():
            found_output.append("=== HTTP Basic Auth ===\n" + r.output)
            for line in r.output.strip().splitlines():
                parts = line.split("|")
                if len(parts) >= 4:
                    creds.append({"proto": "HTTP Basic", "frame": parts[0], "src": parts[1],
                                  "host": parts[2], "credentials": parts[3]})

        result.success = True
        result.output = "\n".join(found_output) if found_output else "No credentials found"
        result.data = {"credentials": creds}
        return result

    def export_objects(
        self,
        pcap_file: str,
        proto: str = "http",
        output_dir: Optional[str] = None,
        timeout: int = 180,
    ) -> AdapterResult:
        """Export objects (files) transferred over HTTP, SMB, FTP, TFTP, or DICOM."""
        result = AdapterResult()
        try:
            pcap_file = self._validate_file(pcap_file)
        except SecurityError as e:
            result.error = str(e)
            return result

        allowed = {"http", "smb", "ftp-data", "tftp", "dicom", "imf"}
        proto = proto.lower()
        if proto not in allowed:
            result.error = f"Protocol must be one of: {', '.join(sorted(allowed))}"
            return result

        if not output_dir:
            output_dir = tempfile.mkdtemp(prefix="tshark_export_")

        r = self._run_command(
            self._tshark_cmd(pcap_file, ["-q", "--export-objects", f"{proto},{output_dir}"]),
            timeout=timeout,
        )

        extracted = []
        try:
            extracted = [
                os.path.join(output_dir, f)
                for f in os.listdir(output_dir)
            ]
        except OSError:
            pass

        result.success = r.return_code == 0
        result.output = r.output
        result.data = {
            "proto": proto,
            "output_dir": output_dir,
            "extracted_files": extracted,
            "count": len(extracted),
        }
        return result

    def apply_filter(
        self,
        pcap_file: str,
        display_filter: str,
        fields: Optional[list[str]] = None,
        limit: int = 500,
        timeout: int = 120,
    ) -> AdapterResult:
        """Apply a tshark display filter and return matching packets."""
        result = AdapterResult()
        try:
            pcap_file = self._validate_file(pcap_file)
            display_filter = self._validate_display_filter(display_filter)
        except SecurityError as e:
            result.error = str(e)
            return result

        if fields:
            # Validate field names — only allow word chars and dots
            for f in fields:
                if not re.match(r'^[\w.]+$', f):
                    result.error = f"Invalid field name: {f}"
                    return result
            args = ["-Y", display_filter, "-T", "fields"]
            for f in fields:
                args += ["-e", f]
            args += ["-E", "separator=|", "-E", "header=y", "-c", str(limit)]
        else:
            args = ["-Y", display_filter, "-c", str(limit)]

        r = self._run_command(self._tshark_cmd(pcap_file, args), timeout=timeout)
        if r.return_code == 0:
            r.success = True
            if fields:
                r.data = {"rows": self._parse_fields(r.output, fields)}
        return r

    def strings_search(
        self,
        pcap_file: str,
        search_string: str,
        timeout: int = 120,
    ) -> AdapterResult:
        """Search packet data for a string (case-insensitive)."""
        result = AdapterResult()
        try:
            pcap_file = self._validate_file(pcap_file)
        except SecurityError as e:
            result.error = str(e)
            return result

        # Validate search string
        if any(c in search_string for c in InputValidator.SHELL_METACHARACTERS):
            result.error = "Invalid characters in search string"
            return result

        display_filter = f'frame contains "{search_string}"'
        r = self._run_command(
            self._tshark_cmd(pcap_file, ["-Y", display_filter]),
            timeout=timeout,
        )
        if r.return_code == 0:
            r.success = True
        r.data = {"search": search_string, "raw": r.output}
        return r

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_fields(output: str, field_names: list[str]) -> list[dict[str, str]]:
        """Parse pipe-separated tshark field output into list of dicts."""
        rows = []
        lines = [l for l in output.splitlines() if l.strip()]
        if not lines:
            return rows

        # First line may be a header (if -E header=y was used)
        start = 0
        headers = field_names
        if lines[0].startswith(field_names[0].split(".")[0]) or "|" not in lines[0]:
            # Try to use the actual header line
            parts = lines[0].split("|")
            if len(parts) == len(field_names):
                headers = parts
                start = 1

        for line in lines[start:]:
            parts = line.split("|")
            if len(parts) >= len(headers):
                rows.append(dict(zip(headers, parts)))
            elif parts:
                padded = parts + [""] * (len(headers) - len(parts))
                rows.append(dict(zip(headers, padded)))

        return rows
