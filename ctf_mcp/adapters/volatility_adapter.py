"""
Volatility3 Adapter
Interface for the vol (volatility3) memory forensics framework
"""

import json
import re
import shutil
import tempfile
import os
from pathlib import Path
from typing import Any, Optional

from .base import ToolAdapter, AdapterResult
from ..utils.security import InputValidator, SecurityError


def _find_vol_binary() -> str:
    """
    Locate the vol binary.

    Search order:
    1. System PATH
    2. Project-local Kali venv (Kali/bin/vol next to the package root)
    3. ~/venv/bin/vol  (common manual install location)
    4. Common virtualenv names relative to home
    """
    # 1. System PATH
    if shutil.which("vol"):
        return "vol"

    # 2. Project-local venv: walk up from this file to find Kali/bin/vol
    here = Path(__file__).resolve()
    for parent in here.parents:
        for venv_name in ("Kali", "venv", ".venv", "env"):
            candidate = parent / venv_name / "bin" / "vol"
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)

    # 3. VENV_PYTHON env var — derive vol from the same venv's bin/
    venv_python = os.environ.get("VENV_PYTHON", "")
    if venv_python:
        candidate = Path(venv_python).parent / "vol"
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)

    # 4. Common home-directory venv locations
    home = Path.home()
    for venv_name in ("venv", ".venv", "env", "Kali", "kali-venv"):
        candidate = home / venv_name / "bin" / "vol"
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)

    # Not found — return bare name so error messages are clear
    return "vol"


class VolatilityAdapter(ToolAdapter):
    """
    Adapter for Volatility3 memory forensics framework.

    Wraps the `vol` binary to run plugins against memory dump files.
    Supports Windows, Linux, and Mac memory images.
    """

    def __init__(self):
        super().__init__()
        self._vol_binary = _find_vol_binary()

    @property
    def name(self) -> str:
        return "volatility"

    @property
    def tool_name(self) -> str:
        return self._vol_binary

    @property
    def description(self) -> str:
        return "Volatility3 memory forensics framework"

    @property
    def min_version(self) -> Optional[str]:
        return None  # Version not exposed via --version flag

    def _get_version(self) -> Optional[str]:
        """Volatility3 doesn't support --version; parse help header instead"""
        result = self._run_command([self.tool_name, "-h"], timeout=15)
        if result.success or result.return_code == 0:
            # Look for version in output e.g. "Volatility 3 Framework 2.x.x"
            match = re.search(r'Volatility\s+3\s+Framework\s+([\d.]+)', result.output)
            if match:
                return match.group(1)
            # If help printed at all, it's available
            if "memory forensics" in result.output.lower():
                return "3.x"
        return None

    def _check_status(self):
        """Override: vol exits with code 2 on -h, not 0"""
        from .base import AdapterStatus
        import shutil
        if not shutil.which(self.tool_name):
            return AdapterStatus.NOT_INSTALLED
        # Run -h; vol returns exit code 2 for missing args but still prints help
        result = self._run_command([self.tool_name, "-h"], timeout=15)
        if "memory forensics" in (result.output + (result.error or "")).lower():
            return AdapterStatus.AVAILABLE
        return AdapterStatus.ERROR

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _validate_file(self, file_path: str) -> str:
        """Validate memory dump file path"""
        try:
            return InputValidator.validate_file_path(
                file_path, must_exist=True, allow_absolute=True
            )
        except Exception as e:
            raise SecurityError(str(e))

    def _validate_plugin(self, plugin: str) -> str:
        """Validate plugin name — only allow word chars and dots"""
        if not re.match(r'^[\w.]+$', plugin):
            raise SecurityError(f"Invalid plugin name: {plugin}")
        return plugin

    def _run_plugin(
        self,
        memory_file: str,
        plugin: str,
        extra_args: Optional[list[str]] = None,
        output_dir: Optional[str] = None,
        timeout: int = 120,
    ) -> AdapterResult:
        """
        Run a volatility3 plugin against a memory file.

        Args:
            memory_file: Path to memory dump
            plugin: Plugin name e.g. windows.pslist
            extra_args: Additional plugin arguments
            output_dir: Directory for file output plugins
            timeout: Timeout in seconds
        """
        args = [self.tool_name, "-q", "-f", memory_file]

        if output_dir:
            args.extend(["-o", output_dir])

        args.append(plugin)

        if extra_args:
            args.extend(extra_args)

        return self._run_command(args, timeout=timeout)

    def _run_plugin_json(
        self,
        memory_file: str,
        plugin: str,
        extra_args: Optional[list[str]] = None,
        timeout: int = 120,
    ) -> AdapterResult:
        """Run plugin with JSON renderer for structured output"""
        args = [self.tool_name, "-q", "-r", "json", "-f", memory_file, plugin]
        if extra_args:
            args.extend(extra_args)

        result = self._run_command(args, timeout=timeout)

        if result.success and result.output.strip():
            try:
                result.data = json.loads(result.output)
            except json.JSONDecodeError:
                # Fall back to raw output
                result.data = {"raw": result.output}

        return result

    @staticmethod
    def _parse_table(output: str) -> list[dict[str, str]]:
        """
        Parse volatility3 text table output into a list of dicts.

        Volatility3 table format:
            Col1\tCol2\tCol3
            val1\tval2\tval3
        """
        rows = []
        lines = [l for l in output.splitlines() if l.strip()]

        if len(lines) < 2:
            return rows

        # First non-empty line is headers
        headers = [h.strip() for h in lines[0].split('\t')]

        for line in lines[1:]:
            # Skip separator lines and progress output
            if re.match(r'^[-=*]+$', line.strip()):
                continue
            if line.startswith('Volatility') or line.startswith('Progress'):
                continue

            values = [v.strip() for v in line.split('\t')]
            if len(values) >= len(headers):
                rows.append(dict(zip(headers, values)))
            elif values:
                # Pad missing columns with empty string
                padded = values + [''] * (len(headers) - len(values))
                rows.append(dict(zip(headers, padded)))

        return rows

    # ------------------------------------------------------------------
    # Plugin methods
    # ------------------------------------------------------------------

    def info(self, memory_file: str, timeout: int = 60) -> AdapterResult:
        """Get OS and kernel info from memory dump"""
        result = AdapterResult()
        try:
            memory_file = self._validate_file(memory_file)
        except SecurityError as e:
            result.error = str(e)
            return result

        # Try windows first, then linux, then mac
        for plugin in ["windows.info", "linux.banner", "mac.pslist"]:
            r = self._run_plugin(memory_file, plugin, timeout=timeout)
            if r.success and r.output.strip():
                r.data = {"plugin": plugin, "rows": self._parse_table(r.output)}
                return r

        result.error = "Could not determine OS from memory image. Try specifying the plugin directly."
        return result

    def pslist(
        self,
        memory_file: str,
        os_type: str = "windows",
        timeout: int = 120,
    ) -> AdapterResult:
        """List running processes"""
        result = AdapterResult()
        try:
            memory_file = self._validate_file(memory_file)
        except SecurityError as e:
            result.error = str(e)
            return result

        plugin_map = {
            "windows": "windows.pslist",
            "linux": "linux.pslist",
            "mac": "mac.pslist",
        }
        plugin = plugin_map.get(os_type.lower(), "windows.pslist")

        r = self._run_plugin(memory_file, plugin, timeout=timeout)
        if r.success:
            r.data = {"plugin": plugin, "processes": self._parse_table(r.output)}
        return r

    def pstree(
        self,
        memory_file: str,
        os_type: str = "windows",
        timeout: int = 120,
    ) -> AdapterResult:
        """Show process tree to spot injected/orphaned processes"""
        result = AdapterResult()
        try:
            memory_file = self._validate_file(memory_file)
        except SecurityError as e:
            result.error = str(e)
            return result

        plugin_map = {
            "windows": "windows.pstree",
            "linux": "linux.pstree",
            "mac": "mac.pstree",
        }
        plugin = plugin_map.get(os_type.lower(), "windows.pstree")

        r = self._run_plugin(memory_file, plugin, timeout=timeout)
        if r.success:
            r.data = {"plugin": plugin, "tree": self._parse_table(r.output)}
        return r

    def cmdline(self, memory_file: str, timeout: int = 120) -> AdapterResult:
        """Get command line arguments for each process"""
        result = AdapterResult()
        try:
            memory_file = self._validate_file(memory_file)
        except SecurityError as e:
            result.error = str(e)
            return result

        r = self._run_plugin(memory_file, "windows.cmdline", timeout=timeout)
        if r.success:
            r.data = {"plugin": "windows.cmdline", "rows": self._parse_table(r.output)}
        return r

    def netscan(
        self,
        memory_file: str,
        os_type: str = "windows",
        timeout: int = 120,
    ) -> AdapterResult:
        """Scan for network connections in memory"""
        result = AdapterResult()
        try:
            memory_file = self._validate_file(memory_file)
        except SecurityError as e:
            result.error = str(e)
            return result

        plugin_map = {
            "windows": "windows.netscan",
            "linux": "linux.netstat",
            "mac": "mac.netstat",
        }
        plugin = plugin_map.get(os_type.lower(), "windows.netscan")

        r = self._run_plugin(memory_file, plugin, timeout=timeout)
        if r.success:
            r.data = {"plugin": plugin, "connections": self._parse_table(r.output)}
        return r

    def filescan(self, memory_file: str, timeout: int = 180) -> AdapterResult:
        """Scan for file objects open in memory"""
        result = AdapterResult()
        try:
            memory_file = self._validate_file(memory_file)
        except SecurityError as e:
            result.error = str(e)
            return result

        r = self._run_plugin(memory_file, "windows.filescan", timeout=timeout)
        if r.success:
            r.data = {"plugin": "windows.filescan", "files": self._parse_table(r.output)}
        return r

    def dumpfiles(
        self,
        memory_file: str,
        virtaddr: Optional[str] = None,
        physaddr: Optional[str] = None,
        output_dir: Optional[str] = None,
        timeout: int = 120,
    ) -> AdapterResult:
        """Extract a file from memory by virtual or physical address"""
        result = AdapterResult()
        try:
            memory_file = self._validate_file(memory_file)
        except SecurityError as e:
            result.error = str(e)
            return result

        if not output_dir:
            output_dir = tempfile.mkdtemp(prefix="vol_dump_")

        extra_args = []
        if virtaddr:
            if not re.match(r'^0x[\da-fA-F]+$', virtaddr):
                result.error = f"Invalid virtual address: {virtaddr}"
                return result
            extra_args.extend(["--virtaddr", virtaddr])
        elif physaddr:
            if not re.match(r'^0x[\da-fA-F]+$', physaddr):
                result.error = f"Invalid physical address: {physaddr}"
                return result
            extra_args.extend(["--physaddr", physaddr])

        r = self._run_plugin(
            memory_file, "windows.dumpfiles",
            extra_args=extra_args,
            output_dir=output_dir,
            timeout=timeout,
        )
        if r.success:
            # List extracted files
            extracted = []
            try:
                extracted = [
                    os.path.join(output_dir, f)
                    for f in os.listdir(output_dir)
                ]
            except OSError:
                pass
            r.data = {
                "plugin": "windows.dumpfiles",
                "output_dir": output_dir,
                "extracted_files": extracted,
            }
        return r

    def hashdump(self, memory_file: str, timeout: int = 120) -> AdapterResult:
        """Extract NTLM password hashes from Windows memory"""
        result = AdapterResult()
        try:
            memory_file = self._validate_file(memory_file)
        except SecurityError as e:
            result.error = str(e)
            return result

        r = self._run_plugin(memory_file, "windows.hashdump", timeout=timeout)
        if r.success:
            r.data = {"plugin": "windows.hashdump", "hashes": self._parse_table(r.output)}
        return r

    def hivelist(self, memory_file: str, timeout: int = 120) -> AdapterResult:
        """List registry hives in memory"""
        result = AdapterResult()
        try:
            memory_file = self._validate_file(memory_file)
        except SecurityError as e:
            result.error = str(e)
            return result

        r = self._run_plugin(memory_file, "windows.registry.hivelist", timeout=timeout)
        if r.success:
            r.data = {"plugin": "windows.registry.hivelist", "hives": self._parse_table(r.output)}
        return r

    def printkey(
        self,
        memory_file: str,
        key: str,
        timeout: int = 120,
    ) -> AdapterResult:
        """Read a registry key from memory"""
        result = AdapterResult()
        try:
            memory_file = self._validate_file(memory_file)
        except SecurityError as e:
            result.error = str(e)
            return result

        # Validate registry key path — allow word chars, backslashes, spaces, hyphens
        if not re.match(r'^[\w\\ \-./]+$', key):
            result.error = f"Invalid registry key: {key}"
            return result

        r = self._run_plugin(
            memory_file, "windows.registry.printkey",
            extra_args=["--key", key],
            timeout=timeout,
        )
        if r.success:
            r.data = {"plugin": "windows.registry.printkey", "key": key, "values": self._parse_table(r.output)}
        return r

    def malfind(
        self,
        memory_file: str,
        os_type: str = "windows",
        timeout: int = 180,
    ) -> AdapterResult:
        """Find injected/suspicious code regions in process memory"""
        result = AdapterResult()
        try:
            memory_file = self._validate_file(memory_file)
        except SecurityError as e:
            result.error = str(e)
            return result

        plugin_map = {
            "windows": "windows.malfind",
            "linux": "linux.malfind",
            "mac": "mac.malfind",
        }
        plugin = plugin_map.get(os_type.lower(), "windows.malfind")

        r = self._run_plugin(memory_file, plugin, timeout=timeout)
        if r.success:
            r.data = {"plugin": plugin, "findings": self._parse_table(r.output)}
        return r

    def run_plugin(
        self,
        memory_file: str,
        plugin: str,
        extra_args: Optional[list[str]] = None,
        timeout: int = 120,
    ) -> AdapterResult:
        """Run any arbitrary volatility3 plugin"""
        result = AdapterResult()
        try:
            memory_file = self._validate_file(memory_file)
            plugin = self._validate_plugin(plugin)
        except SecurityError as e:
            result.error = str(e)
            return result

        return self._run_plugin(memory_file, plugin, extra_args=extra_args, timeout=timeout)
