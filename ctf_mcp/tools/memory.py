"""
Memory Forensics Tools Module for CTF-MCP
Volatility3-based memory analysis for CTF challenges
"""

from ..adapters.volatility_adapter import VolatilityAdapter


class MemoryTools:
    """Memory forensics tools powered by Volatility3"""

    def __init__(self):
        self._vol = VolatilityAdapter()

    def _unavailable(self) -> str:
        return (
            "vol (volatility3) is not installed or not in PATH.\n"
            "Install: pip install volatility3  or  apt install python3-volatility3"
        )

    def get_tools(self) -> dict[str, str]:
        """Return available tools and their descriptions"""
        return {
            "info":      "Get OS/kernel info from a memory dump. Good first step to identify the image.",
            "pslist":    "List all running processes from memory (windows/linux/mac).",
            "pstree":    "Show process parent-child tree. Useful for spotting injected or orphaned processes.",
            "cmdline":   "Get the command line arguments of each Windows process.",
            "netscan":   "Find network connections and sockets in memory (windows/linux/mac).",
            "filescan":  "Scan for open file handles in Windows memory.",
            "dumpfiles": "Extract a file from memory by virtual or physical address.",
            "hashdump":  "Extract NTLM password hashes from a Windows memory image.",
            "hivelist":  "List Windows registry hives loaded in memory.",
            "printkey":  "Read a specific Windows registry key from memory.",
            "malfind":   "Find memory regions with injected/suspicious code (RWX regions, PE headers).",
            "run_plugin":"Run any arbitrary volatility3 plugin against a memory dump.",
        }

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    def info(self, memory_file: str, timeout: int = 60) -> str:
        """
        Get OS and kernel information from a memory dump.
        Run this first to identify the image type before running other plugins.

        :param memory_file: Path to the memory dump file (.mem, .raw, .vmem, .dmp)
        :param timeout: Maximum run time in seconds
        """
        if not self._vol.is_available:
            return self._unavailable()

        result = self._vol.info(memory_file=memory_file, timeout=timeout)

        if not result.success:
            return f"Plugin failed: {result.error}\n\nOutput:\n{result.output}"

        lines = [
            f"Memory Image Info: {memory_file}",
            "-" * 50,
            result.output,
        ]
        return "\n".join(lines)

    def pslist(
        self,
        memory_file: str,
        os_type: str = "windows",
        timeout: int = 120,
    ) -> str:
        """
        List all running processes found in memory.

        :param memory_file: Path to the memory dump file
        :param os_type: OS type: windows (default), linux, or mac
        :param timeout: Maximum run time in seconds
        """
        if not self._vol.is_available:
            return self._unavailable()

        result = self._vol.pslist(memory_file=memory_file, os_type=os_type, timeout=timeout)

        if not result.success:
            return f"pslist failed: {result.error}\n\nOutput:\n{result.output}"

        procs = result.data.get("processes", [])
        lines = [
            f"Process List ({os_type}) — {memory_file}",
            f"Found {len(procs)} processes",
            "-" * 50,
            result.output,
        ]
        return "\n".join(lines)

    def pstree(
        self,
        memory_file: str,
        os_type: str = "windows",
        timeout: int = 120,
    ) -> str:
        """
        Show process parent-child tree from memory.
        Useful for spotting injected, orphaned, or suspicious processes.

        :param memory_file: Path to the memory dump file
        :param os_type: OS type: windows (default), linux, or mac
        :param timeout: Maximum run time in seconds
        """
        if not self._vol.is_available:
            return self._unavailable()

        result = self._vol.pstree(memory_file=memory_file, os_type=os_type, timeout=timeout)

        if not result.success:
            return f"pstree failed: {result.error}\n\nOutput:\n{result.output}"

        lines = [
            f"Process Tree ({os_type}) — {memory_file}",
            "-" * 50,
            result.output,
        ]
        return "\n".join(lines)

    def cmdline(self, memory_file: str, timeout: int = 120) -> str:
        """
        Get the command line arguments used to launch each Windows process.
        Useful for finding suspicious commands, encoded PowerShell, etc.

        :param memory_file: Path to a Windows memory dump file
        :param timeout: Maximum run time in seconds
        """
        if not self._vol.is_available:
            return self._unavailable()

        result = self._vol.cmdline(memory_file=memory_file, timeout=timeout)

        if not result.success:
            return f"cmdline failed: {result.error}\n\nOutput:\n{result.output}"

        lines = [
            f"Process Command Lines — {memory_file}",
            "-" * 50,
            result.output,
        ]
        return "\n".join(lines)

    def netscan(
        self,
        memory_file: str,
        os_type: str = "windows",
        timeout: int = 120,
    ) -> str:
        """
        Find network connections and open sockets in memory.
        Shows local/remote IPs, ports, state, and owning process.

        :param memory_file: Path to the memory dump file
        :param os_type: OS type: windows (default), linux, or mac
        :param timeout: Maximum run time in seconds
        """
        if not self._vol.is_available:
            return self._unavailable()

        result = self._vol.netscan(memory_file=memory_file, os_type=os_type, timeout=timeout)

        if not result.success:
            return f"netscan failed: {result.error}\n\nOutput:\n{result.output}"

        conns = result.data.get("connections", [])
        lines = [
            f"Network Scan ({os_type}) — {memory_file}",
            f"Found {len(conns)} connections/sockets",
            "-" * 50,
            result.output,
        ]
        return "\n".join(lines)

    def filescan(self, memory_file: str, timeout: int = 180) -> str:
        """
        Scan Windows memory for open file handles.
        Useful for finding files accessed by malware or containing flags.

        :param memory_file: Path to a Windows memory dump file
        :param timeout: Maximum run time in seconds
        """
        if not self._vol.is_available:
            return self._unavailable()

        result = self._vol.filescan(memory_file=memory_file, timeout=timeout)

        if not result.success:
            return f"filescan failed: {result.error}\n\nOutput:\n{result.output}"

        files = result.data.get("files", [])
        lines = [
            f"File Scan — {memory_file}",
            f"Found {len(files)} file objects",
            "-" * 50,
            result.output,
        ]
        return "\n".join(lines)

    def dumpfiles(
        self,
        memory_file: str,
        virtaddr: str = None,
        physaddr: str = None,
        output_dir: str = None,
        timeout: int = 120,
    ) -> str:
        """
        Extract a file from memory by its virtual or physical address.
        Get the address first from filescan output.

        :param memory_file: Path to a Windows memory dump file
        :param virtaddr: Virtual address of file object (e.g. 0xfffffa8...)
        :param physaddr: Physical address of file object (e.g. 0x3f1a000)
        :param output_dir: Directory to write extracted files (default: temp dir)
        :param timeout: Maximum run time in seconds
        """
        if not self._vol.is_available:
            return self._unavailable()

        if not virtaddr and not physaddr:
            return "Error: provide either virtaddr or physaddr (get these from memory_filescan output)"

        result = self._vol.dumpfiles(
            memory_file=memory_file,
            virtaddr=virtaddr,
            physaddr=physaddr,
            output_dir=output_dir,
            timeout=timeout,
        )

        if not result.success:
            return f"dumpfiles failed: {result.error}\n\nOutput:\n{result.output}"

        data = result.data
        lines = [
            f"File Dump — {memory_file}",
            f"Output directory: {data.get('output_dir')}",
            f"Extracted files ({len(data.get('extracted_files', []))}):",
            "-" * 50,
        ]
        for f in data.get("extracted_files", []):
            lines.append(f"  {f}")
        lines.append("")
        lines.append(result.output)
        return "\n".join(lines)

    def hashdump(self, memory_file: str, timeout: int = 120) -> str:
        """
        Extract NTLM password hashes from a Windows memory image.
        Output can be fed directly into hashcat (-m 1000) or john.

        :param memory_file: Path to a Windows memory dump file
        :param timeout: Maximum run time in seconds
        """
        if not self._vol.is_available:
            return self._unavailable()

        result = self._vol.hashdump(memory_file=memory_file, timeout=timeout)

        if not result.success:
            return f"hashdump failed: {result.error}\n\nOutput:\n{result.output}"

        hashes = result.data.get("hashes", [])
        lines = [
            f"NTLM Hash Dump — {memory_file}",
            f"Found {len(hashes)} accounts",
            "-" * 50,
            result.output,
            "",
            "Tip: crack with  cracking_hashcat  (hash_type=1000) or  cracking_john",
        ]
        return "\n".join(lines)

    def hivelist(self, memory_file: str, timeout: int = 120) -> str:
        """
        List Windows registry hives loaded in memory.
        Use the hive offsets with memory_printkey to read specific keys.

        :param memory_file: Path to a Windows memory dump file
        :param timeout: Maximum run time in seconds
        """
        if not self._vol.is_available:
            return self._unavailable()

        result = self._vol.hivelist(memory_file=memory_file, timeout=timeout)

        if not result.success:
            return f"hivelist failed: {result.error}\n\nOutput:\n{result.output}"

        hives = result.data.get("hives", [])
        lines = [
            f"Registry Hive List — {memory_file}",
            f"Found {len(hives)} hives",
            "-" * 50,
            result.output,
        ]
        return "\n".join(lines)

    def printkey(
        self,
        memory_file: str,
        key: str,
        timeout: int = 120,
    ) -> str:
        """
        Read a Windows registry key and its values from memory.

        :param memory_file: Path to a Windows memory dump file
        :param key: Registry key path e.g. "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        :param timeout: Maximum run time in seconds
        """
        if not self._vol.is_available:
            return self._unavailable()

        result = self._vol.printkey(memory_file=memory_file, key=key, timeout=timeout)

        if not result.success:
            return f"printkey failed: {result.error}\n\nOutput:\n{result.output}"

        lines = [
            f"Registry Key: {key}",
            f"Memory: {memory_file}",
            "-" * 50,
            result.output,
        ]
        return "\n".join(lines)

    def malfind(
        self,
        memory_file: str,
        os_type: str = "windows",
        timeout: int = 180,
    ) -> str:
        """
        Find memory regions with injected or suspicious code.
        Looks for RWX pages, PE headers in unexpected locations, shellcode.

        :param memory_file: Path to the memory dump file
        :param os_type: OS type: windows (default), linux, or mac
        :param timeout: Maximum run time in seconds
        """
        if not self._vol.is_available:
            return self._unavailable()

        result = self._vol.malfind(memory_file=memory_file, os_type=os_type, timeout=timeout)

        if not result.success:
            return f"malfind failed: {result.error}\n\nOutput:\n{result.output}"

        findings = result.data.get("findings", [])
        lines = [
            f"Malfind ({os_type}) — {memory_file}",
            f"Suspicious regions found: {len(findings)}",
            "-" * 50,
            result.output,
        ]
        return "\n".join(lines)

    def run_plugin(
        self,
        memory_file: str,
        plugin: str,
        extra_args: str = "",
        timeout: int = 120,
    ) -> str:
        """
        Run any volatility3 plugin directly against a memory dump.
        Use this for plugins not covered by the other memory tools.

        Common plugins: windows.handles, windows.modules, windows.dlllist,
        windows.memmap, windows.vadinfo, windows.envars, linux.bash, linux.check_syscall

        :param memory_file: Path to the memory dump file
        :param plugin: Full plugin name e.g. windows.dlllist or linux.bash
        :param extra_args: Space-separated extra arguments e.g. "--pid 1234"
        :param timeout: Maximum run time in seconds
        """
        if not self._vol.is_available:
            return self._unavailable()

        extra = extra_args.split() if extra_args.strip() else None

        result = self._vol.run_plugin(
            memory_file=memory_file,
            plugin=plugin,
            extra_args=extra,
            timeout=timeout,
        )

        if not result.success:
            return f"Plugin '{plugin}' failed: {result.error}\n\nOutput:\n{result.output}"

        lines = [
            f"Plugin: {plugin}",
            f"Memory: {memory_file}",
            "-" * 50,
            result.output,
        ]
        return "\n".join(lines)
