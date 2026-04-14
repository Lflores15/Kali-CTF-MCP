"""
PCAP Analysis Tools Module for CTF-MCP
TShark-based packet capture analysis for CTF challenges
"""

from typing import Optional

from ..adapters.tshark_adapter import TSharkAdapter


class PcapTools:
    """PCAP analysis tools powered by tshark"""

    def __init__(self):
        self._tshark = TSharkAdapter()

    def _unavailable(self) -> str:
        return (
            "tshark is not installed or not in PATH.\n"
            "Install: sudo apt install tshark  or  brew install wireshark"
        )

    def get_tools(self) -> dict[str, str]:
        return {
            "summary":            "Get capture file info: packet count, duration, data rate, file size.",
            "protocol_hierarchy": "Show protocol breakdown of a PCAP. Run this first to see what's in a capture.",
            "conversations":      "List conversations (who talked to whom) for tcp/udp/ip/eth.",
            "follow_stream":      "Follow a TCP/UDP stream by index and return its contents (ascii/hex).",
            "http_requests":      "Extract HTTP requests and responses: method, host, URI, status code.",
            "dns_queries":        "Extract DNS queries and resolved addresses.",
            "credentials":        "Hunt for credentials: FTP USER/PASS, HTTP Basic auth.",
            "export_objects":     "Export transferred files from HTTP/SMB/FTP/TFTP streams to disk.",
            "filter":             "Apply any tshark display filter and return matching packets.",
            "strings_search":     "Search all packet data for a string. Useful for finding flags.",
        }

    # ------------------------------------------------------------------
    # Tools
    # ------------------------------------------------------------------

    def summary(self, pcap_file: str, timeout: int = 30) -> str:
        """
        Get a summary of the capture file: packet count, duration, protocols, file size.
        Good first step on any PCAP challenge.

        :param pcap_file: Path to the .pcap or .pcapng file
        :param timeout: Maximum run time in seconds
        """
        if not self._tshark.is_available:
            return self._unavailable()

        result = self._tshark.summary(pcap_file=pcap_file, timeout=timeout)

        if not result.success:
            return f"Summary failed: {result.error}\n\nOutput:\n{result.output}"

        return f"PCAP Summary: {pcap_file}\n{'-' * 50}\n{result.output}"

    def protocol_hierarchy(self, pcap_file: str, timeout: int = 60) -> str:
        """
        Show the protocol hierarchy of a capture file.
        Run this first — it tells you exactly what protocols are in the capture
        so you know which tools to use next.

        :param pcap_file: Path to the .pcap or .pcapng file
        :param timeout: Maximum run time in seconds
        """
        if not self._tshark.is_available:
            return self._unavailable()

        result = self._tshark.protocol_hierarchy(pcap_file=pcap_file, timeout=timeout)

        if not result.success:
            return f"Protocol hierarchy failed: {result.error}\n\nOutput:\n{result.output}"

        return f"Protocol Hierarchy: {pcap_file}\n{'-' * 50}\n{result.output}"

    def conversations(
        self,
        pcap_file: str,
        proto: str = "tcp",
        timeout: int = 60,
    ) -> str:
        """
        List all conversations between hosts for a given protocol.
        Shows bytes transferred, packet counts, and duration per conversation.

        :param pcap_file: Path to the .pcap or .pcapng file
        :param proto: Protocol to analyze: tcp (default), udp, ip, eth
        :param timeout: Maximum run time in seconds
        """
        if not self._tshark.is_available:
            return self._unavailable()

        result = self._tshark.conversations(pcap_file=pcap_file, proto=proto, timeout=timeout)

        if not result.success:
            return f"Conversations failed: {result.error}\n\nOutput:\n{result.output}"

        return f"Conversations ({proto.upper()}) — {pcap_file}\n{'-' * 50}\n{result.output}"

    def follow_stream(
        self,
        pcap_file: str,
        stream_index: int = 0,
        proto: str = "tcp",
        mode: str = "ascii",
        timeout: int = 60,
    ) -> str:
        """
        Follow a TCP or UDP stream by stream index and return its content.
        This is where flags and credentials most often hide.
        Use pcap_conversations to find which stream indices are interesting first.

        :param pcap_file: Path to the .pcap or .pcapng file
        :param stream_index: Stream index to follow (0-based, from conversations output)
        :param proto: Protocol: tcp (default), udp, http, tls
        :param mode: Output mode: ascii (default), hex, raw
        :param timeout: Maximum run time in seconds
        """
        if not self._tshark.is_available:
            return self._unavailable()

        result = self._tshark.follow_stream(
            pcap_file=pcap_file,
            stream_index=stream_index,
            proto=proto,
            mode=mode,
            timeout=timeout,
        )

        if not result.success:
            return f"Follow stream failed: {result.error}\n\nOutput:\n{result.output}"

        lines = [
            f"Stream {stream_index} ({proto.upper()}, {mode}) — {pcap_file}",
            "-" * 50,
            result.output,
        ]
        return "\n".join(lines)

    def http_requests(self, pcap_file: str, timeout: int = 60) -> str:
        """
        Extract all HTTP requests and responses from a capture.
        Shows frame number, source IP, method, host, URI, and response code.

        :param pcap_file: Path to the .pcap or .pcapng file
        :param timeout: Maximum run time in seconds
        """
        if not self._tshark.is_available:
            return self._unavailable()

        result = self._tshark.http_requests(pcap_file=pcap_file, timeout=timeout)

        if not result.success:
            return f"HTTP extraction failed: {result.error}\n\nOutput:\n{result.output}"

        reqs = result.data.get("requests", [])
        lines = [
            f"HTTP Requests — {pcap_file}",
            f"Found {len(reqs)} HTTP packets",
            "-" * 50,
            result.output,
        ]
        return "\n".join(lines)

    def dns_queries(self, pcap_file: str, timeout: int = 60) -> str:
        """
        Extract DNS queries and their resolved addresses.
        Useful for finding C2 domains, exfiltration via DNS, or visited sites.

        :param pcap_file: Path to the .pcap or .pcapng file
        :param timeout: Maximum run time in seconds
        """
        if not self._tshark.is_available:
            return self._unavailable()

        result = self._tshark.dns_queries(pcap_file=pcap_file, timeout=timeout)

        if not result.success:
            return f"DNS extraction failed: {result.error}\n\nOutput:\n{result.output}"

        queries = result.data.get("queries", [])
        lines = [
            f"DNS Queries — {pcap_file}",
            f"Found {len(queries)} DNS packets",
            "-" * 50,
            result.output,
        ]
        return "\n".join(lines)

    def credentials(self, pcap_file: str, timeout: int = 60) -> str:
        """
        Hunt for cleartext credentials in the capture.
        Checks FTP USER/PASS commands and HTTP Basic authentication.

        :param pcap_file: Path to the .pcap or .pcapng file
        :param timeout: Maximum run time in seconds
        """
        if not self._tshark.is_available:
            return self._unavailable()

        result = self._tshark.credentials(pcap_file=pcap_file, timeout=timeout)

        if not result.success:
            return f"Credential extraction failed: {result.error}\n\nOutput:\n{result.output}"

        creds = result.data.get("credentials", [])
        lines = [
            f"Credentials — {pcap_file}",
            f"Found {len(creds)} credential entries",
            "-" * 50,
            result.output,
        ]
        return "\n".join(lines)

    def export_objects(
        self,
        pcap_file: str,
        proto: str = "http",
        output_dir: str = None,
        timeout: int = 180,
    ) -> str:
        """
        Export files transferred over a protocol to disk.
        Supports http, smb, ftp-data, tftp, dicom, imf.
        Use pcap_http_requests first to see what files were transferred.

        :param pcap_file: Path to the .pcap or .pcapng file
        :param proto: Protocol to export from: http (default), smb, ftp-data, tftp, dicom, imf
        :param output_dir: Directory to write extracted files (default: temp dir)
        :param timeout: Maximum run time in seconds
        """
        if not self._tshark.is_available:
            return self._unavailable()

        result = self._tshark.export_objects(
            pcap_file=pcap_file,
            proto=proto,
            output_dir=output_dir,
            timeout=timeout,
        )

        if not result.success:
            return f"Export failed: {result.error}\n\nOutput:\n{result.output}"

        data = result.data
        lines = [
            f"Exported Objects ({proto.upper()}) — {pcap_file}",
            f"Output directory: {data.get('output_dir')}",
            f"Files extracted: {data.get('count', 0)}",
            "-" * 50,
        ]
        for f in data.get("extracted_files", []):
            lines.append(f"  {f}")
        if result.output.strip():
            lines.append("")
            lines.append(result.output)
        return "\n".join(lines)

    def filter(
        self,
        pcap_file: str,
        display_filter: str,
        fields: str = "",
        limit: int = 500,
        timeout: int = 120,
    ) -> str:
        """
        Apply a tshark display filter and return matching packets.
        Use any valid Wireshark display filter syntax.

        Examples:
          tcp.port == 4444
          http.request.method == "POST"
          frame contains "password"
          ip.addr == 192.168.1.1 && tcp

        :param pcap_file: Path to the .pcap or .pcapng file
        :param display_filter: Wireshark display filter expression
        :param fields: Comma-separated field names to extract e.g. "ip.src,tcp.dstport,data.text"
        :param limit: Maximum number of packets to return (default 500)
        :param timeout: Maximum run time in seconds
        """
        if not self._tshark.is_available:
            return self._unavailable()

        field_list = [f.strip() for f in fields.split(",") if f.strip()] if fields else None

        result = self._tshark.apply_filter(
            pcap_file=pcap_file,
            display_filter=display_filter,
            fields=field_list,
            limit=limit,
            timeout=timeout,
        )

        if not result.success:
            return f"Filter failed: {result.error}\n\nOutput:\n{result.output}"

        lines = [
            f"Filter: {display_filter}",
            f"PCAP: {pcap_file}",
            "-" * 50,
            result.output,
        ]
        return "\n".join(lines)

    def strings_search(
        self,
        pcap_file: str,
        search_string: str,
        timeout: int = 120,
    ) -> str:
        """
        Search all packet data for a string (case-sensitive).
        Useful for finding flags, passwords, or other keywords embedded in traffic.

        :param pcap_file: Path to the .pcap or .pcapng file
        :param search_string: String to search for in packet data
        :param timeout: Maximum run time in seconds
        """
        if not self._tshark.is_available:
            return self._unavailable()

        result = self._tshark.strings_search(
            pcap_file=pcap_file,
            search_string=search_string,
            timeout=timeout,
        )

        if not result.success:
            return f"Search failed: {result.error}\n\nOutput:\n{result.output}"

        lines = [
            f"String Search: '{search_string}' in {pcap_file}",
            "-" * 50,
            result.output if result.output.strip() else "No matches found.",
        ]
        return "\n".join(lines)
