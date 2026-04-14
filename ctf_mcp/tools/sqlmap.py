"""
SQLMap Tools Module for CTF-MCP
Exposes sqlmap SQL injection automation as MCP tools.
"""

from typing import Optional

from ..adapters.sqlmap_adapter import SqlmapAdapter


class SqlmapTools:
    """MCP tools backed by the sqlmap adapter."""

    def __init__(self):
        self._adapter = SqlmapAdapter()

    def get_tools(self) -> dict[str, str]:
        return {
            "sqlmap_scan":             "Scan a URL for SQL injection vulnerabilities",
            "sqlmap_dbs":              "Enumerate databases on a vulnerable target",
            "sqlmap_tables":           "Enumerate tables in a specific database",
            "sqlmap_dump":             "Dump contents of a specific table",
            "sqlmap_waf":              "Detect WAF/IPS protecting a target",
            "sqlmap_shell":            "Generate sqlmap shell command (sql or os)",
        }

    # ------------------------------------------------------------------

    def sqlmap_scan(
        self,
        url: str,
        data: Optional[str] = None,
        cookie: Optional[str] = None,
        level: int = 1,
        risk: int = 1,
    ) -> str:
        """
        Scan a URL for SQL injection vulnerabilities.

        Args:
            url:    Target URL (e.g. http://target/page?id=1)
            data:   POST body if POST request (e.g. "user=foo&pass=bar")
            cookie: Cookie header string
            level:  Test depth 1-5 (default 1)
            risk:   Risk level 1-3 (default 1)
        """
        result = self._adapter.scan(url, data=data, cookie=cookie, level=level, risk=risk)
        if not result.success:
            return f"[ERROR] {result.error or result.output}"

        lines = ["SQLMap Scan Results", "=" * 40]
        d = result.data or {}
        lines.append(f"Vulnerable: {'YES' if d.get('vulnerable') else 'NO'}")

        vulns = d.get("vulnerabilities", [])
        if vulns:
            lines.append(f"\nInjection points found: {len(vulns)}")
            for v in vulns:
                lines.append(f"  Parameter : {v['parameter']}")
                lines.append(f"  Type      : {v['type']}")
                lines.append("")
        else:
            lines.append("\nNo injection points identified.")

        if result.output:
            lines += ["", "--- Raw output ---", result.output[-3000:]]

        return "\n".join(lines)

    def sqlmap_dbs(
        self,
        url: str,
        data: Optional[str] = None,
        cookie: Optional[str] = None,
    ) -> str:
        """
        Enumerate databases on a vulnerable target.

        Args:
            url:    Target URL
            data:   POST body (optional)
            cookie: Cookie string (optional)
        """
        result = self._adapter.enumerate_dbs(url, data=data, cookie=cookie)
        if not result.success:
            return f"[ERROR] {result.error or result.output}"

        dbs = (result.data or {}).get("databases", [])
        lines = ["Databases Found", "=" * 40]
        if dbs:
            for db in dbs:
                lines.append(f"  * {db}")
        else:
            lines.append("No databases found (target may not be injectable).")

        if result.output:
            lines += ["", "--- Raw output ---", result.output[-3000:]]

        return "\n".join(lines)

    def sqlmap_tables(
        self,
        url: str,
        database: str,
        data: Optional[str] = None,
        cookie: Optional[str] = None,
    ) -> str:
        """
        Enumerate tables in a specific database.

        Args:
            url:      Target URL
            database: Database name to enumerate
            data:     POST body (optional)
            cookie:   Cookie string (optional)
        """
        result = self._adapter.enumerate_tables(url, database, data=data, cookie=cookie)
        if not result.success:
            return f"[ERROR] {result.error or result.output}"

        tables = (result.data or {}).get("tables", [])
        lines = [f"Tables in '{database}'", "=" * 40]
        if tables:
            for t in tables:
                lines.append(f"  * {t}")
        else:
            lines.append("No tables found.")

        if result.output:
            lines += ["", "--- Raw output ---", result.output[-3000:]]

        return "\n".join(lines)

    def sqlmap_dump(
        self,
        url: str,
        database: str,
        table: str,
        data: Optional[str] = None,
        cookie: Optional[str] = None,
    ) -> str:
        """
        Dump contents of a specific table.

        Args:
            url:      Target URL
            database: Database name
            table:    Table name to dump
            data:     POST body (optional)
            cookie:   Cookie string (optional)
        """
        result = self._adapter.dump_table(url, database, table, data=data, cookie=cookie)
        if not result.success:
            return f"[ERROR] {result.error or result.output}"

        lines = [f"Dump: {database}.{table}", "=" * 40]
        if result.output:
            lines.append(result.output[-5000:])
        else:
            lines.append("Dump completed — check sqlmap output directory for CSV files.")

        return "\n".join(lines)

    def sqlmap_waf(self, url: str) -> str:
        """
        Detect WAF/IPS protecting a target URL.

        Args:
            url: Target URL
        """
        result = self._adapter.test_waf(url)
        if not result.success:
            return f"[ERROR] {result.error or result.output}"

        d = result.data or {}
        lines = ["WAF Detection", "=" * 40]
        if d.get("waf_detected"):
            lines.append(f"WAF detected: {d.get('waf_name', 'Unknown')}")
        else:
            lines.append("No WAF/IPS detected.")

        if result.output:
            lines += ["", "--- Raw output ---", result.output[-2000:]]

        return "\n".join(lines)

    def sqlmap_shell(
        self,
        url: str,
        shell_type: str = "sql",
        data: Optional[str] = None,
        cookie: Optional[str] = None,
    ) -> str:
        """
        Generate the sqlmap command to open an interactive shell.

        Args:
            url:        Target URL
            shell_type: 'sql' for SQL shell, 'os' for OS shell
            data:       POST body (optional)
            cookie:     Cookie string (optional)
        """
        result = self._adapter.get_shell(url, shell_type=shell_type, data=data, cookie=cookie)
        if not result.success:
            return f"[ERROR] {result.error or result.output}"

        d = result.data or {}
        lines = [
            f"SQLMap {shell_type.upper()} Shell Command",
            "=" * 40,
            "",
            d.get("command", ""),
            "",
            "Run the command above in your terminal for an interactive shell.",
            "(Cannot be run non-interactively via MCP)",
        ]
        return "\n".join(lines)
