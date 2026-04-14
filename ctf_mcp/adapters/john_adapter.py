"""
John the Ripper Adapter
Interface for the john password cracking tool
"""

import os
import re
import tempfile
from typing import Optional

from .base import ToolAdapter, AdapterResult
from ..utils.security import InputValidator, SecurityError


class JohnAdapter(ToolAdapter):
    """
    Adapter for John the Ripper password cracking tool.

    Provides:
    - Hash format identification (via --list=formats)
    - Dictionary attacks (--wordlist)
    - Single crack mode (--single)
    - Incremental brute-force (--incremental)
    - Showing cracked passwords from pot file (--show)
    """

    # Map common hash names to john --format values
    HASH_FORMATS = {
        "md5": "raw-md5",
        "sha1": "raw-sha1",
        "sha256": "raw-sha256",
        "sha512": "raw-sha512",
        "md5crypt": "md5crypt",
        "sha512crypt": "sha512crypt",
        "bcrypt": "bcrypt",
        "ntlm": "nt",
        "lm": "lm",
        "mysql": "mysql",
        "mysql5": "mysql-sha1",
        "md4": "raw-md4",
        "sha224": "raw-sha224",
        "sha384": "raw-sha384",
        "whirlpool": "whirlpool",
        "descrypt": "descrypt",
        "zip": "pkzip",
        "pdf": "pdf",
        "7z": "7z",
        "rar": "rar",
    }

    @property
    def name(self) -> str:
        return "john"

    @property
    def tool_name(self) -> str:
        return "john"

    @property
    def description(self) -> str:
        return "John the Ripper password cracker"

    @property
    def min_version(self) -> Optional[str]:
        return None  # Any version is acceptable

    def _get_version(self) -> Optional[str]:
        result = self._run_command([self.tool_name, "--version"], timeout=10)
        if result.success or result.output:
            # "John the Ripper 1.9.0-jumbo-1 ..."
            match = re.search(r'John the Ripper\s+([\d.]+)', result.output, re.I)
            if match:
                return match.group(1)
            # Fallback: return first line
            first_line = result.output.strip().splitlines()[0] if result.output.strip() else None
            return first_line
        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def list_formats(self) -> AdapterResult:
        """
        List all hash formats supported by the installed john build.

        Returns:
            AdapterResult with a list of format names
        """
        result = self._run_command([self.tool_name, "--list=formats"], timeout=15)
        if result.success or result.output:
            formats = [f.strip() for f in re.split(r'[\s,]+', result.output) if f.strip()]
            result.success = True
            result.data = {"formats": formats}
        return result

    def crack_dictionary(
        self,
        hash_value: str,
        hash_format: str = "",
        wordlist: str = "",
        rules: str = "",
        timeout: int = 600,
    ) -> AdapterResult:
        """
        Crack a hash using a wordlist attack.

        Args:
            hash_value: Hash string (or user:hash line) to crack
            hash_format: John --format value (e.g. raw-md5). Auto-detect if empty.
            wordlist: Full path to wordlist file
            rules: Optional rule set name (e.g. "best64")
            timeout: Attack timeout in seconds

        Returns:
            AdapterResult with cracked password
        """
        result = AdapterResult()

        try:
            hash_value = InputValidator.validate_hash_value(hash_value)
            if wordlist:
                wordlist = InputValidator.validate_file_path(wordlist, must_exist=True)
        except SecurityError as e:
            result.error = str(e)
            return result

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(hash_value.strip() + "\n")
            hash_file = f.name

        try:
            args = [self.tool_name]
            if hash_format:
                fmt = self.HASH_FORMATS.get(hash_format.lower(), hash_format)
                args.append(f"--format={fmt}")
            if wordlist:
                args.append(f"--wordlist={wordlist}")
            if rules:
                args.append(f"--rules={rules}")
            args.append(hash_file)

            cmd_result = self._run_command(args, timeout=timeout)

            # Retrieve cracked passwords from pot
            show_result = self._run_command(
                [self.tool_name, "--show", hash_file], timeout=10
            )
            cracked_lines = [
                line for line in show_result.output.splitlines()
                if ":" in line and not line.startswith("0 password")
            ]

            if cracked_lines:
                password = cracked_lines[0].split(":", 1)[1].strip()
                result.success = True
                result.data = {"cracked": True, "password": password, "hash": hash_value}
                result.output = f"Cracked: {password}"
            else:
                result.success = False
                result.data = {"cracked": False}
                result.output = cmd_result.output or "Hash not cracked"
                result.error = cmd_result.error

        finally:
            os.unlink(hash_file)

        return result

    def crack_incremental(
        self,
        hash_value: str,
        hash_format: str = "",
        incremental_mode: str = "All",
        timeout: int = 600,
    ) -> AdapterResult:
        """
        Crack a hash using incremental (brute-force) mode.

        Args:
            hash_value: Hash string to crack
            hash_format: John --format value. Auto-detect if empty.
            incremental_mode: Incremental mode name (All, Alpha, Digits, etc.)
            timeout: Attack timeout in seconds

        Returns:
            AdapterResult with cracked password
        """
        result = AdapterResult()

        try:
            hash_value = InputValidator.validate_hash_value(hash_value)
        except SecurityError as e:
            result.error = str(e)
            return result

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(hash_value.strip() + "\n")
            hash_file = f.name

        try:
            args = [self.tool_name, f"--incremental={incremental_mode}"]
            if hash_format:
                fmt = self.HASH_FORMATS.get(hash_format.lower(), hash_format)
                args.append(f"--format={fmt}")
            args.append(hash_file)

            cmd_result = self._run_command(args, timeout=timeout)

            show_result = self._run_command(
                [self.tool_name, "--show", hash_file], timeout=10
            )
            cracked_lines = [
                line for line in show_result.output.splitlines()
                if ":" in line and not line.startswith("0 password")
            ]

            if cracked_lines:
                password = cracked_lines[0].split(":", 1)[1].strip()
                result.success = True
                result.data = {"cracked": True, "password": password}
                result.output = f"Cracked: {password}"
            else:
                result.success = False
                result.data = {"cracked": False}
                result.output = cmd_result.output or "Hash not cracked"

        finally:
            os.unlink(hash_file)

        return result

    def show_cracked(self, hash_value: str, hash_format: str = "") -> AdapterResult:
        """
        Show already-cracked passwords from the pot file for a given hash.

        Args:
            hash_value: Hash string to look up
            hash_format: John --format value. Auto-detect if empty.

        Returns:
            AdapterResult with cracked password(s)
        """
        result = AdapterResult()

        try:
            hash_value = InputValidator.validate_hash_value(hash_value)
        except SecurityError as e:
            result.error = str(e)
            return result

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(hash_value.strip() + "\n")
            hash_file = f.name

        try:
            args = [self.tool_name, "--show"]
            if hash_format:
                fmt = self.HASH_FORMATS.get(hash_format.lower(), hash_format)
                args.append(f"--format={fmt}")
            args.append(hash_file)

            cmd_result = self._run_command(args, timeout=10)
            cracked_lines = [
                line for line in cmd_result.output.splitlines()
                if ":" in line and not line.startswith("0 password")
            ]

            result.success = bool(cracked_lines)
            result.output = cmd_result.output
            result.data = {
                "cracked": cracked_lines,
                "count": len(cracked_lines),
            }

        finally:
            os.unlink(hash_file)

        return result
