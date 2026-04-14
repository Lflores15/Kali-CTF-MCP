import shutil
import subprocess
import os
import tempfile
from pathlib import Path

# Common wordlist locations across platforms
_WORDLIST_CANDIDATES = [
    "/usr/share/wordlists",
    "/usr/local/share/wordlists",
    os.path.expanduser("~/wordlists"),
]
WORDLIST_DIR = next((d for d in _WORDLIST_CANDIDATES if os.path.isdir(d)), _WORDLIST_CANDIDATES[0])


class CrackingTools:
    def get_tools(self):
        return {
            "hashcat": "Crack a hash using hashcat with a wordlist or mask attack",
            "list_wordlists": "List available wordlists in common wordlist directories",
            "john": "Crack a hash or password file using John the Ripper (auto-detect, wordlist, or incremental mode)",
            "john_show": "Show passwords cracked by John the Ripper from the pot file for a given hash file",
        }

    def list_wordlists(self) -> str:
        """List all available wordlists recursively under common wordlist directories"""
        results = []
        for base in _WORDLIST_CANDIDATES:
            if not os.path.isdir(base):
                continue
            for root, dirs, files in os.walk(base):
                for f in files:
                    full_path = os.path.join(root, f)
                    size = os.path.getsize(full_path)
                    results.append(f"{full_path} ({size // 1024} KB)")
        return "\n".join(results) if results else "No wordlists found"

    def hashcat(
        self,
        hash_value: str,
        hash_type: int,
        wordlist: str = "",
        wordlist_name: str = "rockyou.txt",
        attack_mode: int = 0,
        mask: str = "",
        extra_args: str = "",
    ) -> str:
        """
        Crack a hash using hashcat.
        :param hash_value: The hash to crack
        :param hash_type: Hashcat hash type (0=MD5, 100=SHA1, 1000=NTLM, 1800=sha512crypt)
        :param wordlist: Full path to wordlist (overrides wordlist_name if provided)
        :param wordlist_name: Filename to search for under /usr/share/wordlists/ (default: rockyou.txt)
        :param attack_mode: 0=wordlist, 3=brute-force mask
        :param mask: Mask for attack mode 3 (e.g. ?a?a?a?a?a?a)
        :param extra_args: Additional hashcat flags
        """
        # Resolve wordlist path
        if attack_mode == 0:
            if wordlist:
                resolved = wordlist
            else:
                resolved = self._find_wordlist(wordlist_name)
                if not resolved:
                    available = self.list_wordlists()
                    return f"Wordlist '{wordlist_name}' not found.\n\nAvailable:\n{available}"

        # Write hash to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(hash_value.strip() + "\n")
            hash_file = f.name

        try:
            cmd = ["hashcat", "-m", str(hash_type), "-a", str(attack_mode), hash_file]

            if attack_mode == 0:
                cmd.append(resolved)
            elif attack_mode == 3:
                if not mask:
                    return "Error: mask required for attack_mode=3 (e.g. ?a?a?a?a?a?a)"
                cmd.append(mask)

            if extra_args:
                cmd.extend(extra_args.split())

            cmd += ["--force", "--quiet", "--potfile-disable"]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            output = result.stdout.strip() or result.stderr.strip()
            return output if output else "No result / hash not cracked"

        except subprocess.TimeoutExpired:
            return "Timeout: hashcat ran for >120s. Try a smaller wordlist or mask."
        except FileNotFoundError:
            return "Error: hashcat not found. Run: sudo apt install hashcat"
        finally:
            os.unlink(hash_file)

    def _find_wordlist(self, name: str) -> str:
        """Search common wordlist directories recursively for a wordlist by filename"""
        for base in _WORDLIST_CANDIDATES:
            if not os.path.isdir(base):
                continue
            for root, dirs, files in os.walk(base):
                if name in files:
                    return os.path.join(root, name)
        return ""

    # ------------------------------------------------------------------
    # John the Ripper
    # ------------------------------------------------------------------

    def john(
        self,
        hash_value: str,
        hash_format: str = "",
        wordlist: str = "",
        wordlist_name: str = "rockyou.txt",
        mode: str = "wordlist",
        extra_args: str = "",
    ) -> str:
        """
        Crack a hash using John the Ripper.
        :param hash_value: The hash (or user:hash line) to crack
        :param hash_format: John format name (e.g. raw-md5, raw-sha1, bcrypt). Auto-detect if empty.
        :param wordlist: Full path to wordlist (overrides wordlist_name if provided)
        :param wordlist_name: Filename to search for under wordlist directories (default: rockyou.txt)
        :param mode: Attack mode — "wordlist" (default), "single", or "incremental"
        :param extra_args: Additional john flags passed verbatim
        """
        if shutil.which("john") is None:
            return "Error: john not found. Install with: sudo apt install john  (or brew install john on macOS)"

        # Write hash to a temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(hash_value.strip() + "\n")
            hash_file = f.name

        try:
            cmd = ["john"]

            if hash_format:
                cmd.append(f"--format={hash_format}")

            if mode == "wordlist":
                if wordlist:
                    resolved = wordlist
                else:
                    resolved = self._find_wordlist(wordlist_name)
                    if not resolved:
                        available = self.list_wordlists()
                        return f"Wordlist '{wordlist_name}' not found.\n\nAvailable:\n{available}"
                cmd.append(f"--wordlist={resolved}")
            elif mode == "single":
                cmd.append("--single")
            elif mode == "incremental":
                cmd.append("--incremental")
            else:
                return f"Error: unknown mode '{mode}'. Use: wordlist, single, or incremental"

            if extra_args:
                cmd.extend(extra_args.split())

            cmd.append(hash_file)

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            output = (result.stdout + result.stderr).strip()

            # Immediately show cracked passwords
            show_result = subprocess.run(
                ["john", "--show", hash_file],
                capture_output=True, text=True, timeout=10,
            )
            cracked = show_result.stdout.strip()

            if cracked and cracked != "0 password hashes cracked, 0 left":
                return f"Cracked:\n{cracked}\n\nJohn output:\n{output}"
            return output if output else "No result / hash not cracked"

        except subprocess.TimeoutExpired:
            return "Timeout: john ran for >120s. Try a smaller wordlist."
        finally:
            os.unlink(hash_file)

    def john_show(
        self,
        hash_value: str,
        hash_format: str = "",
    ) -> str:
        """
        Show passwords already cracked by John the Ripper (reads from ~/.john/john.pot).
        :param hash_value: The hash (or user:hash line) to look up
        :param hash_format: John format name (e.g. raw-md5). Auto-detect if empty.
        """
        if shutil.which("john") is None:
            return "Error: john not found. Install with: sudo apt install john"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(hash_value.strip() + "\n")
            hash_file = f.name

        try:
            cmd = ["john", "--show"]
            if hash_format:
                cmd.append(f"--format={hash_format}")
            cmd.append(hash_file)

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            output = result.stdout.strip()
            return output if output else "No cracked passwords found in pot file"
        finally:
            os.unlink(hash_file)
