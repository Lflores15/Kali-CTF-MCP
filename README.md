# Kali-MCP

A modular [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server for CTF challenges. Exposes security tooling directly to AI assistants across crypto, web, pwn, reverse engineering, forensics, memory analysis, PCAP, and network categories.

Based on [CTF-MCP](https://github.com/Coff0xc/CTF-MCP) by Coff0xc — extended with additional tools, focused category servers, SSE transport, a process manager, and a TUI dashboard.

---

## Features

- **Focused category servers** — run only the tools you need, reducing per-session token overhead
- **SSE transport** — each server runs over HTTP/SSE, connectable by any MCP-compatible client
- **`manage.sh`** — start, stop, restart, and tail logs for all servers from one script
- **`dashboard.py`** — curses TUI to manage servers, browse loaded tools, and view Claude stats

---

## Architecture

```
sse_server.py           # HTTP/SSE entrypoint — accepts category + port args
ctf_mcp/
  server_factory.py     # Shared make_server() factory used by all servers
  server.py             # Full server (all tools, stdio transport)
  servers/              # Focused category servers (stdio transport)
  tools/                # MCP tool definitions (thin wrappers over adapters)
  adapters/             # CLI/library wrappers with input validation
manage.sh               # Process manager using PID files and log files
dashboard.py            # Curses TUI
```

---

## Category Servers

| Category  | Port | Description |
|-----------|------|-------------|
| full      | 8000 | All tools + orchestrator |
| crypto    | 8001 | Ciphers, encoding, hashing, RSA attacks |
| web       | 8002 | SQLi, XSS, JWT, SSRF, SSTI, XXE, deserialization |
| pwn       | 8003 | ROP, shellcode, heap exploitation, pwntools |
| reverse   | 8004 | ELF/PE analysis, disassembly, gadget finding |
| forensics | 8005 | Steganography, PCAP analysis, memory forensics |

---

## External Tools Required

The following tools must be installed and available on `PATH`:

| Tool | Used for | Install |
|------|----------|---------|
| [Volatility3](https://github.com/volatilityfoundation/volatility3) | Memory forensics | `pip install volatility3` |
| [tshark](https://www.wireshark.org/docs/man-pages/tshark.html) | PCAP analysis | via Wireshark or `brew install wireshark` |
| [nmap](https://nmap.org) | Network scanning | `brew install nmap` / `apt install nmap` |
| [hashcat](https://hashcat.net) | Password cracking | `brew install hashcat` / `apt install hashcat` |
| [John the Ripper](https://www.openwall.com/john/) | Password cracking | `brew install john-jumbo` / `apt install john` |
| [binwalk](https://github.com/ReFirmLabs/binwalk) | Firmware analysis | `pip install binwalk` |
| [steghide](https://steghide.sourceforge.net) | Steganography | `apt install steghide` |
| [pwntools](https://github.com/Gallopsled/pwntools) | Binary exploitation | `pip install pwntools` (Linux only) |
| [angr](https://github.com/angr/angr) | Binary analysis | `pip install angr` (Linux only) |

---

## Installation

```bash
git clone https://github.com/Lflores15/Kali-MCP.git
cd Kali-MCP

python3 -m venv venv
source venv/bin/activate

# Install with all Python dependencies
pip install -e ".[full]"

# Configure environment
cp .env.dist .env
# Edit .env and set VENV_PYTHON to your venv's python path
```

---

## Configuration

`.env.dist` is provided as a template — copy it to `.env` and fill in your values:

```env
# Path to the Python interpreter in your virtualenv
VENV_PYTHON=/path/to/your/venv/bin/python
```

This is read by `manage.sh` and `dashboard.py` to launch servers.

---

## Running Servers

### manage.sh

```bash
./manage.sh start all          # start all category servers
./manage.sh start crypto       # start only the crypto server
./manage.sh stop all           # stop all servers
./manage.sh restart forensics  # restart one server
./manage.sh status             # show running/stopped state
./manage.sh logs forensics     # tail a server's log
```

Servers run detached with PID files in `.pids/` and logs in `.logs/`.

### Manual

```bash
python3 sse_server.py                 # full server, port 8000
python3 sse_server.py crypto 8001     # crypto only, port 8001
python3 sse_server.py forensics 8005  # forensics only, port 8005
```

### Dashboard

```bash
python3 dashboard.py
```

| Key | Action |
|-----|--------|
| `↑` / `↓` | Navigate servers |
| `s` | Start / stop selected server |
| `r` | Restart selected server |
| `PgUp` / `PgDn` | Scroll tool list |
| `q` | Quit |

---

## Connecting to Claude

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ctf-crypto": {
      "url": "http://localhost:8001/sse"
    },
    "ctf-web": {
      "url": "http://localhost:8002/sse"
    },
    "ctf-pwn": {
      "url": "http://localhost:8003/sse"
    },
    "ctf-reverse": {
      "url": "http://localhost:8004/sse"
    },
    "ctf-forensics": {
      "url": "http://localhost:8005/sse"
    }
  }
}
```

Or connect to port 8000 for all tools at once.

---

## Credits

Built on top of [CTF-MCP](https://github.com/Coff0xc/CTF-MCP) by [Coff0xc](https://github.com/Coff0xc).

This project also wraps the following open-source tools and libraries:

- [Volatility3](https://github.com/volatilityfoundation/volatility3) — Volatility Foundation (Apache 2.0)
- [pwntools](https://github.com/Gallopsled/pwntools) — MIT
- [angr](https://github.com/angr/angr) — BSD 2-Clause
- [capstone](https://github.com/capstone-engine/capstone) — BSD
- [keystone-engine](https://github.com/keystone-engine/keystone) — GPL-2.0
- [z3](https://github.com/Z3Prover/z3) — Microsoft Research (MIT)
- [gmpy2](https://github.com/aleaxit/gmpy) — LGPL-3.0
- [sympy](https://github.com/sympy/sympy) — BSD
- [pycryptodome](https://github.com/Legrandin/pycryptodome) — BSD / public domain
- [binwalk](https://github.com/ReFirmLabs/binwalk) — MIT
- [hashcat](https://github.com/hashcat/hashcat) — MIT
- [John the Ripper](https://github.com/openwall/john) — GPL-2.0
- [nmap](https://nmap.org) — NPSL / GPL-2.0
- [Wireshark / tshark](https://www.wireshark.org) — GPL-2.0
- [MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk) — MIT
- [Starlette](https://github.com/encode/starlette) / [uvicorn](https://github.com/encode/uvicorn) — BSD

---

## License

MIT — see [LICENSE](LICENSE).
