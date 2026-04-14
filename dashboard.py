#!/usr/bin/env python3
"""
CTF-MCP Dashboard — interactive TUI for managing category servers.
Run: python3 dashboard.py
"""

import curses
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

SCRIPT_DIR  = Path(__file__).parent
PID_DIR     = SCRIPT_DIR / ".pids"
LOG_DIR     = SCRIPT_DIR / ".logs"
_env_file = SCRIPT_DIR / ".env"
if _env_file.exists():
    for _line in _env_file.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            os.environ.setdefault(_k.strip(), _v.strip())

VENV_PYTHON = os.environ.get("VENV_PYTHON", "python3")
SSE_SCRIPT  = SCRIPT_DIR / "sse_server.py"
CLAUDE_DIR  = Path.home() / ".claude"

TRANSPORTS        = ["sse", "streamable"]
TRANSPORT_PATHS   = {"sse": "/sse", "streamable": "/mcp"}
CURRENT_TRANSPORT = os.environ.get("MCP_TRANSPORT", "sse")  # mutable via 'T' key in TUI

PID_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)

# ---------------------------------------------------------------------------
# Tool manifest — precomputed
# ---------------------------------------------------------------------------

TOOL_NAMES: dict[str, list[str]] = {
    "crypto": [
        "crypto_base64_encode","crypto_base64_decode","crypto_base32_encode","crypto_base32_decode",
        "crypto_base58_encode","crypto_base58_decode","crypto_base85_encode","crypto_base85_decode",
        "crypto_rot_n","crypto_caesar","crypto_caesar_bruteforce","crypto_vigenere",
        "crypto_vigenere_key_length","crypto_atbash","crypto_affine","crypto_rail_fence",
        "crypto_rail_fence_bruteforce","crypto_bacon","crypto_playfair","crypto_hill_cipher",
        "crypto_polybius","crypto_morse","crypto_tap_code","crypto_substitution_analyze",
        "crypto_xor","crypto_xor_single_byte_bruteforce","crypto_xor_repeating_key",
        "crypto_aes_encrypt","crypto_aes_decrypt","crypto_des_encrypt","crypto_des_decrypt",
        "crypto_rc4","crypto_hash_data","crypto_hash_all","crypto_hash_identify","crypto_hash_crack",
        "crypto_rsa_factor","crypto_rsa_decrypt","crypto_rsa_common_modulus","crypto_rsa_wiener",
        "crypto_rsa_hastad","crypto_rsa_low_exponent","crypto_rsa_franklin_reiter",
        "crypto_rsa_parity_oracle","crypto_rsa_bleichenbacher","crypto_freq_analysis",
        "crypto_index_of_coincidence","crypto_entropy","crypto_mod_inverse","crypto_crt",
        "crypto_discrete_log","crypto_euler_phi","crypto_primitive_root",
        "misc_hex_encode","misc_hex_decode","misc_url_encode","misc_url_decode",
        "misc_html_encode","misc_html_decode","misc_binary_convert","misc_find_flag",
        "misc_strings_extract","misc_reverse_string","misc_reverse_words","misc_char_swap",
        "misc_remove_whitespace","misc_to_leetspeak","misc_detect_encoding","misc_gcd","misc_lcm",
    ],
    "web": [
        "web_sql_payloads","web_sql_waf_bypass","web_sql_extract_template",
        "web_xss_payloads","web_xss_filter_bypass","web_xss_polyglot",
        "web_lfi_payloads","web_rfi_payloads","web_path_traversal",
        "web_ssti_payloads","web_ssti_identify","web_cmd_injection","web_cmd_blind",
        "web_ssrf_payloads","web_ssrf_protocols","web_ssrf_cloud_metadata",
        "web_xxe_payloads","web_xxe_oob","web_xxe_blind",
        "web_jwt_decode","web_jwt_forge","web_jwt_crack","web_jwt_attacks",
        "web_php_serialize","web_php_unserialize_exploit","web_pickle_payload",
        "web_java_deserialize","web_nodejs_deserialize","web_yaml_deserialize",
        "web_prototype_pollution","web_open_redirect","web_csrf_token_bypass","web_csrf_poc_generate",
        "web_http_smuggling","web_http_header_injection","web_crlf_injection","web_host_header_attack",
        "web_graphql_introspection","web_graphql_parse_schema","web_graphql_injection",
        "web_websocket_test","web_oauth_attacks","web_cors_exploit","web_cache_poison",
        "web_pdf_ssrf","web_upload_bypass","web_race_condition","web_url_decode_recursive",
        "web_http_header_analyze","web_postgres_query","web_mysql_query",
        "misc_hex_encode","misc_hex_decode","misc_url_encode","misc_url_decode",
        "misc_html_encode","misc_html_decode","misc_binary_convert","misc_find_flag",
        "misc_strings_extract","misc_reverse_string","misc_reverse_words","misc_char_swap",
        "misc_remove_whitespace","misc_to_leetspeak","misc_detect_encoding","misc_gcd","misc_lcm",
    ],
    "pwn": [
        "pwn_shellcode_gen","pwn_shellcode_encode","pwn_pattern_create","pwn_pattern_offset",
        "pwn_rop_gadgets","pwn_rop_chain_builder","pwn_ret2libc","pwn_ret2csu",
        "pwn_format_string","pwn_format_string_leak","pwn_libc_offset","pwn_one_gadget",
        "pwn_libc_database","pwn_heap_tcache","pwn_heap_fastbin","pwn_heap_house_of_force",
        "pwn_heap_house_of_spirit","pwn_heap_unsorted_bin","pwn_heap_chunk_structure",
        "pwn_stack_pivot","pwn_stack_layout","pwn_pack","pwn_unpack","pwn_flat",
        "pwn_got_plt","pwn_sigreturn","pwn_syscall_table",
        "reverse_disasm","reverse_asm","reverse_elf_info","reverse_pe_info",
        "reverse_deobfuscate","reverse_find_strings","reverse_find_gadgets_in_hex",
        "reverse_checksec","reverse_elf_sections","reverse_elf_symbols",
        "misc_hex_encode","misc_hex_decode","misc_url_encode","misc_url_decode",
        "misc_html_encode","misc_html_decode","misc_binary_convert","misc_find_flag",
        "misc_strings_extract","misc_reverse_string","misc_reverse_words","misc_char_swap",
        "misc_remove_whitespace","misc_to_leetspeak","misc_detect_encoding","misc_gcd","misc_lcm",
    ],
    "reverse": [
        "reverse_disasm","reverse_asm","reverse_elf_info","reverse_pe_info",
        "reverse_deobfuscate","reverse_find_strings","reverse_find_gadgets_in_hex",
        "reverse_checksec","reverse_elf_sections","reverse_elf_symbols",
        "misc_hex_encode","misc_hex_decode","misc_url_encode","misc_url_decode",
        "misc_html_encode","misc_html_decode","misc_binary_convert","misc_find_flag",
        "misc_strings_extract","misc_reverse_string","misc_reverse_words","misc_char_swap",
        "misc_remove_whitespace","misc_to_leetspeak","misc_detect_encoding","misc_gcd","misc_lcm",
    ],
    "forensics": [
        "forensics_file_magic","forensics_exif_extract","forensics_steghide_detect",
        "forensics_lsb_extract","forensics_strings_file","forensics_binwalk_scan",
        "forensics_hex_dump","forensics_entropy_analysis","forensics_png_chunks","forensics_zip_analysis",
        "memory_info","memory_pslist","memory_pstree","memory_cmdline","memory_netscan",
        "memory_filescan","memory_dumpfiles","memory_hashdump","memory_hivelist",
        "memory_printkey","memory_malfind","memory_run_plugin",
        "pcap_summary","pcap_protocol_hierarchy","pcap_conversations","pcap_follow_stream",
        "pcap_http_requests","pcap_dns_queries","pcap_credentials","pcap_export_objects",
        "pcap_filter","pcap_strings_search",
        "misc_hex_encode","misc_hex_decode","misc_url_encode","misc_url_decode",
        "misc_html_encode","misc_html_decode","misc_binary_convert","misc_find_flag",
        "misc_strings_extract","misc_reverse_string","misc_reverse_words","misc_char_swap",
        "misc_remove_whitespace","misc_to_leetspeak","misc_detect_encoding","misc_gcd","misc_lcm",
    ],
}
# Full = union of everything
_all: list[str] = []
_seen: set[str] = set()
for _tools in TOOL_NAMES.values():
    for _t in _tools:
        if _t not in _seen:
            _all.append(_t)
            _seen.add(_t)
for _extra in ["cracking_hashcat","cracking_list_wordlists","cracking_john","cracking_john_show",
               "network_quick_scan","network_port_scan","network_service_scan","network_aggressive_scan",
               "network_ping_sweep","network_os_detect","network_vuln_scan","network_script_scan"]:
    if _extra not in _seen:
        _all.append(_extra)
TOOL_NAMES["full"] = _all

SERVERS = [
    {"name": "full",      "port": 8000, "tools": len(TOOL_NAMES["full"]),      "desc": "All tools"},
    {"name": "crypto",    "port": 8001, "tools": len(TOOL_NAMES["crypto"]),    "desc": "Crypto + Misc"},
    {"name": "web",       "port": 8002, "tools": len(TOOL_NAMES["web"]),       "desc": "Web + Misc"},
    {"name": "pwn",       "port": 8003, "tools": len(TOOL_NAMES["pwn"]),       "desc": "Pwn + RE + Misc"},
    {"name": "reverse",   "port": 8004, "tools": len(TOOL_NAMES["reverse"]),   "desc": "Reverse + Misc"},
    {"name": "forensics", "port": 8005, "tools": len(TOOL_NAMES["forensics"]), "desc": "Forensics + Mem + PCAP"},
]

# ---------------------------------------------------------------------------
# Claude stats
# ---------------------------------------------------------------------------

def load_claude_info() -> dict:
    info: dict = {}

    # Version
    try:
        out = subprocess.check_output(["claude", "--version"], stderr=subprocess.DEVNULL, text=True).strip()
        info["version"] = out.split()[0] if out else "?"
    except Exception:
        info["version"] = "?"

    # Settings (advisor model)
    try:
        s = json.loads((CLAUDE_DIR / "settings.json").read_text())
        info["advisor"] = s.get("advisorModel", "?")
    except Exception:
        info["advisor"] = "?"

    # Stats cache
    try:
        sc = json.loads((CLAUDE_DIR / "stats-cache.json").read_text())
        info["total_messages"] = sc.get("totalMessages", 0)
        info["total_sessions"] = sc.get("totalSessions", 0)

        model_usage = sc.get("modelUsage", {})
        total_input = total_output = total_cache_read = total_cache_create = 0
        for m, u in model_usage.items():
            total_input        += u.get("inputTokens", 0)
            total_output       += u.get("outputTokens", 0)
            total_cache_read   += u.get("cacheReadInputTokens", 0)
            total_cache_create += u.get("cacheCreationInputTokens", 0)

        info["input_tokens"]        = total_input
        info["output_tokens"]       = total_output
        info["cache_read_tokens"]   = total_cache_read
        info["cache_create_tokens"] = total_cache_create

        # Most recent model
        daily = sc.get("dailyModelTokens", [])
        if daily:
            last = daily[-1].get("tokensByModel", {})
            if last:
                info["current_model"] = max(last, key=last.get)
            else:
                info["current_model"] = "?"
        else:
            info["current_model"] = "?"

        # Activity last 7 days
        today = datetime.now(timezone.utc).date()
        recent_msgs = recent_tools = 0
        for d in sc.get("dailyActivity", []):
            try:
                from datetime import date
                dd = date.fromisoformat(d["date"])
                if (today - dd).days <= 7:
                    recent_msgs  += d.get("messageCount", 0)
                    recent_tools += d.get("toolCallCount", 0)
            except Exception:
                pass
        info["recent_messages"]   = recent_msgs
        info["recent_tool_calls"] = recent_tools

    except Exception:
        pass

    return info


def fmt_num(n: int) -> str:
    if n >= 1_000_000:
        return f"{n/1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n/1_000:.1f}K"
    return str(n)


def shorten_model(name: str) -> str:
    return (name
        .replace("claude-", "")
        .replace("-20250929", "")
        .replace("-20251001", ""))

# ---------------------------------------------------------------------------
# Process management
# ---------------------------------------------------------------------------

def pid_file(name: str) -> Path: return PID_DIR / f"{name}.pid"
def log_file(name: str) -> Path: return LOG_DIR / f"{name}.log"

def get_pid(name: str) -> int | None:
    pf = pid_file(name)
    if not pf.exists():
        return None
    try:
        pid = int(pf.read_text().strip())
        os.kill(pid, 0)
        return pid
    except (ValueError, ProcessLookupError, PermissionError):
        pf.unlink(missing_ok=True)
        return None

def is_running(name: str) -> bool:
    return get_pid(name) is not None

def start_server(name: str, port: int) -> bool:
    if is_running(name):
        return True
    with open(log_file(name), "a") as lf:
        proc = subprocess.Popen(
            [VENV_PYTHON, str(SSE_SCRIPT), name, str(port),
             "--transport", CURRENT_TRANSPORT],
            stdout=lf, stderr=lf,
            start_new_session=True,
        )
    pid_file(name).write_text(str(proc.pid))
    time.sleep(0.5)
    return is_running(name)

def stop_server(name: str) -> bool:
    pid = get_pid(name)
    if pid is None:
        return True
    try:
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    pid_file(name).unlink(missing_ok=True)
    time.sleep(0.3)
    return not is_running(name)

def start_all():
    for s in SERVERS:
        if not is_running(s["name"]):
            start_server(s["name"], s["port"])

def stop_all():
    for s in SERVERS:
        stop_server(s["name"])

# ---------------------------------------------------------------------------
# Color pairs
# ---------------------------------------------------------------------------
C_TITLE    = 1
C_HEADER   = 2
C_RUNNING  = 3
C_STOPPED  = 4
C_SEL      = 5
C_KEY      = 6
C_URL      = 7
C_DIM      = 8
C_BORDER   = 9
C_STAT     = 10
C_SKILL_ON = 11
C_SKILL_OF = 12
C_LABEL    = 13

def init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(C_TITLE,    curses.COLOR_CYAN,    -1)
    curses.init_pair(C_HEADER,   curses.COLOR_WHITE,   -1)
    curses.init_pair(C_RUNNING,  curses.COLOR_GREEN,   -1)
    curses.init_pair(C_STOPPED,  curses.COLOR_RED,     -1)
    curses.init_pair(C_SEL,      curses.COLOR_BLACK,   curses.COLOR_CYAN)
    curses.init_pair(C_KEY,      curses.COLOR_YELLOW,  -1)
    curses.init_pair(C_URL,      curses.COLOR_CYAN,    -1)
    curses.init_pair(C_DIM,      curses.COLOR_WHITE,   -1)
    curses.init_pair(C_BORDER,   curses.COLOR_BLUE,    -1)
    curses.init_pair(C_STAT,     curses.COLOR_MAGENTA, -1)
    curses.init_pair(C_SKILL_ON, curses.COLOR_GREEN,   -1)
    curses.init_pair(C_SKILL_OF, curses.COLOR_WHITE,   -1)
    curses.init_pair(C_LABEL,    curses.COLOR_YELLOW,  -1)

# ---------------------------------------------------------------------------
# Drawing helpers
# ---------------------------------------------------------------------------

def addstr_clipped(win, y: int, x: int, text: str, attr: int = 0, max_w: int = 0):
    h, w = win.getmaxyx()
    max_w = max_w or (w - x - 1)
    if y >= h or x >= w - 1 or max_w <= 0:
        return
    text = text[:max_w]
    try:
        win.addstr(y, x, text, attr)
    except curses.error:
        pass

def draw_hline(win, y: int, x1: int, x2: int, attr: int = 0):
    h, w = win.getmaxyx()
    if y >= h:
        return
    win.attron(attr)
    for x in range(x1, min(x2, w - 1)):
        try:
            win.addch(y, x, "─")
        except curses.error:
            pass
    win.attroff(attr)

def draw_vline(win, x: int, y1: int, y2: int, attr: int = 0):
    h, w = win.getmaxyx()
    if x >= w:
        return
    win.attron(attr)
    for y in range(y1, min(y2, h - 1)):
        try:
            win.addch(y, x, "│")
        except curses.error:
            pass
    win.attroff(attr)

# ---------------------------------------------------------------------------
# Panel: Servers
# Column layout (offsets from panel x+1):
#   0  : cursor (1) + space (1)  = 2
#   2  : name  (10)              = 12
#   12 : status (9)              = 21
#   21 : port  (6)               = 27
#   27 : tools (6)               = 33
#   33 : description
# ---------------------------------------------------------------------------

_C_CURSOR = 0
_C_NAME   = 2
_C_STATUS = 12
_C_PORT   = 21
_C_TOOLS  = 27
_C_DESC   = 33

def draw_servers(win, x: int, y: int, panel_w: int, panel_h: int, selected: int):
    border_attr = curses.color_pair(C_BORDER)
    base = x + 1  # left edge of content

    # Header — use same fixed offsets
    hdr_attr = curses.color_pair(C_HEADER) | curses.A_BOLD
    addstr_clipped(win, y, base + _C_CURSOR, "  ",        hdr_attr)
    addstr_clipped(win, y, base + _C_NAME,   "SERVER    ", hdr_attr)
    addstr_clipped(win, y, base + _C_STATUS, "STATUS   ", hdr_attr)
    addstr_clipped(win, y, base + _C_PORT,   "PORT  ",    hdr_attr)
    addstr_clipped(win, y, base + _C_TOOLS,  "TOOLS ",    hdr_attr)
    addstr_clipped(win, y, base + _C_DESC,   "DESCRIPTION", hdr_attr)
    draw_hline(win, y + 1, x, x + panel_w, border_attr)

    row = y + 2
    for i, srv in enumerate(SERVERS):
        if row >= y + panel_h - 1:
            break
        running = is_running(srv["name"])
        is_sel  = (i == selected)
        cursor  = "►" if is_sel else " "
        status  = "ON " if running else "OFF"

        if is_sel:
            # Highlight entire row
            line = (
                f"{cursor} "
                f"{srv['name']:<10}"
                f"{'● ' + status:<9}"
                f"{srv['port']:<6}"
                f"{srv['tools']:<6}"
                f"{srv['desc']}"
            )
            addstr_clipped(win, row, base, line.ljust(panel_w - 1),
                           curses.color_pair(C_SEL) | curses.A_BOLD, panel_w - 1)
        else:
            # Cursor
            addstr_clipped(win, row, base + _C_CURSOR, f"{cursor} ", curses.A_BOLD)
            # Name
            addstr_clipped(win, row, base + _C_NAME, f"{srv['name']:<10}")
            # Status (colored, fixed width)
            s_attr = (curses.color_pair(C_RUNNING) | curses.A_BOLD) if running else curses.color_pair(C_STOPPED)
            badge = ("● " + status).ljust(9)
            addstr_clipped(win, row, base + _C_STATUS, badge, s_attr)
            # Port
            addstr_clipped(win, row, base + _C_PORT, f"{srv['port']:<6}")
            # Tools
            addstr_clipped(win, row, base + _C_TOOLS, f"{srv['tools']:<6}",
                           curses.color_pair(C_URL) | curses.A_BOLD)
            # Description
            desc_w = panel_w - _C_DESC - 2
            addstr_clipped(win, row, base + _C_DESC,
                           srv["desc"][:desc_w], curses.color_pair(C_DIM))
        row += 1

# ---------------------------------------------------------------------------
# Panel: Skills
# ---------------------------------------------------------------------------

def draw_skills(win, x: int, y: int, panel_w: int, panel_h: int,
                selected: int, skill_scroll: int):
    border_attr = curses.color_pair(C_BORDER)
    srv         = SERVERS[selected]
    name        = srv["name"]
    running     = is_running(name)
    tools       = TOOL_NAMES.get(name, [])

    # Header
    status_str = "LIVE" if running else "offline"
    status_attr = curses.color_pair(C_RUNNING) | curses.A_BOLD if running else curses.color_pair(C_STOPPED)
    header = f" SKILLS — {name} ["
    addstr_clipped(win, y, x + 1, header, curses.color_pair(C_LABEL) | curses.A_BOLD)
    cx = x + 1 + len(header)
    addstr_clipped(win, y, cx, status_str, status_attr)
    cx += len(status_str)
    addstr_clipped(win, y, cx, f"] {len(tools)} tools", curses.color_pair(C_LABEL) | curses.A_BOLD)

    draw_hline(win, y + 1, x, x + panel_w, border_attr)

    visible = panel_h - 3
    display = tools[skill_scroll: skill_scroll + visible]

    skill_attr_on  = curses.color_pair(C_SKILL_ON)
    skill_attr_off = curses.color_pair(C_SKILL_OF) | curses.A_DIM

    # Fixed prefix column width: longest prefix is "forensics" = 9 chars + "_" = 10
    prefix_col_w = 11  # "forensics_ " padded
    for i, tool in enumerate(display):
        row = y + 2 + i
        if row >= y + panel_h - 1:
            break
        prefix, _, short = tool.partition("_")
        attr = skill_attr_on if running else skill_attr_off
        # Prefix column (dim, fixed width)
        addstr_clipped(win, row, x + 2,
                       f"{prefix}_".ljust(prefix_col_w), curses.color_pair(C_DIM))
        # Tool name column (colored)
        short_x = x + 2 + prefix_col_w
        addstr_clipped(win, row, short_x, short, attr, x + panel_w - short_x - 1)

    # Scroll indicator
    if len(tools) > visible:
        pct = int(skill_scroll / max(1, len(tools) - visible) * 100)
        addstr_clipped(win, y + panel_h - 1, x + 1,
                       f" ↕ {skill_scroll+1}-{min(skill_scroll+visible, len(tools))}/{len(tools)} ({pct}%)",
                       curses.color_pair(C_DIM))

# ---------------------------------------------------------------------------
# Panel: Claude Info
# ---------------------------------------------------------------------------

def draw_claude(win, x: int, y: int, panel_w: int, panel_h: int, claude_info: dict):
    border_attr = curses.color_pair(C_BORDER)
    label_attr  = curses.color_pair(C_LABEL) | curses.A_BOLD
    val_attr    = curses.color_pair(C_TITLE) | curses.A_BOLD
    dim_attr    = curses.color_pair(C_DIM)

    addstr_clipped(win, y, x + 1, " CLAUDE INFO", label_attr)
    draw_hline(win, y + 1, x, x + panel_w, border_attr)

    def row_kv(row: int, key: str, val: str, vattr=None):
        if row >= y + panel_h - 1:
            return
        addstr_clipped(win, row, x + 2, f"{key:<14}", dim_attr, panel_w - 3)
        addstr_clipped(win, row, x + 2 + 14, val, vattr or val_attr, panel_w - 17)

    r = y + 2
    row_kv(r, "Version",  claude_info.get("version", "?"));            r += 1
    row_kv(r, "Model",    shorten_model(claude_info.get("current_model", "?")));  r += 1
    row_kv(r, "Advisor",  claude_info.get("advisor", "?"));            r += 1
    r += 1  # spacer

    if r < y + panel_h - 1:
        addstr_clipped(win, r, x + 2, "── USAGE (all-time) ──", curses.color_pair(C_BORDER))
        r += 1

    row_kv(r, "Messages",   f"{claude_info.get('total_messages', 0):,}");   r += 1
    row_kv(r, "Sessions",   f"{claude_info.get('total_sessions', 0):,}");   r += 1
    row_kv(r, "Output tok", fmt_num(claude_info.get("output_tokens", 0)));  r += 1
    row_kv(r, "Input tok",  fmt_num(claude_info.get("input_tokens", 0)));   r += 1
    row_kv(r, "Cache read", fmt_num(claude_info.get("cache_read_tokens", 0))); r += 1
    r += 1

    if r < y + panel_h - 1:
        addstr_clipped(win, r, x + 2, "── LAST 7 DAYS ──", curses.color_pair(C_BORDER))
        r += 1
    row_kv(r, "Messages",   f"{claude_info.get('recent_messages', 0):,}");  r += 1
    row_kv(r, "Tool calls", f"{claude_info.get('recent_tool_calls', 0):,}"); r += 1

# ---------------------------------------------------------------------------
# Status bar + keybindings
# ---------------------------------------------------------------------------

def draw_statusbar(win, h: int, w: int, message: str, tick: int):
    running_count = sum(1 for s in SERVERS if is_running(s["name"]))
    active_tools  = sum(s["tools"] for s in SERVERS if is_running(s["name"]))
    spinner = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"[tick % 10]

    draw_hline(win, h - 4, 1, w - 1, curses.color_pair(C_BORDER))

    stat = f"  {spinner}  Servers: {running_count}/{len(SERVERS)}   Active tools: {active_tools}   Transport: {CURRENT_TRANSPORT.upper()}"
    addstr_clipped(win, h - 3, 2, stat, curses.color_pair(C_STAT) | curses.A_BOLD, w - 4)

    if message:
        msg_x = 2 + len(stat) + 4
        addstr_clipped(win, h - 3, msg_x, f"│ {message}", curses.color_pair(C_KEY) | curses.A_BOLD, w - msg_x - 2)

    # Right side of stat line: [?] Help
    addstr_clipped(win, h - 3, w - 10, "[?]", curses.color_pair(C_KEY) | curses.A_BOLD)
    addstr_clipped(win, h - 3, w - 7,  " Help", curses.color_pair(C_DIM))

    draw_hline(win, h - 2, 1, w - 1, curses.color_pair(C_BORDER))

# ---------------------------------------------------------------------------
# Help overlay
# ---------------------------------------------------------------------------

HELP_ENTRIES = [
    ("Navigation", [
        ("↑ / ↓",        "Select server"),
        ("PgUp / PgDn",  "Scroll skill list"),
    ]),
    ("Server Control", [
        ("Space / Enter", "Start or stop selected server"),
        ("A",             "Start all servers"),
        ("X",             "Stop all servers"),
        ("R",             "Restart selected server"),
    ]),
    ("Config", [
        ("T",             "Cycle transport  (SSE → Streamable → ...)"),
    ]),
    ("Other", [
        ("L",             "View logs for selected server"),
        ("?",             "Show this help"),
        ("Q",             "Quit dashboard"),
    ]),
]

def show_help(win):
    h, w = win.getmaxyx()

    # Each section: 1 blank + 1 header + 1 underline + entries + 1 trailing blank
    box_h = sum(4 + len(entries) for _, entries in HELP_ENTRIES) + 3
    # Wide enough for the longest line: 2 indent + 16 key + 2 gap + desc + 2 border
    max_desc  = max(len(desc) for _, entries in HELP_ENTRIES for _, desc in entries)
    box_w     = min(w - 4, max(50, 2 + 16 + 2 + max_desc + 2))
    key_col   = 4
    desc_col  = key_col + 16 + 1   # 4 indent + 16 key + 1 gap
    desc_max  = box_w - desc_col - 2  # leave room for right border

    by = max(1, (h - box_h) // 2)
    bx = max(1, (w - box_w) // 2)

    # Draw shadow
    for r in range(box_h):
        addstr_clipped(win, by + r + 1, bx + 2, " " * box_w, curses.color_pair(C_BORDER))

    # Draw box
    panel = curses.newwin(box_h, box_w, by, bx)
    panel.bkgd(" ", curses.color_pair(C_BORDER))
    panel.border()

    title = "  Keybindings  (any key to close)  "
    addstr_clipped(panel, 0, max(1, (box_w - len(title)) // 2), title,
                   curses.color_pair(C_TITLE) | curses.A_BOLD)

    row = 1
    for section, entries in HELP_ENTRIES:
        row += 1  # blank line before section
        addstr_clipped(panel, row, 2, section, curses.color_pair(C_KEY) | curses.A_BOLD)
        row += 1  # underline below section header
        addstr_clipped(panel, row, 2, "─" * (box_w - 4), curses.color_pair(C_BORDER))
        for key, desc in entries:
            row += 1
            addstr_clipped(panel, row, key_col,  f"{key:<16}", curses.color_pair(C_STAT) | curses.A_BOLD)
            addstr_clipped(panel, row, desc_col, desc,         curses.color_pair(C_DIM), desc_max)
        row += 1  # blank line after section

    panel.refresh()
    panel.getch()
    win.touchwin()
    win.refresh()

# ---------------------------------------------------------------------------
# Log viewer
# ---------------------------------------------------------------------------

def show_logs(win, name: str):
    lf = log_file(name)
    h, w = win.getmaxyx()
    win.erase()
    win.border()
    title = f"  Logs: {name}  (press any key to close)  "
    addstr_clipped(win, 0, max(1, (w - len(title)) // 2), title,
                   curses.color_pair(C_TITLE) | curses.A_BOLD)
    if not lf.exists():
        addstr_clipped(win, 2, 2, "No log file found.", curses.color_pair(C_STOPPED))
    else:
        lines   = lf.read_text(errors="replace").splitlines()
        visible = h - 4
        display = lines[-visible:] if len(lines) > visible else lines
        for i, line in enumerate(display):
            addstr_clipped(win, i + 2, 2, line, 0, w - 4)
    win.refresh()
    win.getch()

# ---------------------------------------------------------------------------
# Main draw
# ---------------------------------------------------------------------------

def draw(win, selected: int, message: str, tick: int,
         skill_scroll: int, claude_info: dict):
    h, w = win.getmaxyx()
    win.erase()
    win.attron(curses.color_pair(C_BORDER))
    win.border()
    win.attroff(curses.color_pair(C_BORDER))

    title = "  CTF-MCP Dashboard  "
    addstr_clipped(win, 0, max(1, (w - len(title)) // 2), title,
                   curses.color_pair(C_TITLE) | curses.A_BOLD)

    content_h = h - 4   # rows available between title border and status bar
    content_y = 1

    # ── Layout: 3 panels when wide, 1 panel when narrow ──────────────────
    if w >= 120:
        srv_w   = 56
        claude_w = 28
        skill_w  = w - srv_w - claude_w - 2   # remainder

        # Server panel (left)
        draw_vline(win, srv_w, content_y, content_y + content_h, curses.color_pair(C_BORDER))
        draw_servers(win, 1, content_y, srv_w, content_h, selected)

        # Skills panel (middle)
        draw_vline(win, srv_w + skill_w, content_y, content_y + content_h, curses.color_pair(C_BORDER))
        draw_skills(win, srv_w, content_y, skill_w, content_h, selected, skill_scroll)

        # Claude panel (right)
        draw_claude(win, srv_w + skill_w, content_y, claude_w, content_h, claude_info)

    elif w >= 80:
        srv_w   = w // 2
        right_w = w - srv_w - 1
        half_h  = content_h // 2

        draw_vline(win, srv_w, content_y, content_y + content_h, curses.color_pair(C_BORDER))
        draw_servers(win, 1, content_y, srv_w, content_h, selected)
        draw_skills(win, srv_w, content_y, right_w, half_h, selected, skill_scroll)
        draw_hline(win, content_y + half_h, srv_w, w - 1, curses.color_pair(C_BORDER))
        draw_claude(win, srv_w, content_y + half_h, right_w, content_h - half_h, claude_info)

    else:
        draw_servers(win, 1, content_y, w - 2, content_h, selected)

    draw_statusbar(win, h, w, message, tick)
    win.refresh()

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(500)
    init_colors()

    selected     = 0
    message      = ""
    msg_ttl      = 0
    tick         = 0
    skill_scroll = 0
    claude_info  = load_claude_info()
    info_refresh = 0   # refresh claude info every 30 ticks (~15s)

    while True:
        if info_refresh <= 0:
            claude_info  = load_claude_info()
            info_refresh = 30

        draw(stdscr, selected, message if msg_ttl > 0 else "", tick, skill_scroll, claude_info)

        key = stdscr.getch()
        tick        += 1
        info_refresh -= 1
        if msg_ttl > 0:
            msg_ttl -= 1

        if key in (ord("q"), ord("Q")):
            break

        elif key == curses.KEY_UP:
            selected     = (selected - 1) % len(SERVERS)
            skill_scroll = 0

        elif key == curses.KEY_DOWN:
            selected     = (selected + 1) % len(SERVERS)
            skill_scroll = 0

        elif key == curses.KEY_NPAGE:   # Page Down → scroll skills
            tools = TOOL_NAMES.get(SERVERS[selected]["name"], [])
            skill_scroll = min(skill_scroll + 10, max(0, len(tools) - 1))

        elif key == curses.KEY_PPAGE:   # Page Up → scroll skills
            skill_scroll = max(0, skill_scroll - 10)

        elif key in (ord("t"), ord("T")):
            global CURRENT_TRANSPORT
            CURRENT_TRANSPORT = TRANSPORTS[(TRANSPORTS.index(CURRENT_TRANSPORT) + 1) % len(TRANSPORTS)]
            ep = TRANSPORT_PATHS[CURRENT_TRANSPORT]
            message = f"Transport → {CURRENT_TRANSPORT.upper()}  (new servers will use {ep})"
            msg_ttl = 6

        elif key in (ord(" "), ord("\n"), curses.KEY_ENTER):
            srv = SERVERS[selected]
            if is_running(srv["name"]):
                stop_server(srv["name"])
                message = f"Stopped {srv['name']}"
            else:
                ok = start_server(srv["name"], srv["port"])
                ep = TRANSPORT_PATHS[CURRENT_TRANSPORT]
                message = (f"Started {srv['name']} → :{srv['port']}{ep} [{CURRENT_TRANSPORT}]"
                           if ok else f"Failed to start {srv['name']} — check logs (L)")
            msg_ttl = 8

        elif key in (ord("a"), ord("A")):
            start_all()
            message = "Started all servers"
            msg_ttl = 8

        elif key in (ord("x"), ord("X")):
            stop_all()
            message = "Stopped all servers"
            msg_ttl = 8

        elif key in (ord("r"), ord("R")):
            srv = SERVERS[selected]
            stop_server(srv["name"])
            ok = start_server(srv["name"], srv["port"])
            ep = TRANSPORT_PATHS[CURRENT_TRANSPORT]
            message = (f"Restarted {srv['name']} → :{srv['port']}{ep} [{CURRENT_TRANSPORT}]"
                       if ok else f"Failed to restart {srv['name']} — check logs (L)")
            msg_ttl = 8

        elif key in (ord("l"), ord("L")):
            show_logs(stdscr, SERVERS[selected]["name"])
            stdscr.timeout(500)

        elif key == ord("?"):
            show_help(stdscr)
            stdscr.timeout(500)

        elif key == curses.KEY_RESIZE:
            stdscr.erase()
            skill_scroll = 0


def run():
    try:
        curses.wrapper(main)
    except KeyboardInterrupt:
        pass
    print("Dashboard closed.")


if __name__ == "__main__":
    run()
