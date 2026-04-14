"""ctf-forensics-mcp — Forensics challenge tools (~32 tools: forensics + memory + pcap)"""
from ..server_factory import make_server, run
from ..tools.forensics import ForensicsTools
from ..tools.memory import MemoryTools
from ..tools.pcap import PcapTools
from ..tools.misc import MiscTools


def main():
    modules = [
        ("forensics", ForensicsTools()),
        ("memory",    MemoryTools()),
        ("pcap",      PcapTools()),
        ("misc",      MiscTools()),
    ]
    run(make_server("ctf-forensics-mcp", modules))


if __name__ == "__main__":
    main()
