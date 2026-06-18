# Shared installed paths for Qubes Snitch
# Keeping paths here prevents CLI, daemon, tests, and installer assumptions from drifting

from pathlib import Path

# /etc comes from the template, while /rw/usrlocal is persistent per AppVM and stores user decisions
CONFIG_DIR = Path("/etc/qubes-snitch")
RULES_DIR = Path("/rw/usrlocal/qubes-snitch/rules")
CONFIG_FILE = CONFIG_DIR / "config.yml"

# /run is tmpfs, so sockets, lock files, and generated nft batches are recreated each boot
RUN_DIR = Path("/run/qubes-snitch")
SOCKET_FILE = RUN_DIR / "socket"
LOCK_FILE = RUN_DIR / "cli.lock"
NFT_FILE = RUN_DIR / "rules.nft"
