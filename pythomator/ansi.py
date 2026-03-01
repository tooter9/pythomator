"""
pythomator — GPL-3.0
ansi escape codes, terminal color/bold helpers.
"""

import sys

RESET  = '\033[0m'
BOLD   = '\033[1m'
DIM    = '\033[2m'
RED    = '\033[91m'
GREEN  = '\033[92m'
YELLOW = '\033[93m'
BLUE   = '\033[94m'
CYAN   = '\033[96m'
WHITE  = '\033[97m'
GRAY   = '\033[90m'


def is_tty() -> bool:
    return sys.stdout.isatty()


def col(text: str, *codes: str) -> str:
    if not is_tty():
        return text
    return ''.join(codes) + text + RESET


def pcol(text: str, *codes: str) -> str:
    if not is_tty():
        return text
    return '\001' + ''.join(codes) + '\002' + text + '\001' + RESET + '\002'


def pad(s: str, raw_len: int, width: int) -> str:
    return s + ' ' * max(0, width - raw_len)
