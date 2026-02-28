import shutil
from datetime import datetime
from typing import List

from . import __version__

from rich.console import Console
from rich.table   import Table
from rich.rule    import Rule
from rich         import box

console     = Console()
err_console = Console(stderr=True)


def _term_width() -> int:
    return shutil.get_terminal_size((80, 24)).columns


def print_banner():
    console.print()
    console.print(Rule(
        f"[bold cyan]pythomator[/bold cyan] [dim]v{__version__}[/dim]",
        style="dim cyan",
    ))
    console.print()


def print_banner_compact():
    console.print()
    console.print(Rule(
        f"[bold cyan]pythomator[/bold cyan] [dim]v{__version__}[/dim]",
        style="dim cyan",
    ))
    console.print()


def print_success(msg: str):
    console.print(f"  [bold green]✓[/bold green]  {msg}")


def print_error(msg: str):
    err_console.print(f"  [bold red]✗[/bold red]  [red]{msg}[/red]")


def print_info(msg: str):
    console.print(f"  [dim]{msg}[/dim]")


def print_warning(msg: str):
    console.print(f"  [bold yellow]![/bold yellow]  [yellow]{msg}[/yellow]")


def print_key_value(key: str, value: str):
    console.print(f"  [dim]{key}[/dim]  [bold]{value}[/bold]")


def print_section(title: str):
    console.print()
    console.print(f"  [bold cyan]{title}[/bold cyan]")
    console.print(f"  [dim cyan]{'─' * (len(title) + 2)}[/dim cyan]")


def print_dir_listing(entries: List[dict], long_fmt: bool = False):
    if not entries:
        print_info("(empty)")
        return

    dirs  = [e for e in entries if e['type'] == 'dir']
    files = [e for e in entries if e['type'] == 'file']

    if long_fmt:
        tbl = Table(
            box=box.ROUNDED,
            show_header=True,
            header_style="bold dim",
            padding=(0, 1),
            show_edge=True,
            border_style="dim cyan",
        )
        tbl.add_column("Type",     style="dim",     no_wrap=True)
        tbl.add_column("Size",     justify="right", no_wrap=True)
        tbl.add_column("Modified",                  no_wrap=True, min_width=16)
        tbl.add_column("Name",                      min_width=20)

        for e in entries:
            if e['type'] == 'dir':
                ico = "[bold blue]dir[/bold blue]"
                sz  = "[dim]—[/dim]"
                nm  = f"[bold blue]{e['name']}/[/bold blue]"
            else:
                ico = "[green]file[/green]"
                sz  = f"[cyan]{_fmt_size(e['size'])}[/cyan]"
                nm  = e['name']
            mt = f"[dim]{_fmt_time(e['mtime'])}[/dim]"
            tbl.add_row(ico, sz, mt, nm)

        console.print()
        console.print(tbl)

    else:
        tw    = _term_width()
        avail = tw - 4
        console.print()

        def _print_group(items_plain, items_rich):
            if not items_plain:
                return
            max_len = max(len(n) for n in items_plain)
            col_w   = max(max_len + 3, 16)
            n_cols  = max(1, avail // col_w)

            for i in range(0, len(items_plain), n_cols):
                row_plain = items_plain[i:i + n_cols]
                row_rich  = items_rich[i:i + n_cols]
                line = "  "
                for j, (plain, rich_) in enumerate(zip(row_plain, row_rich)):
                    is_last = (j == len(row_plain) - 1)
                    padding = '' if is_last else ' ' * max(0, col_w - len(plain))
                    line += rich_ + padding
                console.print(line)

        if dirs:
            dir_plain = [e['name'] + '/' for e in dirs]
            dir_rich  = [f"[bold blue]{e['name']}/[/bold blue]" for e in dirs]
            _print_group(dir_plain, dir_rich)

        if files:
            if dirs:
                console.print()
            file_plain = [e['name'] for e in files]
            file_rich  = [e['name'] for e in files]
            _print_group(file_plain, file_rich)

        console.print()


def _fmt_size(n: int) -> str:
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024 or unit == 'TB':
            return f"{n:.0f} B" if unit == 'B' else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def _fmt_time(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M')
