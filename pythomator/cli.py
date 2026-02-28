import getpass
import io
import os
import sys
import time
from datetime import datetime
from os.path import abspath, basename, dirname, exists, isdir, isfile, join

import click
from tqdm import tqdm

from . import __version__
from .vault   import Vault, create_vault
from .shell   import VaultShell
from .display import (
    print_banner, print_banner_compact,
    print_success, print_error, print_info,
    print_warning, print_dir_listing,
    print_section,
)

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"], "max_content_width": 100}


def _open_vault(vault_dir: str, password: str = None) -> Vault:
    if not password:
        try:
            password = getpass.getpass("  Password: ")
        except (KeyboardInterrupt, EOFError):
            print()
            print_error("Interrupted.")
            sys.exit(1)
    print_info("Unlocking vault…")
    try:
        v = Vault(vault_dir, password)
    except Exception as e:
        print_error(str(e))
        sys.exit(1)
    return v


def _fmt_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} B" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def _fmt_time(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


def _confirm(prompt: str) -> bool:
    try:
        ans = input(f"  {prompt} [y/N] ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print()
        return False
    return ans in ('y', 'yes')


@click.group(context_settings=CONTEXT_SETTINGS)
@click.version_option(__version__, prog_name="pythomator")
def cli():
    """pythomator — encrypted vault manager.

    \b
    Run without arguments for the interactive menu.

    \b
    Commands:
      pythomator                       Interactive menu
      pythomator create ./MyVault      Create a new vault
      pythomator open   ./MyVault      Open vault (interactive shell)
      pythomator ls     ./MyVault      List vault contents
      pythomator put    ./MyVault file.txt /
      pythomator get    ./MyVault /file.txt .
    """
    pass


@cli.command("open")
@click.argument("vault_dir")
@click.option("--password", "-p", default=None, help="Vault password (prompted if omitted)")
def cmd_open(vault_dir, password):
    """Open a vault in an interactive shell session.

    \b
    Example:
      pythomator open ./MyVault

    \b
    Shell commands:
      ls [path]         List directory
      ll [path]         Long listing
      cd <path>         Change directory
      put <name>        Encrypt & upload (from local dir)
      get <vault_path>  Decrypt & download (to local dir)
      mkdir <path>      Create directory
      del <path>        Delete file
      rmdir <path> -r   Delete directory
      tree              Show directory tree
      find <name>       Search for files
      lcd [path]        Change local directory
      lls [path]        List local directory
      info              Show vault info
      help / ?          Full help
      exit / q          Lock and leave
    """
    print_banner()
    vault_dir = abspath(vault_dir)
    if not exists(vault_dir):
        print_error(f"Vault directory not found: {vault_dir}")
        sys.exit(1)
    with _open_vault(vault_dir, password) as vault:
        shell = VaultShell(vault, vault_dir)
        shell.run()


@cli.command("create")
@click.argument("vault_dir")
@click.option("--password", "-p", default=None, help="Vault password (prompted if omitted)")
def cmd_create(vault_dir, password):
    """Create a new encrypted vault in VAULT_DIR.

    \b
    Examples:
      pythomator create ./MyVault
      pythomator create ./MyVault -p s3cr3t
    """
    print_banner()
    vault_dir = abspath(vault_dir)

    if not exists(vault_dir):
        try:
            os.makedirs(vault_dir)
        except OSError as e:
            print_error(f"Cannot create directory: {e}")
            sys.exit(1)

    if os.listdir(vault_dir):
        print_error(f"Directory is not empty: {vault_dir}")
        sys.exit(1)

    if not password:
        click.echo()
        while True:
            try:
                password = getpass.getpass("  New password:     ")
            except (KeyboardInterrupt, EOFError):
                print()
                print_error("Interrupted.")
                sys.exit(1)
            if not password:
                print_warning("Password cannot be empty — try again.")
                continue
            try:
                confirm_pw = getpass.getpass("  Confirm password: ")
            except (KeyboardInterrupt, EOFError):
                print()
                print_error("Interrupted.")
                sys.exit(1)
            if password == confirm_pw:
                break
            print_warning("Passwords do not match — try again.")

    try:
        create_vault(vault_dir, password)
    except Exception as e:
        print_error(str(e))
        sys.exit(1)

    print()
    print_success(f"Vault created: {vault_dir}")
    click.echo(f"  Open it with:  pythomator open {vault_dir}")
    click.echo()


@cli.command("ls")
@click.argument("vault_dir")
@click.argument("path", default="/")
@click.option("--password",  "-p", default=None)
@click.option("--recursive", "-r", is_flag=True)
@click.option("--long",      "-l", is_flag=True)
def cmd_ls(vault_dir, path, password, recursive, long):
    """List contents of a vault directory.

    \b
    Examples:
      pythomator ls ./MyVault
      pythomator ls ./MyVault /Documents -l
      pythomator ls ./MyVault / -r
    """
    print_banner_compact()
    with _open_vault(abspath(vault_dir), password) as vault:
        if recursive:
            total_files = total_dirs = total_size = 0
            for root, dirs, files in vault.walk(path):
                entries = vault.listdir(root)
                click.echo(f"\n  {root}/")
                print_dir_listing(entries, long_fmt=long)
                total_files += len(files)
                total_dirs  += len(dirs)
                total_size  += sum(e["size"] for e in entries if e["type"] == "file")
            click.echo()
            print_info(f"Total: {total_files} file(s) in {total_dirs} dir(s), {_fmt_size(total_size)}")
        else:
            try:
                entries = vault.listdir(path)
            except Exception as e:
                print_error(str(e))
                sys.exit(1)
            label = path if path not in ('', '/') else '/ (root)'
            click.echo(f"\n  {label}")
            print_dir_listing(entries, long_fmt=long)
            total_size = sum(e["size"] for e in entries if e["type"] == "file")
            click.echo()
            print_info(f"{len(entries)} item(s), {_fmt_size(total_size)} total")
            click.echo()


@cli.command("put")
@click.argument("vault_dir")
@click.argument("source", nargs=-1, required=True)
@click.argument("dest")
@click.option("--password",  "-p", default=None)
@click.option("--force",     "-f", is_flag=True)
@click.option("--recursive", "-r", is_flag=True)
def cmd_put(vault_dir, source, dest, password, force, recursive):
    """Encrypt and upload file(s) into the vault.

    \b
    Examples:
      pythomator put ./MyVault report.pdf /Documents
      pythomator put ./MyVault ./Photos /Pictures -r
      pythomator put ./MyVault note.txt / -f
    """
    print_banner_compact()
    with _open_vault(abspath(vault_dir), password) as vault:
        with tqdm(
            unit='file',
            desc='Uploading',
            dynamic_ncols=True,
            bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {postfix}]',
        ) as pbar:
            result = vault.put_many(
                list(source), dest,
                force=force, recursive=recursive,
                progress=pbar,
            )

        print()
        for src_err, msg in result['errors']:
            print_warning(f"Skipped {src_err}: {msg}")
        print_success(
            f"Uploaded {result['files']} file(s) "
            f"[{_fmt_size(result['bytes'])}] "
            f"in {result['elapsed']:.1f}s"
        )
        click.echo()


@cli.command("get")
@click.argument("vault_dir")
@click.argument("source", nargs=-1, required=True)
@click.argument("dest")
@click.option("--password",  "-p", default=None)
@click.option("--force",     "-f", is_flag=True)
@click.option("--recursive", "-r", is_flag=True)
def cmd_get(vault_dir, source, dest, password, force, recursive):
    """Decrypt and download file(s) from the vault.

    \b
    Examples:
      pythomator get ./MyVault /report.pdf ~/Downloads
      pythomator get ./MyVault /Pictures ~/Restored -r
    """
    print_banner_compact()
    dest = abspath(os.path.expanduser(dest))
    with _open_vault(abspath(vault_dir), password) as vault:
        with tqdm(
            unit='file',
            desc='Downloading',
            dynamic_ncols=True,
            bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {postfix}]',
        ) as pbar:
            result = vault.get_many(
                list(source), dest,
                force=force, recursive=recursive,
                progress=pbar,
            )

        print()
        for vpath_err, msg in result['errors']:
            print_warning(f"Skipped {vpath_err}: {msg}")
        print_success(
            f"Downloaded {result['files']} file(s) "
            f"[{_fmt_size(result['bytes'])}] "
            f"in {result['elapsed']:.1f}s"
        )
        click.echo()


def main():
    if len(sys.argv) == 1:
        from .menu import Menu
        Menu().run()
    else:
        cli()


if __name__ == "__main__":
    main()
