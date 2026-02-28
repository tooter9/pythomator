import os
import shutil
import sys
import zipfile
import re
from os.path import exists, expanduser, isdir, join

if os.name == 'nt':
    try:
        import colorama
        colorama.init(autoreset=True)
    except ImportError:
        pass

from . import __version__
from .vault import Vault, create_vault
from .shell import VaultShell
from .ansi import col, BOLD, DIM, RED, GREEN, YELLOW, CYAN, WHITE

VAULTS_DIR = expanduser("~/pythomator")


class Menu:
    def __init__(self):
        self._ensure_vaults_dir()

    def _ensure_vaults_dir(self):
        os.makedirs(VAULTS_DIR, exist_ok=True)

    @staticmethod
    def _sanitize_name(name):
        if not name:
            return "my_vault"
        name = re.sub(r'[<>:\"/\\|?*]', '_', name.strip())
        name = re.sub(r'[\x00-\x1F\x7F]', '', name).strip('. ')
        if len(name) > 200 or name.upper() in {
            'CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5',
            'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3', 'LPT4',
            'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
        } or not name:
            name = f"vault_{name or '1'}"
        return name

    def _get_vaults(self):
        vaults = []
        try:
            for name in sorted(os.listdir(VAULTS_DIR)):
                path = join(VAULTS_DIR, name)
                if isdir(path) and exists(join(path, "vault.cryptomator")):
                    vaults.append((name, path))
        except OSError:
            pass
        return vaults

    def _clear(self):
        sys.stdout.flush()
        os.system('cls' if os.name == 'nt' else 'clear')

    def _header(self):
        w       = 38
        ver     = f"v{__version__}  "
        label   = "  pythomator  "
        title   = label + ver.rjust(w - len(label))
        sub_txt = "  FOSS"
        sub     = sub_txt.ljust(w)
        top  = col('  ╭' + '─' * w + '╮', CYAN)
        mid1 = col('  │', CYAN) + col(title, BOLD, WHITE) + col('│', CYAN)
        mid2 = col('  │', CYAN) + col(sub, DIM)           + col('│', CYAN)
        bot  = col('  ╰' + '─' * w + '╯', CYAN)
        print(f"\n{top}\n{mid1}\n{mid2}\n{bot}\n")

    def _opt(self, n, text, color=WHITE):
        print(col(f'  {n}', BOLD, CYAN) + col('  ›  ', DIM) + col(text, color))

    def _ask_password(self, prompt="  Password: ", confirm=False):
        import getpass
        while True:
            try:
                pw = getpass.getpass(col(prompt, BOLD, YELLOW))
            except (KeyboardInterrupt, EOFError):
                print()
                return None
            if not pw:
                print(col("  Password cannot be empty.", RED))
                print()
                continue
            if not confirm:
                return pw
            try:
                pw2 = getpass.getpass(col("  Confirm:  ", BOLD, YELLOW))
            except (KeyboardInterrupt, EOFError):
                print()
                return None
            if pw == pw2:
                return pw
            print(col("  Passwords do not match.", RED))
            print()

    def _pause(self, msg="  Press Enter to continue..."):
        try:
            input(col(msg, DIM))
        except (KeyboardInterrupt, EOFError):
            pass

    def _choose(self, prompt="  Choose: "):
        try:
            return input(col(prompt, BOLD, CYAN)).strip()
        except (KeyboardInterrupt, EOFError):
            print()
            return ''

    def run(self):
        while True:
            self._clear()
            self._header()
            self._opt('1', 'Create vault')
            self._opt('2', 'Open vault')
            self._opt('3', 'Manage vault')
            self._opt('4', 'Help')
            self._opt('0', 'Exit', YELLOW)
            print()
            choice = self._choose()

            if choice == '1':
                self._do_create()
            elif choice == '2':
                self._do_open()
            elif choice == '3':
                self._do_manage_select()
            elif choice == '4':
                self._do_help()
            elif choice == '0':
                print()
                sys.exit(0)

    def _do_create(self):
        self._clear()
        self._header()
        print(col('  Create vault', BOLD, WHITE))
        print()

        try:
            name = input(col("  Vault name: ", BOLD, CYAN)).strip()
        except (KeyboardInterrupt, EOFError):
            print()
            return

        if not name:
            print(col("  Name cannot be empty.", RED))
            self._pause()
            return

        original_name = name
        name = self._sanitize_name(name)
        if name != original_name:
            print(col(f"  Name adjusted to: {name}", YELLOW))

        vault_dir = join(VAULTS_DIR, name)

        if exists(vault_dir):
            print(col(f"\n  Vault '{name}' already exists.", RED))
            self._pause()
            return

        pw = self._ask_password("  Password: ", confirm=True)
        if pw is None:
            return

        print()
        try:
            print(col("  Generating keys...", DIM))
            os.makedirs(vault_dir)
            create_vault(vault_dir, pw)
            print(col(f"  Vault '{name}' created.", GREEN))
        except Exception as e:
            if exists(vault_dir):
                shutil.rmtree(vault_dir, ignore_errors=True)
            print(col(f"\n  Error: {e}", RED))
            self._pause()
            return

        try:
            with Vault(vault_dir, pw) as vault:
                self._clear()
                VaultShell(vault, vault_dir).run()
        except Exception as e:
            print(col(f"\n  {e}", RED))
            self._pause()

    def _do_open(self):
        while True:
            self._clear()
            self._header()
            print(col('  Open vault', BOLD, WHITE))
            print()
            vaults = self._get_vaults()

            if not vaults:
                print(col("  No vaults found.", DIM))
                print(col("  Create one first (option 1).", DIM))
                self._pause("\n  Press Enter to go back...")
                return

            for i, (name, _) in enumerate(vaults, 1):
                self._opt(str(i), name)
            self._opt('0', 'Back', YELLOW)
            print()
            choice = self._choose("  Choose vault: ")

            if choice in ('0', ''):
                return

            try:
                idx = int(choice) - 1
                if idx < 0 or idx >= len(vaults):
                    continue
            except ValueError:
                continue

            name, vault_dir = vaults[idx]

            pw = self._ask_password(f"  Password for '{name}': ")
            if pw is None:
                continue

            print(col("  Unlocking...", DIM))
            try:
                with Vault(vault_dir, pw) as vault:
                    self._clear()
                    VaultShell(vault, vault_dir).run()
                return
            except Exception as e:
                print(col(f"\n  {e}", RED))
                self._pause("  Press Enter to go back...")

    def _do_manage_select(self):
        while True:
            self._clear()
            self._header()
            print(col('  Manage vault', BOLD, WHITE))
            print()
            vaults = self._get_vaults()

            if not vaults:
                print(col("  No vaults found.", DIM))
                self._pause("\n  Press Enter to go back...")
                return

            for i, (name, _) in enumerate(vaults, 1):
                self._opt(str(i), name)
            self._opt('0', 'Back', YELLOW)
            print()
            choice = self._choose("  Choose vault: ")

            if choice in ('0', ''):
                return

            try:
                idx = int(choice) - 1
                if idx < 0 or idx >= len(vaults):
                    continue
            except ValueError:
                continue

            name, vault_dir = vaults[idx]
            self._manage_vault(name, vault_dir)
            return

    def _manage_vault(self, name, vault_dir):
        while True:
            self._clear()
            self._header()
            print(col(f'  Vault: {name}', BOLD, WHITE))
            print()
            self._opt('1', 'Change password')
            self._opt('2', 'Rename')
            self._opt('3', 'Delete', RED)
            self._opt('4', 'Export backup (.zip)')
            self._opt('0', 'Back', YELLOW)
            print()
            choice = self._choose()

            if choice == '0':
                return
            elif choice == '1':
                self._do_change_password(name, vault_dir)
            elif choice == '2':
                result = self._do_rename(name, vault_dir)
                if result:
                    name, vault_dir = result
            elif choice == '3':
                if self._do_delete(name, vault_dir):
                    return
            elif choice == '4':
                self._do_backup(name, vault_dir)

    def _do_change_password(self, name, vault_dir):
        pw = self._ask_password(f"  Current password for '{name}': ")
        if pw is None:
            return

        print(col("  Verifying...", DIM))
        try:
            with Vault(vault_dir, pw) as vault:
                print(col("\n  Enter new password.\n", BOLD))
                new_pw = self._ask_password("  New password: ", confirm=True)
                if not new_pw:
                    return
                vault.change_password(new_pw)
                print(col("\n  Password changed successfully.", GREEN))
        except Exception as e:
            print(col(f"\n  {e}", RED))
        self._pause()

    def _do_rename(self, name, vault_dir):
        try:
            new_name_input = input(col(f"  New name for '{name}': ", BOLD, CYAN)).strip()
        except (KeyboardInterrupt, EOFError):
            print()
            return None

        if not new_name_input or new_name_input == name:
            return None

        new_name = self._sanitize_name(new_name_input)
        if new_name != new_name_input:
            print(col(f"  Name sanitized to: {new_name}", YELLOW))

        new_path = join(VAULTS_DIR, new_name)

        if exists(new_path):
            print(col(f"\n  A vault named '{new_name}' already exists.", RED))
            self._pause()
            return None

        try:
            os.rename(vault_dir, new_path)
            print(col(f"\n  Renamed to '{new_name}'.", GREEN))
            self._pause()
            return new_name, new_path
        except Exception as e:
            print(col(f"\n  Error: {e}", RED))
            self._pause()
            return None

    def _do_delete(self, name, vault_dir):
        print(col(f"  Delete vault '{name}'?", RED))
        print(col("  This is permanent and cannot be undone!\n", DIM))
        try:
            confirm = input(col("  Type vault name to confirm: ", BOLD, RED)).strip()
        except (KeyboardInterrupt, EOFError):
            print()
            return False

        if confirm != name:
            print(col("  Cancelled.", DIM))
            self._pause()
            return False

        try:
            shutil.rmtree(vault_dir)
            print(col(f"\n  Vault '{name}' deleted.", GREEN))
        except Exception as e:
            print(col(f"\n  Error: {e}", RED))
            self._pause()
            return False

        self._pause()
        return True

    def _do_backup(self, name, vault_dir):
        default = join(expanduser("~"), f"{name}-backup.zip")
        try:
            dest = input(col(f"  Save to [{default}]: ", BOLD, CYAN)).strip() or default
        except (KeyboardInterrupt, EOFError):
            print()
            return

        if exists(dest):
            print(col(f"  {os.path.basename(dest)} already exists!", YELLOW))
            try:
                if input(col("  Overwrite? (y/N): ", BOLD, YELLOW)).lower() not in ('y', 'yes'):
                    print(col("  Cancelled.", DIM))
                    self._pause()
                    return
            except (KeyboardInterrupt, EOFError):
                return

        print(col("\n  Creating backup...", DIM))
        try:
            count = 0
            with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
                for root, dirs, files in os.walk(vault_dir):
                    rel_root = os.path.relpath(root, vault_dir)
                    if rel_root != '.':
                        zf.write(root, rel_root)
                        count += 1
                    for fname in files:
                        full = join(root, fname)
                        rel  = os.path.relpath(full, vault_dir)
                        zf.write(full, rel)
                        count += 1

            print(col(f"  Backup saved: {dest}", GREEN))
            print(col(f"  {count} items", DIM))
        except Exception as e:
            print(col(f"  Error: {e}", RED))
        self._pause()

    def _do_help(self):
        self._clear()
        self._header()
        print(col('  Commands', BOLD, WHITE))
        print()
        print(col(f"  Vaults stored in:  {VAULTS_DIR}", DIM))
        print()

        sections = [
            ("Navigation", [
                ("ls [path]",           "List vault contents"),
                ("ll [path]",           "List with sizes and dates"),
                ("cd <path>",           "Enter vault directory"),
                ("pwd",                 "Show current vault path"),
                ("tree [path]",         "Show directory tree"),
                ("find <name>",         "Search by name"),
            ]),
            ("File transfer", [
                ("put <file>",          "Encrypt & upload from local dir"),
                ("put <file> -r",       "Upload directory recursively"),
                ("put <file> -f",       "Overwrite if exists"),
                ("get <path>",          "Decrypt & download to local dir"),
                ("get <path> -r",       "Download directory recursively"),
            ]),
            ("Local", [
                ("lcd [path]",          "Change local working directory"),
                ("lls [path]",          "List local directory"),
            ]),
            ("Management", [
                ("mkdir <path>",        "Create directory in vault"),
                ("del <path>",          "Delete file from vault"),
                ("rmdir <path> [-r]",   "Delete directory"),
                ("cat <path>",          "Print file contents"),
                ("info [path]",         "Show vault / file info"),
            ]),
        ]

        _sep = col('  ' + '─' * max(20, shutil.get_terminal_size((80, 24)).columns - 4), DIM)
        for section_name, cmds in sections:
            print(col(f"  {section_name}", BOLD, CYAN))
            print(_sep)
            for cmd, desc in cmds:
                print(col(f"    {cmd:<26}", BOLD, WHITE) + col(desc, DIM))
            print()

        print(col("  Examples", BOLD, CYAN))
        print(_sep)
        examples = [
            ("put report.pdf",              "upload from local dir"),
            ("put photos/ /Pictures -r",    "upload folder recursively"),
            ("get /report.pdf",             "download to local dir"),
            ("ll /Documents",               "detailed listing"),
            ("cd Documents",                "enter Documents folder"),
            ("del old_file.txt",            "delete from vault"),
            ("lcd ~/Desktop",               "switch local dir to Desktop"),
        ]
        for cmd, desc in examples:
            print(col(f"    {cmd:<26}", BOLD, WHITE) + col(desc, DIM))
        print()

        self._pause("  Press Enter to go back...")


def run_menu():
    Menu().run()
