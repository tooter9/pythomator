import io
import os
import shlex
import shutil
import sys
import time
from datetime import datetime
from os.path import abspath, basename, dirname, exists, isdir, join

try:
    import readline
except ImportError:
    pass

from tqdm import tqdm

from .vault import Vault
from .ansi  import col, pcol, BOLD, DIM, RED, GREEN, YELLOW, BLUE, CYAN, WHITE, GRAY


def _fmt_size(n: float) -> str:
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024 or unit == 'TB':
            return f"{n:.0f} B" if unit == 'B' else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def _fmt_time(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M')


def _term_width() -> int:
    return shutil.get_terminal_size((80, 24)).columns


def _print_columns(items, indent: int = 2, min_col_w: int = 16, gap: int = 2):
    if not items:
        return
    max_raw = max(r for _, r in items)
    col_w   = max(max_raw + gap, min_col_w)
    avail   = _term_width() - indent
    n_cols  = max(1, avail // col_w)
    pad_str = ' ' * indent

    for i in range(0, len(items), n_cols):
        row = items[i:i + n_cols]
        line = pad_str
        for j, (text, raw) in enumerate(row):
            is_last = (j == len(row) - 1)
            line += text
            if not is_last:
                line += ' ' * max(0, col_w - raw)
        print(line)


class VaultShell:

    _HELP_SECTIONS = [
        ("Navigation", [
            ("ls [path]",            "List vault contents"),
            ("ll [path]",            "Detailed listing with sizes and dates"),
            ("cd <path>",            "Enter vault directory"),
            ("pwd",                  "Show current vault path"),
            ("tree [path]",          "Directory tree view"),
            ("find <name>",          "Search files and dirs by name"),
        ]),
        ("File transfer", [
            ("put <file>",           "Encrypt & upload from local dir"),
            ("put <file> [dest] -r", "Upload directory recursively"),
            ("put <file> [dest] -f", "Overwrite if exists"),
            ("get <vault_path>",     "Decrypt & download to local dir"),
            ("get <vault_path> -r",  "Download directory recursively"),
        ]),
        ("Local system", [
            ("lcd [path]",           "Change local working directory"),
            ("lls [path]",           "List local directory"),
        ]),
        ("File management", [
            ("mkdir <path>",         "Create directory in vault"),
            ("del <path>",           "Delete file from vault"),
            ("rmdir <path> [-r]",    "Delete directory (add -r for recursive)"),
            ("cat <path>",           "Print file contents to screen"),
            ("info [path]",          "Show vault or file info"),
        ]),
        ("Other", [
            ("clr / clear",          "Clear screen"),
            ("help / ?",             "This help"),
            ("0 / exit",             "Lock vault and exit"),
        ]),
    ]

    def __init__(self, vault: Vault, vault_path: str):
        self.vault      = vault
        self.vault_path = vault_path
        self.vault_name = basename(vault_path.rstrip('/\\'))
        self.cwd        = '/'
        self.local_dir  = os.path.expanduser('~')

    def _ok(self, msg: str):
        print(col('  ✓  ', BOLD, GREEN) + msg)

    def _err(self, msg: str):
        print(col('  ✗  ', BOLD, RED) + msg, file=sys.stderr)

    def _warn(self, msg: str):
        print(col('  !  ', BOLD, YELLOW) + msg)

    def _info(self, msg: str):
        print('  ' + col(msg, DIM))

    def _dim(self, msg: str):
        print(col(msg, DIM))

    def _abs(self, path: str) -> str:
        if not path or path == '.':
            return self.cwd
        if path.startswith('/'):
            return Vault._normalize(path)
        return Vault._normalize(self.cwd + '/' + path)

    def _resolve_local(self, path: str) -> str:
        if os.path.isabs(path) or path.startswith('~'):
            return os.path.expanduser(path)
        return join(self.local_dir, path)

    def _cmd_ls(self, args: list, long: bool = False):
        path = self._abs(args[0]) if args else self.cwd
        try:
            entries = self.vault.listdir(path)
        except Exception as e:
            self._err(str(e))
            return

        if not entries:
            print()
            self._dim('  (empty)')
            print()
            return

        dirs  = [e for e in entries if e['type'] == 'dir']
        files = [e for e in entries if e['type'] == 'file']
        n_d   = len(dirs)
        n_f   = len(files)
        total_sz = sum(e['size'] for e in files)

        if long:
            print()
            sep = col('  ' + '─' * max(20, _term_width() - 4), DIM)
            hdr = (
                col('  ', DIM) +
                col('TYPE', DIM) + '  ' +
                col('      SIZE', DIM) + '  ' +
                col('MODIFIED        ', DIM) + '  ' +
                col('NAME', DIM)
            )
            print(hdr)
            print(sep)

            for e in entries:
                if e['type'] == 'dir':
                    t  = col('dir ', BOLD, BLUE)
                    sz = col('         —', DIM)
                    nm = col(e['name'] + '/', BOLD, BLUE)
                else:
                    t  = col('file', GREEN)
                    sz = col(f"{_fmt_size(e['size']):>10}", CYAN)
                    nm = e['name']
                mt = col(_fmt_time(e['mtime']), DIM)
                print(f"  {t}  {sz}  {mt}  {nm}")

            print(sep)
            parts = []
            if n_d:
                parts.append(f"{n_d} dir{'s' if n_d != 1 else ''}")
            if n_f:
                parts.append(f"{n_f} file{'s' if n_f != 1 else ''}")
            summary = '  ' + ', '.join(parts) if parts else '  0 items'
            if total_sz:
                summary += col(f"  —  {_fmt_size(total_sz)}", DIM)
            print(col(summary, DIM))
            print()

        else:
            print()

            if dirs:
                dir_items = [(col(e['name'] + '/', BOLD, BLUE), len(e['name']) + 1) for e in dirs]
                _print_columns(dir_items)

            if files:
                if dirs:
                    print()
                file_items = [(e['name'], len(e['name'])) for e in files]
                _print_columns(file_items)

            print()
            parts = []
            if n_d:
                parts.append(f"{n_d} dir{'s' if n_d != 1 else ''}")
            if n_f:
                parts.append(f"{n_f} file{'s' if n_f != 1 else ''}")
            summary = '  ' + ', '.join(parts) if parts else '  0 items'
            if total_sz:
                summary += f"  ·  {_fmt_size(total_sz)}"
            print(col(summary, DIM))
            print()

    def _cmd_cd(self, args: list):
        if not args:
            self.cwd = '/'
            return
        target = self._abs(args[0])
        try:
            info = self.vault.resolve(target)
        except Exception as e:
            self._err(str(e))
            return
        if not info.exists:
            self._err(f"No such directory: {target}")
            return
        if not info.is_dir:
            self._err(f"Not a directory: {target}")
            return
        self.cwd = target

    def _cmd_pwd(self, _args):
        print(col('  ' + self.cwd, BOLD, CYAN))

    def _cmd_mkdir(self, args: list):
        if not args:
            self._err("Usage: mkdir <path>")
            return
        path = self._abs(args[0])
        try:
            self.vault.mkdir(path)
            self._ok(f"Created: {path}")
        except FileExistsError:
            self._info(f"Already exists: {path}")
        except Exception as e:
            self._err(str(e))

    def _cmd_put(self, args: list):
        force     = '-f' in args or '--force' in args
        recursive = '-r' in args or '--recursive' in args
        args      = [a for a in args if not a.startswith('-')]

        if not args:
            self._err("Usage: put <local_src> [vault_dest]  [-r] [-f]")
            return

        src  = self._resolve_local(args[0])
        dest = self._abs(args[1]) if len(args) > 1 else self.cwd

        if not exists(src):
            self._err(f"Not found: {src}")
            self._info(f"Local dir: {self.local_dir}")
            return

        if isdir(src) and not recursive:
            self._warn(f"{src} is a directory — use -r to upload recursively")
            return

        with tqdm(
            unit='file',
            desc='Uploading',
            dynamic_ncols=True,
            bar_format='  {desc}  [{bar:30}]  {n_fmt}/{total_fmt}  {postfix}',
        ) as pbar:
            result = self.vault.put_many(
                [src], dest,
                force=force, recursive=recursive,
                progress=pbar,
            )

        for src_err, msg in result['errors']:
            self._warn(f"Skipped {src_err}: {msg}")
        self._ok(
            f"Uploaded {result['files']} file{'s' if result['files'] != 1 else ''}  "
            f"[{_fmt_size(result['bytes'])}]  "
            f"{result['elapsed']:.1f}s"
        )

    def _cmd_get(self, args: list):
        force     = '-f' in args or '--force' in args
        recursive = '-r' in args or '--recursive' in args
        args      = [a for a in args if not a.startswith('-')]

        if not args:
            self._err("Usage: get <vault_src> [local_dest]  [-r] [-f]")
            return

        src  = self._abs(args[0])
        if len(args) > 1:
            expanded = os.path.expanduser(args[1])
            dest = abspath(join(self.local_dir, expanded))
        else:
            dest = self.local_dir

        try:
            info = self.vault.resolve(src)
        except Exception as e:
            self._err(str(e))
            return

        if not info.exists:
            self._err(f"Not found in vault: {src}")
            return

        if info.is_dir and not recursive:
            self._warn(f"{src} is a directory — use -r to download recursively")
            return

        with tqdm(
            unit='file',
            desc='Downloading',
            dynamic_ncols=True,
            bar_format='  {desc}  [{bar:30}]  {n_fmt}/{total_fmt}  {postfix}',
        ) as pbar:
            result = self.vault.get_many(
                [src], dest,
                force=force, recursive=recursive,
                progress=pbar,
            )

        for vpath_err, msg in result['errors']:
            self._warn(f"Skipped {vpath_err}: {msg}")
        self._ok(
            f"Downloaded {result['files']} file{'s' if result['files'] != 1 else ''}  "
            f"[{_fmt_size(result['bytes'])}]  "
            f"{result['elapsed']:.1f}s"
        )

    def _cmd_cat(self, args: list):
        if not args:
            self._err("Usage: cat <vault_path>")
            return
        src = self._abs(args[0])
        try:
            buf = io.BytesIO()
            self.vault.get_to_stream(src, buf)
            data = buf.getvalue()
            try:
                print(data.decode('utf-8'))
            except UnicodeDecodeError:
                self._warn(f"Binary file ({_fmt_size(len(data))}) — cannot display as text")
        except Exception as e:
            self._err(str(e))

    def _cmd_rm(self, args: list):
        force = '-f' in args or '--force' in args
        args  = [a for a in args if not a.startswith('-')]
        if not args:
            self._err("Usage: del <path> [-f]")
            return
        for p in args:
            path = self._abs(p)
            try:
                info = self.vault.resolve(path)
                if not info.exists:
                    self._err(f"Not found: {path}")
                    continue
                if info.is_dir and not info.is_symlink:
                    self._err(f"'{path}' is a directory — use rmdir")
                    continue
            except Exception as e:
                self._err(str(e))
                continue
            if not force:
                try:
                    ans = input(col(f"  Delete '{path}'? [y/N] ", YELLOW)).strip().lower()
                except (KeyboardInterrupt, EOFError):
                    print()
                    return
                if ans not in ('y', 'yes'):
                    self._info("Skipped.")
                    continue
            try:
                self.vault.rm(path)
                self._ok(f"Deleted: {path}")
            except Exception as e:
                self._err(str(e))

    def _cmd_rmdir(self, args: list):
        recursive = '-r' in args or '--recursive' in args
        force     = '-f' in args or '--force' in args
        args      = [a for a in args if not a.startswith('-')]
        if not args:
            self._err("Usage: rmdir <path> [-r]")
            return
        path = self._abs(args[0])
        if not force:
            suffix = ' and all contents' if recursive else ''
            try:
                ans = input(col(
                    f"  Remove '{path}'{suffix}? [y/N] ", YELLOW
                )).strip().lower()
            except (KeyboardInterrupt, EOFError):
                print()
                return
            if ans not in ('y', 'yes'):
                self._info("Skipped.")
                return
        try:
            self.vault.rmdir(path, recursive=recursive)
            if self.cwd == path or self.cwd.startswith(path + '/'):
                self.cwd = dirname(path) or '/'
            self._ok(f"Removed: {path}")
        except Exception as e:
            self._err(str(e))

    def _cmd_lcd(self, args: list):
        target = os.path.expanduser(args[0]) if args else os.path.expanduser('~')
        if not os.path.isabs(target):
            target = join(self.local_dir, target)
        target = abspath(target)
        if not os.path.isdir(target):
            self._err(f"Not found: {target}")
            return
        self.local_dir = target
        self._info(f"Local dir: {target}")

    def _cmd_lls(self, args: list):
        if args:
            path = os.path.expanduser(args[0])
            if not os.path.isabs(path):
                path = join(self.local_dir, path)
            path = abspath(path)
        else:
            path = self.local_dir

        print()
        print(col(f"  {path}", BOLD, YELLOW))
        print()

        try:
            raw_entries = os.listdir(path)
        except Exception as e:
            self._err(str(e))
            return

        if not raw_entries:
            self._dim('  (empty)')
            print()
            return

        dirs    = sorted(e for e in raw_entries if os.path.isdir(join(path, e)))
        files   = sorted(e for e in raw_entries if os.path.isfile(join(path, e)))
        broken  = sorted(
            e for e in raw_entries
            if not os.path.isdir(join(path, e)) and not os.path.isfile(join(path, e))
        )

        if dirs:
            dir_items = [(col(n + '/', BOLD, BLUE), len(n) + 1) for n in dirs]
            _print_columns(dir_items)

        if files:
            if dirs:
                print()
            max_name = max(len(n) for n in files)
            for name in files:
                fp   = join(path, name)
                try:
                    sz = os.path.getsize(fp)
                    sz_str = col(f"  {_fmt_size(sz)}", DIM)
                except OSError:
                    sz_str = ''
                padding = ' ' * max(0, max_name - len(name))
                print(f"  {name}{padding}{sz_str}")

        if broken:
            if dirs or files:
                print()
            for name in broken:
                print(f"  {col(name, RED)}  {col('(broken link)', DIM)}")

        print()
        n_d = len(dirs)
        n_f = len(files)
        n_b = len(broken)
        parts = []
        if n_d:
            parts.append(f"{n_d} dir{'s' if n_d != 1 else ''}")
        if n_f:
            parts.append(f"{n_f} file{'s' if n_f != 1 else ''}")
        if n_b:
            parts.append(col(f"{n_b} broken link{'s' if n_b != 1 else ''}", RED))
        summary = '  ' + ', '.join(parts) if parts else '  0 items'
        print(col(summary, DIM))
        print()

    def _cmd_tree(self, args: list):
        path = self._abs(args[0]) if args else self.cwd
        print()
        self._print_tree(path, '', True)
        print()

    def _print_tree(self, path: str, prefix: str, is_root: bool):
        try:
            entries = self.vault.listdir(path)
        except Exception as e:
            self._err(str(e))
            return

        name = path.rstrip('/').split('/')[-1] or self.vault_name
        if is_root:
            print(col(f"  {name}/", BOLD, BLUE))

        for i, e in enumerate(entries):
            is_last = (i == len(entries) - 1)
            branch  = '└── ' if is_last else '├── '
            next_px = prefix + ('    ' if is_last else '│   ')

            if e['type'] == 'dir':
                line = col(e['name'] + '/', BOLD, BLUE)
                print(f"  {prefix}{branch}{line}")
                child = Vault._normalize(path + '/' + e['name'])
                self._print_tree(child, next_px, False)
            else:
                sz = col(f" ({_fmt_size(e['size'])})", DIM)
                print(f"  {prefix}{branch}{e['name']}{sz}")

    def _cmd_find(self, args: list):
        if not args:
            self._err("Usage: find <pattern>")
            return
        pattern = args[0].lower()
        print()
        found = 0
        try:
            for root, dirs, files in self.vault.walk('/'):
                for fname in dirs + files:
                    if pattern in fname.lower():
                        vpath  = Vault._normalize(root + '/' + fname)
                        suffix = '/' if fname in dirs else ''
                        color  = BLUE if suffix else WHITE
                        print('  ' + col(vpath + suffix, BOLD, color))
                        found += 1
        except Exception as e:
            self._err(str(e))
            return
        print()
        self._info(f"{found} match{'es' if found != 1 else ''} for '{pattern}'")
        print()

    def _cmd_info(self, args: list):
        path = self._abs(args[0]) if args else '/'
        print()

        def kv(k, v, vc=WHITE):
            print(f"  {col(k, DIM)}  {col(str(v), BOLD, vc)}")

        kv('vault', self.vault_name, CYAN)
        kv('path ', self.cwd, BLUE)
        kv('local', self.local_dir, YELLOW)

        if path != '/':
            print()
            print(col(f"  {path}", BOLD))
            try:
                info = self.vault.resolve(path)
                if not info.exists:
                    kv('exists', 'no', RED)
                else:
                    kind = 'directory' if info.is_dir else 'file'
                    kv('type  ', kind, BLUE if info.is_dir else WHITE)
                    if not info.is_dir:
                        try:
                            sz = self.vault.size(path)
                            kv('size  ', _fmt_size(sz), CYAN)
                        except Exception:
                            pass
            except Exception as e:
                self._err(str(e))
        print()

    def _clear_screen(self):
        os.system('clear' if os.name != 'nt' else 'cls')

    def _print_compact_header(self):
        self._clear_screen()
        w   = max(20, _term_width() - 4)
        dot = col('  ·  ', DIM)
        print()
        print(col('  ' + '─' * w, DIM))
        print(
            col('  ', '') +
            col(self.vault_name, BOLD, CYAN) +
            col('  ' + self.cwd, BOLD, BLUE) +
            dot +
            col('help', DIM) + dot + col('clr', DIM) + dot + col('exit', DIM)
        )
        print(col('  ' + '─' * w, DIM))
        print()

    def run(self):
        print()
        self._print_welcome()
        print()

        while True:
            try:
                prompt = (
                    pcol('  ', '') +
                    pcol(self.vault_name, BOLD, CYAN) +
                    pcol('  ' + self.cwd, BOLD, BLUE) +
                    pcol('  ›  ', DIM)
                )
                line = input(prompt).strip()
            except KeyboardInterrupt:
                print()
                print(col("  (use 'exit' or '0' to leave)", DIM))
                continue
            except EOFError:
                self._clear_screen()
                break

            if not line:
                continue

            try:
                parts = shlex.split(line)
            except ValueError:
                self._err("Parse error: unmatched quotes")
                continue
            cmd   = parts[0].lower()
            args  = parts[1:]

            if cmd in ('exit', 'quit', 'q', 'bye', '0'):
                self._clear_screen()
                break
            elif cmd in ('help', '?', 'h'):
                self._print_help()
            elif cmd in ('clr', 'cls', 'clear'):
                self._print_compact_header()
            elif cmd == 'ls':
                self._cmd_ls(args, long=False)
            elif cmd in ('ll', 'la'):
                self._cmd_ls(args, long=True)
            elif cmd == 'cd':
                self._cmd_cd(args)
            elif cmd == 'pwd':
                self._cmd_pwd(args)
            elif cmd == 'mkdir':
                self._cmd_mkdir(args)
            elif cmd == 'put':
                self._cmd_put(args)
            elif cmd == 'get':
                self._cmd_get(args)
            elif cmd == 'cat':
                self._cmd_cat(args)
            elif cmd in ('del', 'rm'):
                self._cmd_rm(args)
            elif cmd == 'rmdir':
                self._cmd_rmdir(args)
            elif cmd == 'lcd':
                self._cmd_lcd(args)
            elif cmd == 'lls':
                self._cmd_lls(args)
            elif cmd in ('tree', 'tr'):
                self._cmd_tree(args)
            elif cmd == 'find':
                self._cmd_find(args)
            elif cmd in ('info', 'stat'):
                self._cmd_info(args)
            else:
                self._err(f"Unknown command: '{cmd}'  (type 'help')")

    def _print_help(self):
        tty  = sys.stdout.isatty()
        _w   = max(20, _term_width() - 4)
        rule = col('  ' + '─' * _w, DIM) if tty else '  ' + '─' * _w
        print()
        for section_name, cmds in self._HELP_SECTIONS:
            if tty:
                print(col(f'  {section_name}', BOLD, CYAN))
                print(rule)
                for cmd, desc in cmds:
                    print(col(f'    {cmd:<28}', BOLD, WHITE) + col(desc, DIM))
            else:
                print(f'  {section_name}')
                print(rule)
                for cmd, desc in cmds:
                    print(f'    {cmd:<28}{desc}')
            print()
        print()

    def _print_welcome(self):
        w   = max(20, _term_width() - 4)
        dot = col('  ·  ', DIM)
        print(col('  ' + '─' * w, DIM))
        print(
            col('  ', '') +
            col(self.vault_name, BOLD, CYAN) +
            col(f'  {self.vault_path}', DIM)
        )
        print(col('  ' + '─' * w, DIM))
        print(
            col('  ', '') +
            col('help', DIM) + dot +
            col('clr', DIM) + dot +
            col('exit', DIM)
        )
