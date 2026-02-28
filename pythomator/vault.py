import base64
import hashlib
import hmac as _hmac
import io
import json
import os
import stat
import tempfile
import time
import uuid
from dataclasses import dataclass
from os.path import basename, dirname, exists, isdir, join, normpath
from typing import Iterator, List, Optional, Tuple

from Crypto.Random import get_random_bytes

from .crypto import (
    _wipe,
    aes_wrap, aes_unwrap, derive_kek,
    hash_dir_id, encrypt_name, decrypt_name,
    encrypt_file_content, decrypt_file_content,
    cleartext_size,
    b64_pad, b64url_no_pad, b64url_decode,
    siv_encrypt,
    HEADER_SIZE, CHUNK_SIZE, CHUNK_OVERHEAD,
    GCM_NONCE_SIZE, GCM_TAG_SIZE, PAYLOAD_SIZE,
)

VAULT_CONFIG_FILENAME    = "vault.cryptomator"
MASTERKEY_FILENAME       = "masterkey.cryptomator"
DATA_DIR_NAME            = "d"
CRYPTOMATOR_FILE_SUFFIX  = ".c9r"
DEFLATED_FILE_SUFFIX     = ".c9s"
DIR_FILE_NAME            = "dir.c9r"
SYMLINK_FILE_NAME        = "symlink.c9r"
CONTENTS_FILE_NAME       = "contents.c9r"
INFLATED_FILE_NAME       = "name.c9s"
DIR_ID_BACKUP_FILE_NAME  = "dirid.c9r"
ROOT_DIR_ID              = ""
MAX_CIPHER_NAME_LENGTH   = 220
MAX_DIR_ID_LENGTH        = 36
MAX_SYMLINK_TARGET_LEN   = 4096
VAULT_VERSION            = 8
MASTERKEY_LEGACY_VERSION = 999

_SCRYPT_MIN_N            = 1 << 14
_SYMLINK_MAX_DEPTH       = 40

_JWT_ALG_MAP = {
    'HS256': hashlib.sha256,
    'HS384': hashlib.sha384,
    'HS512': hashlib.sha512,
}


@dataclass
class NodeInfo:
    virtual_path:    str             = ""
    real_path:       str             = ""
    real_dir:        str             = ""
    dir_id:          str             = ""
    long_name:       Optional[bytes] = None
    is_dir:          bool            = False
    is_symlink:      bool            = False
    symlink_target:  str             = ""
    exists:          bool            = False

    @property
    def contents_path(self) -> str:
        if self.long_name:
            return join(self.real_path, CONTENTS_FILE_NAME)
        return self.real_path

    @property
    def dir_file(self) -> str:
        return join(self.real_path, DIR_FILE_NAME)

    @property
    def name_file(self) -> str:
        return join(self.real_path, INFLATED_FILE_NAME)

    @property
    def symlink_file(self) -> str:
        return join(self.real_path, SYMLINK_FILE_NAME)

    @property
    def dirid_backup(self) -> str:
        return join(self.real_dir, DIR_ID_BACKUP_FILE_NAME)


def _secure_open_write(path: str):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    return os.fdopen(fd, 'w', encoding='utf-8')


def _secure_open_write_binary(path: str):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    return os.fdopen(fd, 'wb')


class Vault:

    def __init__(self, directory: str, password: str):
        if not exists(directory):
            raise FileNotFoundError(f"Vault directory not found: {directory}")
        if not isdir(directory):
            raise NotADirectoryError(f"Not a directory: {directory}")
        self.base           = directory
        self._dir_id_cache: dict = {}
        self.pk: bytearray  = bytearray(0)
        self.hk: bytearray  = bytearray(0)
        self._load_and_verify(password)
        self._locate_root()

    def close(self) -> None:
        _wipe(self.pk)
        _wipe(self.hk)
        self.pk = bytearray(0)
        self.hk = bytearray(0)
        self._dir_id_cache.clear()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def _load_and_verify(self, password: str):
        config_path = join(self.base, VAULT_CONFIG_FILENAME)
        try:
            with open(config_path, 'rb') as fh:
                raw = fh.read().strip()
        except OSError:
            raise FileNotFoundError(f"Cannot read {VAULT_CONFIG_FILENAME}")

        parts = raw.split(b'.')
        if len(parts) != 3:
            raise ValueError(
                f"Invalid {VAULT_CONFIG_FILENAME} – not a JWT (expected 3 dot-separated parts)"
            )

        header_b64, payload_b64, sig_b64 = parts

        try:
            header  = json.loads(b64url_decode(header_b64))
            payload = json.loads(b64url_decode(payload_b64))
            sig     = b64url_decode(sig_b64)
        except Exception as e:
            raise ValueError(f"Failed to decode {VAULT_CONFIG_FILENAME}: {e}") from e

        if header.get('typ') != 'JWT':
            raise ValueError(f"Invalid typ in {VAULT_CONFIG_FILENAME}: {header.get('typ')}")
        alg = header.get('alg', '')
        if alg not in _JWT_ALG_MAP:
            raise ValueError(f"Unsupported algorithm in {VAULT_CONFIG_FILENAME}: {alg}")
        kid = header.get('kid', '')
        if not kid.startswith('masterkeyfile:'):
            raise ValueError(f"Unsupported key source in {VAULT_CONFIG_FILENAME}: {kid}")

        fmt = payload.get('format')
        if fmt != VAULT_VERSION:
            raise ValueError(
                f"Unsupported vault format: {fmt}  (only format {VAULT_VERSION} supported)"
            )
        cipher_combo = payload.get('cipherCombo', '')
        if cipher_combo != 'SIV_GCM':
            raise ValueError(
                f"Unsupported cipherCombo: {cipher_combo}  (only SIV_GCM supported)"
            )

        self.shortening_threshold = payload.get('shorteningThreshold', MAX_CIPHER_NAME_LENGTH)
        self._jti = payload.get('jti', '')

        masterkey_rel  = kid[len('masterkeyfile:'):]
        masterkey_path = join(self.base, masterkey_rel)
        try:
            with open(masterkey_path, 'r', encoding='utf-8') as fh:
                master = json.load(fh)
        except OSError:
            raise FileNotFoundError(f"Cannot read {masterkey_rel}")

        cost       = master['scryptCostParam']
        block_size = master['scryptBlockSize']

        if not isinstance(cost, int) or cost < _SCRYPT_MIN_N or (cost & (cost - 1)) != 0:
            raise ValueError(
                f"Unsafe or invalid scryptCostParam: {cost} "
                f"(must be a power of two >= {_SCRYPT_MIN_N})"
            )
        if not isinstance(block_size, int) or block_size < 1:
            raise ValueError(f"Invalid scryptBlockSize: {block_size}")

        salt = base64.b64decode(b64_pad(master['scryptSalt'].encode()))
        kek  = derive_kek(password, salt, cost, block_size)

        try:
            pk_raw = aes_unwrap(kek, base64.b64decode(b64_pad(master['primaryMasterKey'].encode())))
            hk_raw = aes_unwrap(kek, base64.b64decode(b64_pad(master['hmacMasterKey'].encode())))
        except ValueError as e:
            raise ValueError(f"Wrong password or corrupted masterkey file: {e}") from e
        finally:
            _wipe(kek)

        digest_fn    = _JWT_ALG_MAP[alg]
        jwt_msg      = header_b64 + b'.' + payload_b64
        computed_sig = _hmac.new(bytes(pk_raw) + bytes(hk_raw), jwt_msg, digest_fn).digest()

        if not _hmac.compare_digest(computed_sig, sig):
            _wipe(pk_raw)
            _wipe(hk_raw)
            raise ValueError(
                "Vault signature verification failed – wrong password or corrupted vault"
            )

        version_bytes = int(master['version']).to_bytes(4, 'big')
        expected_vmac = base64.b64encode(
            _hmac.new(bytes(hk_raw), version_bytes, hashlib.sha256).digest()
        ).decode()
        stored_vmac = master.get('versionMac', '')

        if not _hmac.compare_digest(expected_vmac, stored_vmac):
            _wipe(pk_raw)
            _wipe(hk_raw)
            raise ValueError("versionMac mismatch in masterkey file")

        self.pk           = pk_raw
        self.hk           = hk_raw
        self._master      = master
        self._master_path = masterkey_path

    def _locate_root(self):
        edid      = hash_dir_id(self.pk, self.hk, ROOT_DIR_ID)
        self.root = join(self.base, DATA_DIR_NAME, edid[:2], edid[2:])
        if not exists(self.root):
            raise FileNotFoundError(
                f"Encrypted root directory not found: {self.root}"
            )

    @staticmethod
    def _normalize(path: str) -> str:
        if '\x00' in path:
            raise ValueError("Path contains null byte")
        path = path.replace('\\', '/')
        if not path.startswith('/'):
            path = '/' + path
        parts = []
        for p in path.split('/'):
            if p in ('', '.'):
                continue
            elif p == '..':
                if parts:
                    parts.pop()
            else:
                parts.append(p)
        return '/' + '/'.join(parts)

    def _get_real_dir(self, dir_id: str) -> str:
        hdid = hash_dir_id(self.pk, self.hk, dir_id)
        return join(self.base, DATA_DIR_NAME, hdid[:2], hdid[2:])

    def _shorten_name(self, enc_name: bytes, real_dir: str) -> Tuple[str, Optional[bytes]]:
        if len(enc_name) > self.shortening_threshold:
            sha   = hashlib.sha1(enc_name).digest()
            short = base64.urlsafe_b64encode(sha).decode('ascii') + DEFLATED_FILE_SUFFIX
            return join(real_dir, short), enc_name
        return join(real_dir, enc_name.decode('ascii')), None

    def resolve(self, virtual_path: str, _depth: int = 0) -> NodeInfo:
        if _depth > _SYMLINK_MAX_DEPTH:
            raise OSError(f"Too many levels of symbolic links: {virtual_path}")

        virtual_path = self._normalize(virtual_path)
        info = NodeInfo()
        info.virtual_path = virtual_path
        info.real_dir     = self.root

        if virtual_path == '/':
            info.is_dir  = True
            info.exists  = True
            info.dir_id  = ROOT_DIR_ID
            info.real_dir = self.root
            return info

        parts  = [p for p in virtual_path.split('/') if p]
        dir_id = ROOT_DIR_ID

        for i, part in enumerate(parts):
            is_last  = (i == len(parts) - 1)
            real_dir = self._get_real_dir(dir_id)
            enc_name = encrypt_name(self.pk, self.hk, dir_id, part)
            real_path, long_name = self._shorten_name(enc_name, real_dir)

            info.real_path = real_path
            info.long_name = long_name
            info.real_dir  = real_dir

            if not exists(real_path):
                info.exists       = False
                info.virtual_path = '/' + '/'.join(parts[:i + 1])
                return info

            sym_file = join(real_path, SYMLINK_FILE_NAME)
            if exists(sym_file):
                info.is_symlink     = True
                target              = self._read_symlink(sym_file, '/' + '/'.join(parts[:i]))
                info.symlink_target = target
                if is_last:
                    info.exists = True
                    info.dir_id = dir_id
                    return info
                resolved = self.resolve(target, _depth + 1)
                if not resolved.exists:
                    info.exists = False
                    return info
                dir_id        = resolved.dir_id
                info.real_dir = resolved.real_dir
                continue

            dir_file = join(real_path, DIR_FILE_NAME)
            if exists(dir_file):
                cache_key   = dir_file
                next_dir_id = self._dir_id_cache.get(cache_key)
                if next_dir_id is None:
                    with open(dir_file, 'r', encoding='utf-8') as fh:
                        next_dir_id = fh.read(MAX_DIR_ID_LENGTH + 1).strip()
                    if len(next_dir_id) > MAX_DIR_ID_LENGTH:
                        raise ValueError(f"dir.c9r content exceeds maximum length at: {dir_file}")
                    self._dir_id_cache[cache_key] = next_dir_id

                if is_last:
                    info.is_dir   = True
                    info.dir_id   = next_dir_id
                    info.exists   = True
                    info.real_dir = self._get_real_dir(next_dir_id)
                    return info

                dir_id        = next_dir_id
                info.real_dir = self._get_real_dir(next_dir_id)
            elif isdir(real_path):
                contents_file = join(real_path, CONTENTS_FILE_NAME)
                if exists(contents_file):
                    if is_last:
                        info.is_dir = False
                        info.dir_id = dir_id
                        info.exists = True
                        return info
                    info.exists = False
                    return info
                else:
                    info.exists = False
                    return info
            else:
                if is_last:
                    info.is_dir = False
                    info.dir_id = dir_id
                    info.exists = True
                    return info
                info.exists = False
                return info

        return info

    def _read_symlink(self, sym_file: str, parent_vpath: str) -> str:
        enc_size = os.path.getsize(sym_file)
        max_enc  = HEADER_SIZE + GCM_NONCE_SIZE + MAX_SYMLINK_TARGET_LEN + GCM_TAG_SIZE
        if enc_size > max_enc:
            raise ValueError(f"Symlink file too large, refusing to decrypt: {sym_file}")
        with open(sym_file, 'rb') as f:
            buf = io.BytesIO()
            decrypt_file_content(self.pk, f, buf)
        raw = buf.getvalue()
        if len(raw) > MAX_SYMLINK_TARGET_LEN:
            raise ValueError(f"Symlink target exceeds maximum length: {sym_file}")
        target = raw.decode('utf-8')
        if not target.startswith('/'):
            target = normpath(join(parent_vpath, target)).replace('\\', '/')
        return target

    def listdir(self, virtual_path: str) -> List[dict]:
        virtual_path = self._normalize(virtual_path)
        info = self.resolve(virtual_path)
        if not info.exists:
            raise FileNotFoundError(f"No such directory in vault: {virtual_path}")
        if not info.is_dir:
            raise NotADirectoryError(f"Not a directory: {virtual_path}")

        real_dir = info.real_dir
        dir_id   = info.dir_id
        entries  = []

        for entry in os.scandir(real_dir):
            name = entry.name

            if name == DIR_ID_BACKUP_FILE_NAME:
                continue

            if name.endswith(DEFLATED_FILE_SUFFIX):
                name_file = join(real_dir, name, INFLATED_FILE_NAME)
                if not exists(name_file):
                    continue
                with open(name_file, 'r', encoding='utf-8') as fh:
                    enc_name_str = fh.read(MAX_CIPHER_NAME_LENGTH + 10).strip()
                if len(enc_name_str) > MAX_CIPHER_NAME_LENGTH + 4:
                    continue
                try:
                    clear_name = decrypt_name(
                        self.pk, self.hk, dir_id, enc_name_str.encode('ascii')
                    )
                except Exception:
                    continue
                node_path        = join(real_dir, name)
                node_type, stat_path = self._node_type(node_path)

            elif name.endswith(CRYPTOMATOR_FILE_SUFFIX):
                try:
                    clear_name = decrypt_name(
                        self.pk, self.hk, dir_id, name.encode('ascii')
                    )
                except Exception:
                    continue
                node_path        = join(real_dir, name)
                node_type, stat_path = self._node_type(node_path)

            else:
                continue

            if node_type is None:
                continue

            try:
                st = os.stat(stat_path)
            except OSError:
                continue

            size = cleartext_size(st.st_size) if node_type == 'file' else 0
            entries.append({
                'name':         clear_name,
                'type':         node_type,
                'size':         size,
                'mtime':        st.st_mtime,
                'virtual_path': self._normalize(virtual_path + '/' + clear_name),
            })

        return sorted(entries, key=lambda e: (e['type'] != 'dir', e['name'].lower()))

    def _node_type(self, node_path: str) -> Tuple[Optional[str], str]:
        if isdir(node_path):
            if exists(join(node_path, DIR_FILE_NAME)):
                return 'dir', join(node_path, DIR_FILE_NAME)
            elif exists(join(node_path, SYMLINK_FILE_NAME)):
                return 'symlink', join(node_path, SYMLINK_FILE_NAME)
            elif exists(join(node_path, CONTENTS_FILE_NAME)):
                return 'file', join(node_path, CONTENTS_FILE_NAME)
            else:
                return None, ''
        else:
            return 'file', node_path

    def walk(self, virtual_path: str) -> Iterator[Tuple[str, List[str], List[str]]]:
        entries = self.listdir(virtual_path)
        dirs    = [e['name'] for e in entries if e['type'] == 'dir']
        files   = [e['name'] for e in entries if e['type'] == 'file']
        yield virtual_path, dirs, files
        for d in dirs:
            child = self._normalize(virtual_path + '/' + d)
            yield from self.walk(child)

    def mkdir(self, virtual_path: str) -> str:
        virtual_path = self._normalize(virtual_path)
        if virtual_path == '/':
            return self.root

        parent = dirname(virtual_path)
        if parent not in ('', '/'):
            self.mkdir(parent)

        info = self.resolve(virtual_path)
        if info.exists:
            if info.is_dir:
                return info.real_dir
            raise FileExistsError(f"A file already exists at: {virtual_path}")

        real_path = info.real_path
        long_name = info.long_name

        os.makedirs(real_path, exist_ok=True)

        if long_name is not None:
            with open(info.name_file, 'w', encoding='utf-8') as fh:
                fh.write(long_name.decode('ascii'))

        dir_id = str(uuid.uuid4())
        with open(info.dir_file, 'w', encoding='utf-8') as fh:
            fh.write(dir_id)
        self._dir_id_cache[info.dir_file] = dir_id

        contents_dir = self._get_real_dir(dir_id)
        os.makedirs(contents_dir, exist_ok=True)

        dirid_path = join(contents_dir, DIR_ID_BACKUP_FILE_NAME)
        with open(dirid_path, 'wb') as f:
            encrypt_file_content(self.pk, io.BytesIO(dir_id.encode('ascii')), f)

        return contents_dir

    def put(self, src_path: str, virtual_dest: str, force: bool = False) -> int:
        virtual_dest = self._normalize(virtual_dest)
        dest_info    = self.resolve(virtual_dest)

        if dest_info.exists and dest_info.is_dir:
            virtual_dest = self._normalize(virtual_dest + '/' + basename(src_path))
            dest_info    = self.resolve(virtual_dest)

        if dest_info.exists and not force:
            raise FileExistsError(
                f"Destination already exists: {virtual_dest}  (use force=True to overwrite)"
            )

        parent = dirname(virtual_dest) or '/'
        self.mkdir(parent)

        dest_info = self.resolve(virtual_dest)
        real_path = dest_info.real_path
        long_name = dest_info.long_name

        if long_name is not None:
            os.makedirs(real_path, exist_ok=True)
            with open(dest_info.name_file, 'w', encoding='utf-8') as fh:
                fh.write(long_name.decode('ascii'))
            out_path = dest_info.contents_path
        else:
            out_path = real_path

        out_dir = dirname(out_path) or '.'
        os.makedirs(out_dir, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=out_dir, prefix='.pythomator-')
        written = 0
        try:
            with open(src_path, 'rb') as src:
                with os.fdopen(fd, 'wb') as dst:
                    written = encrypt_file_content(self.pk, src, dst)
            fd = -1
            st = os.stat(src_path)
            os.utime(tmp_path, (st.st_atime, st.st_mtime))
            os.replace(tmp_path, out_path)
            tmp_path = None
        except Exception:
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if tmp_path is not None:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            raise
        return written

    def put_stream(
        self, stream, virtual_dest: str, force: bool = False, mtime: Optional[float] = None
    ) -> int:
        virtual_dest = self._normalize(virtual_dest)
        dest_info    = self.resolve(virtual_dest)

        if dest_info.exists and not force:
            raise FileExistsError(
                f"Destination already exists: {virtual_dest}  (use force=True to overwrite)"
            )

        parent = dirname(virtual_dest) or '/'
        self.mkdir(parent)
        dest_info = self.resolve(virtual_dest)

        real_path = dest_info.real_path
        long_name = dest_info.long_name

        if long_name is not None:
            os.makedirs(real_path, exist_ok=True)
            with open(dest_info.name_file, 'w', encoding='utf-8') as fh:
                fh.write(long_name.decode('ascii'))
            out_path = dest_info.contents_path
        else:
            out_path = real_path

        out_dir = dirname(out_path) or '.'
        os.makedirs(out_dir, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=out_dir, prefix='.pythomator-')
        written = 0
        try:
            with os.fdopen(fd, 'wb') as dst:
                written = encrypt_file_content(self.pk, stream, dst)
            fd = -1
            if mtime is not None:
                os.utime(tmp_path, (mtime, mtime))
            os.replace(tmp_path, out_path)
            tmp_path = None
        except Exception:
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if tmp_path is not None:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            raise
        return written

    def get(self, virtual_src: str, dest_path: str, force: bool = False, _depth: int = 0) -> int:
        if _depth > _SYMLINK_MAX_DEPTH:
            raise OSError(f"Too many levels of symbolic links: {virtual_src}")

        virtual_src = self._normalize(virtual_src)
        info        = self.resolve(virtual_src)
        if not info.exists:
            raise FileNotFoundError(f"No such file in vault: {virtual_src}")
        if info.is_dir and not info.is_symlink:
            raise IsADirectoryError(f"Is a directory: {virtual_src}")

        if info.is_symlink:
            return self.get(info.symlink_target, dest_path, force, _depth + 1)

        out_dir = dirname(dest_path) or '.'
        os.makedirs(out_dir, exist_ok=True)

        enc_path = info.contents_path
        fd, tmp_path = tempfile.mkstemp(dir=out_dir, prefix='.pythomator-')
        written = 0
        try:
            with open(enc_path, 'rb') as src:
                with os.fdopen(fd, 'wb') as dst:
                    written = decrypt_file_content(self.pk, src, dst)
            fd = -1
            st = os.stat(enc_path)
            os.utime(tmp_path, (st.st_atime, st.st_mtime))
            if force:
                os.replace(tmp_path, dest_path)
            else:
                try:
                    dest_fd = os.open(dest_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                    os.close(dest_fd)
                    os.replace(tmp_path, dest_path)
                except FileExistsError:
                    os.unlink(tmp_path)
                    raise FileExistsError(
                        f"Destination already exists: {dest_path}  (use force=True to overwrite)"
                    )
            tmp_path = None
        except Exception:
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if tmp_path is not None:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            raise
        return written

    def get_to_stream(self, virtual_src: str, stream, _depth: int = 0) -> int:
        if _depth > _SYMLINK_MAX_DEPTH:
            raise OSError(f"Too many levels of symbolic links: {virtual_src}")

        virtual_src = self._normalize(virtual_src)
        info        = self.resolve(virtual_src)
        if not info.exists:
            raise FileNotFoundError(f"No such file in vault: {virtual_src}")
        if info.is_dir:
            raise IsADirectoryError(f"Is a directory: {virtual_src}")
        if info.is_symlink:
            return self.get_to_stream(info.symlink_target, stream, _depth + 1)
        with open(info.contents_path, 'rb') as src:
            return decrypt_file_content(self.pk, src, stream)

    def rm(self, virtual_path: str):
        virtual_path = self._normalize(virtual_path)
        info         = self.resolve(virtual_path)
        if not info.exists:
            raise FileNotFoundError(f"No such file in vault: {virtual_path}")
        if info.is_dir and not info.is_symlink:
            raise IsADirectoryError(f"Is a directory: {virtual_path}  (use rmdir)")

        real_path = info.real_path

        if info.long_name is not None:
            if exists(info.contents_path):
                os.remove(info.contents_path)
            if exists(info.name_file):
                os.remove(info.name_file)
            if isdir(real_path):
                try:
                    os.rmdir(real_path)
                except OSError:
                    pass
        elif isdir(real_path):
            sym = join(real_path, SYMLINK_FILE_NAME)
            if exists(sym):
                os.remove(sym)
            try:
                os.rmdir(real_path)
            except OSError:
                pass
        else:
            os.remove(real_path)

    def rmdir(self, virtual_path: str, recursive: bool = False):
        virtual_path = self._normalize(virtual_path)
        if virtual_path == '/':
            raise PermissionError("Cannot remove vault root directory")

        info = self.resolve(virtual_path)
        if not info.exists:
            raise FileNotFoundError(f"No such directory: {virtual_path}")
        if not info.is_dir:
            raise NotADirectoryError(f"Not a directory: {virtual_path}")

        entries = self.listdir(virtual_path)
        if entries and not recursive:
            raise OSError(f"Directory not empty: {virtual_path}  (use recursive=True to force)")

        if recursive:
            all_items = list(self.walk(virtual_path))
            for root, dirs, files in reversed(all_items):
                for f in files:
                    try:
                        self.rm(self._normalize(root + '/' + f))
                    except Exception:
                        pass
                for d in dirs:
                    try:
                        self.rmdir(self._normalize(root + '/' + d))
                    except Exception:
                        pass

        contents_dir = info.real_dir
        dirid_bak    = join(contents_dir, DIR_ID_BACKUP_FILE_NAME)
        if exists(dirid_bak):
            os.remove(dirid_bak)
        try:
            os.rmdir(contents_dir)
        except OSError:
            pass
        try:
            os.rmdir(dirname(contents_dir))
        except OSError:
            pass

        real_path = info.real_path
        if info.long_name is not None:
            if exists(info.name_file):
                os.remove(info.name_file)
            dir_file = info.dir_file
            if exists(dir_file):
                if dir_file in self._dir_id_cache:
                    del self._dir_id_cache[dir_file]
                os.remove(dir_file)
            try:
                os.rmdir(real_path)
            except OSError:
                pass
        else:
            dir_file = info.dir_file
            if exists(dir_file):
                if dir_file in self._dir_id_cache:
                    del self._dir_id_cache[dir_file]
                os.remove(dir_file)
            try:
                os.rmdir(real_path)
            except OSError:
                pass

    def change_password(self, new_password: str):
        master    = dict(self._master)
        salt      = get_random_bytes(8)
        master['scryptSalt'] = base64.b64encode(salt).decode()
        kek = derive_kek(new_password, salt, master['scryptCostParam'], master['scryptBlockSize'])
        try:
            master['primaryMasterKey'] = base64.b64encode(aes_wrap(kek, self.pk)).decode()
            master['hmacMasterKey']    = base64.b64encode(aes_wrap(kek, self.hk)).decode()
        finally:
            _wipe(kek)
        master['versionMac'] = base64.b64encode(
            _hmac.new(bytes(self.hk), int(master['version']).to_bytes(4, 'big'), hashlib.sha256).digest()
        ).decode()

        ordered = {
            'primaryMasterKey': master['primaryMasterKey'],
            'hmacMasterKey':    master['hmacMasterKey'],
            'scryptBlockSize':  master['scryptBlockSize'],
            'scryptCostParam':  master['scryptCostParam'],
            'scryptSalt':       master['scryptSalt'],
            'version':          master['version'],
            'versionMac':       master['versionMac'],
        }

        out_dir  = dirname(self._master_path) or '.'
        fd, tmp_path = tempfile.mkstemp(dir=out_dir, prefix='.pythomator-mk-')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                json.dump(ordered, f, indent=2)
            fd = -1
            os.replace(tmp_path, self._master_path)
            tmp_path = None
        except Exception:
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if tmp_path is not None:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
            raise

        self._master = ordered

    def stat(self, virtual_path: str) -> os.stat_result:
        virtual_path = self._normalize(virtual_path)
        info = self.resolve(virtual_path)
        if not info.exists:
            raise FileNotFoundError(f"No such file: {virtual_path}")
        if info.is_symlink:
            return os.stat(info.symlink_file)
        if info.is_dir:
            if virtual_path == '/':
                return os.stat(self.root)
            return os.stat(info.dir_file)
        return os.stat(info.contents_path)

    def size(self, virtual_path: str) -> int:
        st   = self.stat(virtual_path)
        info = self.resolve(virtual_path)
        if info.is_dir:
            return 0
        return cleartext_size(st.st_size)

    def _collect_put_items(
        self,
        sources: List[str],
        vault_dest: str,
        recursive: bool,
    ) -> List[Tuple[str, str]]:
        items = []
        for src in sources:
            src = os.path.abspath(src)
            if not exists(src):
                continue
            if isdir(src) and recursive:
                src_name = basename(src.rstrip('/\\'))
                for root, dirs, files in os.walk(src):
                    rel  = os.path.relpath(root, src)
                    vdir = (
                        f"{vault_dest}/{src_name}" if rel == '.'
                        else f"{vault_dest}/{src_name}/{rel.replace(os.sep, '/')}"
                    )
                    for fname in files:
                        items.append((join(root, fname), f"{vdir}/{fname}"))
            elif not isdir(src):
                items.append((src, f"{vault_dest}/{basename(src)}"))
        return items

    def put_many(
        self,
        sources: List[str],
        vault_dest: str,
        *,
        force: bool = False,
        recursive: bool = False,
        progress=None,
    ) -> dict:
        items   = self._collect_put_items(sources, vault_dest, recursive)
        result  = {'files': 0, 'bytes': 0, 'skipped': 0, 'errors': []}
        t0      = time.time()

        if progress is not None:
            progress.total = len(items)
            progress.refresh()

        for src_path, vpath in items:
            try:
                cb = self.put(src_path, vpath, force=force)
                result['files'] += 1
                result['bytes'] += cb
                if progress is not None:
                    speed = result['bytes'] / max(time.time() - t0, 0.001)
                    progress.set_postfix(speed=_fmt_size(speed) + '/s', file=basename(src_path))
                    progress.update(1)
            except Exception as e:
                result['skipped'] += 1
                result['errors'].append((src_path, str(e)))
                if progress is not None:
                    progress.update(1)

        result['elapsed'] = time.time() - t0
        return result

    def _collect_get_items(
        self,
        sources: List[str],
        local_dest: str,
        recursive: bool,
    ) -> List[Tuple[str, str]]:
        items = []
        for src in sources:
            try:
                info = self.resolve(src)
            except Exception:
                continue
            if not info.exists:
                continue
            if info.is_dir and recursive:
                for root, dirs, files in self.walk(src):
                    rel      = root[len(src):].lstrip('/')
                    out_base = join(local_dest, rel) if rel else local_dest
                    for fname in files:
                        vpath    = root.rstrip('/') + '/' + fname
                        out_path = join(out_base, fname)
                        items.append((vpath, out_path))
            elif not info.is_dir:
                if os.path.isdir(local_dest):
                    out_path = join(local_dest, basename(src))
                else:
                    out_path = local_dest
                items.append((src, out_path))
        return items

    def get_many(
        self,
        sources: List[str],
        local_dest: str,
        *,
        force: bool = False,
        recursive: bool = False,
        progress=None,
    ) -> dict:
        items  = self._collect_get_items(sources, local_dest, recursive)
        result = {'files': 0, 'bytes': 0, 'skipped': 0, 'errors': []}
        t0     = time.time()

        if progress is not None:
            progress.total = len(items)
            progress.refresh()

        for vpath, out_path in items:
            try:
                os.makedirs(dirname(out_path) or '.', exist_ok=True)
                cb = self.get(vpath, out_path, force=force)
                result['files'] += 1
                result['bytes'] += cb
                if progress is not None:
                    speed = result['bytes'] / max(time.time() - t0, 0.001)
                    progress.set_postfix(speed=_fmt_size(speed) + '/s', file=basename(out_path))
                    progress.update(1)
            except Exception as e:
                result['skipped'] += 1
                result['errors'].append((vpath, str(e)))
                if progress is not None:
                    progress.update(1)

        result['elapsed'] = time.time() - t0
        return result


def _fmt_size(n: float) -> str:
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024 or unit == 'TB':
            return f"{n:.0f} B" if unit == 'B' else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def create_vault(vault_dir: str, password: str):
    if not exists(vault_dir):
        raise FileNotFoundError(f"Directory does not exist: {vault_dir}")
    if os.listdir(vault_dir):
        raise OSError(f"Directory is not empty: {vault_dir}")

    pk_ba = bytearray(get_random_bytes(32))
    hk_ba = bytearray(get_random_bytes(32))
    try:
        salt        = get_random_bytes(8)
        scrypt_cost = 1 << 15
        scrypt_r    = 8
        kek         = derive_kek(password, salt, scrypt_cost, scrypt_r)

        version_bytes = MASTERKEY_LEGACY_VERSION.to_bytes(4, 'big')
        vmac = base64.b64encode(
            _hmac.new(bytes(hk_ba), version_bytes, hashlib.sha256).digest()
        ).decode()

        try:
            master = {
                'primaryMasterKey': base64.b64encode(aes_wrap(kek, pk_ba)).decode(),
                'hmacMasterKey':    base64.b64encode(aes_wrap(kek, hk_ba)).decode(),
                'scryptBlockSize':  scrypt_r,
                'scryptCostParam':  scrypt_cost,
                'scryptSalt':       base64.b64encode(salt).decode(),
                'version':          MASTERKEY_LEGACY_VERSION,
                'versionMac':       vmac,
            }
        finally:
            _wipe(kek)

        masterkey_path = join(vault_dir, MASTERKEY_FILENAME)
        with _secure_open_write(masterkey_path) as f:
            json.dump(master, f, indent=2)

        header  = {'alg': 'HS256', 'typ': 'JWT', 'kid': 'masterkeyfile:masterkey.cryptomator'}
        payload = {
            'format':              VAULT_VERSION,
            'shorteningThreshold': MAX_CIPHER_NAME_LENGTH,
            'jti':                 str(uuid.uuid4()),
            'cipherCombo':         'SIV_GCM',
        }
        h_b64       = b64url_no_pad(json.dumps(header,  separators=(',', ':')).encode())
        p_b64       = b64url_no_pad(json.dumps(payload, separators=(',', ':')).encode())
        signed_part = h_b64 + b'.' + p_b64
        sig         = b64url_no_pad(
            _hmac.new(bytes(pk_ba) + bytes(hk_ba), signed_part, hashlib.sha256).digest()
        )
        jwt_token   = signed_part + b'.' + sig

        config_path = join(vault_dir, VAULT_CONFIG_FILENAME)
        with _secure_open_write_binary(config_path) as f:
            f.write(jwt_token)

        edid     = hash_dir_id(pk_ba, hk_ba, ROOT_DIR_ID)
        root_dir = join(vault_dir, DATA_DIR_NAME, edid[:2], edid[2:])
        os.makedirs(root_dir, exist_ok=True)

        dirid_path = join(root_dir, DIR_ID_BACKUP_FILE_NAME)
        with open(dirid_path, 'wb') as f:
            encrypt_file_content(pk_ba, io.BytesIO(ROOT_DIR_ID.encode('ascii')), f)
    finally:
        _wipe(pk_ba)
        _wipe(hk_ba)
