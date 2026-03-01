"""
pythomator — GPL-3.0
low-level crypto: AES-SIV, AES-GCM, AES-KW, scrypt KDF.
"""

import base64
import ctypes
import hashlib
import struct
from typing import Union

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

GCM_NONCE_SIZE           = 12
GCM_TAG_SIZE             = 16
PAYLOAD_SIZE             = 32 * 1024
CHUNK_SIZE               = GCM_NONCE_SIZE + PAYLOAD_SIZE + GCM_TAG_SIZE
CHUNK_OVERHEAD           = GCM_NONCE_SIZE + GCM_TAG_SIZE
HEADER_NONCE_LEN         = 12
HEADER_PAYLOAD_CLEARTEXT = 8 + 32
HEADER_TAG_LEN           = 16
HEADER_SIZE              = HEADER_NONCE_LEN + HEADER_PAYLOAD_CLEARTEXT + HEADER_TAG_LEN
BLOCK_SIZE               = PAYLOAD_SIZE


def _wipe(buf: bytearray) -> None:
    n = len(buf)
    if n == 0:
        return
    try:
        arr = (ctypes.c_char * n).from_buffer(buf)
        ctypes.memset(arr, 0, n)
    except Exception:
        for i in range(n):
            buf[i] = 0


def aes_wrap(kek: Union[bytes, bytearray], key: Union[bytes, bytearray]) -> bytes:
    cipher = AES.new(bytes(kek), AES.MODE_KW)
    return cipher.seal(bytes(key))


def aes_unwrap(kek: Union[bytes, bytearray], wrapped: Union[bytes, bytearray]) -> bytearray:
    try:
        cipher = AES.new(bytes(kek), AES.MODE_KW)
        return bytearray(cipher.unseal(bytes(wrapped)))
    except Exception:
        raise ValueError("Key unwrap failed")


def siv_encrypt(
    pk: Union[bytes, bytearray],
    hk: Union[bytes, bytearray],
    plaintext: bytes,
    ad: bytes | None = None,
) -> bytes:
    aes = AES.new(bytes(hk) + bytes(pk), AES.MODE_SIV)
    if ad is not None:
        aes.update(ad)
    ciphertext, tag = aes.encrypt_and_digest(plaintext)
    return tag + ciphertext


def siv_decrypt(
    pk: Union[bytes, bytearray],
    hk: Union[bytes, bytearray],
    data: bytes,
    ad: bytes | None = None,
) -> bytes:
    aes = AES.new(bytes(hk) + bytes(pk), AES.MODE_SIV)
    if ad is not None:
        aes.update(ad)
    return aes.decrypt_and_verify(data[16:], data[:16])


def hash_dir_id(pk: Union[bytes, bytearray], hk: Union[bytes, bytearray], dir_id: str) -> str:
    encrypted = siv_encrypt(pk, hk, dir_id.encode('utf-8'))
    sha = hashlib.sha1(encrypted).digest()
    return base64.b32encode(sha).decode('ascii')


def encrypt_name(
    pk: Union[bytes, bytearray],
    hk: Union[bytes, bytearray],
    dir_id: str,
    name: str,
) -> bytes:
    plaintext  = name.encode('utf-8')
    ciphertext = siv_encrypt(pk, hk, plaintext, ad=dir_id.encode('utf-8'))
    return base64.urlsafe_b64encode(ciphertext) + b'.c9r'


def decrypt_name(
    pk: Union[bytes, bytearray],
    hk: Union[bytes, bytearray],
    dir_id: str,
    enc_name: bytes,
) -> str:
    if not enc_name.endswith(b'.c9r'):
        raise ValueError("Not a .c9r name")
    b64_part   = enc_name[:-4]
    pad_len    = (-len(b64_part)) % 4
    ciphertext = base64.urlsafe_b64decode(b64_part + b'=' * pad_len)
    plaintext  = siv_decrypt(pk, hk, ciphertext, ad=dir_id.encode('utf-8'))
    return plaintext.decode('utf-8')


def encrypt_file_content(
    pk: Union[bytes, bytearray],
    src,
    dst,
) -> int:
    header_nonce      = get_random_bytes(HEADER_NONCE_LEN)
    content_key_ba    = bytearray(get_random_bytes(32))
    cleartext_payload = bytearray(b'\xFF' * 8) + content_key_ba

    try:
        cipher = AES.new(bytes(pk), AES.MODE_GCM, nonce=header_nonce)
        enc_payload, header_tag = cipher.encrypt_and_digest(bytes(cleartext_payload))
    finally:
        _wipe(cleartext_payload)

    dst.write(header_nonce)
    dst.write(enc_payload)
    dst.write(header_tag)
    written = HEADER_SIZE

    chunk_index = 0
    try:
        while True:
            chunk = src.read(PAYLOAD_SIZE)
            if not chunk:
                break
            chunk_nonce = get_random_bytes(GCM_NONCE_SIZE)
            aad = struct.pack('>Q', chunk_index) + header_nonce
            aes = AES.new(bytes(content_key_ba), AES.MODE_GCM, nonce=chunk_nonce)
            aes.update(aad)
            enc_chunk, chunk_tag = aes.encrypt_and_digest(chunk)
            dst.write(chunk_nonce)
            dst.write(enc_chunk)
            dst.write(chunk_tag)
            written += GCM_NONCE_SIZE + len(enc_chunk) + GCM_TAG_SIZE
            chunk_index += 1
    finally:
        _wipe(content_key_ba)

    return written


def decrypt_file_content(
    pk: Union[bytes, bytearray],
    src,
    dst,
) -> int:
    header = src.read(HEADER_SIZE)
    if len(header) < HEADER_SIZE:
        raise ValueError(
            f"File too short to contain a valid Cryptomator header "
            f"(need {HEADER_SIZE} bytes, got {len(header)})"
        )

    header_nonce = header[:HEADER_NONCE_LEN]
    enc_payload  = header[HEADER_NONCE_LEN:HEADER_NONCE_LEN + HEADER_PAYLOAD_CLEARTEXT]
    header_tag   = header[HEADER_NONCE_LEN + HEADER_PAYLOAD_CLEARTEXT:]

    try:
        cipher  = AES.new(bytes(pk), AES.MODE_GCM, nonce=header_nonce)
        payload = cipher.decrypt_and_verify(enc_payload, header_tag)
    except Exception:
        raise ValueError("File header authentication failed")

    if payload[:8] != b'\xFF' * 8:
        raise ValueError("Invalid file header – reserved bytes are not 0xFF×8")

    content_key_ba = bytearray(payload[8:40])

    written     = 0
    chunk_index = 0
    try:
        while True:
            enc_chunk = src.read(CHUNK_SIZE)
            if not enc_chunk:
                break
            if len(enc_chunk) < GCM_NONCE_SIZE + GCM_TAG_SIZE:
                raise ValueError(
                    f"Chunk {chunk_index} too short ({len(enc_chunk)} bytes) – file is corrupted"
                )
            chunk_nonce   = enc_chunk[:GCM_NONCE_SIZE]
            chunk_payload = enc_chunk[GCM_NONCE_SIZE:-GCM_TAG_SIZE]
            chunk_tag     = enc_chunk[-GCM_TAG_SIZE:]
            aad = struct.pack('>Q', chunk_index) + header_nonce
            aes = AES.new(bytes(content_key_ba), AES.MODE_GCM, nonce=chunk_nonce)
            aes.update(aad)
            try:
                plaintext = aes.decrypt_and_verify(chunk_payload, chunk_tag)
            except Exception:
                raise ValueError(
                    f"Chunk {chunk_index} authentication failed – file may be corrupted or tampered"
                )
            dst.write(plaintext)
            written += len(plaintext)
            chunk_index += 1
    finally:
        _wipe(content_key_ba)

    return written


def derive_kek(password: str, salt: bytes, cost: int, block_size: int) -> bytearray:
    raw = hashlib.scrypt(
        password.encode('utf-8'),
        salt=salt,
        n=cost,
        r=block_size,
        p=1,
        maxmem=0x7FFFFFFF,
        dklen=32,
    )
    return bytearray(raw)


def b64_pad(s: bytes) -> bytes:
    r = len(s) % 4
    if r:
        s += b'=' * (4 - r)
    return s


def b64url_no_pad(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b'=')


def b64url_decode(s: bytes) -> bytes:
    return base64.urlsafe_b64decode(b64_pad(s))


def cleartext_size(encrypted_size: int) -> int:
    if encrypted_size <= HEADER_SIZE:
        return 0
    content_size = encrypted_size - HEADER_SIZE
    if content_size <= 0:
        return 0
    num_chunks = (content_size + CHUNK_SIZE - 1) // CHUNK_SIZE
    overhead   = num_chunks * CHUNK_OVERHEAD
    plain      = content_size - overhead
    return max(plain, 0)
