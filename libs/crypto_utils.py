import hashlib
from typing import Callable, Literal, NewType, Protocol, SupportsIndex, TypeAlias, get_args

from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long as bytes_to_long
from Crypto.Util.number import long_to_bytes as long_to_bytes

Buffer = bytes | bytearray | memoryview
HexStr = NewType("HexStr", str)
"""Hex-encoded bytes"""

HexInt = NewType("HexInt", str)
"""Integer in hex format (`0x...`)"""


EncodeMethod: TypeAlias = Literal["str", "bytes"]
ENCODE_METHODS: dict[EncodeMethod, Callable[[int], bytes]] = {
    "str": lambda x: str(x).encode(),
    "bytes": lambda x: long_to_bytes(x),
}
assert set(get_args(EncodeMethod)) == set(ENCODE_METHODS.keys())


class SupportsHex(Protocol):
    def hex(self, sep: str | bytes = ..., bytes_per_sep: SupportsIndex = ...) -> str: ...


def xor(a: Buffer, b: Buffer) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def to_hexstr(data: SupportsHex) -> HexStr:
    return HexStr(data.hex())


def from_hexstr(data: HexStr) -> bytes:
    return bytes.fromhex(data)


def hexstr_to_bytes(data: str) -> bytes:
    return from_hexstr(HexStr(data))


def int_to_hexstr(value: int) -> HexStr:
    return to_hexstr(long_to_bytes(value))


def int_to_hex(value: int) -> HexInt:
    return HexInt(hex(value))


def hex_to_int(value: HexStr | HexInt) -> int:
    return int(value, 16)


def int_to_bytes(value: int | HexStr | HexInt) -> bytes:
    if isinstance(value, int):
        return long_to_bytes(value)
    return long_to_bytes(hex_to_int(value))


def is_pkcs7_padded(message: Buffer, block_size: int = AES.block_size) -> bool:
    msglen = len(message)
    if msglen == 0 or msglen % block_size != 0:
        return False

    padlen = message[-1]
    if padlen == 0 or padlen > min(block_size, msglen):
        return False

    padding = message[-padlen:]
    return all(p == padlen for p in padding)


def unpad_message(message: Buffer, block_size: int = AES.block_size) -> bytes:
    if is_pkcs7_padded(message, block_size):
        return message[: -message[-1]]
    return message


def decrypt_aes(encrypted: Buffer, key: Buffer, iv: Buffer) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain = cipher.decrypt(encrypted)
    return unpad_message(plain)


def decrypt_aes_hash(encrypted: Buffer, secret: bytes, iv: Buffer, hsh: str = "SHA1") -> bytes:
    h = hashlib.new(hsh)
    h.update(secret)
    key = h.digest()[:16]
    return decrypt_aes(encrypted, key, iv)


def decrypt_aes_hash_enc(
    encrypted: Buffer, secret: int, iv: Buffer, hsh: str = "SHA1", method: EncodeMethod = "str"
) -> bytes:
    return decrypt_aes_hash(encrypted, ENCODE_METHODS[method](secret), iv, hsh)


def sha1_long(data: str) -> int:
    return bytes_to_long(hashlib.sha1(data.encode()).digest())


def check_hash_type(hsh: str) -> str:
    hashlib.new(hsh)
    return hsh.upper()
