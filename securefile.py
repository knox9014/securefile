"""
securefile.py - 파일/폴더 압축 + 암호화 도구 (v2)

사용법:
    python securefile.py encrypt <파일 또는 폴더>     # 압축+암호화 -> .sfz 생성
    python securefile.py decrypt <파일.sfz>          # 복호화+압축해제

v2 새 기능:
    - 대용량 파일 스트리밍 처리 (1MB씩 조각내어 메모리 절약, 수GB도 OK)
    - LZMA 압축 (zlib보다 압축률 우수)
    - 폴더 통째로 암호화 (tar로 묶어서 처리)
    - 청크 단위 AES-256-GCM + 순번 인증 (변조/잘라내기/순서변경 탐지)

파일 포맷 (.sfz v2):
    [MAGIC 4B "SFZ2"][flags 1B][salt 16B][nonce_prefix 8B]
    이후 청크 반복: [final 1B][ct_len 4B][ciphertext...]
        - nonce       = nonce_prefix(8B) + 청크순번(4B)
        - AAD(인증값)  = 청크순번(4B) + final(1B)  -> 순서/끝 위조 차단
"""

import os
import sys
import lzma
import struct
import tarfile
import getpass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

MAGIC = b"SFZ2"
PBKDF2_ITERATIONS = 200_000
SALT_SIZE = 16
NONCE_PREFIX_SIZE = 8
KEY_SIZE = 32                  # AES-256
CHUNK = 1024 * 1024            # 암호화 청크: 압축데이터 1MB마다 한 조각
READ = 256 * 1024             # 입력 파일 읽기 단위


def derive_key(password: str, salt: bytes) -> bytes:
    """비밀번호 + 솔트 -> 안전한 32바이트 키."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


class EncryptWriter:
    """write()로 들어오는 데이터를 LZMA 압축 후 청크 단위로 암호화해 저장한다.

    tarfile / 파일 읽기 양쪽 모두 이 write()에 데이터를 흘려보낸다(push 방식).
    """

    def __init__(self, out, key: bytes, nonce_prefix: bytes):
        self.out = out
        self.aes = AESGCM(key)
        self.prefix = nonce_prefix
        self.comp = lzma.LZMACompressor()
        self.counter = 0
        self.buf = bytearray()

    def write(self, data: bytes) -> int:
        self.buf += self.comp.compress(data)
        while len(self.buf) >= CHUNK:
            self._emit(bytes(self.buf[:CHUNK]), final=False)
            del self.buf[:CHUNK]
        return len(data)

    def _emit(self, data: bytes, final: bool):
        nonce = self.prefix + struct.pack(">I", self.counter)
        aad = struct.pack(">I?", self.counter, final)
        ct = self.aes.encrypt(nonce, data, aad)
        self.out.write(bytes([1 if final else 0]))
        self.out.write(struct.pack(">I", len(ct)))
        self.out.write(ct)
        self.counter += 1

    def close(self):
        """남은 압축 데이터를 flush하고 마지막 청크에 final 표시를 남긴다."""
        self.buf += self.comp.flush()
        while len(self.buf) > CHUNK:
            self._emit(bytes(self.buf[:CHUNK]), final=False)
            del self.buf[:CHUNK]
        self._emit(bytes(self.buf), final=True)   # 마지막 조각(비어도 OK)


class DecryptReader:
    """암호화 파일에서 청크를 하나씩 읽어 복호화+압축해제해 read()로 내보낸다(pull 방식)."""

    def __init__(self, inp, key: bytes, nonce_prefix: bytes):
        self.inp = inp
        self.aes = AESGCM(key)
        self.prefix = nonce_prefix
        self.decomp = lzma.LZMADecompressor()
        self.counter = 0
        self.done = False
        self.buf = bytearray()

    def _fill(self):
        head = self.inp.read(5)
        if len(head) < 5:
            raise ValueError("파일이 잘렸습니다(끝 표시 없음).")
        final = head[0] == 1
        (clen,) = struct.unpack(">I", head[1:5])
        ct = self.inp.read(clen)
        if len(ct) < clen:
            raise ValueError("파일이 손상되었습니다(청크 길이 불일치).")
        nonce = self.prefix + struct.pack(">I", self.counter)
        aad = struct.pack(">I?", self.counter, final)
        try:
            pt = self.aes.decrypt(nonce, ct, aad)
        except Exception:
            raise ValueError("복호화 실패: 비밀번호가 틀렸거나 파일이 변조되었습니다.")
        self.buf += self.decomp.decompress(pt)
        self.counter += 1
        if final:
            self.done = True

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            while not self.done:
                self._fill()
            data, self.buf = bytes(self.buf), bytearray()
            return data
        while len(self.buf) < n and not self.done:
            self._fill()
        data = bytes(self.buf[:n])
        del self.buf[:n]
        return data


def encrypt_path(path: str, password: str) -> str:
    """파일 또는 폴더를 압축+암호화한다. 결과 .sfz 경로를 반환."""
    path = path.rstrip("/\\")
    is_dir = os.path.isdir(path)
    salt = os.urandom(SALT_SIZE)
    nonce_prefix = os.urandom(NONCE_PREFIX_SIZE)
    key = derive_key(password, salt)

    out_path = path + ".sfz"
    with open(out_path, "wb") as out:
        out.write(MAGIC)
        out.write(bytes([1 if is_dir else 0]))
        out.write(salt)
        out.write(nonce_prefix)

        writer = EncryptWriter(out, key, nonce_prefix)
        if is_dir:
            # 폴더를 tar 스트림으로 묶어 그대로 압축/암호화 파이프라인에 흘려보냄
            with tarfile.open(fileobj=writer, mode="w|") as tar:
                tar.add(path, arcname=os.path.basename(path))
        else:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(READ), b""):
                    writer.write(chunk)
        writer.close()
    return out_path


def decrypt_path(path: str, password: str) -> str:
    """.sfz 파일을 복호화+압축해제한다. 결과 경로(파일 또는 폴더)를 반환."""
    with open(path, "rb") as inp:
        if inp.read(4) != MAGIC:
            raise ValueError("올바른 .sfz(v2) 파일이 아닙니다.")
        is_dir = inp.read(1)[0] == 1
        salt = inp.read(SALT_SIZE)
        nonce_prefix = inp.read(NONCE_PREFIX_SIZE)
        key = derive_key(password, salt)

        reader = DecryptReader(inp, key, nonce_prefix)

        if is_dir:
            # 부모 폴더에 풀기 (tar 안에 원본 폴더명이 들어있음)
            out_dir = os.path.dirname(os.path.abspath(path)) or "."
            with tarfile.open(fileobj=reader, mode="r|") as tar:
                tar.extractall(path=out_dir, filter="data")  # filter: 경로탈출 방어
            return out_dir
        else:
            out_path = path[:-4] if path.endswith(".sfz") else path + ".dec"
            if os.path.exists(out_path):
                out_path += ".dec"
            with open(out_path, "wb") as f:
                for chunk in iter(lambda: reader.read(READ), b""):
                    f.write(chunk)
            return out_path


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ("encrypt", "decrypt"):
        print(__doc__)
        sys.exit(1)

    mode, path = sys.argv[1], sys.argv[2]
    if mode == "encrypt" and not os.path.exists(path):
        print(f"경로를 찾을 수 없습니다: {path}")
        sys.exit(1)
    if mode == "decrypt" and not os.path.isfile(path):
        print(f"파일을 찾을 수 없습니다: {path}")
        sys.exit(1)

    password = getpass.getpass("비밀번호: ")
    if mode == "encrypt":
        if password != getpass.getpass("비밀번호 확인: "):
            print("비밀번호가 일치하지 않습니다.")
            sys.exit(1)
        out = encrypt_path(path, password)
        print(f"암호화 완료 -> {out}")
        print(f"  결과 크기: {os.path.getsize(out):,} bytes")
    else:
        out = decrypt_path(path, password)
        print(f"복호화 완료 -> {out}")


if __name__ == "__main__":
    main()
