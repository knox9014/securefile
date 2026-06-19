"""
securepack.py - 통합 엔진: 폴더 → 파일별 최적 압축 → (선택) 암호화

파이프라인:
  폴더 → autopack 파일별 최적 압축(.spk) → 선택적 AES-256-GCM 암호화 → 한 파일

  - 압축: 파일마다 최적 방식 자동 선택 (zstd/bz2/lzma/brotli/store/우리압축기)
  - 암호화: 이미 압축된 .spk를 재압축 없이 바로 암호화 (효율적)
    AES-256-GCM + PBKDF2, 청크별 순번 인증(변조/잘라내기 차단)

사용법:
  python securepack.py pack   <폴더> <출력>      # 압축만 (비밀번호 물어보면 빈칸 엔터)
  python securepack.py unpack <입력> <폴더>      # 복원 (암호화면 비밀번호 입력)

출력이 암호화면 자동 감지하여 복호화 후 복원.
"""

import os
import sys
import struct
import getpass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

import autopack

try:
    from argon2.low_level import hash_secret_raw, Type as _ArgonType
except ImportError:
    hash_secret_raw = None

ENC_MAGIC = b"SPKE"        # 구 컨테이너 (PBKDF2) — 하위호환 복호화용
ENC_MAGIC2 = b"SPK2"       # 신 컨테이너 (Argon2id, 기본)
ENC_MAGICS = (ENC_MAGIC, ENC_MAGIC2)
ITER = 200_000             # PBKDF2 반복(구/대체)
SALT = 16
NPFX = 8
CHUNK = 1 << 20            # 1MB 청크
# Argon2id 기본 파라미터 (64MiB, time 3, 병렬 4) — 무차별 대입 방어 강화
A_MEM, A_TIME, A_PAR = 65536, 3, 4
KDF_PBKDF2, KDF_ARGON2 = 0, 1


def is_encrypted(head4: bytes) -> bool:
    return head4[:4] in ENC_MAGICS


def _derive_pbkdf2(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER)
    return kdf.derive(password.encode("utf-8"))


def _derive_argon2(password: str, salt: bytes, mem=A_MEM, time=A_TIME, par=A_PAR) -> bytes:
    return hash_secret_raw(password.encode("utf-8"), salt, time_cost=time,
                           memory_cost=mem, parallelism=par, hash_len=32, type=_ArgonType.ID)


def _write_header(password: str):
    """신 컨테이너(SPK2) 헤더 바이트 + AESGCM 반환. Argon2id 없으면 PBKDF2로 자동 대체."""
    salt = os.urandom(SALT); npfx = os.urandom(NPFX)
    if hash_secret_raw is not None:
        key = _derive_argon2(password, salt)
        hdr = ENC_MAGIC2 + bytes([KDF_ARGON2]) + struct.pack(">IIB", A_MEM, A_TIME, A_PAR) + salt + npfx
    else:
        key = _derive_pbkdf2(password, salt)
        hdr = ENC_MAGIC2 + bytes([KDF_PBKDF2]) + struct.pack(">I", ITER) + salt + npfx
    return hdr, npfx, AESGCM(key)


def _parse_header(readn, password):
    """readn(n)으로 헤더를 읽어 (npfx, AESGCM) 반환. SPK2/SPKE 모두 지원."""
    magic = readn(4)
    if magic == ENC_MAGIC2:
        kdf = readn(1)[0]
        if kdf == KDF_ARGON2:
            mem, time, par = struct.unpack(">IIB", readn(9))
            salt = readn(SALT); npfx = readn(NPFX)
            if hash_secret_raw is None:
                raise ValueError("이 파일은 Argon2로 암호화됨 — argon2-cffi 설치 필요")
            key = _derive_argon2(password, salt, mem, time, par)
        else:
            (it,) = struct.unpack(">I", readn(4))
            salt = readn(SALT); npfx = readn(NPFX)
            global ITER
            kdf2 = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=it)
            key = kdf2.derive(password.encode("utf-8"))
    elif magic == ENC_MAGIC:                       # 구 형식(PBKDF2)
        salt = readn(SALT); npfx = readn(NPFX)
        key = _derive_pbkdf2(password, salt)
    else:
        raise ValueError("올바른 암호화 컨테이너가 아닙니다.")
    return npfx, AESGCM(key)


# ===== 스트리밍(저RAM) 처리 =====
#   파일을 한 개씩 디스크↔디스크로 흘려보내, 폴더 전체가 아닌 '가장 큰 파일 1개'만큼만 RAM 사용.
#   출력 바이트는 기존 encrypt_bytes/pack_entries와 100% 동일(호환).

class _EncWriter:
    """스트리밍 청크 AES-256-GCM 쓰기 (encrypt_bytes와 동일 포맷)."""
    def __init__(self, fh, password):
        self.fh = fh
        hdr, npfx, aes = _write_header(password)
        fh.write(hdr)
        self.aes = aes
        self.npfx = npfx
        self.ctr = 0
        self.buf = bytearray()

    def write(self, data):
        self.buf += data
        while len(self.buf) > CHUNK:        # 마지막 청크는 close()에서 final 표시
            self._emit(bytes(self.buf[:CHUNK]), False)
            del self.buf[:CHUNK]

    def _emit(self, chunk, final):
        nonce = self.npfx + struct.pack(">I", self.ctr)
        aad = struct.pack(">I?", self.ctr, final)
        ct = self.aes.encrypt(nonce, chunk, aad)
        self.fh.write(struct.pack(">BI", 1 if final else 0, len(ct))); self.fh.write(ct)
        self.ctr += 1

    def close(self):
        self._emit(bytes(self.buf), True)
        self.buf = bytearray()


def _dec_stream(fh, password):
    """암호화 파일에서 복호화된 평문 바이트를 청크 단위로 내보내는 제너레이터."""
    npfx, aes = _parse_header(fh.read, password)
    ctr = 0
    while True:
        head = fh.read(5)
        if len(head) < 5:
            break
        final = head[0]
        (clen,) = struct.unpack(">I", head[1:5])
        ct = fh.read(clen)
        try:
            yield aes.decrypt(npfx + struct.pack(">I", ctr),
                              ct, struct.pack(">I?", ctr, bool(final)))
        except Exception:
            raise ValueError("복호화 실패: 비밀번호가 틀렸거나 파일이 변조되었습니다.")
        ctr += 1
        if final:
            break


class _BufReader:
    """바이트 제너레이터에서 정확히 n바이트를 읽어주는 버퍼."""
    def __init__(self, gen):
        self.gen = gen; self.buf = bytearray(); self.done = False

    def read(self, n):
        while len(self.buf) < n and not self.done:
            try:
                self.buf += next(self.gen)
            except StopIteration:
                self.done = True
        if len(self.buf) < n:
            raise ValueError("아카이브가 손상되었습니다(데이터 부족).")
        out = bytes(self.buf[:n]); del self.buf[:n]; return out


def pack_stream(out_path, files, password="", mode="max"):
    """files: [(이름, 전체경로), ...]. 파일을 하나씩 읽어 압축→(암호화)→디스크로 스트리밍.
    리포트 [(이름, 방식, 원본크기, 압축크기), ...] 반환. RAM ≈ 가장 큰 파일 1개."""
    report = []
    with open(out_path, "wb") as f:
        sink = _EncWriter(f, password) if password else f
        sink.write(autopack.ARCHIVE_MAGIC + struct.pack(">I", len(files)))
        for name, full in files:
            with open(full, "rb") as fh:
                data = fh.read()
            blob, mid = autopack.compress(data, mode)
            nb = name.encode("utf-8")
            sink.write(struct.pack(">H", len(nb)) + nb + struct.pack(">Q", len(blob)) + blob)
            report.append((name, autopack.NAMES[mid], len(data), len(blob)))
        if password:
            sink.close()
    return report


def unpack_stream(in_path, out_dir, password=""):
    """암호화/비암호화 아카이브를 스트리밍 복호화·복원. RAM ≈ 가장 큰 파일 1개."""
    with open(in_path, "rb") as f:
        if is_encrypted(f.read(4)):
            f.seek(0)
            reader = _BufReader(_dec_stream(f, password))
        else:
            f.seek(0)
            reader = _BufReader(iter(lambda: f.read(CHUNK), b""))
        if reader.read(4) != autopack.ARCHIVE_MAGIC:
            raise ValueError("올바른 아카이브가 아닙니다.")
        (count,) = struct.unpack(">I", reader.read(4))
        names = []
        for _ in range(count):
            (nl,) = struct.unpack(">H", reader.read(2))
            name = reader.read(nl).decode("utf-8")
            (bl,) = struct.unpack(">Q", reader.read(8))
            data = autopack.decompress(reader.read(bl))
            dest = os.path.join(out_dir, name)
            os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
            with open(dest, "wb") as out:
                out.write(data)
            names.append(name)
    return names


def encrypt_bytes(data: bytes, password: str) -> bytes:
    """이미 압축된 바이트를 청크 AES-256-GCM으로 암호화 (Argon2id 헤더)."""
    hdr, npfx, aes = _write_header(password)
    out = bytearray(hdr)
    ctr = 0; pos = 0; n = len(data)
    while True:
        chunk = data[pos:pos + CHUNK]; pos += len(chunk)
        final = pos >= n
        nonce = npfx + struct.pack(">I", ctr)
        aad = struct.pack(">I?", ctr, final)
        ct = aes.encrypt(nonce, chunk, aad)
        out += struct.pack(">BI", 1 if final else 0, len(ct)); out += ct
        ctr += 1
        if final:
            break
    return bytes(out)


def decrypt_bytes(blob: bytes, password: str) -> bytes:
    cur = [0]
    def rd(n):
        s = blob[cur[0]:cur[0] + n]; cur[0] += n; return s
    npfx, aes = _parse_header(rd, password)
    ctr = 0; out = bytearray()
    while cur[0] < len(blob):
        pos = cur[0]
        final = blob[pos]
        (ln,) = struct.unpack(">I", blob[pos + 1:pos + 5]); cur[0] += 5
        ct = blob[cur[0]:cur[0] + ln]; cur[0] += ln
        nonce = npfx + struct.pack(">I", ctr)
        aad = struct.pack(">I?", ctr, bool(final))
        try:
            out += aes.decrypt(nonce, ct, aad)
        except Exception:
            raise ValueError("복호화 실패: 비밀번호가 틀렸거나 파일이 변조되었습니다.")
        ctr += 1
        if final:
            break
    return bytes(out)


def pack(folder: str, out_path: str, password: str = "", mode: str = "max"):
    """폴더 → 파일별 최적 압축 → (비밀번호 있으면) 암호화 → 한 파일.
    mode: 'fast' | 'balanced' | 'max'"""
    spk, report = autopack.pack_folder(folder, mode)
    blob = encrypt_bytes(spk, password) if password else spk
    with open(out_path, "wb") as f:
        f.write(blob)
    return report, len(spk), len(blob)


def unpack(in_path: str, out_dir: str, password: str = ""):
    """입력 파일을 (암호화면 복호화 후) 풀어 복원."""
    blob = open(in_path, "rb").read()
    if is_encrypted(blob[:4]):
        if not password:
            raise ValueError("암호화된 파일입니다. 비밀번호가 필요합니다.")
        blob = decrypt_bytes(blob, password)
    return autopack.unpack_archive(blob, out_dir)


def main():
    if len(sys.argv) != 4 or sys.argv[1] not in ("pack", "unpack"):
        print(__doc__); sys.exit(1)
    mode, src, dst = sys.argv[1], sys.argv[2], sys.argv[3]

    if mode == "pack":
        if not os.path.isdir(src):
            print(f"폴더가 아닙니다: {src}"); sys.exit(1)
        pw = getpass.getpass("비밀번호 (암호화 안 하려면 빈칸 엔터): ")
        if pw and pw != getpass.getpass("비밀번호 확인: "):
            print("비밀번호가 일치하지 않습니다."); sys.exit(1)
        report, spk_sz, out_sz = pack(src, dst, pw)
        print(f"\n{'파일':<36}{'방식':>8}{'압축률':>9}")
        for rel, name, osz, csz in sorted(report):
            r = csz / osz * 100 if osz else 0
            print(f"{rel[:36]:<36}{name:>8}{r:>8.1f}%")
        tot = sum(r[2] for r in report)
        enc = " + 암호화" if pw else ""
        print(f"\n총 {len(report)}개 파일  {tot:,} → {out_sz:,} bytes "
              f"({out_sz/tot*100:.1f}%){enc}  → {dst}")
    else:
        pw = ""
        if is_encrypted(open(src, "rb").read(4)):
            pw = getpass.getpass("비밀번호: ")
        names = unpack(src, dst, pw)
        print(f"{len(names)}개 파일 복원 완료 → {dst}")


if __name__ == "__main__":
    main()
