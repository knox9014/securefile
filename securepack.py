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

ENC_MAGIC = b"SPKE"        # 암호화된 컨테이너
ITER = 200_000
SALT = 16
NPFX = 8
CHUNK = 1 << 20            # 1MB 청크


def _derive(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER)
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(data: bytes, password: str) -> bytes:
    """이미 압축된 바이트를 청크 AES-256-GCM으로 암호화."""
    salt = os.urandom(SALT)
    npfx = os.urandom(NPFX)
    aes = AESGCM(_derive(password, salt))
    out = bytearray(ENC_MAGIC); out += salt; out += npfx
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
    if blob[:4] != ENC_MAGIC:
        raise ValueError("올바른 암호화 컨테이너가 아닙니다.")
    salt = blob[4:4 + SALT]
    npfx = blob[4 + SALT:4 + SALT + NPFX]
    aes = AESGCM(_derive(password, salt))
    pos = 4 + SALT + NPFX; ctr = 0; out = bytearray()
    while True:
        final = blob[pos]
        (ln,) = struct.unpack(">I", blob[pos + 1:pos + 5]); pos += 5
        ct = blob[pos:pos + ln]; pos += ln
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
    if blob[:4] == ENC_MAGIC:
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
        if open(src, "rb").read(4) == ENC_MAGIC:
            pw = getpass.getpass("비밀번호: ")
        names = unpack(src, dst, pw)
        print(f"{len(names)}개 파일 복원 완료 → {dst}")


if __name__ == "__main__":
    main()
