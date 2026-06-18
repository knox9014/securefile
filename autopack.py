"""
autopack.py - 파일별 최적 압축 방식 자동 선택기

아이디어: 데이터마다 1등 압축 방식이 다르다(텍스트=bz2, 일반=lzma, 이미 압축됨=저장).
그래서 파일을 보고 가장 작게 나오는 방식을 자동으로 골라 쓴다.

후보 방식:
  0 STORE  - 원본 그대로 (이미 압축됨/무작위 → 압축 시도조차 생략, 속도↑)
  1 ZLIB   - 빠르고 무난
  2 BZ2    - BWT, 텍스트에 강함
  3 LZMA   - 일반적으로 압축률 최고
  4 OURS   - 우리가 직접 만든 압축기 (LZ77+산술부호화+order-1)

포맷(단일): [MAGIC "APK1"][method 1B][payload...]
아카이브(.spk): 폴더 안 파일마다 '개별 최적 방식'으로 압축해 하나로 묶음
  → 섞인 폴더에서 '다 묶어 단일 방식'보다 효율적

사용법:
  python autopack.py c <입력파일> <출력>        # 단일 파일 압축
  python autopack.py d <입력> <출력파일>        # 단일 파일 해제
  python autopack.py pack <폴더> <출력.spk>     # 폴더 → 파일별 최적 압축 아카이브
  python autopack.py unpack <입력.spk> <폴더>   # 아카이브 복원
"""

import sys
import os
import math
import struct
import zlib
import bz2
import lzma

import mycompress

try:
    import zstandard            # 속도+압축률 스위트 스폿, 멀티스레드 내장
except ImportError:
    zstandard = None
try:
    import brotli               # 텍스트/웹 데이터에 강함
except ImportError:
    brotli = None

MAGIC = b"APK1"
STORE, ZLIB, BZ2, LZMA, OURS, ZSTD, BROTLI = 0, 1, 2, 3, 4, 5, 6
NAMES = {STORE: "store", ZLIB: "zlib", BZ2: "bz2", LZMA: "lzma",
         OURS: "ours", ZSTD: "zstd", BROTLI: "brotli"}
THREADS = os.cpu_count() or 1

ENTROPY_SKIP = 7.92        # 이 이상이면 사실상 압축 불가 → 바로 저장
OURS_MAX = 64 << 10        # 우리 압축기는 느리므로 아주 작은 파일에만 후보로(효율 우선)
SAMPLE = 1 << 16           # 엔트로피 추정용 샘플 크기


def _entropy(data: bytes) -> float:
    """바이트 샘플의 섀넌 엔트로피(비트/바이트). 8.0에 가까울수록 무작위."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def _compress_with(method: int, data: bytes) -> bytes:
    if method == ZLIB:
        return zlib.compress(data, 9)
    if method == BZ2:
        return bz2.compress(data, 9)
    if method == LZMA:
        return lzma.compress(data, preset=9)
    if method == ZSTD:
        # 멀티스레드(전 코어) + 높은 레벨 → lzma급 압축률을 훨씬 빠르게
        return zstandard.ZstdCompressor(level=19, threads=THREADS).compress(data)
    if method == BROTLI:
        q = 11 if len(data) <= (4 << 20) else 9   # 큰 파일은 품질 낮춰 속도 확보
        return brotli.compress(data, quality=q)
    if method == OURS:
        return mycompress.compress(data)
    raise ValueError("unknown method")


def _available_libs():
    libs = [ZLIB, BZ2, LZMA]
    if zstandard is not None:
        libs.append(ZSTD)
    if brotli is not None:
        libs.append(BROTLI)
    return libs


TRYALL_MAX = 2 << 20       # 이 크기 이하: 전체를 모든 방식으로 시험(가장 정확)


def _best_among(methods, data: bytes):
    best_id, best = STORE, data
    for m in methods:
        try:
            payload = _compress_with(m, data)
        except Exception:
            continue
        if len(payload) < len(best):
            best_id, best = m, payload
    return best_id, best


def _finalize(method: int, payload: bytes, data: bytes):
    if len(payload) >= len(data):       # 압축이 손해면 원본 저장
        return MAGIC + bytes([STORE]) + data, STORE
    return MAGIC + bytes([method]) + payload, method


def compress(data: bytes, mode: str = "max"):
    """모드별로 압축. (결과, 선택된 방식id) 반환.
    mode: 'fast'(zstd 빠름) | 'balanced'(zstd 고압축) | 'max'(전체 시험, 최소 선택)"""
    # 1) 사전 판단: 샘플 엔트로피가 너무 높으면 압축 시도 자체를 생략
    if len(data) >= 512 and _entropy(data[:SAMPLE]) >= ENTROPY_SKIP:
        return MAGIC + bytes([STORE]) + data, STORE

    # 2) 빠르게/균형: 단일 zstd (압축률 소폭 양보, 수백 배 빠름)
    if mode in ("fast", "balanced") and zstandard is not None:
        level = 6 if mode == "fast" else 19
        payload = zstandard.ZstdCompressor(level=level, threads=THREADS).compress(data)
        return _finalize(ZSTD, payload, data)

    # 3) 최대압축: 후보 전체를 시험해 최소 선택
    lib = _available_libs()
    if len(data) <= TRYALL_MAX:
        methods = lib + ([OURS] if len(data) <= OURS_MAX else [])
        best_id, best = _best_among(methods, data)
    else:
        win_id, _ = _best_among(lib, data[:SAMPLE])   # 큰 파일은 샘플로 결정
        best = _compress_with(win_id, data)
        best_id = win_id
    return _finalize(best_id, best, data)


def decompress(blob: bytes) -> bytes:
    if blob[:4] != MAGIC:
        raise ValueError("올바른 .apk 파일이 아닙니다.")
    method = blob[4]
    payload = blob[5:]
    if method == STORE:
        return payload
    if method == ZLIB:
        return zlib.decompress(payload)
    if method == BZ2:
        return bz2.decompress(payload)
    if method == LZMA:
        return lzma.decompress(payload)
    if method == ZSTD:
        return zstandard.ZstdDecompressor().decompress(payload)
    if method == BROTLI:
        return brotli.decompress(payload)
    if method == OURS:
        return mycompress.decompress(payload)
    raise ValueError(f"알 수 없는 방식 id: {method}")


# ===== 아카이브: 파일마다 개별 최적 방식으로 압축해 하나로 묶기 =====
#   [MAGIC "SPK1"][count 4B] + 각 항목: [name_len 2B][name][blob_len 8B][apk_blob]
ARCHIVE_MAGIC = b"SPK1"


def pack_folder(root: str, mode: str = "max"):
    """폴더 안 모든 파일을 '각자 최적 방식'으로 압축해 아카이브 바이트로 묶는다.
    (아카이브 바이트, [(상대경로, 방식, 원본크기, 압축크기), ...]) 반환."""
    root = root.rstrip("/\\")
    entries = []
    report = []
    for dirpath, _, files in os.walk(root):
        for fn in sorted(files):
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace("\\", "/")
            data = open(full, "rb").read()
            blob, mid = compress(data, mode)         # 파일마다 개별 최적 선택
            entries.append((rel, blob))
            report.append((rel, NAMES[mid], len(data), len(blob)))

    out = bytearray(ARCHIVE_MAGIC)
    out += struct.pack(">I", len(entries))
    for rel, blob in entries:
        nb = rel.encode("utf-8")
        out += struct.pack(">H", len(nb)) + nb
        out += struct.pack(">Q", len(blob)) + blob
    return bytes(out), report


def unpack_archive(blob: bytes, outdir: str):
    """아카이브를 풀어 outdir 아래에 원래 구조로 복원."""
    if blob[:4] != ARCHIVE_MAGIC:
        raise ValueError("올바른 .spk 아카이브가 아닙니다.")
    pos = 4
    (count,) = struct.unpack(">I", blob[pos:pos+4]); pos += 4
    names = []
    for _ in range(count):
        (nl,) = struct.unpack(">H", blob[pos:pos+2]); pos += 2
        name = blob[pos:pos+nl].decode("utf-8"); pos += nl
        (bl,) = struct.unpack(">Q", blob[pos:pos+8]); pos += 8
        entry = blob[pos:pos+bl]; pos += bl
        data = decompress(entry)
        dest = os.path.join(outdir, name)
        os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
        with open(dest, "wb") as f:
            f.write(data)
        names.append(name)
    return names


def main():
    if len(sys.argv) >= 2 and sys.argv[1] in ("pack", "unpack"):
        if len(sys.argv) != 4:
            print("python autopack.py pack <폴더> <출력.spk>")
            print("python autopack.py unpack <입력.spk> <출력폴더>")
            sys.exit(1)
        if sys.argv[1] == "pack":
            blob, report = pack_folder(sys.argv[2])
            open(sys.argv[3], "wb").write(blob)
            print(f"{'파일':<40}{'방식':>8}{'압축률':>9}")
            for rel, name, osz, csz in report:
                r = csz / osz * 100 if osz else 0
                print(f"{rel[:40]:<40}{name:>8}{r:>8.1f}%")
            tot_o = sum(r[2] for r in report); tot_c = len(blob)
            print(f"\n총 {len(report)}개 파일  {tot_o:,} → {tot_c:,} bytes "
                  f"({tot_c/tot_o*100:.1f}%)  → {sys.argv[3]}")
        else:
            names = unpack_archive(open(sys.argv[2], "rb").read(), sys.argv[3])
            print(f"{len(names)}개 파일 복원 완료 → {sys.argv[3]}")
        return

    if len(sys.argv) != 4 or sys.argv[1] not in ("c", "d"):
        print(__doc__)
        sys.exit(1)
    mode, src, dst = sys.argv[1], sys.argv[2], sys.argv[3]
    data = open(src, "rb").read()
    if mode == "c":
        out, mid = compress(data)
        open(dst, "wb").write(out)
        ratio = len(out) / len(data) * 100 if data else 0
        print(f"선택 방식: {NAMES[mid]}  |  {len(data):,} → {len(out):,} bytes ({ratio:.1f}%)")
    else:
        open(dst, "wb").write(decompress(data))
        print(f"복원 완료 → {dst}")


if __name__ == "__main__":
    main()
