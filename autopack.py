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

포맷: [MAGIC "APK1"][method 1B][payload...]
사용법:
  python autopack.py c <입력> <출력>
  python autopack.py d <입력> <출력>
"""

import sys
import os
import math
import zlib
import bz2
import lzma

import mycompress

MAGIC = b"APK1"
STORE, ZLIB, BZ2, LZMA, OURS = 0, 1, 2, 3, 4
NAMES = {STORE: "store", ZLIB: "zlib", BZ2: "bz2", LZMA: "lzma", OURS: "ours"}

ENTROPY_SKIP = 7.92        # 이 이상이면 사실상 압축 불가 → 바로 저장
OURS_MAX = 4 << 20         # 우리 압축기는 느리므로 이 크기까지만 후보에 포함
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
    if method == OURS:
        return mycompress.compress(data)
    raise ValueError("unknown method")


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


def compress(data: bytes):
    """가장 작게 나오는 방식을 골라 압축. (결과, 선택된 방식id) 반환."""
    # 1) 사전 판단: 샘플 엔트로피가 너무 높으면 압축 시도 자체를 생략
    if len(data) >= 512 and _entropy(data[:SAMPLE]) >= ENTROPY_SKIP:
        return MAGIC + bytes([STORE]) + data, STORE

    lib = [ZLIB, BZ2, LZMA]
    if len(data) <= TRYALL_MAX:
        # 작은 파일: 전체를 모든 방식으로 시험(우리 압축기도 포함) → 진짜 최소 선택
        methods = lib + ([OURS] if len(data) <= OURS_MAX else [])
        best_id, best = _best_among(methods, data)
    else:
        # 큰 파일: 샘플로 방식만 결정 → 전체는 승자 방식으로 1회만 압축(속도↑)
        win_id, _ = _best_among(lib, data[:SAMPLE])
        best = _compress_with(win_id, data)
        best_id = win_id
        if len(best) >= len(data):     # 그래도 손해면 저장
            best_id, best = STORE, data

    return MAGIC + bytes([best_id]) + best, best_id


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
    if method == OURS:
        return mycompress.decompress(payload)
    raise ValueError(f"알 수 없는 방식 id: {method}")


def main():
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
