"""
mycompress.py - 직접 만든 압축기 (연구/학습용)

구조 (앞에서 배운 원리 그대로):
  ① LZ77      : 반복되는 부분을 (길이, 거리)로 치환
  ② 산술 부호화 : 남은 토큰들을 빈도에 따라 '소수 비트'까지 짜내어 인코딩

zstd/LZMA를 이기려는 게 아니라, 원리를 100% 이해하는 우리만의 압축기를 만들고
gzip과 견줘보기 위한 것. 모든 단계는 왕복 테스트로 검증됨.
"""

# ---- 32비트 산술 부호화 상수 ----
PREC = 32
WHOLE = 1 << PREC
HALF = WHOLE >> 1
QUARTER = WHOLE >> 2
THREE_Q = 3 * QUARTER
MASK = WHOLE - 1
MAX_TOTAL = 1 << 16

# ---- LZ77 파라미터 ----
WINDOW = 1 << 20          # 최대 거리 1MB (거리=3바이트로 표현) -> 장거리 반복 포착
MIN_MATCH = 3
MAX_MATCH = 258           # 길이 3..258 -> 0..255 (1바이트)
CHAIN_CAP = 128           # 해시 체인 길이 제한(속도 vs 매칭품질)


# range coder 상수 (바이트 단위 처리 → 비트 단위보다 빠름)
TOP = 1 << 24
BOT = 1 << 16


# ===== 적응형 빈도 모델 =====
class FreqModel:
    def __init__(self, nsym):
        self.nsym = nsym
        self.freq = [1] * nsym
        self.total = nsym
    def cum(self, sym):
        lo = sum(self.freq[:sym])
        return lo, lo + self.freq[sym]
    def find(self, value):
        lo = 0
        for sym in range(self.nsym):
            f = self.freq[sym]
            if lo + f > value:
                return sym, lo, lo + f
            lo += f
        raise ValueError("심볼 탐색 실패")
    def update(self, sym):
        self.freq[sym] += 32; self.total += 32
        if self.total >= MAX_TOTAL:
            self.total = 0
            for i in range(self.nsym):
                self.freq[i] = (self.freq[i] + 1) >> 1
                self.total += self.freq[i]


# ===== range coder (바이트 단위, carryless) =====
class ArithmeticEncoder:
    def __init__(self):
        self.low = 0; self.rng = MASK; self.out = bytearray()
    def encode(self, model, sym):
        c_lo, c_hi = model.cum(sym); total = model.total
        r = self.rng // total
        self.low = (self.low + c_lo * r) & MASK
        self.rng = r * (c_hi - c_lo)
        while True:
            if (self.low ^ ((self.low + self.rng) & MASK)) < TOP:
                pass
            elif self.rng < BOT:
                self.rng = (-self.low) & (BOT - 1)
            else:
                break
            self.out.append((self.low >> 24) & 0xFF)
            self.low = (self.low << 8) & MASK
            self.rng = (self.rng << 8) & MASK
        model.update(sym)
    def finish(self):
        for _ in range(4):
            self.out.append((self.low >> 24) & 0xFF)
            self.low = (self.low << 8) & MASK
        return bytes(self.out)


class ArithmeticDecoder:
    def __init__(self, blob):
        self.data = blob; self.pos = 0
        self.low = 0; self.rng = MASK; self.code = 0
        for _ in range(4):
            self.code = ((self.code << 8) | self._byte()) & MASK
    def _byte(self):
        b = self.data[self.pos] if self.pos < len(self.data) else 0
        self.pos += 1
        return b
    def decode(self, model):
        total = model.total
        r = self.rng // total
        value = ((self.code - self.low) & MASK) // r
        if value >= total:
            value = total - 1
        sym, c_lo, c_hi = model.find(value)
        self.low = (self.low + c_lo * r) & MASK
        self.rng = r * (c_hi - c_lo)
        while True:
            if (self.low ^ ((self.low + self.rng) & MASK)) < TOP:
                pass
            elif self.rng < BOT:
                self.rng = (-self.low) & (BOT - 1)
            else:
                break
            self.code = ((self.code << 8) | self._byte()) & MASK
            self.low = (self.low << 8) & MASK
            self.rng = (self.rng << 8) & MASK
        model.update(sym)
        return sym


# ===== LZ77 파싱 (lazy matching) =====
def lz77_parse(data: bytes):
    n = len(data); tokens = []
    head = {}   # 3바이트 키 -> 최근 위치 리스트

    def insert(pos):
        if pos + 3 <= n:
            k = data[pos:pos+3]
            lst = head.get(k)
            if lst is None:
                head[k] = [pos]
            else:
                lst.insert(0, pos)
                if len(lst) > CHAIN_CAP: lst.pop()

    def find(pos):
        best_len = 0; best_dist = 0
        if pos + MIN_MATCH <= n:
            chain = head.get(data[pos:pos+3])
            if chain:
                maxl = min(MAX_MATCH, n - pos)
                for j in chain:
                    if pos - j > WINDOW: break
                    l = 0
                    while l < maxl and data[j+l] == data[pos+l]:
                        l += 1
                    if l > best_len:
                        best_len = l; best_dist = pos - j
                        if l >= maxl: break
        return best_len, best_dist

    i = 0
    have_prev = False; prev_len = 0; prev_dist = 0; prev_pos = 0
    while i < n:
        cur_len, cur_dist = find(i)
        insert(i)   # 자기 자신과 매칭되지 않도록 탐색 후 삽입
        if have_prev:
            if cur_len > prev_len:
                # i+1이 더 길다 -> 이전 매치 시작 바이트를 리터럴로 흘리고 현재를 보류
                tokens.append((0, data[prev_pos]))
                prev_len, prev_dist, prev_pos = cur_len, cur_dist, i
                i += 1
            else:
                # 이전 매치가 충분히 좋다 -> 확정
                tokens.append((1, prev_len, prev_dist))
                end = prev_pos + prev_len
                p = i + 1
                while p < end:
                    insert(p); p += 1
                i = end
                have_prev = False
        else:
            if cur_len >= MIN_MATCH:
                have_prev = True; prev_len, prev_dist, prev_pos = cur_len, cur_dist, i
                i += 1
            else:
                tokens.append((0, data[i])); i += 1
    if have_prev:   # 마지막에 보류된 매치 처리
        tokens.append((1, prev_len, prev_dist))
    return tokens


# ===== 한 블록 압축 (LZ77 + 산술부호화) =====
def _compress_block(data: bytes) -> bytes:
    flag = FreqModel(3)      # 0=리터럴, 1=매치, 2=끝
    # order-1 문맥 모델: 직전 출력 바이트(문맥)별로 리터럴 확률표를 따로 둠
    lit_ctx = [FreqModel(256) for _ in range(256)]
    length = FreqModel(256)  # (길이-3)
    dist_hi = FreqModel(256)
    dist_mid = FreqModel(256)
    dist_lo = FreqModel(256)
    enc = ArithmeticEncoder()
    prev_byte = 0; out_pos = 0
    for tok in lz77_parse(data):
        if tok[0] == 0:
            b = tok[1]
            enc.encode(flag, 0); enc.encode(lit_ctx[prev_byte], b)
            out_pos += 1; prev_byte = b
        else:
            _, l, d = tok
            enc.encode(flag, 1)
            enc.encode(length, l - MIN_MATCH)
            dd = d - 1                       # 거리 = 3바이트(24비트)
            enc.encode(dist_hi, (dd >> 16) & 0xFF)
            enc.encode(dist_mid, (dd >> 8) & 0xFF)
            enc.encode(dist_lo, dd & 0xFF)
            out_pos += l; prev_byte = data[out_pos - 1]   # 매치의 마지막 바이트가 다음 문맥
    enc.encode(flag, 2)      # 끝 표시
    return enc.finish()


def _decompress_block(blob: bytes) -> bytes:
    flag = FreqModel(3)
    lit_ctx = [FreqModel(256) for _ in range(256)]
    length = FreqModel(256)
    dist_hi = FreqModel(256); dist_mid = FreqModel(256); dist_lo = FreqModel(256)
    dec = ArithmeticDecoder(blob)
    out = bytearray()
    prev_byte = 0
    while True:
        f = dec.decode(flag)
        if f == 2: break
        if f == 0:
            b = dec.decode(lit_ctx[prev_byte])
            out.append(b); prev_byte = b
        else:
            l = dec.decode(length) + MIN_MATCH
            dd = (dec.decode(dist_hi) << 16) | (dec.decode(dist_mid) << 8) | dec.decode(dist_lo)
            start = len(out) - (dd + 1)
            for k in range(l):           # 겹치는 복사도 바이트 단위로 안전
                out.append(out[start + k])
            prev_byte = out[-1]
    return bytes(out)


# ===== 공개 API: 블록 단위로 '압축 vs 원본' 중 작은 쪽 선택 =====
#   무작위/이미 압축된 블록은 그냥 원본으로 저장(store) -> 데이터가 커지는 것을 방지
BLOCK = 1 << 20          # 1MB 블록 (장거리 반복 포착 + store 단위)
MODE_STORE = 0
MODE_COMPRESSED = 1


def compress(data: bytes) -> bytes:
    out = bytearray()
    for off in range(0, len(data), BLOCK):
        block = data[off:off + BLOCK]
        comp = _compress_block(block)
        if len(comp) < len(block):       # 압축이 이득일 때만 압축 저장
            out.append(MODE_COMPRESSED)
            out += len(comp).to_bytes(4, "big")
            out += comp
        else:                             # 손해면 원본 그대로(store)
            out.append(MODE_STORE)
            out += len(block).to_bytes(4, "big")
            out += block
    return bytes(out)


def decompress(blob: bytes) -> bytes:
    out = bytearray()
    i = 0
    n = len(blob)
    while i < n:
        mode = blob[i]; i += 1
        ln = int.from_bytes(blob[i:i + 4], "big"); i += 4
        payload = blob[i:i + ln]; i += ln
        if mode == MODE_COMPRESSED:
            out += _decompress_block(payload)
        else:
            out += payload
    return bytes(out)


if __name__ == "__main__":
    samples = [
        b"", b"A",
        b"hello hello hello world world world hello world",
        bytes(range(256)) * 4,
        ("압축 테스트 반복 데이터 " * 80).encode("utf-8"),
    ]
    for s in samples:
        c = compress(s); d = decompress(c)
        ok = (d == s)
        ratio = (len(c) / len(s) * 100) if s else 0
        print(f"len={len(s):6d} -> comp={len(c):6d} ({ratio:5.1f}%)  {'OK' if ok else 'FAIL'}")
        assert ok, "roundtrip 실패!"
    print("all roundtrip OK")
