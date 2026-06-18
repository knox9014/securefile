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


# ===== 비트 입출력 =====
class BitWriter:
    def __init__(self):
        self.out = bytearray(); self.acc = 0; self.nbits = 0
    def write_bit(self, bit):
        self.acc = (self.acc << 1) | (bit & 1); self.nbits += 1
        if self.nbits == 8:
            self.out.append(self.acc); self.acc = 0; self.nbits = 0
    def finish(self):
        if self.nbits:
            self.acc <<= (8 - self.nbits); self.out.append(self.acc)
        return bytes(self.out)


class BitReader:
    def __init__(self, data):
        self.data = data; self.pos = 0; self.acc = 0; self.nbits = 0
    def read_bit(self):
        if self.nbits == 0:
            self.acc = self.data[self.pos] if self.pos < len(self.data) else 0
            self.pos += 1; self.nbits = 8
        self.nbits -= 1
        return (self.acc >> self.nbits) & 1


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


# ===== 산술 부호화기 =====
class ArithmeticEncoder:
    def __init__(self):
        self.low = 0; self.high = MASK; self.pending = 0; self.bw = BitWriter()
    def _emit(self, bit):
        self.bw.write_bit(bit)
        while self.pending > 0:
            self.bw.write_bit(bit ^ 1); self.pending -= 1
    def encode(self, model, sym):
        c_lo, c_hi = model.cum(sym); total = model.total
        rng = self.high - self.low + 1
        self.high = self.low + (rng * c_hi) // total - 1
        self.low = self.low + (rng * c_lo) // total
        while True:
            if self.high < HALF: self._emit(0)
            elif self.low >= HALF: self._emit(1); self.low -= HALF; self.high -= HALF
            elif self.low >= QUARTER and self.high < THREE_Q:
                self.pending += 1; self.low -= QUARTER; self.high -= QUARTER
            else: break
            self.low = (self.low << 1) & MASK
            self.high = ((self.high << 1) | 1) & MASK
        model.update(sym)
    def finish(self):
        self.pending += 1
        self._emit(0 if self.low < QUARTER else 1)
        return self.bw.finish()


class ArithmeticDecoder:
    def __init__(self, blob):
        self.low = 0; self.high = MASK; self.br = BitReader(blob); self.code = 0
        for _ in range(PREC):
            self.code = (self.code << 1) | self.br.read_bit()
    def decode(self, model):
        rng = self.high - self.low + 1; total = model.total
        value = ((self.code - self.low + 1) * total - 1) // rng
        sym, c_lo, c_hi = model.find(value)
        self.high = self.low + (rng * c_hi) // total - 1
        self.low = self.low + (rng * c_lo) // total
        while True:
            if self.high < HALF: pass
            elif self.low >= HALF:
                self.low -= HALF; self.high -= HALF; self.code -= HALF
            elif self.low >= QUARTER and self.high < THREE_Q:
                self.low -= QUARTER; self.high -= QUARTER; self.code -= QUARTER
            else: break
            self.low = (self.low << 1) & MASK
            self.high = ((self.high << 1) | 1) & MASK
            self.code = ((self.code << 1) | self.br.read_bit()) & MASK
        model.update(sym)
        return sym


# ===== LZ77 파싱 =====
def lz77_parse(data: bytes):
    n = len(data); i = 0; tokens = []
    head = {}   # 3바이트 키 -> 최근 위치 리스트
    while i < n:
        best_len = 0; best_dist = 0
        if i + MIN_MATCH <= n:
            key = data[i:i+3]
            chain = head.get(key)
            if chain:
                maxl = min(MAX_MATCH, n - i)
                for j in chain:
                    if i - j > WINDOW: break
                    l = 0
                    while l < maxl and data[j+l] == data[i+l]:
                        l += 1
                    if l > best_len:
                        best_len = l; best_dist = i - j
                        if l >= maxl: break
        if best_len >= MIN_MATCH:
            tokens.append((1, best_len, best_dist)); advance = best_len
        else:
            tokens.append((0, data[i])); advance = 1
        end = i + advance
        while i < end:
            if i + 3 <= n:
                k = data[i:i+3]
                lst = head.get(k)
                if lst is None:
                    head[k] = [i]
                else:
                    lst.insert(0, i)
                    if len(lst) > CHAIN_CAP: lst.pop()
            i += 1
    return tokens


# ===== 한 블록 압축 (LZ77 + 산술부호화) =====
def _compress_block(data: bytes) -> bytes:
    flag = FreqModel(3)      # 0=리터럴, 1=매치, 2=끝
    lit = FreqModel(256)
    length = FreqModel(256)  # (길이-3)
    dist_hi = FreqModel(256)
    dist_mid = FreqModel(256)
    dist_lo = FreqModel(256)
    enc = ArithmeticEncoder()
    for tok in lz77_parse(data):
        if tok[0] == 0:
            enc.encode(flag, 0); enc.encode(lit, tok[1])
        else:
            _, l, d = tok
            enc.encode(flag, 1)
            enc.encode(length, l - MIN_MATCH)
            dd = d - 1                       # 거리 = 3바이트(24비트)
            enc.encode(dist_hi, (dd >> 16) & 0xFF)
            enc.encode(dist_mid, (dd >> 8) & 0xFF)
            enc.encode(dist_lo, dd & 0xFF)
    enc.encode(flag, 2)      # 끝 표시
    return enc.finish()


def _decompress_block(blob: bytes) -> bytes:
    flag = FreqModel(3); lit = FreqModel(256); length = FreqModel(256)
    dist_hi = FreqModel(256); dist_mid = FreqModel(256); dist_lo = FreqModel(256)
    dec = ArithmeticDecoder(blob)
    out = bytearray()
    while True:
        f = dec.decode(flag)
        if f == 2: break
        if f == 0:
            out.append(dec.decode(lit))
        else:
            l = dec.decode(length) + MIN_MATCH
            dd = (dec.decode(dist_hi) << 16) | (dec.decode(dist_mid) << 8) | dec.decode(dist_lo)
            start = len(out) - (dd + 1)
            for k in range(l):           # 겹치는 복사도 바이트 단위로 안전
                out.append(out[start + k])
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
