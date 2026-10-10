#!/usr/bin/env python3
"""
a9_aes.py - minimal pure-Python AES-CBC (128/192/256), stdlib-only.

Fallback so the A9 tools run with NO external dependencies (e.g. on a laptop
joined to the camera's AP with no internet to `pip install pycryptodome`).
MD5 stays in hashlib (stdlib). Not constant-time; fine for local interop.

API mirrors what the tools need:
    AESCBC(key, iv).encrypt(data)   # data must be a multiple of 16
    AESCBC(key, iv).decrypt(data)
"""
# --- AES core (FIPS-197) ---
_sbox = []
_inv_sbox = [0]*256
def _init_sbox():
    p = q = 1
    sbox = [0]*256
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xFF
        if q & 0x80: q ^= 0x09
        xformed = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) \
                  ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
        sbox[p] = (xformed ^ 0x63) & 0xFF
        if p == 1: break
    sbox[0] = 0x63
    return sbox
_sbox = _init_sbox()
for i, v in enumerate(_sbox):
    _inv_sbox[v] = i
_rcon = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36,0x6C,0xD8,0xAB,0x4D]

def _xtime(a): return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1)
def _mul(a, b):
    r = 0
    for _ in range(8):
        if b & 1: r ^= a
        hi = a & 0x80; a = (a << 1) & 0xFF
        if hi: a ^= 0x1B
        b >>= 1
    return r

def _key_expansion(key):
    Nk = len(key) // 4
    Nr = {4:10, 6:12, 8:14}[Nk]
    w = [list(key[4*i:4*i+4]) for i in range(Nk)]
    for i in range(Nk, 4*(Nr+1)):
        t = list(w[i-1])
        if i % Nk == 0:
            t = t[1:] + t[:1]
            t = [_sbox[b] for b in t]
            t[0] ^= _rcon[i//Nk - 1]
        elif Nk > 6 and i % Nk == 4:
            t = [_sbox[b] for b in t]
        w.append([w[i-Nk][j] ^ t[j] for j in range(4)])
    return w, Nr

def _add_round_key(s, w, rnd):
    for c in range(4):
        for r in range(4):
            s[r][c] ^= w[rnd*4 + c][r]

def _bytes_to_state(b):
    return [[b[r + 4*c] for c in range(4)] for r in range(4)]
def _state_to_bytes(s):
    return bytes(s[r][c] for c in range(4) for r in range(4))

def _encrypt_block(block, w, Nr):
    s = _bytes_to_state(block)
    _add_round_key(s, w, 0)
    for rnd in range(1, Nr):
        s = [[_sbox[s[r][c]] for c in range(4)] for r in range(4)]
        s = [s[r][r:] + s[r][:r] for r in range(4)]           # ShiftRows
        for c in range(4):                                     # MixColumns
            a = [s[r][c] for r in range(4)]
            s[0][c] = _mul(a[0],2)^_mul(a[1],3)^a[2]^a[3]
            s[1][c] = a[0]^_mul(a[1],2)^_mul(a[2],3)^a[3]
            s[2][c] = a[0]^a[1]^_mul(a[2],2)^_mul(a[3],3)
            s[3][c] = _mul(a[0],3)^a[1]^a[2]^_mul(a[3],2)
        _add_round_key(s, w, rnd)
    s = [[_sbox[s[r][c]] for c in range(4)] for r in range(4)]
    s = [s[r][r:] + s[r][:r] for r in range(4)]
    _add_round_key(s, w, Nr)
    return _state_to_bytes(s)

def _decrypt_block(block, w, Nr):
    s = _bytes_to_state(block)
    _add_round_key(s, w, Nr)
    for rnd in range(Nr-1, 0, -1):
        s = [s[r][-r:] + s[r][:-r] if r else s[r] for r in range(4)]  # InvShiftRows
        s = [[_inv_sbox[s[r][c]] for c in range(4)] for r in range(4)]
        _add_round_key(s, w, rnd)
        for c in range(4):                                             # InvMixColumns
            a = [s[r][c] for r in range(4)]
            s[0][c] = _mul(a[0],14)^_mul(a[1],11)^_mul(a[2],13)^_mul(a[3],9)
            s[1][c] = _mul(a[0],9)^_mul(a[1],14)^_mul(a[2],11)^_mul(a[3],13)
            s[2][c] = _mul(a[0],13)^_mul(a[1],9)^_mul(a[2],14)^_mul(a[3],11)
            s[3][c] = _mul(a[0],11)^_mul(a[1],13)^_mul(a[2],9)^_mul(a[3],14)
    s = [s[r][-r:] + s[r][:-r] if r else s[r] for r in range(4)]
    s = [[_inv_sbox[s[r][c]] for c in range(4)] for r in range(4)]
    _add_round_key(s, w, 0)
    return _state_to_bytes(s)

class AESCBC:
    def __init__(self, key, iv):
        self.w, self.Nr = _key_expansion(key)
        self.iv = bytes(iv)
    def encrypt(self, data):
        assert len(data) % 16 == 0
        out = bytearray(); prev = self.iv
        for i in range(0, len(data), 16):
            blk = bytes(a ^ b for a, b in zip(data[i:i+16], prev))
            prev = _encrypt_block(blk, self.w, self.Nr)
            out += prev
        return bytes(out)
    def decrypt(self, data):
        assert len(data) % 16 == 0
        out = bytearray(); prev = self.iv
        for i in range(0, len(data), 16):
            ct = data[i:i+16]
            dec = _decrypt_block(ct, self.w, self.Nr)
            out += bytes(a ^ b for a, b in zip(dec, prev))
            prev = ct
        return bytes(out)

if __name__ == "__main__":
    # self-test against a known NIST AES-256-CBC vector
    key = bytes.fromhex("603deb1015ca71be2b73aef0857d7781"
                        "1f352c073b6108d72d9810a30914dff4")
    iv  = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt  = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    ct  = bytes.fromhex("f58c4c04d6e5f1ba779eabfb5f7bfbd6")
    assert AESCBC(key, iv).encrypt(pt) == ct, "encrypt FAIL"
    assert AESCBC(key, iv).decrypt(ct) == pt, "decrypt FAIL"
    print("a9_aes self-test OK (AES-256-CBC NIST vector)")
