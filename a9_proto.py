#!/usr/bin/env python3
"""
a9_proto.py - shared PPRPC protocol primitives for the A9 tools.

One home for the pieces every tool used to duplicate: varint/protobuf, AES (with a
pure-Python fallback), the shared prekey (from a9_keys), CTRL crypto + framing, the
MEDIA frame decode, a pcap reader with sequence-aware TCP reassembly, and the device
constants. Pure stdlib unless pycryptodome is installed (used automatically if so).

See PROTOCOL.md for the wire format these implement.
"""
import struct, hashlib, os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))   # find siblings under -I / any cwd
import a9_aes, a9_keys

# ---------- constants ----------
PORT = 20190
UDP_PREFIX = b"\x51\x70"
HB_CONST = 18446744073709551586          # field 2 of a heartbeat pong
CMD_LANAUTH   = 2650
CMD_VIDEOPLAY = 2610
CMD_SETRES    = 2612     # resolution/stream-type (recording stream; live stays 640x480)
CMD_NIGHT     = 2635     # night mode
CMD_HELLO     = 106      # post-LanAuth "ready" ping
CMD_PING      = 107      # heartbeat
CMD_STATUS    = 2780     # camera device-status push (DID, battery, firmware, ...)

# ---------- AES (prefer pycryptodome, else the bundled pure-Python a9_aes) ----------
try:
    from Crypto.Cipher import AES as _AES
    def aes_cbc_encrypt(key, iv, data): return _AES.new(key, _AES.MODE_CBC, iv).encrypt(data)
    def aes_cbc_decrypt(key, iv, data): return _AES.new(key, _AES.MODE_CBC, iv).decrypt(data)
except Exception:
    def aes_cbc_encrypt(key, iv, data): return a9_aes.AESCBC(key, iv).encrypt(data)
    def aes_cbc_decrypt(key, iv, data): return a9_aes.AESCBC(key, iv).decrypt(data)

# ---------- shared prekey (lazy + cached, so --help works without configuration) ----------
_PREKEY = None
def ctrl_prekey():
    global _PREKEY
    if _PREKEY is None:
        _PREKEY = a9_keys.ctrl_prekey()
    return _PREKEY

# ---------- varint ----------
def enc_varint(n):
    out = b""
    while True:
        b = n & 0x7f; n >>= 7
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            return out

def dec_varint(buf, i):
    shift = val = 0
    while i < len(buf):
        x = buf[i]; i += 1
        val |= (x & 0x7f) << shift
        if not (x & 0x80):
            return val, i
        shift += 7
    raise ValueError("truncated varint")
read_varint = dec_varint   # alias

# ---------- protobuf (lenient) ----------
def pb_parse(buf):
    out = {}; i = 0; n = len(buf)
    while i < n:
        try:
            tag, i = dec_varint(buf, i)
        except ValueError:
            break
        f, wt = tag >> 3, tag & 7
        try:
            if wt == 0:   v, i = dec_varint(buf, i)
            elif wt == 2:
                ln, i = dec_varint(buf, i)
                if i + ln > n: break
                v = buf[i:i+ln]; i += ln
            elif wt == 5:
                if i + 4 > n: break
                v = struct.unpack("<I", buf[i:i+4])[0]; i += 4
            elif wt == 1:
                if i + 8 > n: break
                v = struct.unpack("<Q", buf[i:i+8])[0]; i += 8
            else: break
        except Exception:
            break
        out.setdefault(f, []).append(v)
    return out

def pb_field_bytes(field, data):
    return enc_varint((field << 3) | 2) + enc_varint(len(data)) + data

def pb_varint_field(field, value):
    return enc_varint((field << 3) | 0) + enc_varint(value)

# ---------- CTRL crypto ----------
def ctrl_key(cmd, seq, rpc):
    return hashlib.md5(b"%s,ID:%d-SEQ:%d-RPC:%d"
                       % (ctrl_prekey(), cmd, seq, rpc)).hexdigest().encode()

def ctrl_encrypt(cmd, seq, rpc, plaintext):
    if not plaintext:
        return b""
    key = ctrl_key(cmd, seq, rpc)
    pad = 16 - (len(plaintext) % 16)
    return aes_cbc_encrypt(key, key[:16], plaintext + bytes([pad]) * pad)

def ctrl_decrypt(cmd, seq, rpc, ct):
    if len(ct) == 0 or len(ct) % 16:
        return None
    key = ctrl_key(cmd, seq, rpc)
    pt = aes_cbc_decrypt(key, key[:16], ct)
    pad = pt[-1]
    return pt[:-pad] if 1 <= pad <= 16 and pt.endswith(bytes([pad]) * pad) else None

# ---------- CTRL framing ----------
def build_ctrl(seq, cmd, plaintext=b"", flag=0x0C):
    rpc = flag & 3
    payload = ctrl_encrypt(cmd, seq, rpc, plaintext)
    exhdr = enc_varint(seq) + enc_varint(cmd) + bytes([flag])
    if rpc == 1:                         # replies carry an extra trailing varint (Code, =0)
        exhdr += enc_varint(0)
    body = exhdr + payload
    return bytes([0x48]) + enc_varint(len(body)) + body

def ctrl_exhdr(body):
    """returns (cmd_id, seq, rpc, remaining_ciphertext)."""
    p = 0
    seq, p = dec_varint(body, p)
    cmd, p = dec_varint(body, p)
    flag = body[p]; p += 1
    rpc = flag & 3
    if rpc == 1:
        _, p = dec_varint(body, p)
    return cmd, seq, rpc, body[p:]

def iter_pprpc(stream):
    """Yield (msgtype, flag, body) for each PPRPC frame in a reassembled byte stream."""
    i = 0; n = len(stream)
    while i < n:
        ctrl = stream[i]; msgtype = (ctrl >> 4) & 0xF
        if msgtype not in (2, 3, 4, 5, 6, 7, 8):
            i += 1; continue
        j = i + 1
        try:
            remain, j = dec_varint(stream, j)
        except ValueError:
            i += 1; continue
        if remain <= 0 or j + remain > n:
            i += 1; continue
        body = stream[j:j + remain]; i = j + remain
        yield msgtype, ctrl & 0xF, body

# ---------- MEDIA ----------
def media_exhdr(body):
    """returns (frame_start_flag, AVChannel, AVSeq, TT, enclen, data)."""
    p = 0
    flag = body[p] >> 7; p += 1          # byte0 bit7 = frame-start
    p += 1                                # byte1 = EncType (assumed CBC)
    vs = []
    for _ in range(7):
        v, p = dec_varint(body, p); vs.append(v)
    return flag, vs[0], vs[1], vs[2], vs[3], body[p:]

def decrypt_media_frame(frags, session_key):
    """Reassemble + decrypt one MJPEG frame from its MEDIA fragments; carve SOI..EOI."""
    blob = b""
    for body in frags:
        flag, avch, avseq, tt, enclen, data = media_exhdr(body)
        if enclen > 0:
            key = hashlib.md5(b"%s,AVSeq:%d-TT:%d-AVChannel:%d"
                              % (session_key, avseq, tt, avch)).hexdigest().encode()
            n = min(enclen - (enclen % 16), len(data) - (len(data) % 16))
            blob += aes_cbc_decrypt(key, key[16:32], data[:n]) + data[n:]
        else:
            blob += data
    soi = blob.find(b"\xff\xd8")
    eoi = blob.find(b"\xff\xd9", soi + 2) if soi >= 0 else -1
    return blob[soi:eoi + 2] if (soi >= 0 and eoi >= 0) else None

def decode_status_2780(pt):
    """Decode a cmd-2780 device-status payload into a dict (battery, firmware, ...)."""
    f = pb_parse(pt)
    inner = f.get(1, [b""])[0]
    if not isinstance(inner, bytes):
        return None
    o = pb_parse(inner)
    did = o.get(2, [b""])[0]
    st = {"did": did.decode("utf-8", "replace") if isinstance(did, bytes) else None,
          "ts": o.get(6, [None])[0]}
    nested = o.get(4, [None])[0]
    if isinstance(nested, bytes):
        nf = pb_parse(nested)
        flags = nf.get(2, [None])[0]
        if isinstance(flags, bytes):
            st["status_bytes"] = flags.hex()
            # byte[1] tracked 70 -> 100 across captures (battery charging); byte[0]
            # changed too (06 -> 02), likely a charge/status flag. Confirm vs the app.
            if len(flags) >= 2: st["battery"] = flags[1]
            if len(flags) >= 1: st["flag0"] = flags[0]
        v = nf.get(1, [None])[0]         # constant 70 across captures; not battery
        if isinstance(v, int): st["field1"] = v
        info = [x.decode("utf-8", "replace") for x in nf.get(4, [])
                if isinstance(x, bytes) and x and all(32 <= c < 127 for c in x)]
        if info: st["info"] = info
    return st

# ---------- pcap ----------
def reassemble_tcp(segs):
    """Sequence-aware TCP reassembly. Places each segment at its seq offset so
    retransmits/overlaps don't duplicate bytes and missing segments don't collapse
    gaps (they stay as zero-fill, keeping later data aligned). No 32-bit wrap handling."""
    if not segs:
        return b""
    base = min(s for s, _ in segs)
    buf = bytearray()
    for seq, pl in sorted(segs):
        off = seq - base
        if off < 0:
            continue
        end = off + len(pl)
        if end > len(buf):
            buf.extend(b"\x00" * (end - len(buf)))
        buf[off:end] = pl                # overwrite overlaps; retransmits are identical
    return bytes(buf)

def read_pcap_streams(path, port=PORT):
    """Parse a classic pcap and return {(src,sport,dst,dport): reassembled_tcp_bytes}
    for TCP flows touching `port`. Supports DLT EN10MB/RAW/NULL/LINUX_SLL/SLL2."""
    import sys
    data = open(path, "rb").read()
    magic = data[:4]
    if magic == b"\xa1\xb2\xc3\xd4":   end = ">"
    elif magic == b"\xd4\xc3\xb2\xa1": end = "<"
    elif magic == b"\x0a\x0d\x0d\x0a":
        sys.exit("pcapng not supported; capture with tcpdump -w (classic pcap)")
    else:
        sys.exit("not a pcap file")
    linktype = struct.unpack(end + "I", data[20:24])[0]
    i = 24; flows = {}
    while i + 16 <= len(data):
        _, _, caplen, _ = struct.unpack(end + "IIII", data[i:i+16]); i += 16
        pkt = data[i:i+caplen]; i += caplen
        if linktype == 1:
            if len(pkt) >= 14 and pkt[12:14] not in (b"\x08\x00", b"\x86\xdd"): continue
            off = 14
        elif linktype == 101: off = 0
        elif linktype == 0:   off = 4
        elif linktype == 113: off = 16
        elif linktype == 276: off = 20
        else: off = 0
        if len(pkt) < off + 20: continue
        ip = pkt[off:]
        if (ip[0] >> 4) != 4: continue
        ihl = (ip[0] & 0xF) * 4
        if ip[9] != 6: continue
        src = ".".join(map(str, ip[12:16])); dst = ".".join(map(str, ip[16:20]))
        tcp = ip[ihl:]
        sport, dport = struct.unpack(">HH", tcp[0:4])
        seq = struct.unpack(">I", tcp[4:8])[0]
        payload = tcp[(tcp[12] >> 4) * 4:]
        if not payload or port not in (sport, dport): continue
        flows.setdefault((src, sport, dst, dport), []).append((seq, payload))
    return {k: reassemble_tcp(v) for k, v in flows.items()}

# ---------- live socket reader ----------
import time as _time
class FrameReader:
    MAX_FRAME = 8 * 1024 * 1024
    MAX_BUF   = 24 * 1024 * 1024
    def __init__(self, sock):
        self.s = sock; self.buf = b""
    def _fill(self, timeout=5.0):
        self.s.settimeout(timeout)
        chunk = self.s.recv(65536)
        if not chunk:
            raise ConnectionError("camera closed connection")
        self.buf += chunk
        if len(self.buf) > self.MAX_BUF:
            raise ConnectionError("receive buffer exceeded limit (desync?)")
    def next_frame(self, timeout=5.0):
        """return (msgtype, msgflag, body) or raise TimeoutError/ConnectionError."""
        deadline = _time.time() + timeout
        while True:
            b = self.buf
            if b:
                ctrl = b[0]; msgtype = (ctrl >> 4) & 0xF
                if msgtype in (2, 3, 4, 5, 6, 7, 8):
                    try:
                        remain, j = dec_varint(b, 1)
                        if remain > self.MAX_FRAME:
                            raise ConnectionError("frame length over limit (desync?)")
                        if j + remain <= len(b):
                            body = b[j:j+remain]
                            self.buf = b[j+remain:]
                            return msgtype, ctrl & 0xF, body
                    except ValueError:
                        pass
                else:
                    self.buf = b[1:]; continue   # resync
            if _time.time() > deadline:
                raise TimeoutError("no complete frame within timeout")
            self._fill(max(0.2, deadline - _time.time()))
