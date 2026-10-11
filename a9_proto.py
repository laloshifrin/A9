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
    """Return (start, AVChannel, AVSeq, TT, enclen, payload).

    Five varints are followed by a fixed two-byte fragment marker. In this
    camera's captures, ordinary markers are 01 00, 02 00, etc.; ff 00 marks
    the final fragment. Reading that marker as varints consumes JPEG bytes.
    """
    if len(body) < 2:
        raise ValueError("truncated MEDIA header")
    flag = body[0] >> 7
    p = 2
    vs = []
    for _ in range(5):
        v, p = dec_varint(body, p)
        vs.append(v)
    if p + 2 > len(body):
        raise ValueError("truncated MEDIA fragment marker")
    p += 2
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
MAX_TCP_STREAM = 64 * 1024 * 1024
MAX_JPEG_BYTES = 8 * 1024 * 1024

class MediaFragments(list):
    """Bound the total retained bytes for a single JPEG."""
    def __init__(self):
        super().__init__()
        self.byte_count = 0
    def append(self, body):
        if len(self) >= 4096 or self.byte_count + len(body) > MAX_JPEG_BYTES:
            self.clear()
            raise ValueError("MEDIA frame exceeded fragment/byte limit")
        super().append(body)
        self.byte_count += len(body)
    def clear(self):
        super().clear()
        self.byte_count = 0

def reassemble_tcp(segs):
    """Reassemble contiguous bytes, unwrap sequence numbers, reject gaps/oversize.

    Segments must be in capture order. Conflicting retransmissions are rejected.
    Missing bytes are never synthesized.
    """
    if not segs:
        return b""
    anchor = segs[0][0]
    high = anchor
    unwrapped = []
    for seq, payload in segs:
        offset = ((seq - (high & 0xffffffff) + (1 << 31)) % (1 << 32)) - (1 << 31)
        absolute = high + offset
        high = max(high, absolute + len(payload))
        unwrapped.append((absolute, payload))
    base = min(seq for seq, _ in unwrapped)
    buf = bytearray()
    for seq, payload in sorted(unwrapped):
        off = seq - base
        end = off + len(payload)
        if end > MAX_TCP_STREAM:
            raise ValueError("TCP stream exceeds reassembly limit")
        if off > len(buf):
            raise ValueError("capture has missing TCP bytes")
        overlap = min(len(payload), len(buf) - off)
        if buf[off:off + overlap] != payload[:overlap]:
            raise ValueError("conflicting TCP retransmission")
        buf.extend(payload[overlap:])
    return bytes(buf)

def read_pcap_streams(path, port=PORT):
    """Return {(src,sport,dst,dport,session): bytes} for classic IPv4 TCP pcap.

    SYNs and closed connections separate reused tuples. Captures starting midstream
    are supported, but capture gaps are rejected.
    """
    with open(path, "rb") as f:
        header = f.read(24)
        if len(header) != 24:
            raise ValueError("truncated pcap header")
        magic = header[:4]
        if magic == b"\xa1\xb2\xc3\xd4": end = ">"
        elif magic == b"\xd4\xc3\xb2\xa1": end = "<"
        elif magic == b"\x0a\x0d\x0d\x0a":
            raise ValueError("pcapng not supported; use classic pcap")
        else: raise ValueError("not a pcap file")
        linktype = struct.unpack(end + "I", header[20:24])[0]
        offsets = {1:14, 101:0, 0:4, 113:16, 276:20}
        if linktype not in offsets:
            raise ValueError("unsupported pcap link type")
        flows = {}; connections = {}; session_id = 0
        while True:
            record = f.read(16)
            if not record: break
            if len(record) != 16: raise ValueError("truncated pcap record")
            _, _, caplen, _ = struct.unpack(end + "IIII", record)
            if caplen > MAX_TCP_STREAM: raise ValueError("pcap packet exceeds limit")
            pkt = f.read(caplen)
            if len(pkt) != caplen: raise ValueError("truncated pcap packet")
            off = offsets[linktype]
            if linktype == 1 and pkt[12:14] != b"\x08\x00": continue
            ip = pkt[off:]
            if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6: continue
            ihl = (ip[0] & 15) * 4
            total = struct.unpack(">H", ip[2:4])[0]
            if ihl < 20 or total < ihl + 20 or total > len(ip):
                raise ValueError("truncated or invalid IPv4/TCP packet")
            if struct.unpack(">H", ip[6:8])[0] & 0x3fff:
                raise ValueError("fragmented IPv4 is unsupported")
            tcp = ip[ihl:total]
            sport, dport, seq = struct.unpack(">HHI", tcp[:8])
            if port not in (sport, dport): continue
            hlen = (tcp[12] >> 4) * 4
            if hlen < 20 or hlen > len(tcp): raise ValueError("invalid TCP header")
            src = ".".join(map(str, ip[12:16])); dst = ".".join(map(str, ip[16:20]))
            flow = (src, sport, dst, dport)
            conn = tuple(sorted(((src, sport), (dst, dport))))
            flags = tcp[13]
            syn = bool(flags & 2 and not flags & 16)
            previous = connections.get(conn)
            if previous is None or (syn and (previous[1] != (flow, seq) or previous[2])):
                session_id += 1
                connections[conn] = (session_id, (flow, seq) if syn else None, False)
            elif previous[2] and not flags & 16:
                session_id += 1
                connections[conn] = (session_id, None, False)
            current = connections[conn]
            payload = tcp[hlen:]
            if payload:
                flows.setdefault(flow + (current[0],), []).append(((seq + bool(flags & 2)) & 0xffffffff, payload))
            if flags & 5:
                connections[conn] = (current[0], current[1], True)
    return {flow: reassemble_tcp(segments) for flow, segments in flows.items()}

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
