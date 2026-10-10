#!/usr/bin/env python3
"""
extract_a9_snapshot.py - REAL PCAP -> REAL JPEG for XCThings/Linklemo A9 cameras.

    python3 extract_a9_snapshot.py capture.pcap > snapshot.jpg
    python3 extract_a9_snapshot.py capture.pcap snapshot.jpg

For a camera you own. Parses a local TCP capture of 192.168.9.252:20190, decodes
the PPRPC CTRL handshake to recover the per-session MEDIA key base, then decrypts
and reassembles the first complete MJPEG frame from the MEDIA stream.

Deps: Python stdlib + pycryptodome.  (Pillow only if you want --validate.)

======================  PROVEN / CONFIRMED on a real capture  ==================
Transport: TCP 20190.  PPRPC frame = ctrl(1B: msgtype hi-nibble, flag lo) +
remainlength(varint) + exhdr(varints) + payload.  msgtype 4=CTRL,6=MEDIA.

CTRL crypto (confirmed, decodes LanAuth etc.):
  key = md5hex("<A9_PREKEY>,ID:<cmdid>-SEQ:<seq>-RPC:<flag&3>")  (AES-256)
  AES-256-CBC, IV=key[:16], PKCS#7.   (gen_crypt_key@0x5d790, wrapper@0x5daa0)

MEDIA key base = per-session key from the LanAuth RESPONSE (cmd 2650, S->C,
protobuf field 1: a 32-hex-char string). This is H+0x88 in firmware (0x58f08).

MEDIA crypto (confirmed - one frame decoded to a valid 640x480 JPEG):
  Each frame = 8 fragments. MEDIA exhdr varints: v0=AVChannel, v1=AVSeq(frame
  index), v2=TT(ms timestamp), v3=enclen (encrypted-prefix length, nonzero only
  on the first fragment), v5=fragment index.
  Only the FIRST fragment's first `enclen` bytes are encrypted; everything else
  (rest of frag0 + all continuation fragments) is PLAINTEXT JPEG.
  key = md5hex("<session_key>,AVSeq:<v1>-TT:<v2>-AVChannel:<v0>")   (AES-256)
  encrypted prefix = AES-256-CBC, IV=key[16:32], over floor(enclen/16)*16 bytes.
  (media handler@0x5fbb4, media wrapper@0x5e3dc: IV built from key+0x10 via "%s")

Reassembled JPEG = decrypt(frag0 prefix) + frag0 plaintext tail + frag1..7 data,
carved SOI(FFD8)..EOI(FFD9).
===============================================================================
"""
import sys, struct, hashlib, os

def _load_aes():
    """Prefer pycryptodome; fall back to bundled pure-Python a9_aes (stdlib-only,
    so the tool works with no internet / no pip, e.g. on the camera's AP)."""
    try:
        from Crypto.Cipher import AES
        return (lambda k, iv, d: AES.new(k, AES.MODE_CBC, iv).encrypt(d),
                lambda k, iv, d: AES.new(k, AES.MODE_CBC, iv).decrypt(d))
    except Exception:
        import importlib.util
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "a9_aes.py")
        s = importlib.util.spec_from_file_location("a9_aes", p)
        m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
        return (lambda k, iv, d: m.AESCBC(k, iv).encrypt(d),
                lambda k, iv, d: m.AESCBC(k, iv).decrypt(d))
aes_cbc_encrypt, aes_cbc_decrypt = _load_aes()

PORT = 20190
def _ctrl_secret():
    import importlib.util
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "a9_keys.py")
    s = importlib.util.spec_from_file_location("a9_keys", p)
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
    return m.ctrl_prekey()
CTRL_SECRET = _ctrl_secret()

# ---------- varint ----------
def read_varint(b, i):
    shift = 0; val = 0
    while i < len(b):
        x = b[i]; i += 1
        val |= (x & 0x7f) << shift
        if not (x & 0x80):
            return val, i
        shift += 7
    raise ValueError("truncated varint")

# ---------- protobuf (lenient) ----------
def parse_protobuf(buf):
    out = {}; i = 0; n = len(buf)
    while i < n:
        try:
            tag, i = read_varint(buf, i)
        except ValueError:
            break
        f, wt = tag >> 3, tag & 7
        try:
            if wt == 0:   v, i = read_varint(buf, i)
            elif wt == 2:
                ln, i = read_varint(buf, i)
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

# ---------- minimal pcap reader (classic; DLT EN10MB=1 and RAW=101) ----------
def read_pcap_streams(path):
    data = open(path, "rb").read()
    magic = data[:4]
    if magic == b"\xa1\xb2\xc3\xd4": end = ">"
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
        if not payload or PORT not in (sport, dport): continue
        flows.setdefault((src, sport, dst, dport), []).append((seq, payload))
    streams = {}
    for key, segs in flows.items():
        segs.sort()
        streams[key] = b"".join(p for _, p in segs)
    return streams

# ---------- PPRPC framing ----------
def iter_pprpc(stream):
    i = 0; n = len(stream)
    while i < n:
        ctrl = stream[i]; msgtype = (ctrl >> 4) & 0xF
        if msgtype not in (2, 3, 4, 5, 6, 7, 8):
            i += 1; continue
        j = i + 1
        try:
            remain, j = read_varint(stream, j)
        except ValueError:
            i += 1; continue
        if remain <= 0 or j + remain > n:
            i += 1; continue
        body = stream[j:j + remain]; i = j + remain
        yield msgtype, ctrl & 0xF, body

def ctrl_exhdr(body):
    """returns (cmd_id, seq, rpc, payload)."""
    p = 0
    seq, p = read_varint(body, p)          # msgid (1st varint) = SEQ
    cmd, p = read_varint(body, p)          # field2 (2nd varint) = ID (command)
    flag = body[p]; p += 1
    rpc = flag & 3
    if rpc == 1:
        _, p = read_varint(body, p)        # extra varint present when flag&3==1
    return cmd, seq, rpc, body[p:]

def ctrl_decrypt(cmd, seq, rpc, ct):
    if len(ct) == 0 or len(ct) % 16: return None
    key = hashlib.md5(b"%s,ID:%d-SEQ:%d-RPC:%d" % (CTRL_SECRET, cmd, seq, rpc)).hexdigest().encode()
    pt = aes_cbc_decrypt(key, key[:16], ct)
    pad = pt[-1]
    if 1 <= pad <= 16 and pt.endswith(bytes([pad]) * pad):
        return pt[:-pad]
    return None

def media_exhdr(body):
    """returns (flag, v0_avchannel, v1_avseq, v2_tt, v3_enclen, data)."""
    p = 0
    flag = body[p] >> 7; p += 1          # byte0 bit7 = frame-start
    p += 1                                # byte1
    vs = []
    for _ in range(7):
        v, p = read_varint(body, p); vs.append(v)
    return flag, vs[0], vs[1], vs[2], vs[3], body[p:]

# ---------- main extraction ----------
def recover_session_key(streams):
    """MEDIA base = 32-hex-char string in the LanAuth response (S->C CTRL)."""
    import re
    hex32 = re.compile(rb'^[0-9a-f]{32}$')
    for (src, sp, dst, dp), st in streams.items():
        if sp != PORT:  # responses come FROM the camera
            continue
        for mt, flag, body in iter_pprpc(st):
            if mt != 4: continue
            cmd, seq, rpc, ct = ctrl_exhdr(body)
            pt = ctrl_decrypt(cmd, seq, rpc, ct)
            if not pt: continue
            for vals in parse_protobuf(pt).values():
                for v in vals:
                    if isinstance(v, bytes) and hex32.match(v):
                        return v
    return None

def extract_first_jpeg(streams, session_key):
    # collect MEDIA fragments from the camera->client stream, in order
    frags = []
    for (src, sp, dst, dp), st in streams.items():
        if sp != PORT: continue
        for mt, flag, body in iter_pprpc(st):
            if mt == 6:
                frags.append(body)
    if not frags:
        sys.exit("no MEDIA (msgtype 6) packets found")
    # group into frames by frame-start flag (bit7 of byte0)
    starts = [k for k, f in enumerate(frags) if (f[0] >> 7) == 1]
    if not starts:
        sys.exit("no MEDIA frame-start fragment found")
    s = starts[0]
    e = starts[1] if len(starts) > 1 else len(frags)
    blob = b""
    for k in range(s, e):
        flag, avch, avseq, tt, enclen, data = media_exhdr(frags[k])
        if enclen > 0:
            key = hashlib.md5(b"%s,AVSeq:%d-TT:%d-AVChannel:%d"
                              % (session_key, avseq, tt, avch)).hexdigest().encode()
            n = enclen - (enclen % 16)
            dec = aes_cbc_decrypt(key, key[16:32], data[:n])
            blob += dec + data[n:]
        else:
            blob += data
    soi = blob.find(b"\xff\xd8")
    eoi = blob.find(b"\xff\xd9", soi + 2)
    if soi < 0 or eoi < 0:
        sys.exit("could not find JPEG SOI/EOI after reassembly")
    return blob[soi:eoi + 2]

def main():
    if len(sys.argv) < 2:
        sys.exit("usage: extract_a9_snapshot.py capture.pcap [snapshot.jpg]")
    streams = read_pcap_streams(sys.argv[1])
    if not streams:
        sys.exit(f"no tcp/{PORT} traffic in capture")
    sk = recover_session_key(streams)
    if not sk:
        sys.exit("could not recover session key from CTRL handshake")
    sys.stderr.write(f"[*] session key recovered ({len(sk)} chars) — do not publish it\n")
    jpg = extract_first_jpeg(streams, sk)
    sys.stderr.write(f"[*] recovered JPEG: {len(jpg)} bytes\n")
    if len(sys.argv) >= 3:
        open(sys.argv[2], "wb").write(jpg)
        sys.stderr.write(f"[*] wrote {sys.argv[2]}\n")
    else:
        sys.stdout.buffer.write(jpg)

if __name__ == "__main__":
    main()
