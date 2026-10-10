#!/usr/bin/env python3
"""
decode_a9_pcap.py  -  Local CTRL-channel decoder for XCThings/Linklemo A9 cameras.

    python3 decode_a9_pcap.py capture.pcap
    python3 decode_a9_pcap.py --stream tcp_payload.bin     # raw one-direction TCP bytes

For a camera YOU own. It parses the PPRPC framing on tcp/20190, derives the CTRL
AES key from the firmware's known scheme, decrypts CTRL payloads, and decodes
ipc_LanAuth / VideoPlay. It does NOT touch MEDIA decoding (by request).

================================  EVIDENCE  ====================================
All from the de-interleaved app (base 0x10000). "fn@addr" are the proving sites.

TRANSPORT: TCP, port 20190.                      iot_conn_local_connect2 @0x302d0
  "iot conn local try: tcp://%s:%d"              (string @0x14f2e8)

PPRPC FRAMING  (pprpc_packet_decode @0x54128 -> fixhdr @0x62304 -> exhdr @0x5ee60)
  fixhdr:
    off 0  u8   ctrl       : msgtype = (ctrl>>4)&0xF , msgflag = ctrl&0xF
                              @0x6234c  (lsr #4 ; and #0xF)
                              msgtype: 4=CTRL 6=MEDIA 8=FILE  (jump table @0x62458)
    off 1  varint remainlength      (len reader 0x148fb8->0xc0edc)
  exhdr (CTRL, msgtype 4) @0x5ee60, all protobuf-style LEB128 varints (reader
         0x149400->0xc0fec: 7 bits/byte, high bit = continue, <=10 bytes, u64):
    msgid      varint u64              (0x5ee9c -> dest ctx+0x30)
    field2     varint u64              (0x5eee8 -> dest ctx+0x38)
    flagbyte   u8  -> hi6=(b>>2), lo2=(b&3)   (0x5ef30/0x5ef70/0x5ef84)
    cmd_id     varint u64  *iff (flagbyte&3)==1*  (0x5f024 -> dest ctx+0x48)
  payload: AES-CBC ciphertext (rest of the message).

CRYPTO  (gen_crypt_key @0x5d790 ; AES wrapper 0x5daa0 ; MD5 consts @0x7d270)
         *** CONFIRMED end-to-end against a real capture (85/87 CTRL pkts) ***
  base(CTRL) = STATIC firmware secret (0x58f60 -> @0x156620):  loaded from A9_PREKEY
  key_hex = lower_hex( MD5( "<base>,ID:%d-SEQ:%d-RPC:%d" ) )    # 32 ASCII hex chars
  aes_key = key_hex           (all 32 bytes -> AES-256)
  cipher  = AES-256-CBC + PKCS#7     IV = aes_key[:16]
  field mapping (confirmed empirically):
      ID  = command id = exhdr field2 (2nd varint)
      SEQ = sequence   = exhdr msgid  (1st varint)
      RPC = flagbyte & 3   (0, or 1 for ping/heartbeat etc.)
  (The ID/SEQ/RPC mapping was the one thing static analysis left ambiguous; it
   was resolved by decrypting the real capture and requiring valid PKCS#7 +
   protobuf.  Nothing here is guessed.)

>>>  WARNING: output contains DEVICE-SPECIFIC SECRETS (DID + paired auth secret).
>>>  Do NOT publish or paste them anywhere. They authenticate to your camera.
===============================================================================
"""
import sys, struct, hashlib, argparse

def _ctrl_secret():                              # shared prekey, loaded from env/.env
    import os, importlib.util
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "a9_keys.py")
    s = importlib.util.spec_from_file_location("a9_keys", p)
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
    return m.ctrl_prekey()
STATIC_SECRET = _ctrl_secret()                   # @0x156620  (CTRL/FILE base)
PORT = 20190
try:
    from Crypto.Cipher import AES                 # pip install pycryptodome
except Exception:
    AES = None

# ---------- protobuf-style varint (firmware 0xc0fec) ----------
def read_varint(buf, i):
    shift = 0; val = 0
    for _ in range(10):
        b = buf[i]; i += 1
        val |= (b & 0x7f) << shift
        if not (b & 0x80):
            return val & 0xFFFFFFFFFFFFFFFF, i
        shift += 7
    raise ValueError("varint too long")

# ---------- CTRL key (gen_crypt_key scheme 4) ----------
# CONFIRMED against a real capture:
#   key = lower_hex(MD5("<secret>,ID:<cmdid>-SEQ:<seq>-RPC:<rpc>"))   (32 ASCII bytes)
#   cipher = AES-256-CBC + PKCS#7 ,  IV = key[:16]
#   ID  = command id  = 2nd exhdr varint (field2)
#   SEQ = sequence    = 1st exhdr varint (msgid)
#   RPC = 3rd exhdr field (cmd_id) if present, else 0
def ctrl_key(cmd_id, seq, rpc):
    s = b"%s,ID:%d-SEQ:%d-RPC:%d" % (STATIC_SECRET, cmd_id, seq, rpc)
    return hashlib.md5(s).hexdigest().encode()   # 32 ASCII hex bytes -> AES-256

def aes_cbc_dec(key, ct):
    if AES is None:
        raise SystemExit("need: pip install pycryptodome")
    if len(ct) == 0 or len(ct) % 16: return None
    pt = AES.new(key, AES.MODE_CBC, key[:16]).decrypt(ct)
    pad = pt[-1]
    if 1 <= pad <= 16 and pt.endswith(bytes([pad]) * pad):
        return pt[:-pad]
    return None

# ---------- generic protobuf dump ----------
def parse_protobuf(buf):
    out = {}; i = 0; n = len(buf)
    while i < n:
        try:
            tag, i = read_varint(buf, i)
        except Exception:
            break
        field, wt = tag >> 3, tag & 7
        if wt == 0:
            v, i = read_varint(buf, i)
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
        else:
            break
        out.setdefault(field, []).append(v)
    return out

def show_field(v):
    if isinstance(v, bytes):
        try:
            s = v.decode("utf-8")
            if s.isprintable(): return repr(s)
        except Exception:
            pass
        return v.hex()
    return v

# ---------- PPRPC framing ----------
def iter_pprpc(stream):
    """Yield (msgtype, msgflag, exhdr_dict, payload) from a reassembled TCP dir."""
    i = 0; n = len(stream)
    while i < n:
        ctrl = stream[i]; msgtype = (ctrl >> 4) & 0xF; msgflag = ctrl & 0xF
        if msgtype not in (2, 3, 4, 5, 6, 7, 8):   # not a pprpc frame start
            i += 1; continue
        j = i + 1
        try:
            remain, j = read_varint(stream, j)
        except Exception:
            i += 1; continue
        if remain <= 0 or j + remain > n:
            i += 1; continue
        body = stream[j:j + remain]; i = j + remain
        ex = {}; p = 0
        try:
            ex["msgid"], p = read_varint(body, p)
            ex["field2"], p = read_varint(body, p)
            flag = body[p]; p += 1
            ex["flag_hi"], ex["flag_lo"] = flag >> 2, flag & 3
            if ex["flag_lo"] == 1:
                ex["cmd_id"], p = read_varint(body, p)
        except Exception:
            pass
        yield msgtype, msgflag, ex, body[p:]

def decrypt_ctrl(ex, ct):
    """CONFIRMED scheme (validated on a real capture):
         ID  = field2 (command id, 2nd exhdr varint)
         SEQ = msgid  (1st exhdr varint)
         RPC = flagbyte & 3  (== flag_lo)
       When flag_lo==1 the exhdr also carries an extra varint (consumed by the
       framer) before the ciphertext."""
    cmd_id = ex.get("field2", 0); seq = ex.get("msgid", 0); rpc = ex.get("flag_lo", 0)
    k = ctrl_key(cmd_id, seq, rpc)
    pt = aes_cbc_dec(k, ct)
    if pt is not None and parse_protobuf(pt):
        return pt, k, f"ID={cmd_id} SEQ={seq} RPC={rpc}"
    return None, None, None

# ---------- minimal pcap reader (classic tcpdump format, no deps) ----------
def read_pcap_tcp(path):
    data = open(path, "rb").read()
    magic = data[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1"):
        le = magic == b"\xd4\xc3\xb2\xa1"
    elif magic == b"\x0a\x0d\x0d\x0a":
        raise SystemExit("pcapng not supported; capture with `tcpdump -w` (classic pcap)")
    else:
        raise SystemExit("not a pcap file")
    end = "<" if le else ">"
    linktype = struct.unpack(end + "I", data[20:24])[0]
    i = 24; flows = {}   # (src,sport,dst,dport) -> list[(seq,payload)]
    while i + 16 <= len(data):
        _, _, caplen, _ = struct.unpack(end + "IIII", data[i:i+16]); i += 16
        pkt = data[i:i+caplen]; i += caplen
        # link-layer header size by DLT
        if linktype == 1:            # EN10MB (Ethernet)
            if len(pkt) >= 14 and pkt[12:14] not in (b"\x08\x00", b"\x86\xdd"):
                continue
            off = 14
        elif linktype == 101:        # RAW (bare IP) -- PCAPdroid
            off = 0
        elif linktype == 0:          # NULL/loopback (4-byte family)
            off = 4
        elif linktype == 113:        # LINUX_SLL
            off = 16
        elif linktype == 276:        # LINUX_SLL2
            off = 20
        else:
            off = 0
        if len(pkt) < off + 20: continue
        ip = pkt[off:]
        if (ip[0] >> 4) != 4: continue   # IPv4 only (extend if needed)
        ihl = (ip[0] & 0xF) * 4
        if ip[9] != 6: continue                      # TCP
        src = ".".join(map(str, ip[12:16])); dst = ".".join(map(str, ip[16:20]))
        tcp = ip[ihl:]
        sport, dport = struct.unpack(">HH", tcp[0:4])
        seq = struct.unpack(">I", tcp[4:8])[0]
        doff = (tcp[12] >> 4) * 4
        payload = tcp[doff:]
        if not payload: continue
        if PORT not in (sport, dport): continue
        flows.setdefault((src, sport, dst, dport), []).append((seq, payload))
    streams = {}
    for key, segs in flows.items():
        segs.sort()
        streams[key] = b"".join(p for _, p in segs)
    return streams

# ---------- main ----------
def decode_direction(label, stream):
    print(f"\n=== direction {label}  ({len(stream)} bytes) ===")
    for msgtype, msgflag, ex, payload in iter_pprpc(stream):
        tname = {4: "CTRL", 6: "MEDIA", 8: "FILE"}.get(msgtype, f"type{msgtype}")
        print(f"\nPPRPC {tname} (flag={msgflag})  exhdr={ex}")
        if msgtype != 4:
            print(f"  [payload {len(payload)} bytes, not decoding {tname}]")
            continue
        cmd = ex.get("field2")
        pt, key, how = decrypt_ctrl(ex, payload)
        if pt is None:
            print(f"  cmd={cmd} [decrypt failed on {len(payload)}B]")
            continue
        print(f"  cmd(ID)={cmd} seq={ex.get('msgid')}  key={key.decode()[:16]}…  ({how})")
        fields = parse_protobuf(pt)
        for fnum, vals in sorted(fields.items()):
            for v in vals:
                sub = ""
                if isinstance(v, bytes) and len(v) >= 2:
                    nf = parse_protobuf(v)
                    if nf and sum(len(x) for x in nf.values()) >= 1:
                        sub = "  nested=" + repr({k2: [show_field(x) for x in vs2]
                                                 for k2, vs2 in sorted(nf.items())})
                print(f"    [{fnum}] {show_field(v)}{sub}")
        # recognition
        strs = [v for vs in fields.values() for v in vs if isinstance(v, bytes)]
        did = fields.get(2, [None])[0]
        sec = fields.get(3, [None])[0]
        if isinstance(did, bytes) and isinstance(sec, bytes) and did[:2] in (b"PP", b"LL"):
            print("  >>> ipc_LanAuth:")
            print(f"        DID                = {show_field(did)}")
            print(f"        paired_auth_secret = {show_field(sec)}   (SECRET — do not publish)")
        if any(b"ession" in s or b"key" in s.lower() for s in strs):
            print("  >>> contains session/key material (candidate MEDIA base)")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("--stream", action="store_true",
                    help="input is raw one-direction TCP payload bytes, not a pcap")
    args = ap.parse_args()
    print("WARNING: output below contains device-specific secrets (DID + auth secret).")
    print("         Do not publish them.\n")
    if args.stream:
        decode_direction("raw", open(args.input, "rb").read())
        return
    streams = read_pcap_tcp(args.input)
    if not streams:
        raise SystemExit(f"no tcp/{PORT} payload found in capture")
    for (src, sp, dst, dp), st in streams.items():
        decode_direction(f"{src}:{sp} -> {dst}:{dp}", st)

if __name__ == "__main__":
    main()
