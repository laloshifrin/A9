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
import sys, os, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # find siblings under -I / any cwd
import a9_proto as P

PORT = P.PORT
read_varint = P.read_varint          # lenient varint (shared)
ctrl_key = P.ctrl_key                # md5(prekey,ID:-SEQ:-RPC:) -> 32-hex AES-256 key

# ---------- CTRL key / cipher (gen_crypt_key scheme 4), CONFIRMED on a real capture ----------
#   key = lower_hex(MD5("<prekey>,ID:<cmdid>-SEQ:<seq>-RPC:<rpc>"))   (32 ASCII bytes)
#   cipher = AES-256-CBC + PKCS#7 ,  IV = key[:16]
#   ID = exhdr field2 (2nd varint), SEQ = exhdr msgid (1st varint), RPC = flagbyte & 3
def aes_cbc_dec(key, ct):
    if len(ct) == 0 or len(ct) % 16:
        return None
    pt = P.aes_cbc_decrypt(key, key[:16], ct)
    pad = pt[-1]
    return pt[:-pad] if 1 <= pad <= 16 and pt.endswith(bytes([pad]) * pad) else None

parse_protobuf = P.pb_parse          # shared lenient protobuf parser

def show_field(v):
    if isinstance(v, bytes):
        try:
            s = v.decode("utf-8")
            if s.isprintable(): return repr(s)
        except Exception:
            pass
        return v.hex()
    return v

# ---------- PPRPC framing (verbose: exhdr parsed into a dict for printing) ----------
def iter_pprpc(stream):
    """Yield (msgtype, msgflag, exhdr_dict, payload), reusing a9_proto's framing."""
    for msgtype, msgflag, body in P.iter_pprpc(stream):
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

# ---------- pcap reader (shared, sequence-aware TCP reassembly) ----------
def read_pcap_tcp(path):
    return P.read_pcap_streams(path, PORT)

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
