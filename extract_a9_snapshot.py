#!/usr/bin/env python3
"""
extract_a9_snapshot.py - REAL PCAP -> REAL JPEG for XCThings/Linklemo A9 cameras.

    python3 extract_a9_snapshot.py capture.pcap > snapshot.jpg
    python3 extract_a9_snapshot.py capture.pcap snapshot.jpg

For a camera you own. Parses a local TCP capture of tcp/20190, decodes the PPRPC CTRL
handshake to recover the per-session MEDIA key, then decrypts and reassembles the first
complete MJPEG frame. All protocol/crypto lives in a9_proto (see PROTOCOL.md).

Deps: Python stdlib (a9_proto uses pycryptodome if present, else the bundled a9_aes).

WARNING: the recovered session key and frames are device-specific; don't publish them.
"""
import sys, os, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # find siblings under -I / any cwd
import a9_proto as P

def recover_session_key(streams):
    """MEDIA base = 32-hex-char string in the LanAuth response (S->C CTRL)."""
    hex32 = re.compile(rb'^[0-9a-f]{32}$')
    for (src, sp, dst, dp), st in streams.items():
        if sp != P.PORT:                       # responses come FROM the camera
            continue
        for mt, flag, body in P.iter_pprpc(st):
            if mt != 4: continue
            cmd, seq, rpc, ct = P.ctrl_exhdr(body)
            pt = P.ctrl_decrypt(cmd, seq, rpc, ct)
            if not pt: continue
            for vals in P.pb_parse(pt).values():
                for v in vals:
                    if isinstance(v, bytes) and hex32.match(v):
                        return v
    return None

def extract_first_jpeg(streams, session_key):
    frags = [body for (src, sp, dst, dp), st in streams.items() if sp == P.PORT
             for mt, flag, body in P.iter_pprpc(st) if mt == 6]
    if not frags:
        sys.exit("no MEDIA (msgtype 6) packets found")
    starts = [k for k, f in enumerate(frags) if (f[0] >> 7) == 1]
    if not starts:
        sys.exit("no MEDIA frame-start fragment found")
    s = starts[0]; e = starts[1] if len(starts) > 1 else len(frags)
    jpg = P.decrypt_media_frame(frags[s:e], session_key)
    if not jpg:
        sys.exit("could not find JPEG SOI/EOI after reassembly")
    return jpg

def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        sys.exit("usage: extract_a9_snapshot.py capture.pcap [snapshot.jpg]")
    streams = P.read_pcap_streams(sys.argv[1])
    if not streams:
        sys.exit(f"no tcp/{P.PORT} traffic in capture")
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
