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

def authenticated_sessions(streams):
    """Yield the response stream and key from each exact LanAuth response."""
    hex32 = re.compile(rb"[0-9a-f]{32}")
    for flow, stream in streams.items():
        if flow[1] != P.PORT: continue
        for mt, flag, body in P.iter_pprpc(stream):
            if mt != 4: continue
            cmd, seq, rpc, ct = P.ctrl_exhdr(body)
            if cmd != P.CMD_LANAUTH or rpc != 1: continue
            pt = P.ctrl_decrypt(cmd, seq, rpc, ct)
            key = P.pb_parse(pt).get(1, [None])[0] if pt else None
            if isinstance(key, bytes) and hex32.fullmatch(key):
                yield flow, key

def select_session(streams, session_key=None):
    matches = [(flow, key) for flow, key in authenticated_sessions(streams)
               if (session_key is None or key == session_key)
               and any(mt == 6 for mt, _, _ in P.iter_pprpc(streams[flow]))]
    if not matches:
        raise SystemExit("no LanAuth response with a MEDIA key found")
    if len(matches) != 1:
        raise SystemExit("capture contains multiple authenticated sessions; use a single-session capture")
    return matches[0]

def recover_session_key(streams):
    return select_session(streams)[1]

def session_frames(streams, flow, session_key):
    """Yield complete JPEGs from one authenticated response stream."""
    frags = P.MediaFragments()
    started = False
    for mt, flag, body in P.iter_pprpc(streams[flow]):
        if mt != 6 or not body: continue
        if body[0] >> 7:
            if started and frags:
                jpg = P.decrypt_media_frame(frags, session_key)
                if jpg: yield jpg
            frags = P.MediaFragments()
            started = True
        if started: frags.append(body)
    if started and frags:
        jpg = P.decrypt_media_frame(frags, session_key)
        if jpg: yield jpg

def extract_first_jpeg(streams, session_key):
    flow, key = select_session(streams, session_key)
    jpg = next(session_frames(streams, flow, key), None)
    if jpg is None:
        raise SystemExit("no complete JPEG in authenticated session")
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
