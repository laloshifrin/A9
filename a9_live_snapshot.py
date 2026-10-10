#!/usr/bin/env python3
"""
a9_live_snapshot.py - ACTIVE local snapshot client for XCThings/Linklemo A9 cameras.

    # zero-input: discover the camera, read its own credentials, grab a frame:
    python3 a9_live_snapshot.py -o snapshot.jpg

    # credentials from a prior capture, or passed directly:
    python3 a9_live_snapshot.py 192.168.9.252 --creds-from capture.pcap -o snapshot.jpg
    python3 a9_live_snapshot.py 192.168.9.252 --did PPHAABBCCDDEE0011 \
        --secret '$L9$0123456789abcdef0123456789abcdef' -o snapshot.jpg

Connects to a camera YOU own on tcp/20190, does ipc_LanAuth + ipc_VideoPlay, decrypts
one MJPEG frame, writes JPEG. With no IP/credentials it runs UDP discovery to find the
camera and read its DID + IP + secret. Protocol/crypto live in a9_proto; see PROTOCOL.md.

Deps: Python stdlib (a9_proto uses pycryptodome if present, else the bundled a9_aes).

WARNING: DID / paired_auth_secret / session_key are device credentials. Keep them private.
"""
import sys, os, socket, time, argparse
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # find siblings under -I / any cwd
import a9_proto as P
import a9_discover as D

def send_ctrl(s, seq, cmd, plaintext=b""):
    s.sendall(P.build_ctrl(seq, cmd, plaintext))
    return seq + 1

# ---------- credential / command sourcing from a pcap ----------
def capture_client_stream(path):
    streams = P.read_pcap_streams(path)
    clients = [stream for flow, stream in streams.items() if flow[3] == P.PORT]
    if len(clients) != 1:
        raise SystemExit("capture must contain exactly one client session")
    return clients[0]

def creds_from_pcap(path):
    matches = []
    for mt, flag, body in P.iter_pprpc(capture_client_stream(path)):
        if mt != 4: continue
        cmd, seq, rpc, ct = P.ctrl_exhdr(body)
        if cmd != P.CMD_LANAUTH or rpc != 0: continue
        pt = P.ctrl_decrypt(cmd, seq, rpc, ct)
        fields = P.pb_parse(pt) if pt else {}
        did = fields.get(2, [None])[0]
        secret = fields.get(3, [None])[0]
        if isinstance(did, bytes) and isinstance(secret, bytes):
            matches.append((did, secret))
    if len(matches) > 1:
        raise SystemExit("capture contains multiple LanAuth requests")
    return matches[0] if matches else (None, None)

def replay_commands_from_pcap(path):
    """Ordered (cmd, plaintext) for the C->S CTRL commands the app sent, excluding
    LanAuth and heartbeats. Mirrors the app's exact pre-MEDIA sequence if --full-replay."""
    out = []
    for mt, flag, body in P.iter_pprpc(capture_client_stream(path)):
        if mt != 4: continue
        cmd, seq, rpc, ct = P.ctrl_exhdr(body)
        if rpc != 0 or cmd in (P.CMD_LANAUTH, P.CMD_HELLO, P.CMD_PING): continue
        pt = b"" if not ct else P.ctrl_decrypt(cmd, seq, rpc, ct)
        if pt is not None:
            out.append((cmd, pt))
    return out

# ---------- main ----------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ip", nargs="?", help="camera IP; omit (or 'auto') to UDP-discover it")
    ap.add_argument("--did"); ap.add_argument("--secret")
    ap.add_argument("--creds-from", help="pcap to lift DID+secret from")
    ap.add_argument("--disc-wait", type=float, default=3.0, help="seconds to wait for discovery")
    ap.add_argument("--config", default=D.CONFIG_DEFAULT,
                    help="config file with did/ip/secret; used if present to skip discovery")
    ap.add_argument("--no-config", action="store_true", help="ignore config; force discovery")
    ap.add_argument("--save-config", action="store_true", help="write did/ip/secret to --config")
    ap.add_argument("-o", "--out", help="output file (default stdout)")
    ap.add_argument("--start-seq", type=int, default=3)
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--set-resolution", type=int, metavar="CODE",
                    help="cmd 2612 {2:CODE} (10=HD, 15=UHD); affects the recording stream, "
                         "the LIVE preview stays 640x480")
    ap.add_argument("--night-mode", type=int, metavar="MODE", help="cmd 2635 {2:MODE}")
    ap.add_argument("--debug", action="store_true", help="log every frame sent/received")
    ap.add_argument("--full-replay", action="store_true",
                    help="replay the whole captured command sequence (from --creds-from)")
    a = ap.parse_args()

    did, secret = a.did, a.secret
    if a.creds_from and not (did and secret):
        p_did, p_secret = creds_from_pcap(a.creds_from)
        if p_did and p_secret:
            if did and did != p_did.decode():
                raise SystemExit("--did does not match the capture's camera")
            did = did or p_did.decode()
            secret = secret or p_secret.decode()
    target_ip, did, secret = D.resolve_credentials(
        None if a.ip in (None, "auto") else a.ip, did, secret,
        a.config, a.no_config, a.disc_wait)

    if a.save_config and did and secret and target_ip:
        D.save_config(a.config, {"did": did.decode(), "ip": target_ip,
                                 "port": P.PORT, "secret": secret.decode()})
        sys.stderr.write(f"[*] saved {a.config} (contains the secret; 0600, keep local)\n")

    if not (did and secret):
        sys.exit("no credentials: pass --did/--secret or --creds-from <pcap>, or ensure the "
                 "camera answers UDP discovery on this network")
    if not target_ip:
        sys.exit("no camera IP: pass it as an argument, or let discovery find it")
    sys.stderr.write(f"[*] DID={did.decode()}  target={target_ip}  (secret hidden)\n")

    s = socket.create_connection((target_ip, P.PORT), timeout=a.timeout)
    try:
        jpg = _grab(s, did, secret, a)
    finally:
        try: s.close()
        except OSError: pass
    if not jpg:
        sys.exit("no complete MEDIA frame received")
    sys.stderr.write(f"[*] recovered JPEG: {len(jpg)} bytes\n")
    if a.out:
        open(a.out, "wb").write(jpg); sys.stderr.write(f"[*] wrote {a.out}\n")
    else:
        sys.stdout.buffer.write(jpg)

def _grab(s, did, secret, a):
    rdr = P.FrameReader(s)
    seq = a.start_seq

    # 1) LanAuth -> session key
    s.sendall(P.build_ctrl(seq, P.CMD_LANAUTH,
                           P.pb_field_bytes(2, did) + P.pb_field_bytes(3, secret))); seq += 1
    sys.stderr.write("[*] sent ipc_LanAuth\n")
    session_key = None
    t_end = time.time() + a.timeout
    while time.time() < t_end and session_key is None:
        mt, mf, body = rdr.next_frame(timeout=a.timeout)
        if mt == 4:
            cmd, rseq, rpc, ct = P.ctrl_exhdr(body)
            if cmd == P.CMD_LANAUTH:
                pt = P.ctrl_decrypt(cmd, rseq, rpc, ct)
                if pt:
                    f = P.pb_parse(pt)
                    if 1 in f and isinstance(f[1][0], bytes):
                        session_key = f[1][0]
    if not session_key:
        sys.exit("LanAuth did not yield a session key (wrong credentials?)")
    sys.stderr.write(f"[*] session key received ({len(session_key)} chars)\n")

    def answer_heartbeats(cmd, rseq, rpc, ct):
        if rpc != 0:
            return
        if cmd == P.CMD_PING:
            pt = P.ctrl_decrypt(cmd, rseq, rpc, ct)
            echo = P.pb_parse(pt).get(1, [0])[0] if pt else 0
            pong = (P.pb_varint_field(1, echo) + P.pb_varint_field(2, P.HB_CONST)
                    + P.pb_varint_field(3, int(time.time() * 1000)))
            s.sendall(P.build_ctrl(rseq, P.CMD_PING, pong, flag=0x0D))
        elif cmd == P.CMD_HELLO:
            s.sendall(P.build_ctrl(rseq, P.CMD_HELLO, P.pb_varint_field(1, 1), flag=0x0D))

    def pump(dur):
        media = P.MediaFragments(); end = time.time() + dur
        while time.time() < end:
            try:
                mt, mf, body = rdr.next_frame(timeout=max(0.05, end - time.time()))
            except TimeoutError:
                break
            if mt == 4:
                cmd, rseq, rpc, ct = P.ctrl_exhdr(body)
                if a.debug: sys.stderr.write(f"    <- CTRL cmd={cmd} seq={rseq} rpc={rpc} len={len(ct)}\n")
                answer_heartbeats(cmd, rseq, rpc, ct)
            elif mt == 6:
                media.append(body)
        return media

    seq = send_ctrl(s, seq, P.CMD_HELLO, P.pb_varint_field(1, 1)); pump(0.2)
    if a.set_resolution is not None:
        seq = send_ctrl(s, seq, P.CMD_SETRES, P.pb_varint_field(2, a.set_resolution)); pump(0.1)
        sys.stderr.write(f"[*] set-resolution code={a.set_resolution} (recording stream)\n")
    if a.night_mode is not None:
        seq = send_ctrl(s, seq, P.CMD_NIGHT, P.pb_varint_field(2, a.night_mode)); pump(0.1)
        sys.stderr.write(f"[*] night-mode={a.night_mode}\n")

    if a.full_replay and a.creds_from:
        replay = replay_commands_from_pcap(a.creds_from)
    else:
        replay = [(2653, b""), (2645, b""), (P.CMD_VIDEOPLAY, b"")]
    early_media = P.MediaFragments()
    for cmd, pt in replay:
        seq = send_ctrl(s, seq, cmd, pt)
        if a.debug: sys.stderr.write(f"  -> cmd={cmd} payload={len(pt)}B\n")
        for body in pump(0.12): early_media.append(body)
    sys.stderr.write(f"[*] replayed {len(replay)} commands; collecting MEDIA…\n")

    # collect one complete MEDIA frame, answering heartbeats so we stay connected
    frags = P.MediaFragments(); started = False; jpg = None
    def feed(body):
        nonlocal frags, started, jpg
        if (body[0] >> 7) == 1:
            if started and frags:
                j = P.decrypt_media_frame(frags, session_key)
                if j: jpg = j; return True
            frags = P.MediaFragments(); frags.append(body); started = True
        elif started:
            frags.append(body)
        return False
    for body in early_media:
        if feed(body): break
    t_end = time.time() + a.timeout
    while jpg is None and time.time() < t_end:
        try:
            mt, mf, body = rdr.next_frame(timeout=a.timeout)
        except TimeoutError:
            break
        if mt == 4:
            cmd, rseq, rpc, ct = P.ctrl_exhdr(body)
            answer_heartbeats(cmd, rseq, rpc, ct)
        elif mt == 6:
            if feed(body): break
    if jpg is None and frags:
        jpg = P.decrypt_media_frame(frags, session_key)
    return jpg

if __name__ == "__main__":
    main()
