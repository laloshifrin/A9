#!/usr/bin/env python3
"""
a9_live_snapshot.py - ACTIVE local snapshot client for XCThings/Linklemo A9 cameras.

    # zero-input: discover the camera, harvest its own credentials, grab a frame:
    python3 a9_live_snapshot.py -o snapshot.jpg

    # credentials straight from a prior capture of your own camera:
    python3 a9_live_snapshot.py 192.168.9.252 --creds-from capture.pcap -o snapshot.jpg

    # or pass them directly:
    python3 a9_live_snapshot.py 192.168.9.252 --did PPHAABBCCDDEE0011 \
        --secret '$L9$0123456789abcdef0123456789abcdef' -o snapshot.jpg

Connects to a camera YOU own on tcp/20190, does ipc_LanAuth, ipc_VideoPlay,
receives the MJPEG MEDIA stream, decrypts and reassembles one frame, writes JPEG.
With no IP/credentials it runs UDP discovery (a9_discover.py) to find the camera
and read its DID + IP + paired_auth_secret directly off the wire.
See PROTOCOL.md for the full protocol. Deps: Python stdlib + pycryptodome.

WARNING: DID / paired_auth_secret / session_key are device credentials — keep private.
"""
import sys, socket, struct, hashlib, argparse, time, os

def _load_aes():
    """Prefer pycryptodome; fall back to bundled pure-Python a9_aes (stdlib-only,
    so this runs with no internet / no pip, e.g. joined to the camera's AP)."""
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
CMD_LANAUTH = 2650
CMD_VIDEOPLAY = 2610
CMD_SETRES  = 2612   # resolution/stream-type: payload {2: code}; observed 10=HD, 15=UHD
CMD_NIGHT   = 2635   # night mode: payload {2: mode}; observed 1 and 2
CMD_HELLO   = 106    # post-LanAuth "ready" ping: {1:1}
CMD_PING    = 107    # heartbeat; camera pings (rpc=0), client MUST pong (rpc=1) or it drops us
HB_CONST    = 18446744073709551586   # field 2 constant observed in 107 pongs
# NOTE: CMD_SETRES changes the RECORDING/main stream; the LIVE preview stays 640x480.

# ---------- varint ----------
def enc_varint(n):
    out = b""
    while True:
        b = n & 0x7f; n >>= 7
        out += bytes([b | (0x80 if n else 0)])
        if not n: break
    return out

def dec_varint(buf, i):
    shift = val = 0
    while i < len(buf):
        x = buf[i]; i += 1
        val |= (x & 0x7f) << shift
        if not (x & 0x80): return val, i
        shift += 7
    raise ValueError("truncated varint")

# ---------- protobuf ----------
def pb_field_bytes(field, data):
    return enc_varint((field << 3) | 2) + enc_varint(len(data)) + data

def pb_parse(buf):
    out = {}; i = 0; n = len(buf)
    while i < n:
        try: tag, i = dec_varint(buf, i)
        except ValueError: break
        f, wt = tag >> 3, tag & 7
        try:
            if wt == 0: v, i = dec_varint(buf, i)
            elif wt == 2:
                ln, i = dec_varint(buf, i)
                if i + ln > n: break
                v = buf[i:i+ln]; i += ln
            elif wt == 5:
                if i+4 > n: break
                v = struct.unpack("<I", buf[i:i+4])[0]; i += 4
            elif wt == 1:
                if i+8 > n: break
                v = struct.unpack("<Q", buf[i:i+8])[0]; i += 8
            else: break
        except Exception: break
        out.setdefault(f, []).append(v)
    return out

# ---------- CTRL crypto ----------
def ctrl_key(cmd, seq, rpc):
    return hashlib.md5(b"%s,ID:%d-SEQ:%d-RPC:%d" % (CTRL_SECRET, cmd, seq, rpc)).hexdigest().encode()

def ctrl_encrypt(cmd, seq, rpc, plaintext):
    if not plaintext:
        return b""
    key = ctrl_key(cmd, seq, rpc)
    pad = 16 - (len(plaintext) % 16)
    pt = plaintext + bytes([pad]) * pad
    return aes_cbc_encrypt(key, key[:16], pt)

def ctrl_decrypt(cmd, seq, rpc, ct):
    if len(ct) == 0 or len(ct) % 16: return None
    key = ctrl_key(cmd, seq, rpc)
    pt = aes_cbc_decrypt(key, key[:16], ct)
    pad = pt[-1]
    return pt[:-pad] if 1 <= pad <= 16 and pt.endswith(bytes([pad]) * pad) else None

# ---------- framing ----------
def build_ctrl(seq, cmd, plaintext=b"", flag=0x0C):
    rpc = flag & 3
    payload = ctrl_encrypt(cmd, seq, rpc, plaintext)
    exhdr = enc_varint(seq) + enc_varint(cmd) + bytes([flag])
    if rpc == 1:                      # replies carry an extra trailing varint (observed 0)
        exhdr += enc_varint(0)
    body = exhdr + payload
    return bytes([0x48]) + enc_varint(len(body)) + body

def ctrl_exhdr(body):
    p = 0
    seq, p = dec_varint(body, p)
    cmd, p = dec_varint(body, p)
    flag = body[p]; p += 1
    rpc = flag & 3
    if rpc == 1:
        _, p = dec_varint(body, p)
    return cmd, seq, rpc, body[p:]

def pb_varint_field(field, value):
    return enc_varint((field << 3) | 0) + enc_varint(value)

def send_ctrl(sock, seq, cmd, plaintext=b""):
    sock.sendall(build_ctrl(seq, cmd, plaintext))
    return seq + 1

def media_exhdr(body):
    p = 0
    flag = body[p] >> 7; p += 1
    p += 1
    vs = []
    for _ in range(7):
        v, p = dec_varint(body, p); vs.append(v)
    return flag, vs[0], vs[1], vs[2], vs[3], body[p:]

# ---------- stream reader ----------
class FrameReader:
    def __init__(self, sock):
        self.s = sock; self.buf = b""
    def _fill(self, timeout=5.0):
        self.s.settimeout(timeout)
        chunk = self.s.recv(65536)
        if not chunk: raise ConnectionError("camera closed connection")
        self.buf += chunk
    def next_frame(self, timeout=5.0):
        """return (msgtype, msgflag, body) or raise on timeout/close."""
        deadline = time.time() + timeout
        while True:
            # try to parse a complete frame from buffer
            b = self.buf
            if b:
                ctrl = b[0]; msgtype = (ctrl >> 4) & 0xF
                if msgtype in (2,3,4,5,6,7,8):
                    try:
                        remain, j = dec_varint(b, 1)
                        if j + remain <= len(b):
                            body = b[j:j+remain]
                            self.buf = b[j+remain:]
                            return msgtype, ctrl & 0xF, body
                    except ValueError:
                        pass
                else:
                    self.buf = b[1:]; continue  # resync
            if time.time() > deadline:
                raise TimeoutError("no complete frame within timeout")
            self._fill(max(0.2, deadline - time.time()))

# ---------- MEDIA frame reassembly ----------
def decrypt_media_frame(frags, session_key):
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
    return blob[soi:eoi+2] if (soi >= 0 and eoi >= 0) else None

# ---------- credential sourcing ----------
def creds_from_pcap(path):
    import importlib.util, os
    spec = importlib.util.spec_from_file_location(
        "X", os.path.join(os.path.dirname(os.path.abspath(__file__)), "extract_a9_snapshot.py"))
    X = importlib.util.module_from_spec(spec); spec.loader.exec_module(X)
    streams = X.read_pcap_streams(path)
    did = secret = None
    for (s_, sp, d_, dp), st in streams.items():
        if dp != PORT: continue
        for mt, flag, body in X.iter_pprpc(st):
            if mt != 4: continue
            cmd, seq, rpc, ct = ctrl_exhdr(body)
            if cmd == CMD_LANAUTH:
                pt = ctrl_decrypt(cmd, seq, rpc, ct)
                if pt:
                    f = pb_parse(pt)
                    if 2 in f and 3 in f:
                        return f[2][0], f[3][0]
    return None, None

def _a9disc():
    """Load the sibling a9_discover.py module (discovery + config helpers)."""
    import importlib.util
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "a9_discover.py")
    s = importlib.util.spec_from_file_location("a9_discover", p)
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
    return m

def creds_from_discovery(ip=None, did_filter=None, wait=3.0):
    """Run UDP discovery and return (did, secret, ip) for the matching camera.
    did_filter (str) picks a specific camera when several answer."""
    D = _a9disc()
    devs = D.discover(ip, wait=wait)
    if not devs:
        return None, None, None
    dev = next((d for d in devs if d.get("did") == did_filter), None) if did_filter else None
    dev = dev or devs[0]
    did = dev["did"].encode() if dev.get("did") else None
    secret = dev["secret"].encode() if dev.get("secret") else None
    return did, secret, dev.get("ip")

def replay_commands_from_pcap(path):
    """Ordered list of (cmd, plaintext) for the C->S CTRL commands the app sent,
    excluding LanAuth (sent fresh) and heartbeats (106/107, handled dynamically).
    Used to mirror the app's exact pre-MEDIA sequence (VideoPlay, 2780, 2649, …)."""
    import importlib.util, os
    spec = importlib.util.spec_from_file_location(
        "X", os.path.join(os.path.dirname(os.path.abspath(__file__)), "extract_a9_snapshot.py"))
    X = importlib.util.module_from_spec(spec); spec.loader.exec_module(X)
    streams = X.read_pcap_streams(path)
    out = []
    for (s_, sp, d_, dp), st in streams.items():
        if dp != PORT: continue
        for mt, flag, body in X.iter_pprpc(st):   # stream order == send order
            if mt != 4: continue
            cmd, seq, rpc, ct = ctrl_exhdr(body)
            if cmd in (CMD_LANAUTH, CMD_HELLO, CMD_PING): continue
            pt = b"" if len(ct) == 0 else ctrl_decrypt(cmd, seq, rpc, ct)
            if pt is not None:                # keep empty-payload cmds (VideoPlay, 2653, 2649…)
                out.append((cmd, pt))
    return out

# ---------- main ----------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ip", nargs="?", help="camera IP; omit (or 'auto') to UDP-discover it")
    ap.add_argument("--did"); ap.add_argument("--secret")
    ap.add_argument("--creds-from", help="pcap to lift DID+secret from")
    ap.add_argument("--disc-wait", type=float, default=3.0,
                    help="seconds to wait for discovery replies (default 3)")
    ap.add_argument("--config", default="a9_camera.json",
                    help="config file with did/ip/secret; used if present to skip discovery "
                         "(create with: a9_discover.py --save-config)")
    ap.add_argument("--no-config", action="store_true",
                    help="ignore the config file and force fresh discovery")
    ap.add_argument("--save-config", action="store_true",
                    help="after resolving, write did/ip/secret to --config for next time")
    ap.add_argument("-o", "--out", help="output file (default stdout)")
    ap.add_argument("--start-seq", type=int, default=3)
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--set-resolution", type=int, metavar="CODE",
                    help="cmd 2612 {2:CODE} (observed 10=HD, 15=UHD). Affects the "
                         "recording/main stream; the LIVE preview stays 640x480.")
    ap.add_argument("--night-mode", type=int, metavar="MODE",
                    help="cmd 2635 {2:MODE} (observed 1 and 2)")
    ap.add_argument("--debug", action="store_true", help="log every frame sent/received")
    ap.add_argument("--full-replay", action="store_true",
                    help="replay the entire captured command sequence (from --creds-from) "
                         "instead of the lean essentials; use if the lean path doesn't start video")
    a = ap.parse_args()

    did = a.did.encode() if a.did else None
    secret = a.secret.encode() if a.secret else None
    target_ip = None if (a.ip in (None, "auto")) else a.ip
    if a.creds_from and not (did and secret):
        did, secret = creds_from_pcap(a.creds_from)

    # config file: if present, use it instead of discovery
    if not a.no_config and not (did and secret and target_ip):
        cfg = _a9disc().load_config(a.config)
        if cfg:
            if cfg.get("did") and not did: did = cfg["did"].encode()
            if cfg.get("secret") and not secret: secret = cfg["secret"].encode()
            if cfg.get("ip") and target_ip is None: target_ip = cfg["ip"]
            sys.stderr.write(f"[*] loaded {a.config} (did={cfg.get('did')} ip={cfg.get('ip')})\n")

    # auto-discover to fill in whatever's still missing: credentials and/or the camera IP
    if not (did and secret) or target_ip is None:
        sys.stderr.write("[*] discovering camera over UDP…\n")
        d_did, d_secret, d_ip = creds_from_discovery(target_ip, a.did, a.disc_wait)
        if d_did and not did: did = d_did
        if d_secret and not secret: secret = d_secret
        if d_ip and target_ip is None: target_ip = d_ip
        if d_did:
            sys.stderr.write(f"[*] discovered {d_did.decode()} at {d_ip} "
                             f"(secret {'recovered' if d_secret else 'not in reply'})\n")

    if a.save_config and did and secret and target_ip:
        _a9disc().save_config(a.config, {"did": did.decode(), "ip": target_ip,
                                         "port": PORT, "secret": secret.decode()})
        sys.stderr.write(f"[*] saved {a.config} (contains the secret; 0600, keep local)\n")

    if not (did and secret):
        sys.exit("no credentials: pass --did/--secret or --creds-from <pcap>, or ensure the "
                 "camera answers UDP discovery on this network")
    if not target_ip:
        sys.exit("no camera IP: pass it as an argument, or let discovery find it")
    sys.stderr.write(f"[*] DID={did.decode()}  target={target_ip}  (secret hidden)\n")

    s = socket.create_connection((target_ip, PORT), timeout=a.timeout)
    rdr = FrameReader(s)
    seq = a.start_seq

    # 1) LanAuth
    lanauth_pt = pb_field_bytes(2, did) + pb_field_bytes(3, secret)
    s.sendall(build_ctrl(seq, CMD_LANAUTH, lanauth_pt)); seq += 1
    sys.stderr.write("[*] sent ipc_LanAuth\n")

    session_key = None
    t_end = time.time() + a.timeout
    while time.time() < t_end and session_key is None:
        mt, mf, body = rdr.next_frame(timeout=a.timeout)
        if mt == 4:
            cmd, rseq, rpc, ct = ctrl_exhdr(body)
            if cmd == CMD_LANAUTH:
                pt = ctrl_decrypt(cmd, rseq, rpc, ct)
                if pt:
                    f = pb_parse(pt)
                    if 1 in f and isinstance(f[1][0], bytes):
                        session_key = f[1][0]
    if not session_key:
        sys.exit("LanAuth did not yield a session key (wrong credentials?)")
    sys.stderr.write(f"[*] session key received ({len(session_key)} chars)\n")

    def answer_heartbeats(cmd, rseq, rpc, ct):
        """Respond to camera-initiated CTRL so it doesn't drop the connection."""
        if rpc != 0:
            return
        if cmd == CMD_PING:
            pt = ctrl_decrypt(cmd, rseq, rpc, ct)
            echo = pb_parse(pt).get(1, [0])[0] if pt else 0
            pong = (pb_varint_field(1, echo) + pb_varint_field(2, HB_CONST)
                    + pb_varint_field(3, int(time.time() * 1000)))
            s.sendall(build_ctrl(rseq, CMD_PING, pong, flag=0x0D))
        elif cmd == CMD_HELLO:
            s.sendall(build_ctrl(rseq, CMD_HELLO, pb_varint_field(1, 1), flag=0x0D))

    def pump(dur):
        """Briefly process incoming frames, answering heartbeats; return MEDIA bodies."""
        media = []; end = time.time() + dur
        while time.time() < end:
            try:
                mt, mf, body = rdr.next_frame(timeout=max(0.05, end - time.time()))
            except TimeoutError:
                break
            if mt == 4:
                cmd, rseq, rpc, ct = ctrl_exhdr(body)
                if a.debug: sys.stderr.write(f"    <- CTRL cmd={cmd} seq={rseq} rpc={rpc} len={len(ct)}\n")
                answer_heartbeats(cmd, rseq, rpc, ct)
            elif mt == 6:
                if a.debug: sys.stderr.write(f"    <- MEDIA len={len(body)} start={body[0]>>7}\n")
                media.append(body)
            elif a.debug:
                sys.stderr.write(f"    <- type{mt} len={len(body)}\n")
        return media

    # post-LanAuth "ready" ping, like the app
    seq = send_ctrl(s, seq, CMD_HELLO, pb_varint_field(1, 1)); pump(0.2)

    if a.set_resolution is not None:
        seq = send_ctrl(s, seq, CMD_SETRES, pb_varint_field(2, a.set_resolution)); pump(0.1)
        sys.stderr.write(f"[*] set-resolution code={a.set_resolution} "
                         f"(recording stream; live preview stays 640x480)\n")
    if a.night_mode is not None:
        seq = send_ctrl(s, seq, CMD_NIGHT, pb_varint_field(2, a.night_mode)); pump(0.1)
        sys.stderr.write(f"[*] night-mode={a.night_mode}\n")

    # Lean path (default): Discovery/setup pair + VideoPlay is enough to start video.
    # --full-replay re-sends the whole captured sequence (fallback if lean fails).
    if a.full_replay and a.creds_from:
        replay = replay_commands_from_pcap(a.creds_from)
    else:
        replay = [(2653, b""), (2645, b""), (CMD_VIDEOPLAY, b"")]
    early_media = []
    for cmd, pt in replay:
        seq = send_ctrl(s, seq, cmd, pt)
        if a.debug: sys.stderr.write(f"  -> cmd={cmd} payload={len(pt)}B\n")
        early_media += pump(0.12)
    sys.stderr.write(f"[*] replayed {len(replay)} commands; collecting MEDIA…\n")

    # 3) collect one complete MEDIA frame, answering heartbeats so we stay connected
    frags = []; started = False; jpg = None
    def feed(body):
        nonlocal frags, started, jpg
        is_start = (body[0] >> 7) == 1
        if is_start:
            if started and frags:
                j = decrypt_media_frame(frags, session_key)
                if j: jpg = j; return True
            frags = [body]; started = True
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
            cmd, rseq, rpc, ct = ctrl_exhdr(body)
            if a.debug: sys.stderr.write(f"    <- CTRL cmd={cmd} seq={rseq} rpc={rpc}\n")
            answer_heartbeats(cmd, rseq, rpc, ct)
        elif mt == 6:
            if a.debug: sys.stderr.write(f"    <- MEDIA len={len(body)} start={body[0]>>7}\n")
            if feed(body): break
    if jpg is None and frags:
        jpg = decrypt_media_frame(frags, session_key)
    s.close()
    if not jpg:
        sys.exit("no complete MEDIA frame received")
    sys.stderr.write(f"[*] recovered JPEG: {len(jpg)} bytes\n")
    if a.out:
        open(a.out, "wb").write(jpg); sys.stderr.write(f"[*] wrote {a.out}\n")
    else:
        sys.stdout.buffer.write(jpg)

if __name__ == "__main__":
    main()
