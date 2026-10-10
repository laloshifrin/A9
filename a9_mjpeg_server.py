#!/usr/bin/env python3
"""
a9_mjpeg_server.py - live MJPEG/snapshot server for an XCThings/Linklemo A9 camera.

Holds one PPRPC session to a camera you own, decodes the MJPEG stream continuously,
and serves it over HTTP so a browser or Home Assistant can show a live feed:

    python3 a9_mjpeg_server.py                 # discover (or read a9_camera.json)
    python3 a9_mjpeg_server.py 192.168.3.114   # a specific camera
    # then open http://127.0.0.1:8080/

Endpoints:
    /               small HTML viewer
    /stream.mjpg    multipart/x-mixed-replace MJPEG stream  (HA: "MJPEG IP Camera")
    /snapshot.jpg   the latest single frame                 (HA: "Generic Camera" still)
    /status         JSON: battery, firmware, connected/streaming (from cmd-2780 pushes)

Reuses the protocol/crypto from a9_live_snapshot.py (which reuses a9_aes.py), so
no external dependencies. Reconnects automatically if the camera drops the session.

Credentials come from --did/--secret, else a9_camera.json, else UDP discovery
(same precedence as the client). The stream is unauthenticated, so it binds to
127.0.0.1 by default; use --bind 0.0.0.0 to expose it to other hosts (e.g. HA on
another machine) and put it behind your own network controls.

For a camera you own.
"""
import sys, os, socket, time, threading, argparse, importlib.util
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

def _load_live():
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "a9_live_snapshot.py")
    s = importlib.util.spec_from_file_location("a9_live_snapshot", p)
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
    return m
L = _load_live()

# ---------- shared latest-frame state ----------
class Latest:
    def __init__(self):
        self.cond = threading.Condition()
        self.jpeg = None
        self.seq = 0
        self.stop = False
        self.connected = False
        self.status = None          # decoded cmd-2780 device status
        self.last_frame_ts = 0.0
    def publish(self, jpeg):
        with self.cond:
            self.jpeg = jpeg; self.seq += 1; self.last_frame_ts = time.time()
            self.cond.notify_all()
    def set_status(self, st):
        with self.cond:
            self.status = st
    def wait_newer(self, last_seq, timeout):
        with self.cond:
            if self.seq == last_seq:
                self.cond.wait(timeout)
            return self.jpeg, self.seq

CMD_STATUS = 2780   # camera device-status push (DID, battery, firmware, ...)

def decode_status_2780(pt):
    """Decode the plaintext of a cmd-2780 status push into a dict."""
    f = L.pb_parse(pt)
    inner = f.get(1, [b""])[0]
    if not isinstance(inner, bytes):
        return None
    o = L.pb_parse(inner)
    did = o.get(2, [b""])[0]
    did = did.decode("utf-8", "replace") if isinstance(did, bytes) else None
    st = {"did": did, "ts": o.get(6, [None])[0]}
    nested = o.get(4, [None])[0]
    if isinstance(nested, bytes):
        nf = L.pb_parse(nested)
        flags = nf.get(2, [None])[0]
        if isinstance(flags, bytes):
            st["status_bytes"] = flags.hex()
            # byte[1] tracked 70 -> 100 across captures (battery charging); byte[0]
            # changed too (06 -> 02), likely a charge/status flag. Confirm vs the app.
            if len(flags) >= 2:
                st["battery"] = flags[1]
            if len(flags) >= 1:
                st["flag0"] = flags[0]
        v = nf.get(1, [None])[0]       # constant 70 across captures; not battery
        if isinstance(v, int):
            st["field1"] = v
        info = [x.decode("utf-8", "replace") for x in nf.get(4, [])
                if isinstance(x, bytes) and x and all(32 <= c < 127 for c in x)]
        if info:
            st["info"] = info
    return st

# ---------- one camera session (reconnecting) ----------
# This camera stops the MEDIA stream after ~40s while keeping the control channel
# alive (it keeps sending 107 heartbeats). The long-stream keepalive the vendor app
# uses was never in our short "grab a photo" captures, so instead of guessing it we
# rely on what is proven: a fresh session streams reliably for ~40s. A stall watchdog
# in _session reconnects when frames stop, which keeps the feed continuous apart from
# a short (~2-3s) gap at each reconnect.
def camera_loop(ip, did, secret, state, timeout, start_seq):
    while not state.stop:
        try:
            _session(ip, did, secret, state, timeout, start_seq)   # returns on stall
        except Exception as e:
            state.connected = False
            if state.stop: break
            sys.stderr.write(f"[camera] session error: {e}; reconnecting in 2s\n")
            time.sleep(2)
            continue
        state.connected = False
        if not state.stop:
            time.sleep(0.2)   # clean stall return: reconnect promptly

def _session(ip, did, secret, state, timeout, start_seq):
    s = socket.create_connection((ip, L.PORT), timeout=timeout)
    rdr = L.FrameReader(s)
    seq = start_seq
    s.sendall(L.build_ctrl(seq, L.CMD_LANAUTH,
                           L.pb_field_bytes(2, did) + L.pb_field_bytes(3, secret))); seq += 1
    # session key from the LanAuth reply
    session_key = None; t_end = time.time() + timeout
    while time.time() < t_end and session_key is None:
        mt, mf, body = rdr.next_frame(timeout=timeout)
        if mt == 4:
            cmd, rseq, rpc, ct = L.ctrl_exhdr(body)
            if cmd == L.CMD_LANAUTH:
                pt = L.ctrl_decrypt(cmd, rseq, rpc, ct)
                if pt:
                    f = L.pb_parse(pt)
                    if 1 in f and isinstance(f[1][0], bytes):
                        session_key = f[1][0]
    if not session_key:
        raise RuntimeError("LanAuth gave no session key (wrong credentials?)")

    def answer(cmd, rseq, rpc, ct):
        if rpc != 0:
            return
        if cmd == L.CMD_PING:
            pt = L.ctrl_decrypt(cmd, rseq, rpc, ct)
            echo = L.pb_parse(pt).get(1, [0])[0] if pt else 0
            pong = (L.pb_varint_field(1, echo) + L.pb_varint_field(2, L.HB_CONST)
                    + L.pb_varint_field(3, int(time.time() * 1000)))
            s.sendall(L.build_ctrl(rseq, L.CMD_PING, pong, flag=0x0D))
        elif cmd == L.CMD_HELLO:
            s.sendall(L.build_ctrl(rseq, L.CMD_HELLO, L.pb_varint_field(1, 1), flag=0x0D))

    frags = []; started = False; last_media = time.time(); frame_count = 0
    def process(mt, body):
        nonlocal frags, started, last_media, frame_count
        if mt == 4:
            cmd, rseq, rpc, ct = L.ctrl_exhdr(body)
            answer(cmd, rseq, rpc, ct)
            if cmd == CMD_STATUS and ct and len(ct) % 16 == 0:
                pt = L.ctrl_decrypt(cmd, rseq, rpc, ct)
                if pt:
                    st = decode_status_2780(pt)
                    if st:
                        state.set_status(st)
        elif mt == 6:
            last_media = time.time()
            if (body[0] >> 7) == 1:                 # frame-start fragment
                frame_count += 1                     # for the keepalive ack (field 4)
                if started and frags:
                    jpg = L.decrypt_media_frame(frags, session_key)
                    if jpg:
                        state.publish(jpg)
                frags = [body]; started = True
            elif started:
                frags.append(body)

    def pump(dur):
        end = time.time() + dur
        while time.time() < end and not state.stop:
            try:
                mt, mf, body = rdr.next_frame(timeout=max(0.05, end - time.time()))
            except TimeoutError:
                break
            process(mt, body)

    # Answer the camera's initial 106/107 handshake, THEN start video, pumping
    # between sends. The camera will not start the stream if VideoPlay is sent
    # before its handshake is answered.
    s.sendall(L.build_ctrl(seq, L.CMD_HELLO, L.pb_varint_field(1, 1))); seq += 1
    pump(0.3)
    for cmd, pt in [(2653, b""), (2645, b""), (L.CMD_VIDEOPLAY, b"")]:
        s.sendall(L.build_ctrl(seq, cmd, pt)); seq += 1
        pump(0.15)
    state.connected = True
    last_media = time.time()
    sys.stderr.write("[camera] authenticated; streaming\n")

    # Keepalive: the camera throttles the stream unless the client sends a 107 ping
    # (~2/s) acknowledging frames received in field 4. With it, the stream runs
    # indefinitely; STALL is only a fallback for a genuine network drop.
    STALL = 6.0
    last_ping = 0.0
    while not state.stop:
        now = time.time()
        if now - last_ping >= 0.5:
            s.sendall(L.build_ctrl(seq, L.CMD_PING,
                                   L.pb_varint_field(1, int(now * 1000))
                                   + L.pb_varint_field(4, frame_count))); seq += 1
            last_ping = now
        try:
            mt, mf, body = rdr.next_frame(timeout=0.3)
            process(mt, body)
        except TimeoutError:
            pass
        if time.time() - last_media > STALL:
            sys.stderr.write("[camera] media stalled; reconnecting\n")
            break
    try: s.close()
    except OSError: pass

# ---------- HTTP ----------
VIEWER = (b"<!doctype html><meta name=viewport content='width=device-width,initial-scale=1'>"
          b"<title>A9 live</title><body style='margin:0;background:#111'>"
          b"<img src='/stream.mjpg' style='width:100%;height:auto;display:block'></body>")

def make_handler(state, first_timeout):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass  # quiet
        def _wait_first(self):
            end = time.time() + first_timeout
            while self.jpeg0() is None and time.time() < end and not state.stop:
                state.wait_newer(0, 0.5)
            return self.jpeg0()
        def jpeg0(self):
            with state.cond: return state.jpeg
        def do_GET(self):
            if self.path in ("/", "/index.html"):
                self.send_response(200); self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(VIEWER))); self.end_headers()
                self.wfile.write(VIEWER); return
            if self.path.startswith("/status"):
                import json as _json
                with state.cond:
                    st = dict(state.status) if state.status else {}
                    age = (time.time() - state.last_frame_ts) if state.last_frame_ts else None
                    st["connected"] = state.connected
                    st["streaming"] = bool(age is not None and age < 3)
                    st["last_frame_age_s"] = round(age, 1) if age is not None else None
                body = _json.dumps(st, indent=2).encode()
                self.send_response(200); self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store"); self.end_headers()
                self.wfile.write(body); return
            if self.path.startswith("/snapshot"):
                jpg = self._wait_first()
                if not jpg:
                    self.send_error(503, "no frame yet"); return
                self.send_response(200); self.send_header("Content-Type", "image/jpeg")
                self.send_header("Content-Length", str(len(jpg)))
                self.send_header("Cache-Control", "no-store"); self.end_headers()
                self.wfile.write(jpg); return
            if self.path.startswith("/stream"):
                if self._wait_first() is None:
                    self.send_error(503, "no frame yet"); return
                self.send_response(200)
                self.send_header("Content-Type", "multipart/x-mixed-replace; boundary=frame")
                self.send_header("Cache-Control", "no-store"); self.end_headers()
                last = 0
                try:
                    while not state.stop:
                        jpg, last = state.wait_newer(last, 5.0)
                        if jpg is None:
                            continue
                        hdr = (b"--frame\r\nContent-Type: image/jpeg\r\n"
                               b"Content-Length: " + str(len(jpg)).encode() + b"\r\n\r\n")
                        self.wfile.write(hdr); self.wfile.write(jpg); self.wfile.write(b"\r\n")
                except (BrokenPipeError, ConnectionResetError, OSError):
                    return
                return
            self.send_error(404)
    return H

def resolve_creds(a):
    did = a.did.encode() if a.did else None
    secret = a.secret.encode() if a.secret else None
    ip = None if (a.ip in (None, "auto")) else a.ip
    if not a.no_config and not (did and secret and ip):
        cfg = L._a9disc().load_config(a.config)
        if cfg:
            did = did or (cfg.get("did") and cfg["did"].encode())
            secret = secret or (cfg.get("secret") and cfg["secret"].encode())
            ip = ip or cfg.get("ip")
            sys.stderr.write(f"[*] loaded {a.config}\n")
    if not (did and secret) or ip is None:
        sys.stderr.write("[*] discovering camera over UDP…\n")
        d_did, d_secret, d_ip = L.creds_from_discovery(ip, a.did, a.disc_wait)
        did = did or d_did; secret = secret or d_secret; ip = ip or d_ip
    return ip, did, secret

def main():
    ap = argparse.ArgumentParser(description="live MJPEG/snapshot server for an A9 camera")
    ap.add_argument("ip", nargs="?", help="camera IP; omit to use config or UDP discovery")
    ap.add_argument("--did"); ap.add_argument("--secret")
    ap.add_argument("--config", default="a9_camera.json")
    ap.add_argument("--no-config", action="store_true")
    ap.add_argument("--disc-wait", type=float, default=3.0)
    ap.add_argument("--bind", default="127.0.0.1", help="HTTP bind address (default 127.0.0.1; 0.0.0.0 to expose)")
    ap.add_argument("--http-port", type=int, default=8080)
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--start-seq", type=int, default=3)
    a = ap.parse_args()

    ip, did, secret = resolve_creds(a)
    if not (ip and did and secret):
        sys.exit("could not resolve camera IP + credentials (try --did/--secret, a9_camera.json, or discovery)")
    sys.stderr.write(f"[*] camera {did.decode()} @ {ip}  (secret hidden)\n")

    state = Latest()
    th = threading.Thread(target=camera_loop, args=(ip, did, secret, state, a.timeout, a.start_seq), daemon=True)
    th.start()

    httpd = ThreadingHTTPServer((a.bind, a.http_port), make_handler(state, a.timeout + 4))
    url = f"http://{a.bind}:{a.http_port}/"
    sys.stderr.write(f"[*] serving {url}  (stream {url}stream.mjpg , still {url}snapshot.jpg , status {url}status)\n")
    if a.bind == "0.0.0.0":
        sys.stderr.write("[!] bound to 0.0.0.0: the feed is UNAUTHENTICATED and reachable on the LAN.\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        state.stop = True
        with state.cond: state.cond.notify_all()
        httpd.shutdown()

if __name__ == "__main__":
    main()
