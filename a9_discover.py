#!/usr/bin/env python3
"""
a9_discover.py - LAN discovery for XCThings/Linklemo A9 cameras.

    python3 a9_discover.py              # broadcast-scan the local network
    python3 a9_discover.py 192.168.9.252   # also probe one IP directly

Sends the UDP discovery ping (port 20190) and decodes the camera's reply. The
reply is an ordinary CTRL frame with a 2-byte `51 70` UDP prefix (see PROTOCOL.md
section J); cmd 2600, body encrypted with the static CTRL key. The decoded
protobuf carries the camera's DID, IP, port, firmware, and its own
`paired_auth_secret` in cleartext.

Importable: discover(ip=None, wait=3.0) -> list of dicts
    {did, ip, netmask, port, fw, secret, skill}

Stdlib only (uses a9_aes.py fallback), so it runs with no pip / no internet,
e.g. on a laptop joined to the camera's AP.

WARNING: the recovered `secret` is a device credential. Keep it private; do not
commit it or paste it into shared artifacts. The camera handing it out to any
unauthenticated UDP sender is a real weakness - treat the output accordingly.
"""
import sys, socket, struct, hashlib, time, os, argparse, gzip, json

PORT = 20190
CONFIG_DEFAULT = "a9_camera.json"
def _ctrl_secret():
    import importlib.util
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "a9_keys.py")
    s = importlib.util.spec_from_file_location("a9_keys", p)
    m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
    return m.ctrl_prekey()
CTRL_SECRET = _ctrl_secret()
UDP_PREFIX = b"\x51\x70"
CMD_DEVINFO = 2600            # discovery / device-info command

def _load_aes():
    try:
        from Crypto.Cipher import AES
        return lambda k, iv, d: AES.new(k, AES.MODE_CBC, iv).decrypt(d)
    except Exception:
        import importlib.util
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "a9_aes.py")
        s = importlib.util.spec_from_file_location("a9_aes", p)
        m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
        return lambda k, iv, d: m.AESCBC(k, iv).decrypt(d)
_aes_dec = _load_aes()

def _rv(b, i):
    sh = v = 0
    while i < len(b):
        x = b[i]; i += 1; v |= (x & 0x7f) << sh
        if not x & 0x80: return v, i
        sh += 7
    raise ValueError("truncated varint")

def _pb_parse(buf):
    out = {}; i = 0; n = len(buf)
    while i < n:
        try: tag, i = _rv(buf, i)
        except ValueError: break
        f, wt = tag >> 3, tag & 7
        try:
            if wt == 0: v, i = _rv(buf, i)
            elif wt == 2:
                ln, i = _rv(buf, i)
                if i + ln > n: break
                v = buf[i:i+ln]; i += ln
            elif wt == 5: v = struct.unpack("<I", buf[i:i+4])[0]; i += 4
            elif wt == 1: v = struct.unpack("<Q", buf[i:i+8])[0]; i += 8
            else: break
        except Exception: break
        out.setdefault(f, []).append(v)
    return out

def ping_packet():
    """8-byte discovery ping: 51 70 + CTRL(0x48) + varint(len=4) + 'cmd 2600, rpc 0, empty'."""
    # body = seq=1, cmd=2600, flag=0x0c (rpc 0). Matches the app's broadcast ping byte-for-byte.
    body = b"\x01" + b"\xa8\x14" + b"\x0c"      # seq=1, cmd=2600(varint a8 14), flag=0c
    return UDP_PREFIX + b"\x48" + bytes([len(body)]) + body

def parse_reply(data):
    """Decode a discovery reply into a device dict, or None if it isn't one."""
    if len(data) < 6 or data[:2] != UDP_PREFIX:
        return None
    tf = data[2]
    if (tf >> 4) != 4:                          # must be a CTRL frame
        return None
    try:
        ln, i = _rv(data, 3)
        body = data[i:i+ln]
        seq, p = _rv(body, 0)
        cmd, p = _rv(body, p)
        flag = body[p]; p += 1; rpc = flag & 3
        if rpc == 1:
            _, p = _rv(body, p)
        ct = body[p:]
        if not ct or len(ct) % 16:
            return None
        key = hashlib.md5(b"%s,ID:%d-SEQ:%d-RPC:%d" % (CTRL_SECRET, cmd, seq, rpc)).hexdigest().encode()
        pt = _aes_dec(key, key[:16], ct[:len(ct) - len(ct) % 16])
        pad = pt[-1]
        if 1 <= pad <= 16 and pt.endswith(bytes([pad]) * pad):
            pt = pt[:-pad]
        f = _pb_parse(pt)
        def s(field):
            v = f.get(field, [None])[0]
            return v.decode("utf-8", "replace") if isinstance(v, bytes) else v
        skill = None
        if 9 in f and isinstance(f[9][0], bytes) and f[9][0][:2] == b"\x1f\x8b":
            try: skill = json.loads(gzip.decompress(f[9][0]))
            except Exception: skill = None
        did = s(1)
        if not did:
            return None
        return {"did": did, "ip": s(2), "netmask": s(3),
                "port": f.get(4, [PORT])[0], "fw": s(5),
                "secret": s(8), "skill": skill}
    except Exception:
        return None

def discover(ip=None, wait=3.0, rounds=2):
    """Broadcast (and optionally unicast) the ping; return deduped device dicts."""
    pkt = ping_packet()
    found = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind(("", 0)); s.settimeout(0.3)
    try:
        for _ in range(rounds):
            for dst in (("255.255.255.255", PORT),) + (((ip, PORT),) if ip else ()):
                try: s.sendto(pkt, dst)
                except OSError: pass
            end = time.time() + wait
            while time.time() < end:
                try:
                    data, addr = s.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break
                dev = parse_reply(data)
                if dev:
                    dev["reported_ip"] = dev.get("ip")   # what the camera claims (may be stale)
                    dev["src_ip"] = addr[0]              # where the reply actually came from
                    dev["ip"] = addr[0]                  # authoritative for connecting
                    found[dev["did"]] = dev
            if found and ip:
                break
    finally:
        s.close()
    return list(found.values())

def save_config(path, dev):
    """Write a camera's connection details to a JSON config the client can reuse.
    Contains the device credential - stored 0600 and kept local."""
    cfg = {"did": dev.get("did"), "ip": dev.get("ip"), "port": dev.get("port", PORT),
           "secret": dev.get("secret"), "fw": dev.get("fw")}
    with open(path, "w") as f:
        json.dump(cfg, f, indent=2)
    try: os.chmod(path, 0o600)
    except OSError: pass
    return cfg

def load_config(path):
    """Return the saved camera dict, or None if the file is missing/unreadable."""
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None

def main():
    ap = argparse.ArgumentParser(description="discover A9 cameras on the LAN")
    ap.add_argument("ip", nargs="?", help="also probe this IP directly (AP default 192.168.9.252)")
    ap.add_argument("--wait", type=float, default=3.0, help="seconds to listen per round")
    ap.add_argument("--show-secret", action="store_true",
                    help="print the paired_auth_secret (a device credential)")
    ap.add_argument("--save-config", nargs="?", const=CONFIG_DEFAULT, metavar="PATH",
                    help=f"write the first camera's details to a config file "
                         f"(default {CONFIG_DEFAULT}) so the client can skip discovery")
    a = ap.parse_args()
    devs = discover(a.ip, wait=a.wait)
    if not devs:
        sys.exit("[!] no cameras answered. Check you're on the same network/AP.")
    if a.save_config:
        save_config(a.save_config, devs[0])
        print(f"[*] wrote {a.save_config} for {devs[0]['did']} (contains the secret; 0600, keep local)")
    for d in devs:
        print(f"\nDID       : {d['did']}")
        print(f"IP:port   : {d.get('ip')}:{d.get('port')}   (actual, from reply source)")
        if d.get("reported_ip") and d.get("reported_ip") != d.get("ip"):
            print(f"reported  : {d.get('reported_ip')}   (self-reported; stale, ignored)")
        print(f"netmask   : {d.get('netmask')}")
        print(f"firmware  : {d.get('fw')}")
        sec = d.get("secret")
        print(f"secret    : {sec if a.show_secret else '(hidden; --show-secret to reveal)'}")
        if d.get("skill"):
            base = d["skill"].get("base", {})
            print(f"skill.base: protocol={base.get('protocol')} encrypt={base.get('encrypt')}")
    print(f"\n[*] {len(devs)} camera(s). The secret is handed out unauthenticated - keep it private.")

if __name__ == "__main__":
    main()
