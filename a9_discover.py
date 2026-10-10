#!/usr/bin/env python3
"""
a9_discover.py - LAN discovery for XCThings/Linklemo A9 cameras.

    python3 a9_discover.py              # broadcast-scan the local network
    python3 a9_discover.py 192.168.9.252   # also probe one IP directly

Sends the UDP discovery ping (port 20190) and decodes the camera's reply, which is a
CTRL frame with a 2-byte 0x5170 UDP prefix (see PROTOCOL.md section J). The decoded
protobuf carries the camera's DID, IP, port, firmware, and its own paired_auth_secret.

Importable: discover(ip=None, wait=3.0) -> list of dicts
            select_one(devs, did=None)  -> one dict (strict)
            creds_from_discovery(...)    -> (did, secret, ip) bytes/str
            save_config / load_config

Stdlib only (pure-Python AES fallback via a9_proto), so it runs with no pip.

WARNING: the recovered secret is a device credential. Keep it private; do not commit it.
The camera handing it out to any unauthenticated UDP sender is a real weakness.
"""
import sys, socket, time, os, argparse, gzip, json, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # find siblings under -I / any cwd
import a9_proto as P

PORT = P.PORT
UDP_PREFIX = P.UDP_PREFIX
CONFIG_DEFAULT = "a9_camera.json"
CMD_DEVINFO = 2600            # discovery / device-info command

def ping_packet():
    """8-byte discovery ping: 0x5170 + CTRL(0x48) + varint(len) + 'cmd 2600, rpc0, empty'."""
    body = b"\x01" + b"\xa8\x14" + b"\x0c"      # seq=1, cmd=2600 (varint a8 14), flag=0c
    return UDP_PREFIX + b"\x48" + bytes([len(body)]) + body

def parse_reply(data):
    """Decode a discovery reply into a device dict, or None if it isn't one."""
    if len(data) < 6 or data[:2] != UDP_PREFIX or (data[2] >> 4) != 4:
        return None
    try:
        ln, i = P.dec_varint(data, 3)
        cmd, seq, rpc, ct = P.ctrl_exhdr(data[i:i+ln])
        pt = P.ctrl_decrypt(cmd, seq, rpc, ct)
        if pt is None:
            return None
        f = P.pb_parse(pt)
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
                "port": f.get(4, [PORT])[0], "fw": s(5), "secret": s(8), "skill": skill}
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
                    dev["reported_ip"] = dev.get("ip")   # self-reported (may be stale)
                    dev["src_ip"] = addr[0]              # actual reply source
                    dev["ip"] = addr[0]                  # authoritative for connecting
                    found[dev["did"]] = dev
            if found and ip:
                break
    finally:
        s.close()
    return list(found.values())

def select_one(devs, did_filter=None):
    """Pick exactly one camera, strictly.
    - no cameras       -> SystemExit
    - did_filter given -> must match exactly, else SystemExit (never silent fallback)
    - no filter, one   -> that one
    - no filter, many  -> SystemExit asking for --did"""
    if not devs:
        raise SystemExit("no cameras answered discovery (same network/AP?)")
    if did_filter:
        m = [d for d in devs if d.get("did") == did_filter]
        if not m:
            raise SystemExit(f"--did {did_filter} not found. Discovered: "
                             + ", ".join(sorted(d.get('did', '?') for d in devs)))
        return m[0]
    if len(devs) > 1:
        raise SystemExit(f"{len(devs)} cameras answered; select one with --did. Found: "
                         + ", ".join(sorted(d.get('did', '?') for d in devs)))
    return devs[0]

def creds_from_discovery(ip=None, did_filter=None, wait=3.0):
    """Run discovery and return (did_bytes, secret_bytes, ip) for the matching camera."""
    dev = select_one(discover(ip, wait=wait), did_filter)
    did = dev["did"].encode() if dev.get("did") else None
    secret = dev["secret"].encode() if dev.get("secret") else None
    return did, secret, dev.get("ip")

def save_config(path, dev):
    """Write a camera's connection details to JSON the client can reuse. Contains the
    device credential: created 0600 from the start and written atomically."""
    cfg = {"did": dev.get("did"), "ip": dev.get("ip"), "port": dev.get("port", PORT),
           "secret": dev.get("secret"), "fw": dev.get("fw")}
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(prefix=".a9-config-", dir=os.path.dirname(os.path.abspath(path)))
        with os.fdopen(fd, "w") as f:
            json.dump(cfg, f, indent=2)
        os.replace(tmp, path)
    except OSError as e:
        raise SystemExit(f"could not write config {path}: {e}")
    finally:
        if tmp is not None:
            try: os.unlink(tmp)
            except FileNotFoundError: pass
    return cfg

def load_config(path):
    """Return the saved camera dict, or None if the file is missing/unreadable."""
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None

def resolve_credentials(ip=None, did=None, secret=None, config=CONFIG_DEFAULT,
                        no_config=False, wait=3.0):
    """Resolve one camera record without borrowing another camera's credentials."""
    cfg = None if no_config else load_config(config)
    if cfg:
        if not isinstance(cfg, dict):
            raise SystemExit("camera config must be a JSON object")
        if did and cfg.get("did") != did:
            cfg = None
        elif ip and cfg.get("ip") != ip:
            cfg = None
    if cfg:
        did = did or cfg.get("did")
        secret = secret or cfg.get("secret")
        ip = ip or cfg.get("ip")
    if not (did and secret and ip):
        dev = select_one(discover(ip, wait=wait), did)
        if ip and dev.get("ip") != ip:
            raise SystemExit("requested camera IP did not answer discovery")
        did = did or dev.get("did")
        secret = secret or dev.get("secret")
        ip = ip or dev.get("ip")
    if not all(isinstance(v, str) and v for v in (ip, did, secret)):
        raise SystemExit("could not resolve camera IP, DID and secret")
    return ip, did.encode(), secret.encode()

def main():
    ap = argparse.ArgumentParser(description="discover A9 cameras on the LAN")
    ap.add_argument("ip", nargs="?", help="also probe this IP directly (AP default 192.168.9.252)")
    ap.add_argument("--wait", type=float, default=3.0, help="seconds to listen per round")
    ap.add_argument("--show-secret", action="store_true",
                    help="print the paired_auth_secret (a device credential)")
    ap.add_argument("--save-config", nargs="?", const=CONFIG_DEFAULT, metavar="PATH",
                    help=f"write one camera's details to a config file (default "
                         f"{CONFIG_DEFAULT}) so the client can skip discovery; use --did to pick")
    ap.add_argument("--did", help="select this camera (required with --save-config if several answer)")
    a = ap.parse_args()
    devs = discover(a.ip, wait=a.wait)
    if not devs:
        sys.exit("[!] no cameras answered. Check you're on the same network/AP.")
    if a.save_config:
        dev = select_one(devs, a.did)            # strict: exact match / require --did if ambiguous
        save_config(a.save_config, dev)
        print(f"[*] wrote {a.save_config} for {dev['did']} (contains the secret; 0600, keep local)")
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
