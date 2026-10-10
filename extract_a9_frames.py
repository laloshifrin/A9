#!/usr/bin/env python3
"""
extract_a9_frames.py - extract ALL MJPEG frames from a local A9 capture.

    python3 extract_a9_frames.py capture.pcap outdir/

Writes frame_000.jpg, frame_001.jpg, ... into outdir/, and (if Pillow is present)
a contact_sheet.png. Same crypto/reassembly as extract_a9_snapshot.py; see that
file's header for the full protocol notes.

Deps: Python stdlib + pycryptodome (Pillow optional, only for the contact sheet).

WARNING: frames and the recovered session key are device-specific; don't publish.
"""
import sys, os, hashlib, importlib.util

# reuse the proven parsing/crypto (incl. the AES shim) from extract_a9_snapshot.py
_here = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("a9snap", os.path.join(_here, "extract_a9_snapshot.py"))
X = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(X)

def reassemble(frags, s, e, sk):
    blob = b""
    for k in range(s, e):
        flag, avch, avseq, tt, enclen, data = X.media_exhdr(frags[k])
        if enclen > 0:
            key = hashlib.md5(b"%s,AVSeq:%d-TT:%d-AVChannel:%d"
                              % (sk, avseq, tt, avch)).hexdigest().encode()
            n = min(enclen - (enclen % 16), len(data) - (len(data) % 16))
            blob += X.aes_cbc_decrypt(key, key[16:32], data[:n]) + data[n:]
        else:
            blob += data
    soi = blob.find(b"\xff\xd8")
    eoi = blob.find(b"\xff\xd9", soi + 2) if soi >= 0 else -1
    return blob[soi:eoi + 2] if (soi >= 0 and eoi >= 0) else None

def main():
    if len(sys.argv) < 3:
        sys.exit("usage: extract_a9_frames.py capture.pcap outdir/")
    pcap, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    streams = X.read_pcap_streams(pcap)
    sk = X.recover_session_key(streams)
    if not sk:
        sys.exit("could not recover session key from CTRL handshake")
    sys.stderr.write(f"[*] session key recovered ({len(sk)} chars) — do not publish it\n")

    frags = [body for (s_, sp, d_, dp), st in streams.items() if sp == X.PORT
             for mt, flag, body in X.iter_pprpc(st) if mt == 6]
    starts = [k for k, f in enumerate(frags) if (f[0] >> 7) == 1]
    sys.stderr.write(f"[*] {len(frags)} MEDIA fragments, {len(starts)} frames\n")

    ok = miss = 0
    for fi in range(len(starts)):
        s = starts[fi]
        e = starts[fi + 1] if fi + 1 < len(starts) else len(frags)
        jpg = reassemble(frags, s, e, sk)
        if jpg:
            open(os.path.join(outdir, f"frame_{fi:03d}.jpg"), "wb").write(jpg); ok += 1
        else:
            miss += 1
    sys.stderr.write(f"[*] wrote {ok} frames ({miss} incomplete/truncated)\n")

    try:
        from PIL import Image, ImageFile
        ImageFile.LOAD_TRUNCATED_IMAGES = True
        thumbs = []
        for fn in sorted(os.listdir(outdir)):
            if not fn.endswith(".jpg"): continue
            try:
                im = Image.open(os.path.join(outdir, fn)); im.load()
                thumbs.append(im.convert("RGB").resize((160, 120)))
            except Exception:
                pass
        if thumbs:
            cols = 10; rows = (len(thumbs) + cols - 1) // cols
            sheet = Image.new("RGB", (cols * 160, rows * 120), (20, 20, 20))
            for i, t in enumerate(thumbs):
                sheet.paste(t, ((i % cols) * 160, (i // cols) * 120))
            sheet.save(os.path.join(outdir, "contact_sheet.png"))
            sys.stderr.write(f"[*] contact_sheet.png ({len(thumbs)} thumbs)\n")
    except ImportError:
        sys.stderr.write("[*] Pillow not installed; skipped contact sheet\n")

if __name__ == "__main__":
    main()
