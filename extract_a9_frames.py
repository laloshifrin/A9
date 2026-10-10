#!/usr/bin/env python3
"""
extract_a9_frames.py - extract ALL MJPEG frames from a local A9 capture.

    python3 extract_a9_frames.py capture.pcap outdir/

Writes frame_000.jpg, frame_001.jpg, ... into outdir/, and (if Pillow is present) a
contact_sheet.png. Protocol/crypto come from a9_proto; see PROTOCOL.md.

Deps: Python stdlib (Pillow optional, only for the contact sheet).

WARNING: frames and the recovered session key are device-specific; don't publish them.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # find siblings under -I / any cwd
import a9_proto as P
import extract_a9_snapshot as X      # for recover_session_key

def main():
    if len(sys.argv) < 3 or sys.argv[1] in ("-h", "--help"):
        sys.exit("usage: extract_a9_frames.py capture.pcap outdir/")
    pcap, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    streams = P.read_pcap_streams(pcap)
    flow, sk = X.select_session(streams)
    sys.stderr.write(f"[*] session key recovered ({len(sk)} chars); keep private\n")
    count = 0
    for count, jpg in enumerate(X.session_frames(streams, flow, sk), start=1):
        with open(os.path.join(outdir, f"frame_{count - 1:03d}.jpg"), "wb") as f:
            f.write(jpg)
    sys.stderr.write(f"[*] wrote {count} complete frames\n")

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
