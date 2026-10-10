#!/usr/bin/env python3
"""
a9_keys.py - load the pprpc shared "prekey" from the environment, not from source.

The CTRL / discovery AES key is derived per packet from a fixed secret that is
hardcoded in the camera firmware and the vendor app and shared across all units. It
is a shared secret (not device-specific), and it is documented in the public analyses
this project references. To keep it out of the published repo, the tools read it from
the `A9_PREKEY` environment variable, or from a local `.env` file next to this module.

Set it once:
    cp .env.example .env     # then put the value in .env  (see README references)
    # or: export A9_PREKEY=...
"""
import os

def ctrl_prekey():
    """Return the shared prekey as bytes, or exit with guidance if it is not set."""
    v = os.environ.get("A9_PREKEY")
    if not v:
        env = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
        try:
            with open(env) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, val = line.split("=", 1)
                    if k.strip() == "A9_PREKEY":
                        v = val.strip().strip('"').strip("'")
                        break
        except OSError:
            pass
    if not v:
        raise SystemExit(
            "A9_PREKEY is not set.\n"
            "  cp .env.example .env   and put the shared pprpc prekey in it,\n"
            "  or:  export A9_PREKEY=...\n"
            "The value is the publicly-documented shared secret; see the README references.")
    return v.encode()
