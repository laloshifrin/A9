# XCThings / Linklemo A9 — local PPRPC protocol

Reverse-engineered from the `XCThings_Linklemo_A9_INO-IPC-V2.3` flash dump and a
local packet capture of a camera on its own network. Scope: the **local** path
needed to pull one JPEG from a camera you own — LAN auth, video start, and MJPEG
decode. No cloud/OTA/audio/SD/PIR.

Addresses are virtual addresses in the de-interleaved application image
(`app_deint.bin`, XIP base `0x00010000`). Confidence tags: **[M]** measured from
the capture, **[F]** proven in firmware disassembly, **[D]** derived.

> ⚠️ The DID, `paired_auth_secret`, and per-session `session_key` are
> device-specific credentials. Anyone with the DID + paired secret can
> authenticate to your camera on the LAN. Do not publish them.

---

## 0. Firmware image format

- **[F] Full 2 MB SPI flash dump, Beken 32+2 CRC-interleaved.** Every 34-byte unit
  = 32 data bytes + 2 CRC bytes. CRC = **CRC-16/CMS** (poly `0x8005`, init `0xFFFF`,
  non-reflected, stored big-endian).
- Partitions: bootloader raw `0x000000–0x00e0fc`; **application raw `0x011000`,
  de-interleaving to ~1.5 MB at XIP base `0x00010000`**.
- CPU: ARM968E-S (ARMv5TE), little-endian, ARM/Thumb interworking.
- Family markers: `pprpc`, `avsdk`, `xcthings.com`, `rt-thread`; build path
  `/home/liangyuxuan/share/avsdk/src/xciot/pprpc/`.

De-interleave: for each 34-byte block keep the first 32 bytes; CRC check optional.

A dump of this exact board (`XCThings_Linklemo_A9_INO-IPC-V2.3_(BluePCB).bin`) is available
at [`openshwprojects/FlashDumps`](https://github.com/openshwprojects/FlashDumps/tree/main/IoT/BK7252N)
if you would rather not dump your own.

---

## A. Transport

- **[M][F] TCP, port 20190.** AP-mode camera IP `192.168.9.252`. Local-connect
  path `iot_conn_local_connect2` @`0x302d0` logs `iot conn local try: tcp://%s:%d`.
- One TCP connection carries the whole session (CTRL + MEDIA multiplexed by frame
  type). No separate media port.

---

## B. PPRPC frame

Every message on the stream:

```
+--------+---------------------+------------------+-------------------+
| ctrl   | remainlength        | exhdr            | payload           |
| 1 byte | varint              | (per msgtype)    | (remainlength - exhdr) |
+--------+---------------------+------------------+-------------------+
```

- **[F] `ctrl` byte:** `msgtype = (ctrl >> 4) & 0xF`, `msgflag = ctrl & 0xF`
  (fixhdr decoder @`0x62304`, nibble split @`0x6234c`).
  - `msgtype 4 = CTRL`, `6 = MEDIA`, `8 = FILE` (dispatch jump table @`0x62458`).
  - CTRL frames seen use `ctrl = 0x48`; MEDIA use `ctrl = 0x6A`.
- **[F] `remainlength`:** protobuf-style LEB128 varint = number of body bytes that
  follow (len reader `0x148fb8`→`0xc0edc`).
- **Varints** are standard LEB128, 7 bits/byte, high bit = continue, ≤10 bytes,
  u64 (reader `0x149400`→`0xc0fec`).

### B.1 CTRL exhdr (msgtype 4) — `0x5ee60`

```
seq     varint    # "SEQ": per-connection sequence counter (1st varint)
cmd_id  varint    # "ID":  command id (2nd varint)
flag    1 byte    # rpc = flag & 3   (0 = request, 1 = reply/heartbeat variant)
[extra  varint]   # present only when (flag & 3) == 1
payload           # AES-encrypted (see C); empty for parameterless commands
```

### B.2 MEDIA exhdr (msgtype 6) — `0x5f0cc`

```
byte0   1 byte    # bit7 = frame-start flag; bits0-6 = media type (4 = video)
byte1   1 byte
v0      varint    # AVChannel
v1      varint    # AVSeq  = frame index (0,1,2,…)
v2      varint    # TT     = capture timestamp (ms)
v3      varint    # enclen = encrypted-prefix length (nonzero only on frag0)
v4..v6  varints   # incl. fragment index
payload           # JPEG bytes (see E)
```

---

## C. CTRL encryption

**[F][M] AES-256-CBC + PKCS#7.** `gen_crypt_key` @`0x5d790`, wrapper @`0x5daa0`.

```
keystr = "<A9_PREKEY>,ID:<cmd_id>-SEQ:<seq>-RPC:<flag&3>"
key    = lower_hex( MD5(keystr) )      # 32 ASCII hex chars  -> AES-256 key
IV     = key[:16]                      # first 16 hex chars
plaintext = AES-256-CBC-decrypt(payload, key, IV)  ;  strip PKCS#7
```

- `<A9_PREKEY>` is a static secret @`0x156620` (CTRL/FILE base, accessor `0x58f60`
  ignores the session and returns it). Shared across all units of this firmware;
  **not** per-device. The tools load it from the `A9_PREKEY` env / `.env` rather than
  hardcoding it; the value is the one documented in the public analyses in §L.
- MD5 confirmed (constants @`0x7d270`). Hash→hex is `0xc0d5c` (`"%02x"` @`0x164077`).
- Parameterless commands have an **empty** payload → nothing to encrypt.

---

## D. Command set (local, observed/relevant)

Command ids are the CTRL `cmd_id`. Names from the firmware dispatch table
(cmd-id array base `0x69384` ↔ handler array `0x85594`).

| cmd id | name | dir | payload (protobuf) | notes |
|---|---|---|---|---|
| 2650 | `ipc_LanAuth` | C→S | `{2: DID, 3: paired_auth_secret}` | **[F]** handler idx24; **[M]** DID+secret |
| 2650 | (reply) | S→C | `{1: session_key}` | 32-hex-char **MEDIA base** |
| **2610** | **`ipc_VideoPlay`** | C→S | *(empty)* | **[F]** handler idx4 @`0x82cf8` (logs `ipc_VideoPlay_Req`); starts MEDIA |
| 2610 | (reply) | S→C | `{5:…,6:…,7:…}` | stream params |
| — | `ipc_VideoPause` | — | — | handler idx5 @`0x82da9` |
| — | `ipc_VideoQosSet` | — | — | handler idx6 @`0x82f45` |
| — | `ipc_VideoChanChange` | — | — | handler @`0x8461c` |
| **2612** | resolution / stream-type | C→S | `{2: code}` | observed **10=HD, 15=UHD**; sets the **recording/main** stream — live preview stays 640×480. [M] |
| **2635** | night mode | C→S | `{2: mode}` | observed `1` and `2` (on/off); paired query **2636** (empty). [M] |
| 2780 | device info | C→S | nested `{2: DID, 4:{…}, 6: ts, 7:1}` | model `INNO-IPC-48N-V2.5` etc. |
| 2631 | time sync | C→S | `{3: ts_ms, 6: "Europe/Budapest", 7:1, 8:60}` | not required for video |
| 106/107 | keepalive/ping | both | timestamps | not required |

**VideoPlay wire bytes (empty payload):**
```
48 04 <seq> B2 14 0C
   └ ctrl=0x48, len=4, seq varint, cmd=2610 (0xA32 → B2 14), flag=0x0C (rpc=0)
```

---

## E. MEDIA (video) path

- **[M][F] Codec: MJPEG** (baseline JPEG, observed 640×480). Beken HW JPEG encoder
  (`ejpeg`).
- **[M] One JPEG per frame, split into 8 MEDIA fragments** (frame-start flag on the
  first). `AVSeq`/`TT`/`AVChannel` are constant across a frame’s fragments.
- **[F][M] Only the first fragment’s first `enclen` bytes are AES-encrypted**
  (the JPEG header + start of scan). Everything else — the rest of frag0 and all
  continuation fragments — is **plaintext JPEG**. Gated in the media handler
  `0x5fbb4` by `enclen != 0`.

### E.1 MEDIA key — `gen_crypt_key` scheme 6 (`0x5d790` via `0x5da4c`/`0x5e3dc`)

```
keystr = "<session_key>,AVSeq:<v1>-TT:<v2>-AVChannel:<v0>"
key    = lower_hex( MD5(keystr) )      # 32 ASCII hex chars -> AES-256
IV     = key[16:32]                    # SECOND 16 hex chars (differs from CTRL!)
```
- `session_key` = the per-session base = LanAuth reply field 1 (= `H+0x88` in
  firmware; accessor `0x58f08`).
- AES-256-CBC. Decrypt `floor(enclen/16)*16` bytes of frag0’s payload.

### E.2 Reassembly

```
frame_bytes = decrypt(frag0.payload[:enclen_aligned])
            + frag0.payload[enclen_aligned:]      # plaintext tail
            + frag1.payload + … + frag7.payload   # plaintext
jpeg = frame_bytes[ find(FFD8) : find(FFD9)+2 ]
```

---

## F. Client flow (confirmed working live, over the AP)

```
TCP connect <camera>:20190            # AP mode = 192.168.9.252 (fixed)
  → ipc_LanAuth (2650): send {2:DID, 3:paired_auth_secret}, CTRL-encrypted
  → read reply → session_key
  → ipc_Hello (106): send {1:1}        # "ready" ping
  → (2653 Discovery, 2645: empty; cheap, likely setup)
  → ipc_VideoPlay (2610): empty CTRL frame "48 04 <seq> B2 14 0C"   ← triggers MEDIA
  → loop: read frames
       - CTRL 107 ping (rpc=0)  → MUST reply 107 pong (rpc=1, same seq):
             {1: echo_field1, 2: 18446744073709551586, 3: now_ms}, flag 0x0D
       - CTRL 106 ping (rpc=0)  → reply 106 {1:1} (rpc=1)
       - MEDIA (msgtype 6)      → collect fragments
  → per frame: decrypt frag0 prefix (AES-256-CBC, IV=key[16:32]), reassemble, carve FFD8..FFD9
  → snapshot.jpg
```

**Minimum required** (verified against hardware): `ipc_LanAuth`, answering the
camera's `107` heartbeats, and `ipc_VideoPlay`. Without heartbeat replies the
camera closes the socket a few seconds after connect. `106` and `2653`/`2645` are
cheap setup the app sends; everything else observed in captures (`2631` time-sync,
`2780` device-info, `2649`, `2612` resolution, `2635` night mode, `2636/2611/2615`)
is **not** needed for a snapshot. MEDIA begins the instant `ipc_VideoPlay` is acked.

Reply framing: a CTRL reply (rpc = flag&3 == 1, flag `0x0D`) carries an extra
trailing varint (observed `0`) after the flag byte, before the payload.

rpc value = `flag & 3`: `0` = request/ping, `1` = reply. The replier echoes the
request's `seq`.

---

## I. Device credential — `paired_auth_secret` derivation & extraction

### I.1 How the credential is formed (proven)

The `paired_auth_secret` is **deterministic**, computed on the device from config
fields — no runtime RNG in the generation path:

```
secret = "$L<level>$" + lower_hex( MD5( "<DID>-<X>-<level>" ) )
```
- `DID`   = config field `D+0x10`  (e.g. `PPHAABBCCDDEE0011`; semi-public, maps to AP SSID)
- `X`     = config field `D+0x120` (per-device; never transmitted; not in firmware)
- `level` = a small digit (9 observed)
- `D`     = `*(0x400588)->[0x94]` (device-identity struct, loaded from flash at boot)

Evidence: generator `0x2f28c` (base fmt `"%s-%s-%d"` @`0x14ef7c`; `"$L%d$%s"`
@`0x14ef88`), MD5-hex `0x1492c4→0xc0d5c`, getters DID=`0x1c2f8`→`0x3baa8`(D+0x10),
X=`0x1c2b8`→`0x3bb0c`(D+0x120). The same generator runs inside `local_check_auth2`
(fn `0x2f0a4`), i.e. the device **recomputes and compares** this value to validate
incoming `ipc_LanAuth`. There is also a `local_check_auth1` (base `"%s-%s-%s"`).

So the secret cannot be computed from public info alone — you need `X`, which lives
only in that camera's flash. In practice it behaves like a stored per-device credential.
(Open: whether `X` itself is factory-random or factory-derived — resolvable only by a
flash dump of `D+0x120`.)

### I.2 The device hands out its identity locally — `iot.dev.bdn` (proven mechanism)

During binding/net-config the device exposes `DID` **and** `X` to the local client:

- `iot_bdn_init` (`0x39bf4`) registers dispatcher `0x39908` under namespace
  **`iot.dev.bdn`**, method key **`bdn_cmd_handle`** (string @`0x1514a4`), with a
  `wifi_set` callback.
- A request is a named pprpc RPC. Dispatcher `0x39908` decodes it (`0x2b100`) into a
  `0xce0` struct, reads the method at `struct->[0x40]`, and routes to the handler.
- `bdn_cmd_handle` (`0x39704`): builds a response struct with
  - `resp+0xC4` = `DID`  (`snprintf("%s", DID)`)
  - `resp+0x144` = `"<DID>-<X>-<N>"`  (`0x3bc10`, fmt `"%s-%s-%d"` @`0x151a94`; **`X` in cleartext**)
  then serializes (`0x2b214`) and **sends it to the caller** (`0x394e8`). Response
  cmdid `[+0x40]` = `0x2718` (10008).

Implication: **a client that speaks the `iot.dev.bdn` netcfg exchange gets `X` back**,
and can then compute the secret via I.1. No app, cloud, flash dump, or QR required.
This is how the vendor app obtained the credential over the camera's AP.

### I.3 Provisioning crypto (candidate)

`avsdk_dp_aes_decode` (`0x40864`) uses **AES-256** (`iotsdk_Aes256DecryptBody`) with a
**hardcoded firmware key** `8BGEgMvECdxuVplKLv6dsQraLkz1OgqI`. The provisioning/`dp`
payloads may be wrapped with this static key; since it is in the firmware, those
payloads are decryptable without any per-device secret.

### I.4 Still-open for a turnkey self-provision tool

- **Transport of `iot.dev.bdn`:** BLE vs the AP's TCP/softap channel is unresolved
  (`ble msg decode` strings suggest BLE; the AP path may instead be
  `app_apcfg_tcp`/softap). This decides whether an AP-only tool can run the exchange.
- Exact netcfg **request** schema (cmdid + fields; `wifi_set` carries `ssid`/`pwd`).
- Response protobuf **field tags** for `+0xC4` (DID) and `+0x144` (`DID-X-N`).
- Whether the channel is plaintext or AES-256 under the static key above.

A single capture of a real binding (add-device on the AP) resolves all four at once.

### I.5 How to get the camera back into bindable state (no reset button)

These A9s have **no physical reset button**; rebinding is software:
- **App "remove / unbind device"** — firmware has `avsdk_unbind` / `Unbind` /
  `UnbindByDevice`; unbinding drops the camera back to AP-broadcast mode.
- **Power-cycle heuristic** — firmware logs `long time is unbind status, will wifi_reset`;
  repeated power on/off (or staying unbound) can force it back to AP mode.
- You generally **do not need to reset for snapshots** — once bound, the credential is
  captured from any LanAuth and reused; reset is only needed to study the bind exchange.

### I.6 Post-wipe test — the app needs no account (measured, 2026-10-09)

Deleting all app data and re-registering a fresh account, then opening the app on the
camera's AP, still produced a working session. The wiped app's first `ipc_LanAuth`
carried a valid new secret (`$L6$…`, level 6) and the camera accepted it, establishing a
session key. Three secrets were observed for the same device over time, at levels 9, 0,
and 6.

Two conclusions:
- **No cloud and no account are required.** The credential is acquired locally on the AP.
- **The level is minted per session, not fixed.** A pure client-side derivation from a
  constant DID would always pick the same level. Three different levels mean a level
  parameter is supplied when the secret is formed.

`X` was not recoverable by brute force: no printable string in the firmware or in the
app's `libgojni.so` satisfies all three `MD5("DID-X-level")` constraints, and neither do
`md5(DID)`, `md5(toriQue+DID)`, SHA variants, or `X==DID`. So the I.1 formula stays
**[DERIVED, unverified]** — it was read from the firmware but never confirmed against a
real `X`.

## J. UDP local discovery (measured, 2026-10-09)

Separate from the TCP PPRPC session, the camera runs a UDP discovery responder on the
same port **20190**. This is how a wiped app finds the camera on the AP before any TCP
connection. Captured from PCAPdroid and confirmed by a live probe (`a9_discover.py`).

Client requests (both observed, UDP/20190):
- 8-byte binary ping, broadcast to `255.255.255.255`: `51 70 48 04 <seq> a8 14 0c`
  (`seq` was a small varying counter; `a8 14 0c` constant).
- JSON, unicast to the camera and broadcast: `{"cmd":"Discovery","class_code":"IPAV"}`.
  Firmware checks the class code (`Discovery input class_code:%s, != IPAV` @`0x14a4dc`).

Camera response to the binary ping: a **906-byte** reply. This is **a normal CTRL frame
wrapped in a 2-byte UDP prefix**, not a new format. Cracked using the recovered source of
`github.com/pprpc/core` (Go module proxy; see §K).

Framing (`packets/fix_header.go`, `packets/base.go`):
```
udp packet = 51 70            (udpPreHeader, 2 bytes)
           + (MessageType<<4 | Flag)   (1 byte; 0x48 = CTRL(4), flag 8)
           + varint(Length)
           + body
```
For the 906-byte reply: `51 70 | 48 | 85 07`(varint=901) + 901-byte body. The body is a
standard CTRL frame: `seq=1, cmd=2600, flag=0x0d (rpc=1), extra-varint=0`, then 896 bytes
of AES. So **cmd 2600 is a device-info request**; the client ping is the same frame with
an empty rpc=0 body.

The 896-byte payload decrypts with the **CTRL crypto already in §C** (no new key):
`key = md5hex("<A9_PREKEY>,ID:2600-SEQ:1-RPC:1")`, AES-256-CBC, IV=key[:16],
PKCS#7. Plaintext is a protobuf:

| field | meaning |
|---|---|
| 1 | DID |
| 2 / 3 / 4 | IP / netmask / port (20190) |
| 5 | firmware version |
| 7 | small int (state) |
| **8** | **`paired_auth_secret`** (`$L<level>$<32hex>`, cleartext) |
| 9 | gzipped `skill.json` capability blob (`"protocol":"pprpc","encrypt":3`) |

**This resolves §I and §I.6: the secret is not derived client-side. The camera gives it
out.** Any party that can send one UDP packet on the same L2 (the AP, or the camera's
regular LAN) receives the device's current `paired_auth_secret`, protected only by the
static, cross-unit CTRL key. `X` is never needed by a client; the `md5("DID-X-level")`
formula is only how the device computes its own secret internally. Confirmed live: a probe
on the home LAN returned the device's real `$L9$…` secret. This is a credential-disclosure
vulnerability; keep recovered secrets out of shared artifacts.

**Supersedes the earlier [UNKNOWN] codec note and the §I.3 static-key guess** (the
`UI3lQZ…`/`8BGEgM…` keys drive `avsdk_local_aes256` for other payloads; the discovery
body uses the ordinary CTRL key above).

## K. Source reference — `github.com/pprpc/core`

The transport library the firmware/app are built on. The GitHub repo is gone, but the Go
module proxy keeps an immutable copy:
```
curl https://proxy.golang.org/github.com/pprpc/core/@latest
curl -o core.zip "https://proxy.golang.org/github.com/pprpc/core/@v/<version>.zip"
```
(version seen: `v0.0.0-20200908022406-5592f694d0e7`). Relevant files: `packets/fix_header.go`
(framing, `udpPreHeader`), `packets/packets.go` (`ReadUDPPacket`), `packets/crypt.go`
(AES-128/192/256 CBC **and CFB**; enc type is per-packet), `packets/cmd_packet.go`,
`packets/av_packet.go`. It confirms our CTRL=4 / MEDIA=6 / FILE=8 framing exactly. It does
**not** contain the vendor credential logic (`$L` levels, `X`, the `toriQue` secret) — that
is the application layer above it.

## G. Unknowns / notes

- `paired_auth_secret` format `$L9$<32hex>` looks like a salted credential; it is
  stored on the device (config `D+0x29`, `D = *(0x400588)->[0x94]`) and sent in the
  clear inside the (recoverable) encrypted CTRL request — so a single capture
  yields it, no flash extraction.
- Commands `2653`/`2645`/`2649` were also sent by the app around VideoPlay but are
  not in the main handler table and appear optional; a minimal client can omit them.
- `TT` is a per-fragment ms timestamp; the per-frame key uses the frame-start
  fragment’s values. The 4 fields that matter for a snapshot are `session_key`,
  `AVSeq`, `TT`, `AVChannel`.
- **Long-stream keepalive (solved).** The camera throttles the MEDIA stream to ~1 fps
  after ~40s unless the **client** sends its own `107` ping about twice a second
  (rpc=0, flag `0x0C`) with `{1: now_ms, 4: <cumulative frames received>}`. Field 4 is a
  flow-control ack; with it the stream runs indefinitely at the full ~10 fps (verified
  over 90s). Separately, each side answers the other's ping with a pong (rpc=1, flag
  `0x0D`) `{1: echo_ts, 2: 18446744073709551586, 3: now_ms}`. `a9_mjpeg_server.py` sends
  the keepalive; its stall watchdog is now only a fallback for a real network drop.
  (The earlier short "grab a photo" captures never showed this; a 150s live-view capture did.)
- **Device status / battery** arrives in a camera push, **cmd `2780`** (not the ping).
  Decrypted payload: `{1: <inner>}`; the inner protobuf is
  `{1: DID, 2: DID-str, 4: <status>, 6: ts}` and the `<status>` struct holds a 6-byte
  blob (field 2), the firmware/model strings (field 4), and a constant `field1`=70.
  **Battery = byte[1] of the 6-byte blob**: it read `70` in a capture and `100` a day
  later (charging), while `field1` stayed 70, so `field1` is not battery. `byte[0]` also
  changed (06→02), likely a charge/status flag. `a9_mjpeg_server.py` decodes this and
  serves it at `/status`. The `107` heartbeat carries only timing/flow-control.

---

## H. Tools in this repo

| file | purpose |
|---|---|
| `a9_live_snapshot.py` | **online**: grab a JPEG; auto-discovers IP+creds, or reads a config |
| `a9_mjpeg_server.py` | **online**: live MJPEG + snapshot HTTP server (browser / Home Assistant) |
| `a9_discover.py` | **online**: UDP discovery; decodes DID/IP/port/fw/secret (cmd 2600); writes config |
| `a9_aes.py` | pure-Python AES-CBC fallback (stdlib only, no pip) |
| `a9_keys.py` | loads the shared prekey from `A9_PREKEY` / `.env` (kept out of source) |
| `extract_a9_snapshot.py` | offline: pcap → first JPEG (also a lib used by the live client) |
| `extract_a9_frames.py` | offline: pcap → all frames + contact sheet |
| `decode_a9_pcap.py` | offline: decode CTRL handshake / commands from a pcap |

The firmware images this writeup analyzes (`XCThings_…_(BluePCB).bin`, the 2 MB flash
dump, and `app_deint.bin`, its de-interleaved application image) are **not included** in
the repo. They are the vendor's and are gitignored. Produce your own as in §0; the
addresses here are virtual addresses in the de-interleaved image at base `0x00010000`.

### Usage

```bash
# zero-input: discover the camera, read its own credentials, grab a frame
python3 a9_live_snapshot.py -o snapshot.jpg

# save the camera's details once, then reuse them (skips discovery next time)
python3 a9_discover.py --save-config          # writes a9_camera.json (0600)
python3 a9_live_snapshot.py -o snapshot.jpg   # reads a9_camera.json if present

# force a fresh discovery even if a config exists
python3 a9_live_snapshot.py --no-config -o snapshot.jpg
```

`a9_camera.json` holds `did`, `ip`, `port`, `secret`. It contains a device credential,
so it is written `0600` and must stay local (never commit it). Credential precedence in
the client: `--did/--secret` → `--creds-from <pcap>` → config file → UDP discovery.

## L. References

- **Independent write-up of the same device/protocol** (confirms the framing, the
  hardcoded CTRL secret, the CRC de-interleaving, and the broken IV): FuseTim,
  "The inSecurity Camera", <https://fusetim.space/posts/20251005-the-insecurity-camera/>
- **`pprpc` transport library** (the protocol these cameras are built on):
  GitHub org <https://github.com/pprpc> (repos may be gone; the `core` module survives on
  the Go module proxy — see §K). It is the transport only; vendor command/credential
  logic lives in the firmware/app above it.
- **Firmware dump** of this exact board:
  <https://github.com/openshwprojects/FlashDumps/tree/main/IoT/BK7252N>
- **Related independent work** on the same camera family:
  [`IvanFogel/ino-a9-local-bridge`](https://github.com/IvanFogel/ino-a9-local-bridge)
  (local PPRPC client + MJPEG bridge, Home Assistant) and
  [`Yeti47/cheap-shot`](https://github.com/Yeti47/cheap-shot) (Go PPRPC implementation;
  same shared prekey).
- **Vendor / app**: XC Things; Android app `Linklemo`, package `com.xcthings.fchan`.
- **Hardware**: PCB `INO-IPC-A9` (also sold as "Pinmei A9"), Beken BK7252N SoC.
