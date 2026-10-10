# Security

## Scope and intent

These tools are for **local interoperability and security research on cameras you own**.
They talk to an XCThings / Linklemo "A9" camera on your own network. Do not use them
against devices you do not own or are not authorized to test.

## The weakness this project documents

The camera protocol (`pprpc`) protects its control traffic with AES, but the key is
derived from a **shared secret hardcoded in the firmware and the vendor app, identical
across all units**. As a result:

- Anyone on the same network (the camera's AP, or the LAN it joins) can send one
  unauthenticated UDP discovery packet and decrypt the reply, which contains the
  device's own `paired_auth_secret` in cleartext. That credential is enough to log in
  and view the video.

This is inherent to the device's design, not something these tools introduce. The tools
make the behavior observable; they do not create new access.

See [`PROTOCOL.md`](PROTOCOL.md) for the technical detail.

## Handling of secrets in this repo

- The shared prekey is **not committed**. It is loaded at runtime from `A9_PREKEY`
  (env var or a local, gitignored `.env`); see the README.
- Per-device credentials (`a9_camera.json`), captures (`*.pcap`), firmware binaries,
  and sample images are gitignored and must stay out of any upload or release archive.
  Verify with `git status` / a clean checkout before publishing.

## Reporting

For issues with **these tools**, open a GitHub issue (do not include real device
credentials, captures, or firmware). For the **device vulnerability**, contact the
vendor (XC Things); it affects the product, not this repository.
