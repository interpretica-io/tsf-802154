# tsf-802154

IEEE 802.15.4 from a test suite, packaged as an external Test
Environment (TE) repository.

Library:

- `tapi_802154` — engine-side, built as a shared library: build a
  frame, take one apart, protect it with AES-CCM*, and read what a
  network's traffic gives away.

## Why it is named after a standard

Because 802.15.4 is what Zigbee, Thread and Matter-over-Thread
genuinely share, and naming the module after any one of them would
claim the other two are variations of it. They are not: they share a
radio and a frame format, and diverge completely above it.

Z-Wave and LoRaWAN share neither and are not here. LoRaWAN has
[tsf-lorawan](https://github.com/interpretica-io/tsf-lorawan), which is
a different architecture entirely — long range, hard duty cycle, a
star of stars with a network server rather than a mesh. Putting them
in one module would have been the same mistake in a different place.

So this is the layer they have in common, and anything above it says
which of them it means.

## What a frame is

```
FCF | Seq | DestPAN | DestAddr | SrcPAN | SrcAddr | Payload | FCS
 2     1      0/2      0/2/8      0/2      0/2/8       n       2
```

Every field after the sequence number is optional, and which ones are
present is decided by two two-bit fields inside the frame control. That
is the whole difficulty of parsing one: **the length of the header
cannot be known without reading it.** Everything multi-byte is little
endian, so an extended address written `0011223344556677` appears on
the wire as `7766554433221100`.

The checksum is CRC-16/X.25 — the reflected CCITT polynomial starting
at zero — and a frame that fails it is reported in
`tapi_802154_frame::fcs_valid` rather than raised as an error. A frame
that failed its checksum is exactly what a test watching a noisy radio
wants to see; turning it into an error would throw away the evidence.

## What protects it

Zigbee and Thread protect a frame the same way, because they both
inherit it from 802.15.4: AES-CCM*, keyed with a network key, with a
nonce of

```
SourceExtendedAddress | FrameCounter | SecurityLevel
         8                   4              1
```

Thirteen bytes, and the counter is the part that matters. It is what
makes two frames from one device encrypt differently, so a device that
restarts its counter encrypts two different frames with the **same
keystream** — and exclusive-oring them removes the key. It is exactly
the failure `tsf-lorawan` looks for, for exactly the same reason, and
it is why both modules have a finding for it.

One trap worth naming: the source address goes into the nonce **big
endian**, the opposite of how it travels in the frame header. Getting
it the other way round produces a nonce that is perfectly well formed
and decrypts nothing.

## What the audit reads

| Finding | Severity | What it means |
|---|---|---|
| `ieee802154.counter-reuse` | critical | two frames from one device with one counter |
| `ieee802154.known-key` | critical | a key the test was told to look for |
| `ieee802154.counter-reset` | high | the counter went backwards |
| `ieee802154.unsecured-frames` | high | frames with no security at all |
| `ieee802154.weak-security-level` | medium | protected below what is expected |
| `ieee802154.nothing-seen` | info | no frames were collected |

Acknowledgements are skipped rather than counted as unprotected: the
standard gives them nowhere to put security, so counting them would
report every network alive.

Keys are never built in. `tapi_802154_policy::forbidden_keys` is empty
unless a test fills it — the case it exists for is Zigbee's default
trust centre link key, which is printed in the specification.

## What was verified

Against independent implementations, not against this library's own
reading of the standard.

**Frames — [scapy](https://scapy.net) 2.7.0**, whose `dot15d4` layer is
a separate implementation by other people. Fifteen checks, all
matching: three frames built byte for byte (short addressing, extended
source addressing, and a bare acknowledgement), all of them parsed back
with every field recovered, the checksum algorithm confirmed against
scapy's own output, and a frame with one corrupted byte correctly
reported as having a bad checksum.

**Security — AES-CCM reference vectors** produced by the `cryptography`
library's `AESCCM`. Nine checks across all three integrity-code
lengths: encryption matching byte for byte at 4, 8 and 16 bytes, the
round trip back to the original plaintext, and a frame with one flipped
bit refused at every length. The nonce layout was checked separately.

What has **not** been done is running any of this against a radio or a
live network. There is no 802.15.4 hardware here. An OpenThread
simulation build was attempted — it would have given a real Thread
network in software — and was abandoned when its submodules turned out
not to be fetched by a shallow clone; it is worth doing and is not
done.

So: the frame format and the cryptography are verified against outside
references, and nothing above them is.

## Usage

```yaml
repositories:
  - name: tsf_802154
    url: https://github.com/interpretica-io/tsf-802154.git
    ref: <tag>
    libs: [ tapi_802154 ]
```

```
TE_EXT_REPO_USE([tsf_cybersec], [], [tapi_cybersec])
TE_EXT_REPO_USE([tsf_802154], [], [tapi_802154])
```

Then add `tapi_802154` to `te_libs` in the suite's `meson.build`. It
needs `libcrypto` on the engine and nothing on the agent — frames are
built and checked where the test runs.
