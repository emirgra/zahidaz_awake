# Play Frosting

Play Frosting is a cryptographically signed assertion Google embeds in the APK Signing Block of every APK distributed through Google Play. It identifies the block via magic ID `0x2146444e` ("Google Metadata"), contains ProtoBuf-encoded metadata about the distribution, and is signed with an ECDSA-P256 key controlled by Google. Because the Frosting block must be produced by Google's signing infrastructure, it cannot be forged by a repackager. For analysts, presence of Frosting is the single strongest cryptographic signal that an APK was distributed through Play; absence means the sample was sideloaded, extracted from an App Bundle, or obtained outside Google Play.

## Overview

| Property | Value |
|----------|-------|
| Block ID | `0x2146444e` |
| Label | Google Metadata (commonly called "Frosting") |
| Signature | ECDSA-SHA256 over NIST P-256 (secp256r1) |
| Key material | `frostingPublicKeys` (multiple key rotations over time) |
| Payload format | ProtoBuf, variable size |
| Location | APK Signing Block (before central directory, after ZIP contents) |
| Source | Added by Google Play at distribution time |

## Why It Matters for Analysis

Frosting is the only Play-distribution signal that a repackager cannot forge or preserve. The key insights for triage:

- **Present + valid signature**: APK was obtained directly from Google Play. Repackaging strips or invalidates Frosting.
- **Absent, but Play App Signing cert**: APK was generated via `bundletool` from an Android App Bundle (AAB), not downloaded from Play. The signer will show `BNDLTOOL` and the subject `CN=Android, OU=Android, O=Google Inc.`.
- **Absent, developer-signed cert**: APK was built by the developer and distributed off-Play (direct download, alternative store, sideload).
- **Absent, debug cert or TESTKEY**: Not from Play; hobbyist or testing build.

Certain certificate patterns combine with Frosting to rule in or out legitimate provenance. Play App Signing keys managed by Google are typically RSA 4096 with long validity periods, produced from Google's infrastructure with the subject `CN=Android, OU=Android, O=Google Inc.`. An APK claiming to be Play-distributed but using RSA 1024, short validity, or a developer-typical subject is inconsistent with Play App Signing regardless of other signals.

## Block Structure

The APK Signing Block is a sequence of ID-value pairs, each framed by an 8-byte length prefix, followed by the outer block size and the `APK Sig Block 42` magic. The Frosting block is one such pair:

```
uint64  pair_length           // length of (id + value)
uint32  id = 0x2146444E       // Frosting block identifier
bytes   value                 // ProtoBuf-encoded metadata + ECDSA signature
```

The outer signing block's `uint64 size + "APK Sig Block 42" magic` trailer is separate from this per-pair framing. See the [APK Signature Scheme v2](https://source.android.com/docs/security/features/apksigning/v2) specification for the full container format.

The payload contains ProtoBuf fields including device feature strings (`android.hardware.ram.low`, `com.samsung.feature.SAMSUNG_EXPERIENCE`, preload identifiers like `com.google.android.apps.photos.PIXEL_2018_PRELOAD`) and an ECDSA-SHA256 signature computed over the APK contents, verifiable against Google's embedded `frostingPublicKeys` (P-256 keys, rotated over time).

## Verification

Signature verification requires the `frostingPublicKeys` set maintained by Google. Community tools have reverse-engineered the verification path and bundle these keys:

| Tool | Description |
|------|-------------|
| [avast/apkverifier](https://github.com/avast/apkverifier/blob/master/signingblock/frosting.go) | Go library with full Frosting verification, includes `frostingPublicKeys` |
| [Te-k/apkcli](https://github.com/Te-k/apkcli/blob/master/apkcli/plugins/frosting.py) | Python CLI with `frosting` plugin |
| [obfusk/apksigcopier](https://github.com/obfusk/apksigcopier/issues/46) | Frosting-aware signing block handling |
| F-Droid [fdroidserver](https://gitlab.com/fdroid/fdroidserver/-/issues/935) | Frosting detection for build reproducibility |

### Detection Without Verification

Pure detection (block present vs absent) is trivial: parse the APK Signing Block and look for block ID `0x2146444E`. This is sufficient for many triage purposes — a Frosting block present at all means the APK passed through Google's distribution infrastructure at some point. Full signature verification is only needed to rule out forgery attempts or pre-distribution intermediate builds.

## Relationship to Other Signing Artifacts

| Signal | Meaning |
|--------|---------|
| Frosting block present | APK distributed via Google Play |
| Frosting absent, `BNDLTOOL` signer, `CN=Google Inc.` | AAB-extracted by `bundletool`, legitimate but not directly from Play |
| Frosting absent, developer cert | Off-Play distribution |
| Frosting absent, `CN=Android Debug` | Debug build |
| Frosting absent, `CN=Android, email=android@android.com` (2008-02-29) | AOSP TESTKEY build (Sketchware, custom ROMs, etc.) |

When both v2/v3 signing is declared but the v2/v3 payloads have size 0, this is a DPT Shell artifact or other repackaging indicator, not a Frosting issue. See [DPT Shell](../packers/dpt-shell.md).

## Limitations for Offensive Research

From an offensive perspective, Frosting constrains but does not prevent several scenarios:

- **Repackaging with loss of Frosting**: The attacker drops Frosting and accepts the off-Play provenance signal. Social engineering or alternate distribution (SMS, ads, third-party stores) masks this.
- **Pre-Play malware**: Attackers publishing through developer account compromise produce genuinely Frosted malicious APKs. Frosting proves Play-transit, not good intent. See the [Play Store Evasion](../attacks/play-store-evasion.md) page for developer account market pricing and techniques.
- **Legitimate tamper**: Developers extracting their own AABs via `bundletool` produce valid-looking APKs without Frosting. Frosting absence alone is not a tamper signal.

## Pitfalls

A common analyst error is treating the `CN=Android, O=Google Inc.` subject on a Play App Signing certificate as impersonation. This is the expected fingerprint: Google re-signs APKs on the developer's behalf, producing a cert with Google as the subject. Combined with either Frosting (direct Play download) or the `BNDLTOOL` signer name (AAB extraction), it confirms legitimate Play origin rather than contradicting it.

## References

- [BI.ZONE: Easter Egg in APK Files: What Is Frosting](https://bi-zone.medium.com/easter-egg-in-apk-files-what-is-frosting-f356aa9f4d1)
- [avast/apkverifier Frosting implementation](https://github.com/avast/apkverifier/blob/master/signingblock/frosting.go)
- [Te-k/apkcli Frosting plugin](https://github.com/Te-k/apkcli/blob/master/apkcli/plugins/frosting.py)
- [APK Signing Block considerations (obfusk)](https://gist.github.com/obfusk/31c332b884464cd8aa06ce1ba1583c05)
- [Android-SigMorph: Covert Communication Exploiting Android Signing Schemes (Nullcon 2023)](https://goa2023.nullcon.net/doc/goa-2023/Android-SigMorph-Covert-Communication-Exploiting-Android-Signing-Schemes.pdf)
