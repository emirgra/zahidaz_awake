# Ducex

Ducex is an Android packer used by recent variants of the [Triada](../malware/families/triada.md) trojan family. Public research is thin: the principal analysis is [any.run's July 2025 writeup](https://any.run/cybersecurity-blog/ducex-packer-analysis/), which characterizes Ducex as "an advanced Chinese Android packer" that wraps Triada samples to defeat static signature matching and frustrate dynamic analysis. Earlier AWAKE drafts incorrectly attributed recent Triada packing to [Tencent Legu](tencent-legu.md); Ducex is the correct packer.

## Vendor Information

| Field | Value |
|-------|-------|
| Vendor | Unknown (described as Chinese-origin in [any.run analysis](https://any.run/cybersecurity-blog/ducex-packer-analysis/)) |
| Distribution model | Not publicly offered; observed only as a Triada-bundled protection layer |
| First public analysis | [8 July 2025, any.run](https://any.run/cybersecurity-blog/ducex-packer-analysis/) |
| Status | Active in current Triada samples |

## Identification

| Artifact | Detail |
|----------|--------|
| Native library | `libducex.so` (per [any.run](https://any.run/cybersecurity-blog/ducex-packer-analysis/)) |
| Payload location | Triada payload stored as a large additional section inside Ducex's own `classes.dex`, after the main application code, rather than as a separate asset or library |
| JNI entry | Obfuscated `JNI_OnLoad` after `libducex.so` is loaded |
| Cipher use | RC4 for function encryption, SM4 for additional layers, XOR for strings |

There is no APKiD rule for Ducex as of the most recent inspection of the [APKiD master rules](https://github.com/rednaga/APKiD/blob/master/apkid/rules/apk/packers.yara); identification is currently manual (look for `libducex.so` plus the in-DEX payload section).

## Protection Mechanisms

### Cryptography

Per [any.run](https://any.run/cybersecurity-blog/ducex-packer-analysis/), Ducex uses two block ciphers (RC4 and SM4) for code protection layers and XOR encoding for string literals. The dual-cipher pattern echoes the design of [SecShell](secshell.md), which also uses RC4 and SM4, suggesting a shared lineage or design influence within the Chinese packer ecosystem.

### In-DEX Payload Storage

A distinctive Ducex behavior is storing the real Triada payload as an oversized additional segment inside the packer's own `classes.dex`, after the legitimate application bytecode. This avoids the more easily-spotted "encrypted asset blob plus loader" pattern and means dumping requires reaching the payload section inside the DEX rather than from `/assets/`.

### Anti-analysis

[any.run](https://any.run/cybersecurity-blog/ducex-packer-analysis/) reports active detection of Frida, Xposed, and Substrate from memory. When any of these tools is detected the process terminates immediately. This is RASP-style runtime self-protection layered on top of the static encryption.

## Reversing Approach

Single primary source means the unpacking methodology described here is derived from the [any.run analysis](https://any.run/cybersecurity-blog/ducex-packer-analysis/) and should be cross-validated on additional samples.

1. Identify Ducex by `libducex.so` and confirm with strings/JNI layout
2. Anti-hook bypass first: standard Frida is detected and triggers termination; use [ZygiskFrida](https://github.com/lico-n/ZygiskFrida) for stealth injection, or patch `libducex.so` to disable the detection routines before Frida attach
3. Locate the in-DEX payload section by parsing `classes.dex` and looking for the oversized trailing region after the main code
4. Decrypt the payload using the RC4/SM4 keys recovered from `libducex.so` (extract via static analysis or by hooking the cipher initialization)
5. Reassemble the decrypted payload as a standalone DEX and analyze normally with jadx

## Known Malware Usage

| Family | Notes | Source |
|--------|-------|--------|
| [Triada](../malware/families/triada.md) | Recent variants ship inside Ducex; the wrapper is what made Triada samples appear novel to scanners despite the long-running family lineage | [any.run](https://any.run/cybersecurity-blog/ducex-packer-analysis/) |

## Uncertainties

- Whether Ducex is sold as a packer-as-a-service or remains exclusive to a single threat actor is not stated in public research.
- No vendor or operator identity has been attributed in public reporting; the "Chinese-origin" description from any.run is a characterization, not a sourced attribution.
- The exact RC4 and SM4 key derivation is not enumerated in public material at the time of writing.
- No academic or independent vendor analysis has yet validated the any.run writeup; corroboration from a second primary source (ThreatFabric, Kaspersky, Trend Micro) would strengthen the picture.
