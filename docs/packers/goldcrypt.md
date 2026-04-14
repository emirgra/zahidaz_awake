# GoldCrypt (Golden Encryption)

GoldCrypt (also marketed as Golden Encryption or Golden Crypt) is a commercial-grade Android packer promoted on underground malware forums. Unlike legitimate packers sold by security vendors, GoldCrypt is purpose-built for malware evasion and sold directly to threat actors. It uses RC4-encrypted DEX payloads hidden in deeply nested directory structures with uncommon characters to defeat static analysis tools and automated sandboxes. The packer has been observed in [Mirax](../malware/families/mirax.md) and [Albiriox](../malware/families/albiriox.md) campaigns.

## Overview

| Property | Value |
|----------|-------|
| First Seen | 2025 (earliest observed usage) |
| Type | Underground malware packer |
| Attribution | Unknown, sold on Russian-speaking underground forums |
| Also Known As | Golden Encryption, Golden Crypt, GoldEncrypt |
| Detection | Not well-documented by AV vendors; no standardized detection name |

## Protection Mechanism

GoldCrypt implements a multi-stage unpacking flow:

| Step | Description |
|------|-------------|
| 1 | Malicious DEX payload is encrypted with RC4 using a hardcoded key |
| 2 | Encrypted file is renamed with a valid asset extension and buried in a deeply nested folder path |
| 3 | Folder names use uncommon/special characters to confuse static analysis tools and file path parsers |
| 4 | At runtime, the dropper locates the encrypted DEX from the obfuscated path |
| 5 | RC4 decryption with the embedded key produces the plaintext DEX |
| 6 | Decrypted DEX is loaded via `DexClassLoader` and extracts the final APK from `res/raw/` |
| 7 | Final APK is XOR-decrypted using a key stored in `BuildConfig` |
| 8 | Implant APK is installed, optionally masquerading as a utility app |

The double encryption (RC4 for the DEX loader, XOR for the final implant) and directory path obfuscation create multiple layers that must be defeated sequentially during analysis.

## Identification

### File Artifacts

| Artifact | Description |
|----------|-------------|
| Nested directories | Deeply nested folder paths with uncommon/special characters in names |
| Encrypted DEX | File with valid asset extension containing RC4-encrypted DEX payload |
| RC4 key | Hardcoded decryption key in application class |
| XOR key in BuildConfig | Second-stage decryption key for implant APK in `BuildConfig` class |
| `res/raw/` payload | Encrypted final APK stored in resources |

### Distinguishing from Other Packers

GoldCrypt lacks the visible file artifacts of commercial packers: no `libvirbox_*.so` ([Virbox](virbox.md)), no stub package with hex-based naming, no well-known native library signatures. The primary identification indicators are the deeply nested directory structure with special characters and the two-stage RC4+XOR decryption chain. This makes automated identification harder than for commercial packers that [APKiD](https://github.com/rednaga/APKiD) can flag.

## Unpacking Methodology

1. **Locate the encrypted DEX**: Search the APK for files buried in unusually deep directory paths with special characters in folder names
2. **Extract the RC4 key**: Decompile the dropper's application class to find the hardcoded key
3. **Decrypt the DEX**: Apply RC4 decryption to produce the loader DEX
4. **Analyze the loader**: The DEX contains logic to extract and XOR-decrypt the final APK from `res/raw/`
5. **Extract the XOR key**: Check `BuildConfig` for the second decryption key
6. **Decrypt the implant**: XOR-decrypt the `res/raw/` payload to obtain the final malware APK
7. **Analyze the implant**: The resulting APK may itself use GoldCrypt packing (same technique applied recursively)

## Comparison with Similar Packers

| Feature | GoldCrypt | [Hqwar](hqwar.md) | [Virbox](virbox.md) |
|---------|-----------|-------|--------|
| Market | Underground forums | Underground forums | Commercial (legitimate) |
| DEX encryption | RC4 | RC4 | Custom native |
| Second-stage encryption | XOR (implant APK) | None | None |
| Path obfuscation | Deep nesting + special chars | None | None |
| Native library | None | None | `libvirbox_*.so` |
| APKiD detection | No | Yes | Yes |
| Builder integration | Yes ([Mirax](../malware/families/mirax.md) builder offers as option) | Packer-as-a-service | Standalone tool |

## Known Malware Usage

| Family | Context |
|--------|---------|
| [Mirax](../malware/families/mirax.md) | Builder offers GoldCrypt as one of two packer options (alongside [Virbox](virbox.md)). Used in Spanish-targeting campaigns. |
| [Albiriox](../malware/families/albiriox.md) | [Cleafy noted](https://www.cleafy.com/cleafy-labs/mirax-a-new-android-rat-turning-infected-devices-into-potential-residential-proxy-nodes) the same unpacking patterns as Mirax samples, suggesting GoldCrypt usage. |

## References

- [Cleafy: Mirax analysis (GoldCrypt packer details)](https://www.cleafy.com/cleafy-labs/mirax-a-new-android-rat-turning-infected-devices-into-potential-residential-proxy-nodes) (April 10, 2026)
