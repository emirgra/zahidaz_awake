# DPT Shell

DPT Shell is an open-source Android packer ([luoyesiqiu/dpt-shell](https://github.com/luoyesiqiu/dpt-shell)) that protects applications through instruction extraction: every method's Dalvik bytecode is stripped from the DEX file and stored in a separate asset, then restored at runtime via ART `ClassLinker` hooks. Standard decompilers (jadx, baksmali, dex2jar) fail on DPT-packed apps because the DEX has valid class/method/string tables but garbage `insns[]` arrays, producing `VerifyError: bad dex opcode` on every method body. Despite being designed for legitimate IP protection, DPT Shell appears in redistributed and repackaged APKs.

## Overview

| Property | Value |
|----------|-------|
| Developer | [luoyesiqiu](https://github.com/luoyesiqiu) |
| Type | Open-source packer (instruction extraction) |
| Source | [github.com/luoyesiqiu/dpt-shell](https://github.com/luoyesiqiu/dpt-shell) |
| License | Open source |
| Platform | Android (min API 21) |
| Architectures | ARM v7/v8, x86, x86_64 |

## Identification

### File Artifacts

| Artifact | Location | Description |
|----------|----------|-------------|
| Native library | `assets/vwwwwwvwww/<arch>/libde2f2e7641da6521.so` | Core runtime library |
| Bytecode store | `assets/OoooooOooo` | Extracted method bodies |
| Shell config | `assets/d_shell_data_001` | AES-CBC encrypted configuration |
| Proxy class | `ProxyApplication` | Stub Application class that boots the packer |
| Component factory | `ProxyComponentFactory` | Hijacks all component instantiation |
| JNI bridge | `JniBridge` | 11 native methods: `rapn`, `rcf`, `cbde`, `craa`, `craoc`, `clinit`, `ia`, `ra`, `rde`, `gap`, `gdp` |

### Native Library Strings

The `libde2f2e7641da6521.so` library contains identifiable strings:

- `libdpt.so`
- `DPT_UNKNOWN_DATA`
- `ClassLinker`
- `DefineClass`
- `dexElements`
- `makeDexElements`
- `bytehook-plt-trampolines`

### APKiD Detection

APKiD identifies DPT Shell through the native library naming pattern and asset structure.

### Signing Artifacts

DPT Shell repackaging requires re-signing, so packed apps lose [Play Frosting](../platform-abuse/play-frosting.md) and original v2/v3 signatures. Common artifact: v1+v2+v3 declared but v2/v3 payloads have size 0 (effectively v1-only signing).

## Protection Mechanism

### Packing Phase

1. The packer takes the real DEX and walks every `class_def` -> `class_data_item` -> method
2. Each method's `insns[]` bytecode is extracted and stored in `assets/OoooooOooo`
3. The original `insns[]` is replaced with garbage bytes
4. The gutted DEX is compressed into a ZIP and appended after the official data boundary of a tiny stub `classes.dex` (6 classes, 99 methods)
5. A 4-byte big-endian length is written at the very end of `classes.dex` so the runtime can locate the ZIP

### Runtime Phase

The stub `ProxyApplication` boots the packer:

1. Extracts `libde2f2e7641da6521.so` from `assets/vwwwwwvwww/<arch>/`
2. Uses ByteHook PLT trampolines and direct ART `ClassLinker::DefineClass` manipulation to:
   - Read the appended ZIP from inside `classes.dex`
   - Parse `OoooooOooo` to build a `methodIdx -> bytecode` map
   - Hook `ClassLinker::LoadMethod` to restore each method's real bytecode on demand
3. Patches `ActivityThread` fields (`mBoundApplication`, `mInitialApplication`, `mAllApplications`) to swap `ProxyApplication` for the real `Application` class
4. Intercepts all component instantiation via `ProxyComponentFactory` (activities, services, receivers, providers, class loaders)

### Why Standard Decompilers Fail

The inner DEX has valid structure (class definitions, method signatures, string tables) but every method body contains garbage opcodes. Decompilers parse the structure successfully but crash or produce nonsense when interpreting method bytecode. This makes DPT Shell effective against static analysis while being fully reversible through the `OoooooOooo` file.

## OoooooOooo File Format

From [DPT Shell source](https://github.com/luoyesiqiu/dpt-shell/blob/main/shell/src/main/cpp/dex/MultiDexCode.cpp):

```
MultiDexCode:
  uint16  version          // e.g., 2
  uint16  dexCount         // number of DEX files
  uint32  offsets[dexCount] // byte offset to each DexCode section

DexCode (at offsets[i]):
  uint16  methodCount
  CodeItem[methodCount]:
    uint32  methodIdx       // index into DEX method_ids table
    uint32  insnsSize       // bytecode length in BYTES
    uint8   insns[insnsSize] // the real Dalvik bytecode
```

## Unpacking Methodology

DPT Shell is fully defeatable through static analysis without running the app.

### Step 1: Extract the Inner ZIP

Read the last 4 bytes of `classes.dex` as a big-endian uint32 (`zipLen`). The ZIP lives at offset `fileSize - zipLen - 4`. Extract `classes.dex` (and `classes2.dex` if present) from it.

### Step 2: Parse OoooooOooo

Read the header (version, dexCount, offsets), then for each DEX, read all CodeItem entries to build a `methodIdx -> insns` map.

### Step 3: Build a Method Index Map

Walk each `class_def` -> `class_data_item` in the inner DEX. Track the differential `method_idx` encoding (resets to 0 at the start of each `direct_methods` and `virtual_methods` section per class). Map `methodIdx -> code_off` (the file offset of that method's `code_item`).

### Step 4: Patch Bytecode

For each CodeItem from OoooooOooo, look up `code_off` by `methodIdx`. Write `insns` to `dex[code_off + 16]` (the 16-byte `code_item` header contains `registers_size`, `ins_size`, `outs_size`, `tries_size`, `debug_info_off`, `insns_size` -- skip these).

### Step 5: Fix Checksums

Recompute SHA-1 over bytes 32..end, write to DEX offset 12. Recompute Adler32 over bytes 12..end, write to DEX offset 8.

The result is a valid DEX that decompiles cleanly with jadx.

### Automated Tooling

[shirayukiimountain/dpt-unpack](https://github.com/shirayukiimountain/dpt-unpack) automates the full static unpacking process.

## Shell Config Decryption

`assets/d_shell_data_001` (typically ~160 bytes) contains AES-CBC encrypted shell configuration. The key is derived from the `DPT_UNKNOWN_DATA` native export, with IV derived through byte patches at specific positions (positions 3 -> 0x2f and 9 -> 0x76 observed in analyzed samples).

## Comparison with Similar Packers

| Feature | DPT Shell | [Hqwar](hqwar.md) | [Bangcle](bangcle.md) |
|---------|-----------|-------|---------|
| Source | Open source | Underground | Commercial |
| Technique | Instruction extraction + runtime restoration | RC4-encrypted DEX + DexClassLoader | DEX encryption + native loader |
| Static defeat | Yes (OoooooOooo parsing) | Yes (RC4 key extraction) | Partial (dump from memory) |
| ART hooking | ClassLinker::LoadMethod | No | No |
| Multi-DEX | Yes (dexCount in header) | No | Yes |
| Component hijacking | ProxyComponentFactory | No | Custom Application class |

## Known Usage

| Context | Details |
|---------|---------|
| HK Government News app | Legitimate app (`com.igpsd.govnews`) packed with DPT Shell, likely by redistributor or build pipeline. App code is benign (RSS reader targeting `*.news.gov.hk`). |

DPT Shell has not been widely observed in malware campaigns. Its open-source nature and documented unpacking methodology make it a poor choice for sophisticated threat actors compared to commercial packers or underground options like [GoldCrypt](goldcrypt.md) or [Hqwar](hqwar.md). However, its availability on GitHub means it may appear in low-effort repackaging operations.

## References

- [DPT Shell source code](https://github.com/luoyesiqiu/dpt-shell)
- [DPT Shell MultiDexCode format](https://github.com/luoyesiqiu/dpt-shell/blob/main/shell/src/main/cpp/dex/MultiDexCode.cpp)
- [dpt-unpack automated unpacker](https://github.com/shirayukiimountain/dpt-unpack)
