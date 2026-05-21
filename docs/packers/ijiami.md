# iJiami

Chinese commercial packing service ([ijiami.cn](https://www.ijiami.cn/)) with free and paid tiers. Free tier ships basic DEX encryption; paid tiers add a custom bytecode-VM DEX cipher, OLLVM-protected native loaders, anti-emulation fingerprinting, and a bundled SandHook + Xposed runtime used for stealth JNI binding.

The v4 generation (current as of this writing) is the focus of this page. Earlier generations used simpler whole-DEX encryption that standard runtime DEX dumpers defeat trivially.

## Vendor Information

| Attribute | Details |
|-----------|---------|
| Vendor | iJiami |
| Origin | China |
| Type | Commercial Packer/Protector |
| Bundled runtime | SandHook + Xposed (for ART `Method` patching) |
| APKiD signature | `packer : iJiami` |
| Unpacking difficulty | Easy (legacy), Hard (v4) |

## Identification

| Artifact | Description |
|----------|-------------|
| Native libraries | `libexec.so` (first-stage loader, ~1 MB), `libexecmain.so` (helper, ~65 KB), `libexecoat.so` (anti-analysis stub) |
| Encrypted DEX container | `assets/ijiami.dat` |
| Auxiliary asset names | `IJMDal.Data`, `images/data_max_info_encrypted_*.png` |
| JNI exports | Hash-prefixed obfuscated names (e.g. `a374834853`, `s3420985342`); a literal `ijiami` no-op export in both native libraries |
| Helper struct export | `core` (32-byte runtime struct exported from `libexecmain.so`) |
| Stock UPX behaviour | `upx -d` rejects the native libraries with `NotPackedException: not packed by UPX` |

## Protection

iJiami v4 stacks four independent layers plus a set of anti-analysis and anti-hook techniques. The two tables below are a quick inventory; each item is detailed in the sections that follow.

### Cryptographic and obfuscation primitives

| Primitive | Where | Role |
|-----------|-------|------|
| NRV2E (UCL/UPX family) + literal-byte XOR `0x50` | `libexec.so`, `libexecmain.so` outer container | Native loader packing |
| UPX CT_FILTER (parameterised `cto8` byte) | Code segment of NRV2E block | CALL/JMP relativisation pass |
| XOR with 16-byte ASCII pad `c1xsFn` `:u[_HiD@r` | `.rodata` of both native libs | String obfuscation |
| XOR with inlined per-byte constants | `.data` of `libexecmain`, decrypted in place at boot by `a374834853` / `s3420985342` init exports | `.data` obfuscation (separate from the `.rodata` pad) |
| Single-byte XOR `0xb7`, skip-zeros | `libexecoat.so` payload | Anti-analysis stub |
| SM4-ECB + PKCS#7, standard GM/T 0002-2012 S-box + CK | `libexec` PNG-asset decrypt path | In-binary PNG-asset table (key: `vityThread$Packa`) |
| SM4 with custom S-box | `libexec` - target not fully pinned in public analysis | Secondary SM4 path, distinct from the PNG one |
| zlib + PK-ZIP wrap | `ijiami.dat` plaintext, before encryption | Compression layer underneath the VM cipher |
| Two-library Dalvik-style bytecode VM, per-chunk key derivation | `ijiami.dat` ciphertext | The actual DEX cipher (80-byte chunks) |
| MD5 of plaintext | `ijiami.dat` header `[0x08:0x28]` | Cryptographic post-decryption integrity tag |

### Anti-analysis and anti-hook techniques

| Technique | Implementation |
|-----------|----------------|
| Stock-UPX rejection | NRV2E + literal-XOR defeats `upx -d` and naive "is this UPX?" tooling |
| `RegisterNatives` bypass | Java-reflection binding via `FromReflectedMethod` + direct ART `entryPointFromJni` patching |
| `dlsym` bypass | Custom inter-library symbol resolver walks `libexecmain`'s loaded image at boot and builds a private symbol table |
| SandHook + Xposed bundling | Method-hook framework repurposed as a private binder rather than for hooking other apps |
| Decoy exports | Hash-prefixed dispatch-table getters that return constant pointers; literal `ijiami` export in both libraries is a no-op stub that exists only to satisfy `dlsym("ijiami")` |
| OLLVM | Control-flow flattening + bogus-CF + opaque-predicate inflation throughout `libexecmain` |
| Build-prop fingerprint loops | `ro.build.version.release_or_codename` (~2.7M iter), `ro.yunos.version` (~26k iter) - fixed-iteration regardless of returned value |
| Cross-process cooperation | `fork + ptrace(PTRACE_ATTACH/PTRACE_CONT) + wait` with a `bsd_signal(SIGUSR2)` handler |
| Stack-probe loop in second-stage unpack | A loop that walks ~60 MB of address space sits between the first and second unpack stages of the NRV2E stub. Naive Unicorn / Qiling harnesses hang on it; must be patched out to reach the nested unpack. |

Each item below is detailed in the sections that follow.

### 1. Native loader packing (NRV2E + literal XOR)

`libexec.so` and `libexecmain.so` are packed with a UPX-derived NRV2E stream with one packer-specific twist: every decoded literal byte is XOR'd against the constant `0x50` before being written. The combination defeats stock `upx -d` and all "is this UPX?" identification tooling.

Container layout:

| Block | Contents |
|-------|----------|
| Outer stub | Minimal program headers + `DT_INIT` pointer, just enough to let the dynamic linker enter the unpacker. |
| Magic tag | Four-byte `AJM!`-style packer magic (not `UPX!`). |
| Compressed block 0 | Real ELF header + full program header table. |
| Compressed block 1 | Code segment, with UPX's CALL/JMP relative-offset CT_FILTER applied on top of the NRV2E stream. |
| Raw blocks | `.dynsym`, `.dynstr`, `.rel.dyn`, `.rel.plt`, `.plt`, `.init_array`, `.fini_array`, RW data - uncompressed. |
| Terminator | Zero. |

The `DT_INIT` bootstrap is fully position-independent and bypasses the dynamic linker. Identifying signatures inside `DT_INIT`:

| Pattern | Role |
|---------|------|
| `call X; pop reg` | PIC base recovery. |
| `or ebp, 0xffffffff` | NRV bit-buffer init. |
| Inner loop reading one byte, XOR'ing constant `0x50`, writing one byte | The literal-byte emitter. |
| `push 0x5a; pop eax; int 0x80` (bytes `6A 5A 58 CD 80`) | Raw `mmap` syscall - the stub allocates its output buffer without going through any imported function. |
| `mov eax, 0xc0; ... sysenter` | `__NR_mmap2` fast path next to the slow path above. |

Reconstructing a clean ELF requires: NRV2E decompress with `XOR 0x50` on literals, reverse UPX's CT_FILTER over the code block, then re-stitch the raw `.dynsym/.dynstr/.rel.*/.plt/.init_array/.fini_array` tables and the RW data segment that the packed file already stores uncompressed at their original offsets. The result is a valid ELF that opens cleanly in radare2, Ghidra and IDA.

### 2. `.rodata` XOR-pad string obfuscation

Both native libraries share a single 16-byte ASCII XOR pad applied to `.rodata` strings:

```
pad = c1xsFn`:u[_HiD@r        (16 bytes)
```

```
encoded[i] = plaintext[i] ^ pad[i mod 16]
```

Properties:

- The pad cycle **resets at the start of every NUL-terminated record**, anchored at the first byte of the record (pad index 0).
- A plaintext byte that equals the pad byte at that position encodes as `0x00` - so records can contain inner NULs, and pad characters appearing as plaintext leak as visible ASCII fragments inside an otherwise high-entropy region.
- The pad covers `.rodata` only. The `.data` region of `libexecmain.so` is XOR-decrypted in place at boot by the `a374834853` / `s3420985342` init exports using **inlined per-byte constants** (no shared pad). This is a separate scheme from the `.rodata` pad - hooking the pad decoder will not surface `.data` strings.
- `libexecoat.so` (the auxiliary anti-analysis stub) is a third, unrelated scheme: its payload is encoded with **single-byte XOR `0xb7` applied to non-zero bytes only** (NUL bytes are passed through, so the encoded blob retains its NUL skeleton).

Identification signatures in an unknown library:

1. A large `.rodata` region of high-entropy bytes that contains inner NULs.
2. Short ASCII fragments visible inside that region - these are the pad's own characters leaking through where the plaintext happens to be the pad. With the v4 pad above, the most common leakage is the fragment `c1xs`.
3. PLT/GOT cross-references land at the start of the decoded record, not at the NUL terminator - walking xrefs into the region surfaces real record starts.

Pad recovery is a one-shot known-plaintext attack against any record long enough to span 16 bytes. A JNI method-descriptor string (uniquely determined by JNI conventions) is the unambiguous choice. Once recovered, every record decodes deterministically.

Decoder:

```python
PAD = b'c1xsFn`:u[_HiD@r'

def decode_record(data, off):
    out = bytearray()
    for i in range(MAX_LEN):
        c = data[off + i] ^ PAD[i % 16]
        if c == 0:
            return bytes(out)
        out.append(c)
```

Representative recovered strings (constant across v4 builds): `ijiami.dat`, `IJMDal.Data`, `android/app/LoadedApk`, `android/app/ActivityThread$PackageInfo`, `mClassLoader`, `dalvik/system/PathClassLoader`, `classes.dex`, `images/data_max_info_encrypted_xxxxxx.png`, `/data/app/%s-1.apk`.

### 3. `ijiami.dat` container format

The protected DEX is stored encrypted in `assets/ijiami.dat`. v4 header:

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| `0x00` | 4 | `version` (LE32) | `4` for this generation. |
| `0x04` | 4 | `pt_size` (LE32) | Length of the plaintext (post-decryption). Consistently ~2.4x the ciphertext length, indicating zlib + PK-ZIP wrap before encryption. |
| `0x08` | 32 | `md5_hex` | ASCII hex MD5 of the plaintext - integrity tag. A successful decryption can be validated cryptographically against the header itself. |
| `0x28` | 3 | trailer | Three constant bytes. |
| `0x2b` | rest | ciphertext | 16-byte aligned. |

Ciphertext structure (from autocorrelation and aligned-block-repeat scans of observed v4 samples):

- An **80-byte chunk cycle** is the only periodicity present - the most-frequent 16-byte aligned blocks recur at uniform 80-byte deltas.
- Multiple distinct 5-byte repeating regions appear at different positions, with non-zero XOR between them. These are spans where the plaintext is run-length zero and the keystream leaks verbatim - confirming a **chunked cipher with per-chunk key derivation**, not a single stream-cipher key over the whole file.
- Whole-file single-byte autocorrelation lands in the random-chance regime at sampled periods 1, 5, 16, 80, 256, 1024, 4096.

### 4. Cipher dispatch: two-library bytecode VM

The v4 DEX cipher is not a per-byte cipher leaf. It is a Dalvik-style bytecode interpreter split across both native libraries:

- `libexec.so` holds the VM dispatcher and arithmetic switch.
- `libexecmain.so` holds 256 thunks plus a `getOpCode` PLT-trampoline dispatcher and a 32-byte runtime struct exported as `core`.

The `core` struct fields:

| Offset | Field | Set by |
|--------|-------|--------|
| `0x00` | Data blob pointer | `libexecmain` init |
| `0x04` | 256-thunk table pointer | `libexecmain` init |
| `0x08` | `getOpCode` pointer | `libexecmain` init |
| `0x0c` | Reserved | `libexec` at runtime |
| `0x10` | **VM callback** | **`libexec` at runtime** |

The 256 thunks all follow the template `(**(code **)(core + 0x10))(arg0, OPCODE_N, arg1, varargs)` - thunk `N` bounces back to the runtime-installed callback in `libexec` with the opcode index baked in. The arithmetic switch in `libexec` implements Dalvik-style opcodes:

| Opcode(s) | Operation |
|-----------|-----------|
| `0x5c, 0x9a` | `xor-int` |
| `0x7c, 0x82` | `mul-int` |
| `0xc9, 0xdc` | `or-int` |
| `0xd0` | `div-int` (with zero-check) |
| `0x5e` | `shr-int` |

Wide-register semantics: results are written with sign-extension to the next 8-byte slot.

`getOpCode` looks like a static 256-byte S-box but is not. The underlying table is 256 signed 32-bit offsets from `DT_PLTGOT` that resolve to 256 distinct local handler addresses inside `libexecmain.so`'s own `.text`. Handlers that take arguments or touch memory cannot be reduced to a static lookup.

The 80-byte chunk cycle observed in `ijiami.dat` is produced by this VM, with per-chunk register-file state seeded from chunk index and ciphertext bytes.

### ClassLoader substitution

After the unpacked DEX is in memory, iJiami performs the standard commercial-packer transparent-load trick: walk `ActivityThread.currentActivityThread() -> mBoundApplication -> LoadedApk -> mClassLoader` via reflection and substitute the packer's own ClassLoader (which knows how to resolve classes against the unpacked DEX). The host app's class lookups then resolve transparently to the unpacked code.

The relevant ART/Android internals - `currentActivityThread`, `mBoundApplication`, `LoadedApk`, `mClassLoader`, `getApplicationInfo`, `sourceDir`, `mAppDir` - all appear as plaintext in the recovered `.rodata` string table, which is the easiest static fingerprint of this mechanism.

### Stealth JNI binding via Java reflection

`JNI_OnLoad` runs to completion **without ever calling `RegisterNatives`**. Instead, the packer:

1. Reads a static `Method[]` field from a Java helper class in the packer's stub package via `GetStaticObjectField`.
2. Converts each `Method` to a `jmethodID` via `FromReflectedMethod`.
3. Patches the `entryPointFromJni` slot of each ART `Method` directly, using ART internals supplied by the SandHook + Xposed runtime iJiami bundles.

JNI traffic profile during a full `JNI_OnLoad` pass is a clean dynamic identification fingerprint - counts are stable across v4 builds:

| JNI call | Count | Purpose |
|----------|-------|---------|
| `GetStaticObjectField` | 1 | Read the helper class's `Method[]` |
| `FromReflectedMethod` | 7 | Convert each `Method` -> `jmethodID` (matches the 7 declared wrapper natives) |
| `IsSameObject` | 6 | Compare reflected references |
| `NewObjectArray` | 3 | Build the jmethodID table |
| `CallObjectMethod` / `CallObjectMethodV` | 3 / 3 | Invoke methods on the reflected objects |
| `NewDirectByteBuffer` | 6 | Wrap native pointers as Java byte buffers - the channel through which plaintext flows back to Java |
| `GetCharArrayElements` / `ReleaseCharArrayElements` | 3 / 3 | UTF-16 handling for the obfuscated method names |
| `IsInstanceOf` | 1 | Type check |
| `RegisterNatives` | **0** | Deliberately absent - the binding is reflection-driven, not registration-driven |

Two consequences:

- Hooking `RegisterNatives` to enumerate the packer's native handlers does not work.
- The binding only completes when a real ART is executing the helper class - single-process Unicorn / Qiling cannot satisfy `GetStaticObjectField`.

Inter-library calls between `libexec` and `libexecmain` also bypass the dynamic linker: `libexec` walks the loaded image of `libexecmain` and builds a private runtime symbol table during `JNI_OnLoad`. Hooking `dlsym` misses most cross-library traffic, including the `core[+0x10]` callback installation.

### Anti-emulation and anti-analysis

| Feature | Behaviour |
|---------|-----------|
| Build-prop fingerprint loop | `__system_property_get('ro.build.version.release_or_codename')` + `strcpy` called ~2.7M times per `JNI_OnLoad`. Fixed iteration count - returning the "correct" value does not short-circuit the loop. |
| YunOS fingerprint loop | `ro.yunos.version` queried ~26 000 times. Generic Alibaba/YunOS environment fingerprint, not a YunOS-specific gate. |
| Cross-process cooperation | `fork + ptrace(PTRACE_ATTACH) + ptrace(PTRACE_CONT) + wait` block, plus `bsd_signal(SIGUSR2)` handler. A two-process parent/child cooperating path that single-process emulation cannot exercise. |
| OLLVM density | Control-flow flattening + bogus-CF + opaque-predicate inflation throughout `libexecmain.so`. Millions of opaque-predicate branches per emulated `JNI_OnLoad`. |
| `libexecoat.so` | Anti-analysis stub, single-byte-XOR (`0xb7`) encoded payload over non-zero bytes only. |

### SM4 paths (asset protection, not the DEX cipher)

`libexec.so` contains two SM4 implementations:

1. **Standard SM4-ECB + PKCS#7** using the GM/T 0002-2012 reference S-box and CK round constants baked into `.rodata`. This routine decrypts an in-binary PNG-asset table. The 16-byte master key is recovered by XOR-decoding a 26-byte in-binary blob against the `.rodata` string pad with rotation 12; the plaintext is `ActivityThread$PackageInfo` and the SM4 master key is bytes `[4..20]` of that string: `vityThread$Packa`.
2. **SM4 with a custom (non-standard) S-box.** A second SM4 variant is present in the loader. The exact target of this variant is not pinned in public static analysis - it does not appear to decrypt `ijiami.dat` either.

Neither SM4 path decrypts `ijiami.dat`. Mistaking either of them for the DEX cipher is the most common analyst trap on a first pass - when SM4 byte-patterns appear in the loader, they are asset-layer, not DEX-layer.

### Custom inter-library symbol resolution (anti-hook)

iJiami does not rely on the dynamic linker's PLT for inter-library calls between `libexec` and `libexecmain`. During `JNI_OnLoad`, an unnamed routine in `libexec` walks the loaded image of `libexecmain` and builds a private runtime symbol table; all subsequent cross-library calls go through that table, including the `core[+0x10]` callback installation that arms the bytecode VM.

Consequence: hooking `dlsym` misses essentially all of the cross-library traffic. Cross-library calls must be intercepted at the call-site or by hooking the resolver itself.

### Decoy exports

Two recognisable iJiami fingerprints in the export tables of both native libraries:

- **Hash-prefixed dispatch-table getters** - exports with names like `a374834853` or `s3420985342` (the digits vary per build, the prefix-letter pattern does not). A family of similarly-named exports in `libexec` looks like cipher entry points but are dispatch-table getters that return constant pointers into `libexecmain.so` `.data` and never install the `core[+0x10]` callback. Designed to waste analyst time on dead-end leaves.
- **Named `ijiami` no-op stub** in both libraries - exists only as a named JNI export so `dlsym("ijiami")` succeeds. Has no body.

## Anti-analysis and anti-emulation

The summary table at the top of the protection section lists each technique; the section below explains the trap and the analyst response for each.

### Native-loader unpacking traps

- **Stock `upx -d` rejection.** NRV2E + literal-XOR `0x50` defeats stock UPX with `NotPackedException: not packed by UPX`. The first-pass "is this UPX?" tooling returns no. Analyst response: implement NRV2E with the XOR step and the CT_FILTER reverse pass directly; the stream is otherwise standard.
- **Raw-syscall `mmap`.** The `DT_INIT` bootstrap allocates its output buffer via `int 0x80` (`push 0x5a; pop eax; int 0x80`) or `sysenter` `__NR_mmap2`, never through libc. Hooking `mmap` in libc.so will not catch the unpack. Analyst response: hook the kernel-entry syscall path or instrument at the stub disassembly directly.
- **Stack-probe loop (~60 MB).** Between the first and second NRV2E unpack stages sits a loop that walks ~60 MB of address space. Naive Unicorn / Qiling harnesses hang on it. Analyst response: patch the loop's iteration counter or NOP the probe entirely; the loop has no side effects on the unpacked payload.

### OLLVM and decoy state

- **Density.** `libexecmain.so` is OLLVM-flattened with bogus-CF and opaque-predicate inflation. The `getOpCode` dispatcher's surrounding logic balloons to ~6.9 KB around a single 256-way switch. Millions of opaque-predicate branches fire per emulated `JNI_OnLoad`. Analyst response: deobfuscate with `ollvm-deobfuscator` / `D-810` / Triton-based simplifiers before reading the dispatcher.
- **Opaque-predicate decoy globals.** Two globals near `getOpCode` (referenced by branches inside the dispatcher's `do { } while (true)` loop) look to a decompiler like cryptographic state - they feed conditional flow and are updated in place. They are **algebraically constant** opaque-predicate inputs and carry no cryptographic role. Analyst trap: chasing these as cipher state. Analyst response: constant-fold the opaque predicate; both branches reduce to one.
- **Decoy exports.** Hash-prefixed exports look like cipher leaves and are dispatch-table getters. The literal `ijiami` export is a no-op. Both are time-wasters with no cryptographic content. Analyst response: invoke each suspect export with synthetic args once and look for buffer growth or `core[+0x10]` install - neither happens for the decoys.

### Hook-bypass measures

- **`RegisterNatives` is never called.** A Frida script that hooks `RegisterNatives` to enumerate the packer's natives returns nothing. Analyst response: hook `FromReflectedMethod` instead, or wait for binding to complete and hook the resolved `entryPointFromJni` slots directly.
- **`dlsym` is bypassed.** Cross-library calls between `libexec` and `libexecmain` go through a private runtime symbol table built by walking the loaded image of `libexecmain` at boot. Hooking `dlsym` misses everything, including the `core[+0x10]` callback installation. Analyst response: hook the resolver itself, or intercept at the call-site post-binding.
- **SandHook + Xposed bundled as a binder, not a hooker.** The presence of SandHook + Xposed symbols is misleading - they are used by the packer to patch *its own* `entryPointFromJni` slots, not to hook the host app. A hook-detection signature that fires on SandHook presence will false-positive on every iJiami v4 sample.

### Environment fingerprinting

- **`ro.build.version.release_or_codename` loop (~2.7M iterations per `JNI_OnLoad`).** Reads the build prop and `strcpy`s it ~2.7 million times. The loop is **fixed-iteration**: returning the "correct" value does not short-circuit it. The loop's effect is purely to consume cycles and dirty caches in a way that exposes naive emulators (Unicorn slows to a crawl long before completing).
- **`ro.yunos.version` loop (~26 000 iterations).** Generic Alibaba/YunOS env fingerprint, not a YunOS-specific gate. Same fixed-iteration pattern.
- Analyst response: patch out the loop counters before emulating, but be aware that the loops' side-effects (the `strcpy` chain mutates a buffer) may be inputs to downstream state - verify what the buffer contents are used for before NOPing.

### Cross-process cooperation

- **`fork + ptrace(PTRACE_ATTACH/PTRACE_CONT) + wait`** with a `bsd_signal(SIGUSR2)` handler. Two cooperating processes (parent + ptraced child) exchange register state via the ptrace interface. Single-process Unicorn / Qiling instances do not exercise this path at all - they execute only the parent's code path and never receive the child's contributed state. Analyst response: either build a two-process emulator harness with register-state proxying, or move to on-device runtime dumping (BlackDex / FART) where the cooperation is inherent.

### Reflection-driven binding (Java-side dependency)

- `GetStaticObjectField` reads a `Method[]` from a Java helper class that only exists when a real ART runtime has loaded the packer's stub. Single-process native emulators cannot satisfy this call - there is no Java side. The full cipher dispatch (`core[+0x10]`) is gated behind this binding. Analyst response: this is the structural reason pure-static decryption is bounded; either run on a real ART, or replay the binding's effect by setting `core[+0x10]` to the recovered callback target directly if the target can be identified statically.

## Detection

YARA / triage signatures with low false-positive rates:

- ASCII fragment `c1xs` in a high-entropy `.rodata` region of any `.so` that also imports `mmap` directly via `int 0x80` - the leakage signature of the v4 string pad.
- `AJM!` magic tag followed by an `l_info`-shaped header inside a native library that stock `upx -d` refuses.
- Co-occurrence of exports named `core` + `getOpCode` + at least one hash-prefixed (`a` or `s` followed by 9 digits) export in the same `.so`.
- Presence of `assets/ijiami.dat` with a header whose first 4 bytes are a small LE32 version (1-4) and bytes `[0x08:0x28]` are all ASCII hex.

[APKiD](https://github.com/rednaga/APKiD) ships a `packer : iJiami` rule keyed on the native-library fingerprint.

## Unpacking

Pure-static decryption of `ijiami.dat` is bounded - the cipher is gated behind the Java-reflection binding and the fork/ptrace pair, neither of which single-process emulators reproduce. Use one of the runtime paths instead.

### Primary path: runtime DEX dump

Run the packed app on an instrumented device (root + LSPosed/Magisk) and dump the in-process `ClassLoader` after the unpacked DEX is loaded:

- [BlackDex](https://github.com/CodingGay/BlackDex) - the de-facto industry path against iJiami v4. Works on Android 5.0-12.
- [FART](https://github.com/hanbinglengyue/FART) - active-mode DEX reconstruction; useful when the DEX is loaded but methods are still encrypted on first call.
- [FDex2](https://github.com/luoyesiqiu/FDex2) - Xposed module, lighter-weight than FART, sufficient against legacy iJiami generations.

### Secondary path: Frida intercept on wrapper natives

The packer's Java stub class declares 7 native methods (count stable across v4 builds). Plaintext is returned to Java as `DirectByteBuffer` instances (note the `NewDirectByteBuffer`x6 entry in the JNI profile above - that's the return channel), with method names handled as UTF-16 via `GetCharArrayElements`/`ReleaseCharArrayElements`.

Frida-attach the process, intercept each wrapper native on its `entryPointFromJni` slot *after* the SandHook-driven binding has completed (hooking too early lands on the pre-binding stub), and read the returned `DirectByteBuffer` address + capacity to dump the buffer. Method names are obfuscated but their count and signatures are stable.

### Pure-static path

Statically recoverable: the unpacked native loaders as valid ELFs, the full `.rodata` string table, the SM4 master key for the PNG-asset path, the bytecode VM dispatcher and arithmetic-switch implementations, and the `ijiami.dat` container header (including the plaintext-MD5 integrity tag, which lets any candidate decryption be validated cryptographically).

Not statically recoverable without further work: the DEX plaintext itself. Closing this gap requires either lifting the per-chunk key-derivation program out of the VM and re-executing it, or running a managed ART that can populate the helper class's `Method[]` field so the reflection-based binding completes.

## Comparison

| Feature | iJiami v4 | [DexGuard](dexguard.md) | [Bangcle](bangcle.md) | [Qihoo 360 Jiagu](qihoo-360-jiagu.md) |
|---------|-----------|-------------------------|------------------------|----------------------------------------|
| DEX cipher | Custom bytecode VM, per-chunk key | String-level encryption + class-data obfuscation | Whole-DEX symmetric | Whole-DEX + class-method hiding |
| Native loader protection | NRV2E + XOR + OLLVM | Java-only (no native loader) | UPX-style | UPX-style + OLLVM |
| JNI binding | Reflection + ART `Method` patching | N/A | `RegisterNatives` | `RegisterNatives` |
| Anti-emulation | High (fork+ptrace, prop loops) | Low | Low | Medium |
| Industry unpacker | BlackDex / FART | Manual + Frida string-decrypt hooks | BlackDex / FART | BlackDex / FART |

## Known malware usage

iJiami is a legitimate commercial packing service; the bulk of its real-world deployment is benign Chinese app-store apps. Malware families have used iJiami opportunistically - particularly Chinese-origin banking trojans repacking legitimate apps to evade store-side static analysis. Specific family attributions belong on the per-family pages, not here.

## References

- [APKiD packer signatures](https://github.com/rednaga/APKiD) - the `iJiami` rule.
- [BlackDex](https://github.com/CodingGay/BlackDex), [FART](https://github.com/hanbinglengyue/FART), [FDex2](https://github.com/luoyesiqiu/FDex2) - runtime DEX dumpers.
- [SandHook](https://github.com/ganyao114/SandHook) - the ART method-hook framework iJiami bundles for `entryPointFromJni` patching.
- UPX / NRV - the upstream of the NRV2E bitstream format Ijiami adapts. Reference NRV2E decoder implementations live in [unipacker](https://github.com/unipacker/unipacker) and various `upx-easy-unpack` derivatives - useful starting points for the pure-static unpacking route.
