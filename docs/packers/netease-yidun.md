# NetEase YiDun

NetEase's application security service (易盾, "YiDun" = "Easy Shield"), integrated with their gaming ecosystem. Two distinct products: the **App Packer** (full-app encryption) and the **SDK Reinforcement** (per-method native compilation, branded NIS / NetEase Information Security). The app packer is common in Chinese mobile games. The SDK reinforcement variant appears in both legitimate apps and malware, and currently evades APKiD detection.

## Overview

| Property | App Packer | SDK Reinforcement (NIS) |
|----------|-----------|-------------------|
| **Vendor** | NetEase | NetEase |
| **Package** | `com.netease.nis.wrapper` | `com.netease.nis.sdkwrapper` |
| **Entry class** | `Entry`, `MyJni`, `MyApplication` | `Utils` (native methods `rL()`, `rD()`) |
| **Native library** | `libnesec.so` | `libsecsdk.so` |
| **Assets** | `nedata.db`, `nedig.properties` | Custom-named encrypted blobs |
| **APKiD detection** | Yes (`packer : NetEase`) | No (evades current rules) |
| **Mechanism** | Encrypts entire `classes.dex`, loads at runtime | Compiles individual Java method bodies to native AArch64 at protection time; runtime trampoline dispatches via `methodId` table |
| **Unpacking difficulty** | Hard | Very hard |

## App Packer

### Identification

| Artifact | Description |
|----------|-------------|
| Native library | `libnesec.so`, `libNetHTProtect.so` |
| Package | `com.netease.nis.wrapper` package in DEX stub |
| Asset files | Encrypted payload in `assets/nis/` |

### Protection

- DEX encryption with multi-key scheme
- Anti-debugging and anti-hooking
- Integrity verification of native libraries
- Memory protection (mprotect on decrypted regions)

### Unpacking

The app packer uses `mprotect` to remove read permissions from memory pages containing the decrypted DEX after loading. Hooking `mprotect` prevents this:

```javascript
var mprotect = Module.findExportByName("libc.so", "mprotect");
Interceptor.attach(mprotect, {
    onEnter: function(args) {
        this.addr = args[0];
        this.size = args[1].toInt32();
        this.prot = args[2].toInt32();
        if (this.prot === 0) {
            console.log("[mprotect] Blocking PROT_NONE at " +
                this.addr + " size=" + this.size);
            args[2] = ptr(1);
        }
    }
});
```

After bypassing, [frida-dexdump](https://github.com/hluwa/frida-dexdump) can scan the readable memory for DEX headers. Timing the dump is critical -- the decrypted DEX resides in memory briefly before protection flags are set.

## SDK Reinforcement (NIS / SDK加固)

A separate product from the app packer. Per [NetEase's SDK Reinforcement documentation](https://support.dun.163.com/documents/2017121302?docId=101837745727655936), the required ProGuard keep rule `-keep public class com.netease.nis.sdkwrapper.Utils {public *;}` confirms the SDK variant's namespace.

### What NIS protects, and what it doesn't

NIS protects **individual Java method bodies**, not whole classes, not whole DEX files. The APK's `classes*.dex` files are plain, unencrypted, fully decompilable. Class shapes, method signatures, field names, manifest entries, resource strings — all visible. The only thing unreadable is the body of specifically-marked methods, which has been replaced with a uniform trampoline call into a native dispatcher.

There is no bytecode interpreter, no custom VM. At protection time NIS compiles each protected JVM method to **native AArch64** through an LLVM-based translator that emits a small JNI prologue/epilogue for boxing arguments and return values. The original Java source form is discarded. After unpacking you recover readable AArch64 (decompilable to C-pseudocode in Ghidra/IDA) but never Java source. Every URL, key, integer constant, branching decision, and algorithm is recoverable from the pseudocode; what's lost is variable names, not intelligence.

### Identification

| Artifact | Description |
|----------|-------------|
| Native library | `libsecsdk.so` (stripped ARM64 binary) |
| Package | `com.netease.nis.sdkwrapper.Utils` with native methods `rL()` and `rD()` |
| ProGuard rule | `-keep public class com.netease.nis.sdkwrapper.Utils` in build config |
| Assets | Custom-named encrypted files (randomized English words, `.dat` files) |
| ELF section layout | Tiny `.text` (<64 B) + multiple `.note.gnu.*` sections flagged executable, total entropy >6.5 |
| APKiD | Not detected -- existing [yidun rule](https://github.com/rednaga/APKiD/blob/master/apkid/rules/apk/packers.yara) matches only `wrapper`/`libnesec.so` |
| **Common false positive** | MSA OAID SDK (`com.bun.miitmdid`) frequently co-occurs with these artifacts |

### Trampoline anatomy

Every protected Java method has its original body stripped and replaced with a one-line trampoline:

```java
public ReturnT someMethod(T1 a, T2 b) {
    return (ReturnT) com.netease.nis.sdkwrapper.Utils.rL(
        new Object[]{ this, a, b, methodId, magic });
}
```

`methodId` is an integer assigned at protection time. `magic` is a per-method constant used by the native side as an argument-integrity check — it lets the dispatcher verify the caller is the expected stub and not a tamper that bypassed the obfuscator. `Utils.rL` is a `static native` method backed by `libsecsdk.so`.

Three properties make this shape work:

- **Uniform signature.** Every protected method, regardless of original parameters and return type, funnels through the same JNI call with the same argument shape (`Object[] → Object`). One native dispatcher serves them all.
- **Minimal Java footprint.** The bytecode just looks like a lot of methods doing one boxed-varargs call. No per-method generated Java code.
- **Argument integrity.** The `magic` constant gates dispatch.

Some builds also expose `rD(String, String)` for string-returning paths.

### Native dispatcher

`Utils.rL` maps to an entry point inside `libsecsdk.so`. That function reads the last two slots of its `Object[]` (`methodId` and `magic`), indexes a lookup table by `methodId`, and invokes the native function corresponding to the original Java body. Return values are boxed back into `Object` for the Java caller.

### Library structure

The library uses three sections with `.note.gnu.*` cover names. Standard `.text` is a tiny decoy.

| Role | Typical name | Flags | Contents |
|---|---|---|---|
| Loader stub | `.note.gnu.text` | r-x | Constructors, raw-syscall thunks, OLLVM helpers, dispatcher. Plaintext from process start. |
| Encrypted method bodies | `.note.gnu.proc` | r-x | Maximum-entropy noise on disk. Decrypted in place by `init_array` constructors. |
| methodId → fn-pointer table | `.note.gnu.content` | rw- | Size `8 * N` for `N` protected methods. Populated lazily. |

Tools that disassemble only `.text` find nothing. Tools that list all sections see small "note" sections and skip them.

The lookup table is populated **lazily**: at process spawn most slots are zero, and a slot becomes non-zero only on the first invocation of its corresponding Java method. Dumping `content.bin` immediately after `JNI_OnLoad` yields a mostly-zero buffer. To read a populated table, drive the app through enough lifecycle to invoke every protected method at least once, then re-dump.

Stored values are runtime-absolute addresses (`library_base + vma`). Subtract the library's load base (Frida's `mod.base`) before comparing against file-level VMAs.

Not every non-zero slot is a protected-method-body pointer. The loader stub also caches resolved imports (libc, sibling `.so` modules) in the same table. Only slots whose `value - mod.base` falls inside `libsecsdk.so`'s loader-stub region are real methodId entries; pointers landing in other modules are dynamic-linker lookups — filter them out when building the methodId → VMA map.

### Layered obfuscation

Five transformations stack on top of compiled AArch64. Each is defeatable in isolation; together they raise the cost of cold-start static analysis enough that most analysts give up or switch to pure Frida.

#### 1. Renamed code sections

Real code lives in `.note.gnu.*` sections rather than `.text`. Disassemblers keyed off `.text` find nothing. The fix (see Stage 7 of the workflow) is to rename in-place and flip `sh_type` from `SHT_NOTE` to `SHT_PROGBITS`.

#### 2. Encrypted bodies, in-place decrypted at load

The method-body section is maximum-entropy on disk; standard disassemblers refuse to parse it; entropy scanners flag it as encrypted data rather than code. Decryption happens at library load time inside `init_array` constructors that the dynamic linker calls automatically. Once the constructors return, the section contains ordinary AArch64.

#### 3. Raw-syscall mprotect (no PLT import)

To write into the read-execute method-body section, NIS needs `mprotect(…, PROT_WRITE)`. Importing `mprotect` via the normal PLT path would put the function in the library's import table — a near-universal unpacker tell on capability scans.

NIS issues `mprotect` as a **raw syscall** instead. The library ships a four-instruction inline thunk: load `226` (the AArch64 Linux `mprotect` syscall number) into `x8`, execute `svc #0`, check errno, return. `mprotect` never appears in the dynamic import table; capability-scanning analysts conclude the library couldn't possibly write its own code; meanwhile the flip-decrypt-restore pattern (make writable, decrypt in place, drop the write permission) works perfectly.

The same trick is used for `openat` (56) and `close` (57): the library reads `/proc/self/maps` and `/proc/self/task/*/status` via raw syscalls, so Frida hooks on libc's `open`/`read`/`fopen` see no traffic.

The raw-syscall thunks are reached only via function pointer, never by direct `bl`. Every caller loads the thunk address from a function-pointer table (initialised by the constructors) and calls it via `blr`. A grep for `bl <thunk_vma>` returns zero callers; resolve `ldr xN, [...]; blr xN` indirections to find the real call sites.

#### 4. OLLVM arithmetic helpers

Even after decryption, the loader-stub code is uncomfortable to read. Every ordinary `add` / `sub` / `mul` operation has been rewritten into a three- or four-instruction round-trip through a tiny helper function that computes the same result via algebraic identities. The obfuscated add helper:

```
mvn x0, x0        ; x0 = ~x0
sub x0, x0, x1    ; x0 = ~x0 - x1
mvn x0, x0        ; x0 = ~(~x0 - x1) = x0 + x1
ret
```

Each arithmetic site in the source becomes a `bl <helper>` in the compiled binary. The disassembler sees a call graph dominated by three tiny functions that look important; a decompiler produces pseudocode full of function-call noise; the human reader has to mentally inline every call to read the flow.

This is OLLVM's classic arithmetic-substitution pass. It applies only inside the loader stub (which must stay plaintext); the protected bodies themselves use ordinary arithmetic.

Three helpers, adjacent (16 bytes apart):

| Helper | Pattern | Replacement opcode |
|---|---|---|
| `add(a,b) = a + b` | `mvn x0,x0 ; sub x0,x0,x1 ; mvn x0,x0 ; ret` | `0x8B010000` (`add x0,x0,x1`) |
| `sub(a,b) = a - b` | `mvn x0,x0 ; add x0,x1,x0 ; mvn x0,x0 ; ret` | `0xCB010000` (`sub x0,x0,x1`) |
| `modmul`           | `asr;asr;lsr;lsr;add;add;and;and;sub;sub;mul;ret` | **do NOT rewrite** |

!!! danger "modmul is not a drop-in mul"
    The third helper reduces each signed operand to its low 12 bits before multiplying — the semantics differ from a plain `mul`. Do not auto-rewrite it to `mul x0, x0, x1`. Stage 6 of the workflow only rewrites `add` and `sub` by default; pass `--mul` only after you have confirmed the third helper is *not* the modmul variant for your sample.

#### 5. Scrambled dynstr + 1-byte export shift

The dynamic string table is stored encrypted on disk. The dynamic linker (which resolves symbols via a hash table separately) still works because one of the early constructors decrypts the string table in place before the linker reads it. To a static tool parsing the file on disk, the names are noise.

Side effect: the one or two meaningful exports (`JNI_OnLoad` and the real function pointer for `Utils.rL`) end up at unaligned addresses — the encryption introduces a one-byte shift. The real function prologue is at the adjacent aligned address; the exported value is off by one.

When jumping to a scrambled export, try both `addr` and `addr+1` — pick whichever lands on a valid AArch64 function prologue (`stp x29, x30, [sp, #-N]!` / `sub sp, sp, #N`).

### Tripwires

Decryption and symbol recovery are only half of NIS. The other half makes dynamic inspection painful.

| Signal | Mechanism | Strings to grep | Neutralisation |
|---|---|---|---|
| Map scan | Raw-syscall `openat("/proc/self/maps")` walked for instrumentation strings | `frida-agent`, `re.frida.server`, `libsubstrate` | Hide module names; rename Frida agent |
| Thread-name scan | Walks `/proc/self/task/*/status`, matches `Name:` line | `gum-js-loop`, `linjector`, `/proc/self/task/%s/status`, `%lx-%lx` (cluster in decrypted strings region) | Rename Frida threads |
| Decoy string | Red herring in same string region | `fake-lib` | Ignore |
| Module walk | `dl_iterate_phdr` enumerating loaded shared objects | n/a | Hide injected modules |
| Signal tripwires | `sigaction` installs handlers that call `raise(SIGKILL)` on fault | n/a — installed by a constructor that allocates a 416-byte buffer, zeroes it, calls `sigaction` once per trapped signal | Soft-hook `sigaction` and null out installations for SIGILL (4), SIGTRAP (5), SIGBUS (7), SIGSEGV (11) — **all four**; skipping any one leaves a path to self-kill |

The signal tripwires are the most aggressive: the NIS dispatcher itself uses page-fault and breakpoint tricks in normal operation, so a naive Frida hook that accidentally causes a fault hits the SIGKILL handler immediately. The tripwires arm within the first few hundred milliseconds of process start. Late-attach almost always fails — the library spots Frida at the next scan, installs an unavoidable `SIGKILL` pending signal, and the process dies on the next context switch. **Spawn-attach with sigaction soft-hook installed before constructors run.**

### MSA OAID SDK false positives

The MSA OAID SDK (`com.bun.miitmdid`), China's Mobile Security Alliance device identifier SDK, frequently co-occurs with `com.netease.nis.sdkwrapper.Utils` and `libsecsdk.so` in Chinese-market apps. Apps integrating the OAID SDK may contain these artifacts without being intentionally packed by the app developer. Detection rules targeting `sdkwrapper`/`libsecsdk.so` will flag these apps.

To distinguish malicious use from OAID SDK integration: check whether `Utils.rL()` dispatch protects app-specific classes (intentional packing) or only `com.bun.miitmdid` classes (OAID only). If the only callers of `Utils.rL()` live in the `miitmdid` namespace, the app is just using the OAID SDK and is not packed.

## SDK Reinforcement: unpacking workflow

End-to-end procedure for recovering protected code and behaviour from any NIS-packed APK. NIS keeps the architecture stable across builds but **shifts numeric offsets**: section names, VMAs, helper offsets, decoder-key positions, and the per-sample decoder class name all change between builds. Stage 3's `discover.py` extracts the per-sample values that feed Stages 4-7.

### Prerequisites

- Rooted Android device or emulator (ARM64), `adb` in `PATH`
- `frida-server` running as root on the device, matching host Frida version
- Host Python 3.9+ with `frida-tools` and (optionally) `r2pipe`
- `unzip`, ARM64-capable `objdump`, optional Ghidra/IDA/radare2

```sh
PKG=com.example.target
WORK=/tmp/nis_$PKG
mkdir -p $WORK
```

### Stage 1: Obtain the APK

```sh
for p in $(adb shell pm path $PKG | sed 's/^package://'); do
    adb pull "$p" "$WORK/"
done
```

### Stage 2: Identify NIS, extract the .so

NIS leaves a consistent fingerprint: one bundled `.so` with very high overall entropy (H > 6.5) plus at least one multi-kilobyte CODE-flagged section whose name is not `.text`, while `.text` itself is < 64 bytes. The script probes every native library in the APK (and any split-ABI APK) and prints candidates flagged `NIS-LIKELY`.

```sh
python3 $WORK/scan_apk.py $WORK/*.apk
```

Then extract:

```sh
SO=$WORK/libsecsdk.so
unzip -p $WORK/base.apk 'lib/arm64-v8a/libsecsdk.so' > $SO 2>/dev/null
[ -s $SO ] || unzip -p $WORK/split_config.arm64_v8a.apk 'lib/arm64-v8a/libsecsdk.so' > $SO
```

If the library name is not `libsecsdk.so`, substitute accordingly; the rest of the workflow depends only on the file, not the name.

??? "Full scan_apk.py"

    ```python
    #!/usr/bin/env python3
    import collections, math, os, struct, sys, tempfile, zipfile

    def entropy(b):
        if not b: return 0.0
        c = collections.Counter(b)
        return -sum((n/len(b))*math.log2(n/len(b)) for n in c.values())

    def parse_sections(so_bytes):
        if so_bytes[:4] != b"\x7fELF" or so_bytes[4] != 2:
            return []
        e_shoff  = struct.unpack_from('<Q', so_bytes, 0x28)[0]
        e_shentsize = struct.unpack_from('<H', so_bytes, 0x3a)[0]
        e_shnum  = struct.unpack_from('<H', so_bytes, 0x3c)[0]
        e_shstrndx = struct.unpack_from('<H', so_bytes, 0x3e)[0]
        sh_off = e_shoff + e_shstrndx * e_shentsize
        str_off, str_size = struct.unpack_from('<QQ', so_bytes, sh_off+0x18)
        strtab = so_bytes[str_off:str_off+str_size]
        out = []
        for i in range(e_shnum):
            base = e_shoff + i * e_shentsize
            name_off = struct.unpack_from('<I', so_bytes, base)[0]
            sh_flags = struct.unpack_from('<Q', so_bytes, base+8)[0]
            sh_off_i = struct.unpack_from('<Q', so_bytes, base+0x18)[0]
            sh_size  = struct.unpack_from('<Q', so_bytes, base+0x20)[0]
            end = strtab.find(b'\0', name_off)
            name = strtab[name_off:end].decode('ascii', 'ignore')
            exec_flag = bool(sh_flags & 4)
            out.append((name, sh_off_i, sh_size, exec_flag))
        return out

    def score(so_bytes):
        H = entropy(so_bytes)
        sects = parse_sections(so_bytes)
        tiny_text = False
        big_nontext_code = None
        for name, off, sz, exec_flag in sects:
            if name == '.text' and sz < 64:
                tiny_text = True
            if exec_flag and name and name != '.text' and sz > 8192:
                if big_nontext_code is None or sz > big_nontext_code[2]:
                    big_nontext_code = (name, off, sz)
        return H, tiny_text, big_nontext_code, len(so_bytes)

    def scan(apk_path):
        hits = []
        with zipfile.ZipFile(apk_path) as z:
            for info in z.infolist():
                if info.filename.startswith('lib/') and info.filename.endswith('.so'):
                    b = z.read(info.filename)
                    H, tiny_text, big, size = score(b)
                    hits.append((info.filename, H, tiny_text, big, size))
        hits.sort(key=lambda x: (not x[2], x[1]), reverse=True)
        return hits

    for apk in sys.argv[1:]:
        for name, H, tiny_text, big, size in scan(apk):
            tag = "NIS-LIKELY" if (tiny_text and big and H > 6.5) else "         "
            print(f"{tag}  H={H:4.2f}  {size:>8}  {name}")
            if big:
                print(f"             big CODE section: {big[0]} size={big[2]}")
    ```

### Stage 3: Discover per-sample offsets

Compute section offsets, constructor addresses, raw-syscall thunks, and OLLVM helper VMAs once per sample. The script prints everything Stages 4-7 consume.

```sh
python3 $WORK/discover.py $SO
```

It prints sections (with file offset, VMA, size, flags), per-CODE-section entropy, every `svc #0` site with the preceding `mov x8, #imm` decoded into syscall name, the OLLVM `add`/`sub`/`modmul` helper VMAs, and the constructor list pulled from `init_array` via `R_AARCH64_RELATIVE` relocations.

Save the output — those numbers feed every later stage.

??? "Full discover.py"

    ```python
    #!/usr/bin/env python3
    """Print section offsets, constructor addresses, syscall thunks, and
    OLLVM arithmetic helpers in any NIS-protected .so."""
    import struct, sys, collections, math

    d = open(sys.argv[1], 'rb').read()

    def sections(d):
        e_shoff    = struct.unpack_from('<Q', d, 0x28)[0]
        e_shents   = struct.unpack_from('<H', d, 0x3a)[0]
        e_shnum    = struct.unpack_from('<H', d, 0x3c)[0]
        e_shstrndx = struct.unpack_from('<H', d, 0x3e)[0]
        hdr = e_shoff + e_shstrndx * e_shents
        str_off, str_size = struct.unpack_from('<QQ', d, hdr+0x18)
        strtab = d[str_off:str_off+str_size]
        out = []
        for i in range(e_shnum):
            h = e_shoff + i * e_shents
            name_off = struct.unpack_from('<I', d, h)[0]
            flags    = struct.unpack_from('<Q', d, h+0x08)[0]
            addr     = struct.unpack_from('<Q', d, h+0x10)[0]
            off      = struct.unpack_from('<Q', d, h+0x18)[0]
            size     = struct.unpack_from('<Q', d, h+0x20)[0]
            end = strtab.find(b'\0', name_off)
            name = strtab[name_off:end].decode('ascii', 'ignore')
            exec_flag = bool(flags & 4)
            write_flag = bool(flags & 1)
            out.append((name, off, addr, size, exec_flag, write_flag))
        return out

    sects = sections(d)

    encrypted = None; loader = None
    for name, fo, vma, sz, ex, wr in sects:
        if ex and name != '.text' and sz > 8192:
            if encrypted is None or sz > encrypted[3]:
                if loader is not None and loader[3] >= sz:
                    continue
                encrypted = (name, fo, vma, sz)
    for name, fo, vma, sz, ex, wr in sects:
        if ex and name != '.text' and sz > 8192 and (name, fo, vma, sz) != encrypted:
            if loader is None or sz > loader[3]:
                loader = (name, fo, vma, sz)

    print("sections:")
    for name, fo, vma, sz, ex, wr in sects:
        flg = ('x' if ex else '-') + ('w' if wr else '-')
        print(f"  {name:20} fo=0x{fo:06x}  vma=0x{vma:06x}  size=0x{sz:06x}  flags=r{flg}")

    print(f"\nENCRYPTED region: {encrypted[0]} fo=0x{encrypted[1]:x} vma=0x{encrypted[2]:x} size=0x{encrypted[3]:x}")
    print(f"LOADER STUB:     {loader[0]} fo=0x{loader[1]:x} vma=0x{loader[2]:x} size=0x{loader[3]:x}")

    def entropy(b):
        c = collections.Counter(b); n = len(b)
        return -sum((k/n)*math.log2(k/n) for k in c.values()) if n else 0
    for name, fo, vma, sz, ex, wr in sects:
        if ex and sz >= 64:
            H = entropy(d[fo:fo+sz])
            print(f"entropy  {name:20}  {H:.3f}")

    svc_sites = []
    for i in range(0, len(d)-3, 4):
        w = struct.unpack_from('<I', d, i)[0]
        if (w & 0xFFE0001F) == 0xD4000001:
            prev = struct.unpack_from('<I', d, i-4)[0] if i >= 4 else 0
            syscall_no = None
            if (prev & 0xFFE0001F) == 0xD2800008 or (prev & 0xFFE0001F) == 0x52800008:
                syscall_no = (prev >> 5) & 0xFFFF
            svc_sites.append((i, syscall_no))

    print(f"\nsvc #0 sites: {len(svc_sites)}")
    for fo, nr in svc_sites:
        name = {57:'close',56:'openat',226:'mprotect',63:'read',64:'write',
                93:'exit'}.get(nr, f'nr={nr}')
        vma = None
        for _, sfo, svma, sz, ex, _ in sects:
            if sfo <= fo < sfo + sz:
                vma = svma + (fo - sfo); break
        print(f"  vma=0x{vma:06x}  file+0x{fo:05x}  {name}")

    MVN_X0 = 0xAA2003E0
    RET    = 0xD65F03C0
    helpers = []
    for i in range(0, len(d) - 15, 4):
        w0 = struct.unpack_from('<I', d, i)[0]
        w2 = struct.unpack_from('<I', d, i+8)[0]
        w3 = struct.unpack_from('<I', d, i+12)[0]
        if w0 == MVN_X0 and w2 == MVN_X0 and w3 == RET:
            op = struct.unpack_from('<I', d, i+4)[0]
            if   op == 0xCB010000: kind = 'add(a,b)=a+b  (mvn;sub;mvn)'
            elif op == 0x8B000020: kind = 'sub(a,b)=a-b  (mvn;add;mvn)'
            else: kind = f'unknown op {op:08x}'
            for _, sfo, svma, sz, ex, _ in sects:
                if sfo <= i < sfo + sz:
                    vma = svma + (i - sfo); break
            helpers.append((vma, kind))
    MODMUL_TAIL = [0x9B017C00, 0xD65F03C0]
    for i in range(0, len(d) - 47, 4):
        if struct.unpack_from('<I', d, i+40)[0] == MODMUL_TAIL[0] and \
           struct.unpack_from('<I', d, i+44)[0] == MODMUL_TAIL[1] and \
           struct.unpack_from('<I', d, i)[0]    == 0x937FFC03:
            for _, sfo, svma, sz, ex, _ in sects:
                if sfo <= i < sfo + sz:
                    vma = svma + (i - sfo); break
            helpers.append((vma, 'modmul  (12-bit signed-modulo * ; do NOT rewrite)'))
    print(f"\nOLLVM arithmetic helpers: {len(helpers)}")
    for vma, kind in helpers:
        print(f"  vma=0x{vma:06x}  {kind}")

    e_phoff  = struct.unpack_from('<Q', d, 0x20)[0]
    e_phents = struct.unpack_from('<H', d, 0x36)[0]
    e_phnum  = struct.unpack_from('<H', d, 0x38)[0]
    dyn_off = dyn_sz = 0
    for i in range(e_phnum):
        h = e_phoff + i * e_phents
        p_type = struct.unpack_from('<I', d, h)[0]
        if p_type == 2:
            dyn_off = struct.unpack_from('<Q', d, h+0x08)[0]
            dyn_sz  = struct.unpack_from('<Q', d, h+0x28)[0]
            break
    init_vma = init_sz = rela_vma = rela_sz = 0
    i = dyn_off
    while i < dyn_off + dyn_sz:
        tag, val = struct.unpack_from('<QQ', d, i)
        if tag == 7:  rela_vma = val
        if tag == 8:  rela_sz  = val
        if tag == 25: init_vma = val
        if tag == 27: init_sz  = val
        if tag == 0:  break
        i += 16

    def vma_to_off(vma):
        for _, sfo, svma, sz, _, _ in sects:
            if svma <= vma < svma + sz: return sfo + (vma - svma)
        return None
    rela_fo = vma_to_off(rela_vma)
    ctors = []
    for k in range(0, rela_sz, 24):
        off, info, addend = struct.unpack_from('<QqQ', d, rela_fo + k)
        r_type = info & 0xffffffff
        if r_type == 1027 and init_vma <= off < init_vma + init_sz:
            ctors.append(addend)
    print(f"\nconstructors ({len(ctors)}):")
    for a in ctors: print(f"  vma=0x{a:x}")
    ```

### Stage 4: Runtime memory dump

Spawn the target with Frida attached. The script polls until `libsecsdk.so` loads (constructors finish by then), soft-hooks `sigaction` to neutralise the four fatal-signal tripwires (SIGILL/TRAP/BUS/SEGV — all four required), and dumps four regions: encrypted method bodies (`proc.bin`), loader stub (`text.bin`), methodId table (`content.bin`), and dynstr (`dynstr.bin`).

```sh
python3 $WORK/run_dump.py $PKG $WORK/dumps                           \
    --hooks-template $WORK/dump_hooks.js                             \
    --lib-name libsecsdk.so                                          \
    --encrypted-vma 0x190    --encrypted-size  0x43e70               \
    --loader-vma    0x54040  --loader-size     0x11bc8               \
    --content-vma   0x6aaf8  --content-size    0x2360                \
    --dynstr-vma    0x6d568  --dynstr-size     0x5b0
```

Replace numeric arguments with what Stage 3's `discover.py` printed for your sample. After completion `$WORK/dumps/` holds `proc.bin`, `text.bin`, `content.bin`, `dynstr.bin`.

??? "Full dump_hooks.js"

    ```javascript
    'use strict';

    const CFG = {
      lib:        'libsecsdk.so',
      encrypted:  { vma: __ENCRYPTED_VMA__, size: __ENCRYPTED_SIZE__ },
      loader:     { vma: __LOADER_VMA__,    size: __LOADER_SIZE__ },
      content:    { vma: __CONTENT_VMA__,   size: __CONTENT_SIZE__ },
      dynstr:     { vma: __DYNSTR_VMA__,    size: __DYNSTR_SIZE__ },
    };

    function L(tag, extra) { send(JSON.stringify(Object.assign({tag}, extra || {}))); }

    function neutralise() {
      try {
        const libc = Process.findModuleByName('libc.so');
        if (!libc) return;
        const sa = libc.findExportByName('sigaction');
        if (!sa) return;
        Interceptor.attach(sa, {
          onEnter(a) {
            const s = a[0].toInt32();
            if (s === 4 || s === 5 || s === 7 || s === 11) {
              try { a[1] = NULL; } catch (_) {}
              L('antidebug.sigaction.softened', { sig: s });
            }
          }
        });
      } catch (e) { L('antidebug.err', { msg: String(e) }); }
    }

    let dumped = false;
    function poll() {
      if (dumped) return;
      const mod = Process.findModuleByName(CFG.lib);
      if (!mod) { setTimeout(poll, 100); return; }
      dumped = true;
      L('lib.loaded', { base: mod.base.toString(), size: mod.size });
      setTimeout(() => do_dumps(mod.base), 300);
    }

    function do_dumps(base) {
      for (const [key, spec] of Object.entries({
        proc:    CFG.encrypted,
        text:    CFG.loader,
        content: CFG.content,
        dynstr:  CFG.dynstr,
      })) {
        try {
          const bytes = base.add(spec.vma).readByteArray(spec.size);
          send(JSON.stringify({tag:'dump', key, vma: spec.vma, size: spec.size}), bytes);
          L('dump.ok', {key, size: spec.size});
        } catch (e) {
          L('dump.err', {key, msg: String(e)});
        }
      }
      L('done');
    }

    neutralise();
    setTimeout(poll, 50);
    L('hooks.installed');
    ```

??? "Full run_dump.py driver"

    ```python
    #!/usr/bin/env python3
    import argparse, json, os, re, sys, time
    import frida

    ap = argparse.ArgumentParser()
    ap.add_argument("package")
    ap.add_argument("out_dir")
    ap.add_argument("--hooks-template", required=True,
                    help="dump_hooks.js with __X_VMA__ / __X_SIZE__ placeholders")
    ap.add_argument("--lib-name", default="libsecsdk.so")
    ap.add_argument("--encrypted-vma", type=lambda s: int(s,0), required=True)
    ap.add_argument("--encrypted-size", type=lambda s: int(s,0), required=True)
    ap.add_argument("--loader-vma", type=lambda s: int(s,0), required=True)
    ap.add_argument("--loader-size", type=lambda s: int(s,0), required=True)
    ap.add_argument("--content-vma", type=lambda s: int(s,0), required=True)
    ap.add_argument("--content-size", type=lambda s: int(s,0), required=True)
    ap.add_argument("--dynstr-vma", type=lambda s: int(s,0), required=True)
    ap.add_argument("--dynstr-size", type=lambda s: int(s,0), required=True)
    ap.add_argument("--timeout", type=int, default=60)
    a = ap.parse_args()

    os.makedirs(a.out_dir, exist_ok=True)
    src = open(a.hooks_template).read()
    for k, v in [('ENCRYPTED_VMA', a.encrypted_vma), ('ENCRYPTED_SIZE', a.encrypted_size),
                 ('LOADER_VMA', a.loader_vma), ('LOADER_SIZE', a.loader_size),
                 ('CONTENT_VMA', a.content_vma), ('CONTENT_SIZE', a.content_size),
                 ('DYNSTR_VMA', a.dynstr_vma), ('DYNSTR_SIZE', a.dynstr_size)]:
        src = src.replace(f'__{k}__', str(v))

    done = {'flag': False}
    log = open(os.path.join(a.out_dir, 'dump.log'), 'w')

    def on_message(msg, data):
        if msg.get('type') != 'send':
            log.write(repr(msg)+'\n'); return
        p = json.loads(msg['payload'])
        log.write(json.dumps(p)+'\n'); log.flush()
        if p.get('tag') == 'dump' and data is not None:
            path = os.path.join(a.out_dir, f"{p['key']}.bin")
            open(path, 'wb').write(bytes(data))
            print(f"  wrote {path} ({len(data)} B)")
        elif p.get('tag') == 'done':
            done['flag'] = True
        elif p.get('tag') in ('lib.loaded', 'dump.ok', 'hooks.installed',
                              'antidebug.sigaction.softened'):
            print(f"  [.] {p.get('tag')}")

    dev = frida.get_usb_device(timeout=5)
    pid = dev.spawn([a.package])
    sess = dev.attach(pid)
    script = sess.create_script(src, runtime='qjs')
    script.on('message', on_message)
    script.load()
    dev.resume(pid)
    print(f"[+] spawned {a.package} pid={pid}")
    t0 = time.time()
    while time.time()-t0 < a.timeout and not done['flag']:
        time.sleep(0.2)
    sess.detach()
    try: dev.kill(pid)
    except: pass
    print('[+] dump complete' if done['flag'] else '[!] timed out')
    ```

### Stage 5: Rebuild a clean ELF

Splice the dumped sections back into a copy of the original `.so` at the same file offsets. Same size in, same size out — no other offsets shift. Disassemblers can then read post-decryption bytes directly.

```sh
python3 $WORK/rebuild.py $SO $WORK/dumps $WORK/libsecsdk_clean.so    \
    --proc-fo    0x190    --proc-size    0x43e70                     \
    --text-fo    0x44040  --text-size    0x11bc8                     \
    --content-fo 0x56af8  --content-size 0x2360                      \
    --dynstr-fo  0x59568  --dynstr-size  0x5b0
```

??? "Full rebuild.py"

    ```python
    #!/usr/bin/env python3
    import argparse, hashlib, json, os, sys

    ap = argparse.ArgumentParser()
    ap.add_argument("orig")
    ap.add_argument("dumps_dir")
    ap.add_argument("out")
    ap.add_argument("--proc-fo",    type=lambda s: int(s,0), required=True)
    ap.add_argument("--proc-size",  type=lambda s: int(s,0), required=True)
    ap.add_argument("--text-fo",    type=lambda s: int(s,0), required=True)
    ap.add_argument("--text-size",  type=lambda s: int(s,0), required=True)
    ap.add_argument("--content-fo", type=lambda s: int(s,0), required=True)
    ap.add_argument("--content-size", type=lambda s: int(s,0), required=True)
    ap.add_argument("--dynstr-fo",  type=lambda s: int(s,0), required=True)
    ap.add_argument("--dynstr-size", type=lambda s: int(s,0), required=True)
    a = ap.parse_args()

    buf = bytearray(open(a.orig, 'rb').read())
    regions = [
        ('proc',    a.proc_fo,    a.proc_size),
        ('text',    a.text_fo,    a.text_size),
        ('content', a.content_fo, a.content_size),
        ('dynstr',  a.dynstr_fo,  a.dynstr_size),
    ]
    for key, fo, sz in regions:
        src = os.path.join(a.dumps_dir, f"{key}.bin")
        if not os.path.exists(src):
            print(f"  skip {key}: no dump"); continue
        newb = open(src, 'rb').read()
        if len(newb) != sz:
            newb = newb[:sz].ljust(sz, b'\x00')
        before = hashlib.sha256(bytes(buf[fo:fo+sz])).hexdigest()[:16]
        buf[fo:fo+sz] = newb
        after  = hashlib.sha256(newb).hexdigest()[:16]
        print(f"  {key:8} fo=0x{fo:05x} size=0x{sz:x}  {before} -> {after}")
    open(a.out, 'wb').write(bytes(buf))
    print(f"[+] wrote {a.out}")
    ```

### Stage 6: De-obfuscate OLLVM helpers

Replace every `bl <helper>` that targets an obfuscated `add`/`sub` with the direct AArch64 instruction. Same instruction width, no offsets shift.

```sh
python3 $WORK/deobf.py $WORK/libsecsdk_clean.so $WORK/libsecsdk_deobf.so   \
    --add 0x5fc14 --sub 0x5fc24 --mul 0x5fc34                              \
    --regions 0x190,0x190,0x43e70 0x44040,0x54040,0x11bc8
```

!!! warning "Pass `--mul` only after confirming your sample is not the modmul variant"
    The third helper is sometimes a 12-bit signed-modulo multiply (`asr;asr;lsr;lsr;add;add;and;and;sub;sub;mul;ret`), not a plain `mul`. Stage 3 flags it explicitly. If the helper is modmul, omit `--mul` from this command — auto-rewriting it to `mul x0,x0,x1` corrupts the semantics and produces incorrect decompilation.

??? "Full deobf.py"

    ```python
    #!/usr/bin/env python3
    import argparse, struct, sys

    ap = argparse.ArgumentParser()
    ap.add_argument("inp")
    ap.add_argument("out")
    ap.add_argument("--add", type=lambda s: int(s,0), required=True)
    ap.add_argument("--sub", type=lambda s: int(s,0), required=True)
    ap.add_argument("--mul", type=lambda s: int(s,0), default=0)
    ap.add_argument("--regions", nargs="+", required=True,
                    help="triples: file_off,vma,size (hex). Repeat for each code section.")
    a = ap.parse_args()

    helpers = {a.add: ('add', 0x8B010000),
               a.sub: ('sub', 0xCB010000)}
    if a.mul: helpers[a.mul] = ('mul', 0x9B017C00)

    regions = []
    for r in a.regions:
        fo, vma, sz = [int(x,0) for x in r.split(',')]
        regions.append((fo, vma, sz))

    buf = bytearray(open(a.inp, 'rb').read())
    total = {'add':0, 'sub':0, 'mul':0}
    for fo, vma, sz in regions:
        for i in range(0, sz-3, 4):
            w = struct.unpack_from('<I', buf, fo+i)[0]
            if (w >> 26) != 0b100101:
                continue
            imm = w & 0x03FFFFFF
            if imm & 0x02000000: imm -= 0x04000000
            pc = vma + i
            target = pc + (imm << 2)
            if target in helpers:
                kind, repl = helpers[target]
                struct.pack_into('<I', buf, fo+i, repl)
                total[kind] += 1

    open(a.out, 'wb').write(bytes(buf))
    print(f"[+] rewrote add={total['add']} sub={total['sub']} mul={total['mul']}")
    print(f"[+] wrote {a.out}")
    ```

`libsecsdk_deobf.so` is now byte-complete, but disassemblers that key off section names (Ghidra, IDA's default heuristics) refuse to analyse `.note.gnu.*` sections and emit `halt_baddata` for every function. Stage 7 fixes that.

### Stage 7: Normalise sections for Ghidra/IDA

Rename `.note.gnu.proc → .text`, `.note.gnu.text → .text2`, `.note.gnu.content → .rodata2`, and flip each `sh_type` from `SHT_NOTE (7)` to `SHT_PROGBITS (1)`. Patch in place — no offsets change.

```sh
python3 $WORK/normalise_sections.py $WORK/libsecsdk_deobf.so \
                                    $WORK/libsecsdk_patched.so
```

Verify with `objdump -h $WORK/libsecsdk_patched.so` — `.text` should now be at `vma=0x190 size=0x43e70`.

??? "Full normalise_sections.py"

    ```python
    #!/usr/bin/env python3
    import struct, sys, shutil
    src, dst = sys.argv[1], sys.argv[2]
    shutil.copy(src, dst)
    d = bytearray(open(dst, 'rb').read())
    e_shoff    = struct.unpack_from('<Q', d, 0x28)[0]
    e_shents   = struct.unpack_from('<H', d, 0x3a)[0]
    e_shnum    = struct.unpack_from('<H', d, 0x3c)[0]
    e_shstrndx = struct.unpack_from('<H', d, 0x3e)[0]
    hdr = e_shoff + e_shstrndx * e_shents
    str_off, str_size = struct.unpack_from('<QQ', d, hdr + 0x18)

    RENAMES = {
        b'.note.gnu.proc':    (b'.text',     0x6),
        b'.note.gnu.text':    (b'.text2',    0x6),
        b'.note.gnu.ident':   (b'.text3',    0x6),
        b'.note.gnu.content': (b'.rodata2',  0x3),
    }

    for old, (new, _) in RENAMES.items():
        tag = old + b'\x00'
        i = bytes(d[str_off:str_off + str_size]).find(tag)
        if i < 0:
            continue
        pad = len(old) - len(new)
        d[str_off + i : str_off + i + len(tag)] = new + b'\x00' + b'\x00' * pad

    for i in range(e_shnum):
        base = e_shoff + i * e_shents
        name_off = struct.unpack_from('<I', d, base)[0]
        end = bytes(d[str_off:str_off + str_size]).find(b'\x00', name_off)
        name = bytes(d[str_off + name_off : str_off + end])
        for old, (_, flags) in RENAMES.items():
            if name == old:
                struct.pack_into('<I', d, base + 4,    1)
                struct.pack_into('<Q', d, base + 0x08, flags)

    open(dst, 'wb').write(bytes(d))
    print(f"[+] wrote {dst}")
    ```

### Stage 8: Static analysis

Confirm the decryption worked — entropy of the formerly-encrypted region should drop from ~7.2 to ~5.9.

#### Enumerate function boundaries from .eh_frame

Auto-analysers miss many functions in unpacked code. The `.eh_frame` section contains a CIE/FDE entry per function recording entry and size — use it to drive decompilation.

```sh
python3 $WORK/fde_list.py $WORK/libsecsdk_patched.so > $WORK/fde_list.txt
wc -l $WORK/fde_list.txt
```

??? "Full fde_list.py"

    ```python
    #!/usr/bin/env python3
    import struct, sys
    d = open(sys.argv[1], 'rb').read()
    e_shoff  = struct.unpack_from('<Q', d, 0x28)[0]
    e_shents = struct.unpack_from('<H', d, 0x3a)[0]
    e_shnum  = struct.unpack_from('<H', d, 0x3c)[0]
    e_shstrndx = struct.unpack_from('<H', d, 0x3e)[0]
    hdr = e_shoff + e_shstrndx * e_shents
    str_off, str_size = struct.unpack_from('<QQ', d, hdr + 0x18)
    eh_fo = eh_vma = eh_sz = None
    for i in range(e_shnum):
        b = e_shoff + i * e_shents
        name_off = struct.unpack_from('<I', d, b)[0]
        end = d.find(b'\0', str_off + name_off)
        name = d[str_off + name_off:end].decode('ascii', 'ignore')
        if name == '.eh_frame':
            eh_vma = struct.unpack_from('<Q', d, b + 0x10)[0]
            eh_fo  = struct.unpack_from('<Q', d, b + 0x18)[0]
            eh_sz  = struct.unpack_from('<Q', d, b + 0x20)[0]
    eh = d[eh_fo:eh_fo + eh_sz]

    i = 0
    while i < len(eh) - 4:
        length = struct.unpack_from('<I', eh, i)[0]
        if length == 0:
            break
        hdrlen, total = (12, 12 + struct.unpack_from('<Q', eh, i+4)[0]) \
                        if length == 0xFFFFFFFF else (4, 4 + length)
        cie_id = struct.unpack_from('<I', eh, i + hdrlen)[0]
        if cie_id != 0:
            ofs = i + hdrlen + 4
            init = struct.unpack_from('<i', eh, ofs)[0]
            rng  = struct.unpack_from('<I', eh, ofs + 4)[0]
            pc = eh_vma + ofs + init
            print(f"0x{pc:06x} {rng}")
        i += total
    ```

#### Batch decompile with radare2

Section-name-agnostic, fast.

```sh
pip3 install --user r2pipe
python3 - << 'PY'
import r2pipe
R = r2pipe.open("$WORK/libsecsdk_patched.so", flags=['-2'])
R.cmd('e scr.color=0'); R.cmd('aaa')
out = open("$WORK/r2_decomp.c", 'w')
for line in open("$WORK/fde_list.txt"):
    a, sz = line.split()
    if int(sz) < 32: continue
    R.cmd(f's {a}'); R.cmd('af')
    out.write(f"/* ==== fn_{int(a,16):x} size={sz} ==== */\n")
    out.write(R.cmd('pdc'))
    out.write("\n\n")
R.quit()
PY
```

#### Ghidra headless

Import `libsecsdk_patched.so` (the Stage 7 output, not `libsecsdk_deobf.so`) — the section-header rewrite is required for Ghidra's auto-analyser to treat the code as code.

```sh
ghidra_analyzeHeadless $WORK/ghidra_proj nis \
    -import $WORK/libsecsdk_patched.so \
    -analysisTimeoutPerFile 900 \
    -postScript ExportDecomp.java
```

!!! note "Ghidra script gotchas"
    Drop the post-script into `~/ghidra_scripts/` (the user script directory). Using `-scriptPath` triggers OSGi class-loading failures that silently skip the script. Ghidra 12 removed bundled Jython — use `.java` scripts, not `.py`, unless PyGhidra is installed.

#### Strings and URL harvest

```sh
objdump -d $WORK/libsecsdk_patched.so > $WORK/deobf.asm
grep -oE 'https?://[a-zA-Z0-9./_~+%&?=:-]+' $WORK/deobf.asm | sort -u
strings -n 6 $WORK/libsecsdk_patched.so | \
    grep -iE 'frida|gum-js|linjector|/proc/self|fake-lib|java/lang' | sort -u
```

For the Java side, decompile separately — protected methods appear as `Utils.rL({this, args..., methodId, magic})` trampolines:

```sh
jadx -d $WORK/jadx $WORK/base.apk
grep -RhoE 'sdkwrapper\.Utils\.rL\([^)]*\)' $WORK/jadx/sources |
    grep -oE '[0-9]+,\s*[0-9a-fL]+\s*\}' | sort -u
```

### Stage 9: Map methodIds to native functions

`content.bin` slots hold runtime-absolute pointers (`library_base + vma`), populated lazily on first invocation of each protected method. To get a fuller map, drive the app through its full lifecycle (or use Stage 10's trace to exercise every `rL` call site) before re-reading the table.

```sh
python3 $WORK/mapids.py $WORK/dumps/content.bin 0x7a21230000 0x190 0x43e70
```

Cross-reference the printed `methodId → vma` map with the `(methodId, magic)` pairs from the jadx output: for every protected Java call site you now know which native function in the decompiled `.so` implements it.

??? "Full mapids.py"

    ```python
    #!/usr/bin/env python3
    import struct, sys
    content   = open(sys.argv[1], 'rb').read()
    lib_base  = int(sys.argv[2], 0)
    proc_lo   = int(sys.argv[3], 0)
    proc_size = int(sys.argv[4], 0)
    proc_hi   = proc_lo + proc_size
    for i in range(0, len(content), 8):
        p = struct.unpack_from('<Q', content, i)[0]
        if p == 0: continue
        vma = p - lib_base
        if proc_lo <= vma < proc_hi:
            print(f"methodId {i//8:4d}  ->  vma 0x{vma:x}")
    ```

### Stage 10: Live behavioural capture

Frida at the Java boundary records every `Utils.rL` call with arguments and return value. This is the simplest path to extracting URLs, protocol JSON, AES keys passed into `Cipher.init`, and every decoded string used by protected code.

```sh
frida -U -f $PKG -l $WORK/trace.js --runtime=qjs > $WORK/trace.raw
```

!!! warning "Two CLI gotchas that cost real time"
    1. `-o $WORK/trace.log` only captures `console.log` — not `send()`. `send()` events go to stdout. Either redirect stdout (as above) or rewrite the script to use `console.log(JSON.stringify(...))` instead.
    2. The Frida CLI auto-loads the Java bridge so `Java.perform(...)` is available as a bare global. If you drive the script through the Python API (`frida.Session.create_script`) on Frida 17+, the bridge is **not** injected automatically — you'll get `ReferenceError: Java is not defined`. Either stick with the CLI or prepend `const Java = require('frida-java-bridge');` to the script when loading via the Python API.

??? "Full trace.js"

    ```javascript
    'use strict';

    Java.perform(function () {
      const Utils = Java.use('com.netease.nis.sdkwrapper.Utils');
      ['rL', 'rD'].forEach(function (name) {
        if (!Utils[name]) return;
        Utils[name].overloads.forEach(function (ovl) {
          ovl.implementation = function (args) {
            const arr = Java.use('java.util.Arrays').toString(args);
            const ret = ovl.call(this, args);
            send(JSON.stringify({
              tag: 'rL', method: name,
              args: String(arr).slice(0, 1500),
              ret:  (ret === null ? 'null' : String(ret).slice(0, 500)),
            }));
            return ret;
          };
        });
      });

      // String decoder — one NIS build calls e.g. 'ajgmamwf.XDNuIxwy.rwi6ps(long)'
      // on every runtime-decoded literal. Inspect jadx output to find the decoder
      // class name for your sample, then uncomment and adapt:
      //
      //  const Dec = Java.use('ajgmamwf.XDNuIxwy');
      //  Dec.rwi6ps.implementation = function (k) {
      //    const s = this.rwi6ps(k);
      //    send(JSON.stringify({tag:'decoded', key: String(k), value: String(s)}));
      //    return s;
      //  };

      const Cipher = Java.use('javax.crypto.Cipher');
      Cipher.init.overload('int', 'java.security.Key').implementation = function (op, key) {
        const enc = Java.use('javax.crypto.spec.SecretKeySpec').class.isInstance(key)
                    ? Java.cast(key, Java.use('javax.crypto.spec.SecretKeySpec')).getEncoded()
                    : null;
        if (enc) {
          const hex = Array.from(enc).map(b => (b & 0xff).toString(16).padStart(2,'0')).join('');
          send(JSON.stringify({tag:'cipher.init', op, alg: this.getAlgorithm(), key: hex}));
        }
        return this.init(op, key);
      };

      Cipher.doFinal.overload('[B').implementation = function (b) {
        const out = this.doFinal(b);
        try {
          const s = Java.use('java.lang.String').$new(out);
          if (String(s).indexOf('{') >= 0 || String(s).indexOf('adsource') >= 0) {
            send(JSON.stringify({tag:'cipher.plain', body: String(s).slice(0, 4000)}));
          }
        } catch (_) {}
        return out;
      };
    });
    ```

Let the app run through its full lifecycle — splash, normal use, anything that exercises protected methods. Every `Utils.rL` call appears as a `{tag:'rL', method, args, ret}` event linkable back to a concrete native function via Stage 9's mapping.

### Locating string-decoder keys statically

The Java side calls a `<per-sample-class>.<method>(long)` decoder on every runtime-obfuscated literal. Its two native helpers follow a fixed shape:

```
small_function(long key_sel) {
    buf = alloc(16);
    key = load16B(.data + 0x7c0);   // or 0x7d0 in the second variant
    iv  = load16B(.data + 0x7c8);   // or 0x7d8
    x   = crypto_kernel(buf, key, iv, ...);
    return jni_new_utf_string(x);
}
```

Find the two ~80-byte functions whose body contains an `ldr` from `.data + 0x7c0/0x7c8` (or `.data + 0x7d0/0x7d8`). Read the 32 bytes at those offsets — that's the key material. Decompile the shared callee to identify the cipher (block size + round structure is enough). Feed the keys into the kernel offline to decrypt every Java runtime-decoded literal without running the app.

## What each stage unlocks

| Asset | Source |
|---|---|
| Operator backend URL(s) | `grep` URLs in `deobf.asm`; also in any `cipher.plain` event |
| Crypto algorithm + mode | `cipher.init` events record algorithm string; decompile call site for parameters |
| Symmetric keys (AES/etc.) | `cipher.init` events record key bytes as hex |
| Full protocol JSON schemas | `cipher.plain` events print plaintext request/response bodies |
| Every runtime-decoded string | `decoded` events once the decoder hook is wired to the per-sample class — or static recovery via the `.data + 0x7c0/0x7d0` keys |
| Protocol argument construction | Decompile of the methodId function identified from the `rL` trace |
| Decision logic (per-country, per-geo, gating) | Decompile of the relevant methodId function |
| FCM / push command handler | Decompile the method wired to `FirebaseMessagingService.onMessageReceived` in the jadx output |
| Anti-debug gates | Xref `gum-js-loop` / `linjector` / `/proc/self/task/%s/status` in the decrypted strings region to the scanner function; follow callers to the sigaction tripwire and raw-syscall thunks |

## Comparison with App Packer

| Feature | App Packer | SDK Reinforcement (NIS) |
|---------|-----------|-------------------|
| Protection granularity | Entire DEX | Individual methods |
| Java-visible code | None (encrypted DEX) | Dispatch stubs visible, body logic hidden |
| Method body form | Original Dalvik bytecode (after decryption) | Native AArch64 (compiled at protection time, no Java source recovery) |
| APKiD detection | Yes | No |
| Unpacking approach | Dump decrypted DEX from memory | Discover offsets → dump three sections → splice → de-OLLVM → rename sections → decompile native |
| Analysis difficulty | Hard (standard packer) | Very hard (multi-layer obfuscation, fatal tripwires) |

See [anti-analysis techniques](../attacks/anti-analysis-techniques.md) for the broader pattern of raw-syscall obfuscation and sigaction tripwires across packer families, [static analysis](../reversing/static-analysis.md) for the section-header normalisation trick, and [hooking](../reversing/hooking.md) for the `Cipher.init`/`doFinal` capture pattern.

## References

- [NetEase Yidun SDK Reinforcement documentation](https://support.dun.163.com/documents/2017121302?docId=101837745727655936)
- [NetEase Yidun product page](https://dun.163.com/product/sdk-reinforce)
- [APKiD Packer Signatures](https://github.com/rednaga/APKiD)
- [APKiD Chinese protectors tracking issue](https://github.com/rednaga/APKiD/issues/389)
