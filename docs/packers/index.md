# Android Packers & Obfuscators

Packers (protectors, armoring tools) transform APKs to resist reverse engineering, tampering, and automated analysis. Legitimate developers use them to protect IP. Malware authors use them to evade detection and slow down analysts.

Obfuscators are a lighter category: they transform code to make it harder to read but don't encrypt or pack DEX files. Many protection products combine both.

[APKiD](https://github.com/rednaga/APKiD) can identify most commercial packers and obfuscators automatically.

## Packers / Protectors

| Packer | Vendor | Vendor HQ |
|--------|--------|-----------|
| [360 Jiagu](qihoo-360-jiagu.md) | Qihoo 360 | China |
| [APKProtect](apkprotect.md) | Nagain | China |
| [Arxan (Digital.ai)](arxan.md) | Digital.ai | USA |
| [Baidu Reinforcement](baidu.md) | Baidu | China |
| [Bangcle (SecNeo)](bangcle.md) | Bangcle | China |
| [Kiwisec (几维安全)](kiwisec.md) | Kiwisec | China |
| [SecShell](secshell.md) | Bangcle / SecNeo (梆梆安全) | China |
| [DPT Shell](dpt-shell.md) | luoyesiqiu (open source) | China |
| [Ducex](ducex.md) | Unknown (described as Chinese-origin by [any.run](https://any.run/cybersecurity-blog/ducex-packer-analysis/)) | China |
| [GoldCrypt](goldcrypt.md) | Unknown (underground forums) | Unknown |
| [DexGuard](dexguard.md) | Guardsquare | Belgium |
| [DexProtector](dexprotector.md) | [Licel](https://licelus.com/) | USA / UK |
| [Hqwar](hqwar.md) | Unknown (underground, Russian-speaking author per [Kaspersky](https://securelist.com/hqwar-the-higher-it-flies-the-harder-it-drops/93689/)) | Russia |
| [iJiami](ijiami.md) | iJiami | China |
| [NeteaseYiDun](netease-yidun.md) | NetEase | China |
| [Promon SHIELD](promon.md) | Promon | Norway |
| [Tencent Legu](tencent-legu.md) | Tencent | China |
| [Virbox](virbox.md) | [Beijing SenseShield Technology](https://lm-global.virbox.com/about.html) | China |
| [AppSealing](appsealing.md) | INKA Entworks (rebranded to [DoveRunner](https://doverunner.com/), Mar 2025) | South Korea |
| [LIAPP](liapp.md) | [Lockin Company](https://liapp.lockincomp.com/about) | South Korea |
| [Appdome](appdome.md) | [Appdome Inc](https://www.appdome.com/about/) | USA / Israel |
| [Zimperium zShield](zshield.md) | Zimperium | USA |
| [Verimatrix XTD](verimatrix.md) | Verimatrix Inc. (XTD lineage from Inside Secure, France); [acquired by Guardsquare Feb 2026](https://www.guardsquare.com/press-release/guardsquare-acquires-verimatrix-xtd) | USA / France |

## Obfuscators

| Obfuscator | Type | Notes |
|-----------|------|-------|
| [R8 / ProGuard](r8-proguard.md) | Free (Google/open source) | Default Android build tools. Name obfuscation, dead code removal, optimization. R8 replaced ProGuard. |
| [Redex](redex.md) | Free (Meta, MIT open source) | Meta's DEX bytecode optimizer. Class merging, inlining, InterDex layout, `X.<short>` renaming. Not a packer or RASP, but heavily degrades static analysis of Meta apps. |
| [Allatori](allatori.md) | Commercial | Java/Android obfuscator. String encryption, flow obfuscation, watermarking. |
| [DashO](https://www.preemptive.com/products/dasho/) | Commercial | PreEmptive Solutions. Obfuscation + tamper detection + analytics. |
| [Zelix KlassMaster](https://www.zelix.com/klassmaster/) | Commercial | Aggressive flow obfuscation, string encryption, stack trace obfuscation. |
| [OLLVM (Obfuscator-LLVM)](https://github.com/obfuscator-llvm/obfuscator) | Open source | Control flow flattening, bogus control flow, string encryption for native code. Used by [Mandrake](../malware/families/mandrake.md). |

## Protection Categories at a Glance

This is a category-level comparison (packer vs obfuscator vs RASP). For per-product feature-by-feature analysis, see the [Packer Comparison Matrix](#packer-comparison-matrix) further down.

| Feature | Packers | Obfuscators | RASP |
|---------|---------|-------------|------|
| Name obfuscation | Yes | Yes | No |
| String encryption | Yes | Some | No |
| DEX encryption | Yes | No | No |
| Native code wrapping | Yes | No | No |
| Anti-debugging | Yes | No | Yes |
| Anti-tampering | Yes | No | Yes |
| Root detection | Some | No | Yes |
| Emulator detection | Some | No | Yes |
| Runtime self-protection | Some | No | Yes |

**RASP** (Runtime Application Self-Protection) products like [Promon SHIELD](promon.md) ([vendor page](https://promon.io/products/shield-mobile)), [Appdome OneShield](appdome.md) ([vendor page](https://www.appdome.com/how-to/mobile-app-security/mobile-rasp-and-app-shielding/oneshield-no-code-mobile-rasp-explained/)), [Arxan (Digital.ai)](arxan.md), [DexProtector](dexprotector.md) ([vendor page](https://licelus.com/products/dexprotector)), [LIAPP](liapp.md), and [Verimatrix XTD](verimatrix.md) focus on runtime checks rather than code transformation. They detect hostile environments (root, hooking, debugging, emulator, repackaging) and respond at runtime, often combined with a packer or obfuscator. The term was coined by Gartner; for vendor-neutral background see the [OWASP RASP overview](https://owasp.org/www-pdf-archive/RASP-OWASP-2017.pdf).

## Malware Families by Packer

Commercial packers are increasingly adopted by malware authors. The packer provides anti-analysis protection without the developer needing to build their own.

| Packer | Families | Notes |
|--------|----------|-------|
| [Virbox](virbox.md) | [Gigabud](../malware/families/gigabud.md) ([Zimperium](https://zimperium.com/blog/a-network-of-harm-gigabud-threat-and-its-associates)), [Klopatra](../malware/families/klopatra.md) ([Cleafy](https://www.cleafy.com/cleafy-labs/klopatra-exposing-a-new-android-banking-trojan-operation-with-roots-in-turkey)), GoldDigger / GoldPickaxe ([Group-IB](https://www.group-ib.com/blog/goldfactory-ios-trojan/)) | GoldFactory standardized on Virbox; recent Gigabud / GoldDigger samples wrap a `libstrategy.so` native module per Zimperium. Virbox itself uses randomized native library names rather than a fixed filename. |
| [DexGuard](dexguard.md) | (No primary-sourced banker attribution at present; many higher-tier apps and some unattributed samples use DexGuard but specific malware family use is not substantiated in public research surveyed) | Commercial Guardsquare protection; class-level DEX encryption, native library renaming and encryption ([Guardsquare](https://www.guardsquare.com/dexguard)). No single canonical native library filename. |
| [Tencent Legu](tencent-legu.md) | Various Chinese-market malware | Common in the Chinese market. Identified by version-suffixed `libshella-<version>.so` (ARM) / `libshellx-<version>.so` (x86) and asset `assets/0OO00l111l1l` per [Quarkslab](https://blog.quarkslab.com/a-glimpse-into-tencents-legu-packer.html). |
| [Ducex](ducex.md) | [Triada](../malware/families/triada.md) | Advanced Chinese packer with RC4 / SM4 function encryption and XOR string encryption; `libducex.so` plus in-DEX payload section per [any.run analysis](https://any.run/cybersecurity-blog/ducex-packer-analysis/). Previously misattributed to Tencent Legu on this page. |
| [360 Jiagu](qihoo-360-jiagu.md) | Chinese banking trojans, stalkerware | `libjiagu.so` / `libjiagu_art.so`, asset `assets/jiagu_data.bin` (per [APKiD rules](https://github.com/rednaga/APKiD/blob/master/apkid/rules/apk/packers.yara)). Multi-DEX support. |
| [Bangcle](bangcle.md) | Regional malware, adware | `libsecexe.so` / `libsecmain.so` markers ([APKiD rules](https://github.com/rednaga/APKiD/blob/master/apkid/rules/apk/packers.yara)). |
| [SecShell](secshell.md) | [Joker](../malware/families/joker.md) ([Zscaler](https://www.zscaler.com/blogs/security-research/joker-facestealer-and-coper-banking-malwares-google-play-store)), Chinese malware | `libSecShell.so` plus `assets/secData0.jar` ([APKiD rules](https://github.com/rednaga/APKiD/blob/master/apkid/rules/apk/packers.yara)). Bangcle second-gen. Dual RC4/SM4 cipher, self-packed native code. |
| Custom packers | [Mandrake](../malware/families/mandrake.md), [SoumniBot](../malware/families/soumnibot.md) | OLLVM-obfuscated native loaders ([Mandrake](../malware/families/mandrake.md)), manifest parsing exploits ([SoumniBot](../malware/families/soumnibot.md)) |
| [AppSealing](appsealing.md) | Korean banking apps, Unity games | Shipping library `libcovault-appsec.so` (older builds: `libsecureapp.so`); asset directory `assets/AppSealing/`. Bypass: [AppPealing](https://codeberg.org/pufferffish/apppealing) Xposed module (active against current builds). |
| [LIAPP](liapp.md) | Korean banking apps (KBPay, NH Bank) | Strong Korean protector with backend integrity-attestation flow ([Lockin Company](https://liapp.lockincomp.com/about)). No public bypass tool. |
| No packer (obfuscation only) | [Cerberus](../malware/families/cerberus.md) lineage, [SpyNote](../malware/families/spynote.md) | Rely on string encryption, class renaming, and custom obfuscation instead of commercial packers |

## Universal Unpacking Toolkit

Tools for approaching any packed sample regardless of the specific packer.

### DEX Recovery

| Tool | Purpose | Packer Coverage |
|------|---------|-----------------|
| [frida-dexdump](https://github.com/hluwa/frida-dexdump) | Scans process memory for DEX magic bytes and dumps all loaded DEX files | All packers that decrypt DEX into memory (Chinese packers, DexGuard, DexProtector, AppSealing, LIAPP, Appdome, zShield) |
| [FART](https://github.com/hanbinglengyue/FART) | ART-level DEX dumper that modifies ART internals (`ArtMethod`, ClassLinker, interpreter, and `dex2oat`) and forces invocation of every method to recover function code at runtime | Effective against packers that use `InMemoryDexClassLoader` |
| [DexDump (smartdone)](https://github.com/smartdone/dexdump) | Xposed module for dumping DEX at class loading | Older Chinese packers, some DexGuard builds |
| [reFrida](https://codeberg.org/zahidaz/refrida) | Pre-built Frida scripts including DEX interception and string decryption | Broad coverage with configurable hooks |
| [AppPealing](https://codeberg.org/pufferffish/apppealing) | Xposed module that disables AppSealing checks and dumps decrypted DEX | AppSealing only |

### RASP Bypass

| Tool | Purpose | Notes |
|------|---------|-------|
| [Objection](https://github.com/sensepost/objection) | Runtime mobile exploration. Built-in root, SSL, and debug bypasses | Good starting point, handles common detection patterns |
| [Shamiko](https://github.com/LSPosed/LSPosed.github.io/releases) | Zygisk module that hides Magisk root from detection (distributed via the LSPosed release repository) | Preferred for Promon SHIELD, Arxan, and LIAPP |
| [ZygiskFrida](https://github.com/lico-n/ZygiskFrida) | Injects Frida gadget via Zygisk at process spawn | Avoids ptrace-based detection. Critical for Arxan, DexProtector, and LIAPP |
| [MagiskHide Props Config](https://github.com/Magisk-Modules-Repo/MagiskHidePropsConf) | Modifies device fingerprint properties to defeat emulator detection | Useful when running on physical rooted device |

### Native Analysis

| Tool | Purpose | When to Use |
|------|---------|-------------|
| [Ghidra](https://ghidra-sre.org/) + [D-810](https://github.com/joydo/d810) | Native decompiler with OLLVM deobfuscation plugin | Arxan guard network, Mandrake native loaders, Promon SHIELD library, zShield post-XXTEA |
| [IDA Pro](https://hex-rays.com/) + Keypatch | Native disassembler with inline patching | Virbox VM interpreter, DexProtector native bridge, LIAPP native library |
| [Frida Stalker](https://frida.re/docs/stalker/) | Instruction-level tracing at runtime | Tracing Virbox VM dispatch loop, mapping guard execution in Arxan |
| [XXTEA ELF Unpacker (DavidBuchanan314)](https://gist.github.com/DavidBuchanan314/ceb3637b7a6877dd7f64950c84228043) | Decrypts XXTEA-encrypted ELF bodies from zShield native libraries | zShield only. Removes outermost protection layer, OLLVM flattening remains |

### Recommended Lab Setup

```
Physical device (Pixel 7+, rooted with Magisk + Zygisk)
  ├─ Shamiko (hide root from target app)
  ├─ ZygiskFrida (stealth Frida injection)
  ├─ Objection (runtime exploration)
  └─ mitmproxy (network interception)

Alternative: Android emulator (API 33-35, Android 13-15)
  ├─ frida-server on non-default port (rename binary)
  ├─ Burp Suite / mitmproxy with custom CA
  └─ Note: many commercial packers detect emulators
```

Physical devices are strongly preferred for DexProtector, Promon SHIELD, Arxan, LIAPP, and Appdome analysis. These products aggressively detect emulators and virtual environments. Chinese packers, AppSealing, and DexGuard are generally workable in emulators with basic evasion.

## Unpacking Strategy

Universal sequence before reaching for the per-packer page:

1. Identify the packer (APKiD plus native library and asset inspection)
2. Capture DEX via memory dump (hook `DexClassLoader` / `InMemoryDexClassLoader`), process dump (`/proc/self/maps` regions with DEX magic), or framework hook
3. Reconstruct DEX from the dump
4. Decompile with JADX or Ghidra

The [Analysis Decision Tree](#analysis-decision-tree) below maps observed artifacts to specific packers. For per-packer unpacking specifics, see the individual packer pages. [Frida DEX dumping scripts](../reversing/hooking.md#dex-loading-interception) cover the universal hooking approach.

## Custom Packers

Some malware authors build their own packing solutions rather than using commercial products. These require per-sample analysis but follow predictable patterns.

| Technique | Examples | Analysis Approach |
|-----------|----------|-------------------|
| XOR-encrypted DEX in assets | Budget banking trojans, SMS stealers | Extract asset, brute-force single-byte XOR key (typically visible in native loader) |
| AES-encrypted second stage | Multi-stage droppers | Hook `javax.crypto.Cipher` to intercept key and IV, or extract from native loader |
| Steganographic DEX in images | [Necro](../malware/families/necro.md) | Reverse the pixel-to-byte extraction algorithm from the loader class |
| Manifest manipulation | [SoumniBot](../malware/families/soumnibot.md) | Install on device and dump via `adb shell dumpsys package`, bypassing parser bugs |
| OLLVM-obfuscated native loader | [Mandrake](../malware/families/mandrake.md) | D-810 for OLLVM deobfuscation, Frida Stalker for runtime tracing |
| Encrypted shared preferences payload | Dropper-style malware | Hook `SharedPreferences.getString()` to capture decrypted payload before loading |
| Split APK abuse | Play Store droppers | Reassemble all splits into a single APK using `bundletool`, then analyze normally |

Custom packers are typically easier to break than commercial ones because they lack the sustained engineering investment in anti-tampering and anti-hooking. The main challenge is identifying the specific decryption mechanism, which is usually straightforward once the native loader or Java-based decryptor is located. Outliers exist: [Mandrake](../malware/families/mandrake.md)'s OLLVM-flattened native loader is harder to deal with than several mainstream commercial protectors.

## Packer Comparison Matrix

Head-to-head comparison across all documented packers on the features that matter for analysis.

| Feature | [Virbox](virbox.md) | [DexGuard](dexguard.md) | [DexProtector](dexprotector.md) | [Arxan](arxan.md) | [Promon](promon.md) | [Chinese](tencent-legu.md) | [AppSealing](appsealing.md) | [LIAPP](liapp.md) | [Appdome](appdome.md) | [zShield](zshield.md) | [Verimatrix](verimatrix.md) |
|---------|--------|----------|--------------|-------|--------|--------|-----------|------|---------|---------|-----------|
| DEX encryption | Yes | Yes (class-level) | Yes | Partial | No | Yes (whole DEX) | Yes | Yes (full) | Yes | Yes (.szip) | Yes |
| DEX virtualization | Yes (core) | Optional | No | No | No | No | No | No | No | No | No |
| String encryption | VM-based | Method calls | White-box keys | Yes | No | Basic XOR | Weak | XOR (native) | Native | 32-bit key | Inlined per-site |
| Native protection | Yes | Yes | Yes | Guard network | No (RASP) | No | SO encryption | SO encryption | SO encryption | XXTEA + OLLVM | C/C++ obfuscation |
| Anti-Frida | Yes | Yes | Yes | Yes | Yes | Basic | Basic (port) | Aggressive | Multi-vector | Syscall-based | Yes |
| Anti-root | Yes | Yes | Yes | Yes | Yes | Basic | Moderate | Magisk-aware | Comprehensive | Yes | Yes |
| Anti-emulator | Yes | Yes | Yes | Yes | Yes | Basic | Yes | Aggressive | Yes | Yes | Yes |
| White-box crypto | No | No | vTEE CryptoModule | Yes | No | No | No | No | No | zKeyBox (separate) | EMVCo certified |
| RASP | Partial | Partial | Core feature | Yes | Primary | No | Basic | Core feature | OneShield | Integrity checks | Full suite |
| Code virtualization | DEX + native | Optional | Hide Access | Guard-level | No | No | No | No | No | No | No |
| Server-side attestation | No | No | No | No | No | No | No | Backend integrity flow | No | No | OTA updates |
| Unpacking difficulty | Expert | Medium-Hard | Medium-Hard | Hard | Medium | Easy-Medium | Low-Medium | Hard | Medium-Hard | Medium-Hard | Medium |
| Public bypass tools | None | Limited | Limited | None | Limited | Generic DEX dump | AppPealing | None | None | XXTEA unpacker | None |

## Analysis Decision Tree

When encountering a protected sample, use this sequence to minimize wasted effort:

```
Start
  |
  ├─ Run APKiD (current rules: appsealing, jiagu, bangcle, bangcle_secshell,
  │            tencent_legu, ijiami, dexprotector, naga; Zimperium / InsideSecure /
  │            Appdome / Virbox have no upstream rules yet)
  │   ├─ packer : appsealing → AppSealing (use AppPealing or Frida kill/signal/alarm hooks)
  │   ├─ packer : tencent_legu → Tencent Legu
  │   ├─ packer : jiagu → 360 Jiagu
  │   ├─ packer : bangcle / bangcle_secshell → Bangcle / SecShell
  │   ├─ packer : dexprotector → DexProtector
  │   ├─ Other packer identified → Go to packer-specific page
  │   ├─ Obfuscator only → Proceed with jadx, use deobfuscation scripts
  │   └─ Unknown protection → Fall through to native library / asset checks below
  |
  ├─ Check native libraries (for protectors APKiD does not yet detect)
  │   ├─ libshella-*.so / libshellx-*.so + assets/0OO00l111l1l → Tencent Legu (Quarkslab)
  │   ├─ libjiagu*.so + assets/jiagu_data.bin → Qihoo 360
  │   ├─ libsecexe.so / libsecmain.so → Bangcle
  │   ├─ libSecShell.so + assets/secData0.jar → SecShell
  │   ├─ libcovault-appsec.so (or legacy libsecureapp.so) + assets/AppSealing/ → AppSealing
  │   ├─ libalice.so / libdexprotector.*.so → DexProtector (older builds; newer use randomized .dat/.mp3 assets)
  │   ├─ libstrategy.so wrapped by Virbox runtime → Virbox-protected Gigabud / GoldDigger variant
  │   ├─ lib<random12chars>.so (~3MB, packed ELF) → zShield (DavidBuchanan314 writeup)
  │   ├─ com.lockincomp.* references → LIAPP (no APKiD signature yet)
  │   ├─ Renamed / encrypted .so files plus DEX byte[]->String wrappers → DexGuard (no fixed filename)
  │   ├─ Additional outer DEX + opaque native loader (filename varies) → Possible Appdome (verify against vendor patterns)
  │   └─ Unknown .so → Check strings, imports for packer signatures
  |
  ├─ Check obfuscation level
  │   ├─ a/b/c class names, no string encryption → R8/ProGuard only
  │   ├─ Single-char classes + byte[]->String methods → DexGuard string encryption
  │   ├─ X.<short> class names (e.g., X.A1c) + InterDex layout → Meta Redex
  │   ├─ All strings readable, class names intact → No obfuscation
  │   └─ Native JNI stubs replacing Java methods → Virtualization (Virbox or DexGuard advanced)
  |
  ├─ Check assets
  │   ├─ assets/AppSealing/ directory → AppSealing
  │   ├─ *.szip files (~8MB) + truncated .odex → zShield
  │   ├─ Virbox runtime blobs in assets → Virbox
  │   └─ Encrypted blobs → Generic packer or custom encryption
  |
  └─ Choose approach
      ├─ Obfuscation only → Static analysis with jadx deobfuscation
      ├─ DEX encryption → frida-dexdump or DexClassLoader hook
      ├─ Virtualization → Dynamic analysis only (hook VM interpreter)
      ├─ RASP only → Frida with detection bypass hooks
      ├─ Server-side attestation (LIAPP) → Token replay from clean device
      └─ White-box crypto (Verimatrix CryptoModule, zKeyBox) → Code lifting, not key extraction
```

## Packer Trends in Malware

*Last reviewed: 2026-05*


| Trend | Details |
|-------|---------|
| Commercial packer adoption | Malware authors increasingly use commercial packers (Virbox, DexGuard) rather than custom solutions. Reduces development cost at the expense of identifiable signatures. |
| Multi-layer / double packing | Modern samples combine two commercial packers or a commercial packer with custom obfuscation. See [Double Packing](#double-packing). |
| Packer-as-a-Service | Underground forums offer packing services where customers submit APKs and receive protected versions. No need to license the packer directly. |
| Custom packers declining | Only sophisticated groups like [Mandrake](../malware/families/mandrake.md) developers invest in custom OLLVM-based protection. Most operators use off-the-shelf solutions. |
| RASP integration | Banking trojans increasingly encounter RASP-protected target apps ([Promon](promon.md), [Arxan](arxan.md), [LIAPP](liapp.md), [Appdome](appdome.md)), requiring malware to bypass runtime checks to perform overlay injection or accessibility manipulation. |
| Guardsquare consolidation | Guardsquare's [acquisition of Verimatrix XTD (closed Feb 2026)](https://www.guardsquare.com/press-release/guardsquare-acquires-verimatrix-xtd) means one vendor now controls [DexGuard](dexguard.md), [R8/ProGuard](r8-proguard.md), and [Verimatrix XTD](verimatrix.md). Expect product consolidation and white-box crypto integration into DexGuard. |
| Korean market protectors | [LIAPP](liapp.md) and [AppSealing](appsealing.md) dominate the Korean banking and gaming markets. LIAPP's server-side token verification introduces a new dimension that purely client-side protectors lack. |
| No-code SaaS protection | [Appdome](appdome.md) and [AppSealing](appsealing.md) offer cloud-based protection without build pipeline changes. Appeals to organizations without mobile security engineering teams. |
| Manifest-level evasion | [SoumniBot](../malware/families/soumnibot.md) demonstrated that packing the code is not the only option. Malforming the APK structure itself can defeat analysis tools without any packer. |

## Double Packing

Using two distinct packers on the same APK, layering their protections so that an analyst must defeat both to reach the original code. The outer packer's Application class loads first, decrypts and initializes its runtime, then hands off to the inner packer's Application class, which performs its own decryption before finally loading the real app code.

A typical combination pairs a Chinese packer ([Virbox](virbox.md), [360 Jiagu](qihoo-360-jiagu.md)) as the outer layer with a second packer or custom protection as the inner layer. The outer packer encrypts the inner packer's stub along with the real payload, so static analysis sees only the outermost stub classes.

### How It Works

```
APK
 └─ Outer packer Application (e.g., Virbox l637078ca)
     ├─ Decrypts native library from assets
     ├─ Loads real Application class from SAPP_NAME metadata
     └─ Inner packer Application (e.g., 360 Jiagu GZckWAeyProtected)
         ├─ Initializes its own protection runtime
         └─ Loads the actual app code
```

The outer packer handles DEX encryption and native library protection. The inner packer adds its own anti-analysis layer (anti-debugging, integrity checks, additional code hiding). Each packer's anti-tampering mechanisms independently verify their own integrity, so bypassing one does not disable the other.

### Analysis Impact

| Challenge | Why It's Harder |
|-----------|----------------|
| Two unpacking stages | Must dump DEX after each packer initializes, not just once |
| Nested native libraries | Two sets of `.so` files to reverse, each with different protection |
| Combined anti-analysis | Root/emulator/hooking checks from both packers fire independently |
| Ordering dependency | Inner packer only initializes after outer packer completes, so timing hooks is critical |

### Unpacking Approach

1. Identify both packers via APKiD and native library inspection (e.g., Virbox assets + `libjiagu.so` presence)
2. Dump DEX after the outer packer loads using `frida-dexdump` or `DexClassLoader` hooks
3. The dumped DEX will still be protected by the inner packer
4. Re-analyze the dumped output, then dump again after the inner packer initializes
5. The second dump contains the real app code

Alternatively, wait for both packers to fully initialize before dumping. A late-stage memory dump (after `Application.onCreate()` completes) often captures the fully unpacked DEX, skipping the intermediate stage.

## Detection Evasion Effectiveness

How much each protection layer reduces detection rates across multi-engine static scanning, as an ordinal ranking:

| Protection | Evasion against static AV scanning | Why |
|-----------|-------------------------------------|-----|
| No protection | Baseline | All engines can scan the raw DEX |
| RASP only (no packing) | Negligible | Code is still scannable; RASP operates at runtime |
| [R8 / ProGuard](r8-proguard.md) only | Low | Engines pattern-match on behavior, not names |
| Chinese packer (basic, e.g. [Bangcle](bangcle.md), [360 Jiagu](qihoo-360-jiagu.md)) | Moderate | Engines scan the stub, not the encrypted payload |
| [AppSealing](appsealing.md) | Moderate | DEX encrypted but historically weaker string protection |
| [DexGuard](dexguard.md) | High | String encryption hides IoCs; class-level encryption hides behavior patterns |
| [LIAPP](liapp.md) | High | DEX encryption, native string encryption, and server-side attestation |
| [Appdome](appdome.md) | High | DEX encryption, native library encryption, multi-vector RASP (OneShield) |
| [Verimatrix XTD](verimatrix.md) | High | Code encryption, multi-language obfuscation, inlined string decryption |
| Custom packer + obfuscation | High to Very High | Varies by implementation quality (e.g., [Mandrake](../malware/families/mandrake.md) OLLVM) |
| [zShield](zshield.md) | Very High | XXTEA ELF encryption, .szip DEX, randomized library names |
| [Virbox](virbox.md) (virtualized) | Very High | Proprietary VM instructions are opaque to static scanners |

These bands are qualitative analyst impressions, not the output of a published study. They reflect typical observed behavior on multi-engine static scanning of packed vs unpacked samples within the same family but no fixed methodology, sample corpus, or date is anchored. Per-family detection deltas vary widely. The actionable takeaways: DEX virtualization ([Virbox](virbox.md)) provides the highest static analysis resistance, while basic Chinese packers offer adequate protection against automated scanning but fall quickly to manual Frida-based analysis.
