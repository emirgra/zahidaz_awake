# ART Hooking Libraries

Catalog of Java/ART method-hooking libraries used to build Xposed-style modules, virtualization frameworks, and in-process instrumentation tooling. Most analysts reach for [Frida](hooking.md#frida) or [LSPosed](hooking.md#xposed-framework) directly, but the engines under those tools (and the historical alternatives) show up in malware, training material, and older research repos. This page is the reference for what each library is and when you would actually open its source.

For the practical "how to hook things" content, see [Hooking](hooking.md).

## How ART Method Hooking Works

Every library on this page does the same fundamental thing: replace or patch the entrypoint of an `ArtMethod` struct so that calls into the original method are redirected. The differences are in how the patch is applied and how the original method can still be invoked.

| Approach | Mechanism | Trade-off |
|----------|-----------|-----------|
| Entrypoint replacement | Overwrite `entry_point_from_quick_compiled_code` to point at a stub | Simple, but the stub must rebuild the call frame for the original |
| Inline trampoline | Patch the first instructions of the compiled method with a jump | Works with JIT/AOT code; needs per-architecture trampoline generation |
| Backup-method (dexposed-style) | Clone the `ArtMethod` so the original can be called by invoking the backup | Used by most modern frameworks; relies on internal ART layout |
| Native inline hook | Patch native (`.so`) functions, then proxy Java methods through JNI | Required when the target is an `@FastNative` / `@CriticalNative` method |

The fragility of these techniques is why every library publishes a per-Android-version compatibility matrix: the `ArtMethod` struct layout, the entrypoint fields, and the JIT behavior all change between AOSP releases.

## Library Catalog

| Library | Author | Approach | Status | Notes |
|---------|--------|----------|--------|-------|
| [YAHFA](https://github.com/rk700/YAHFA) | rk700 | Entrypoint replacement + backup method | Maintained (community forks) | Engine used by older LSPosed and many Xposed reimplementations. Reference implementation for the backup-method approach. |
| [SandHook](https://github.com/ganyao114/SandHook) | ganyao114 | Inline trampoline + backup method | Maintained | Default engine in modern [LSPosed](https://github.com/LSPosed/LSPosed) (Zygisk). Better compatibility with newer Android versions than YAHFA. |
| [Epic](https://github.com/tiann/epic) | tiann (KernelSU author) | Dexposed-style entrypoint patch, in-process | Maintained | In-process Java hooking without requiring system-wide Xposed. Popular for app-internal instrumentation. |
| [Pine](https://github.com/canyie/pine) | canyie | Inline trampoline | Maintained | Used by some LSPosed forks and standalone hooking tools. Supports ART up to recent Android versions. |
| [Whale](https://github.com/asLody/whale) | asLody | Native inline hook (PLT + inline) | Archived | Successor to AndHook from the same author. Native-level hooking applicable to both Java (via JNI) and pure native targets. |
| [AndHook](https://github.com/asLody/AndHook) | asLody | ART method entrypoint patch | Archived | Early ART hooking library (2016-2018) from the author of VirtualXposed. Superseded by Whale and the YAHFA/SandHook lineage. Still referenced in older malware research. |
| [Dexposed](https://github.com/alibaba/dexposed) | Alibaba | ART method patch (original) | Archived | Original ART-era hooking framework. Only supports Android 4.4-5.x. Of historical interest only; the technique it introduced underpins most successors. |
| [FastHook](https://github.com/turing-technician/FastHook) | turing-technician | Inline trampoline | Inactive | Smaller-scope alternative. Occasionally seen in CTF writeups and academic papers. |

## When You Would Actually Read These

| Situation | Library to Open |
|-----------|-----------------|
| Building a production Xposed module | Use [LSPosed](https://github.com/LSPosed/LSPosed) directly; don't pick the engine. |
| Debugging why an LSPosed hook fails on a new Android version | [SandHook](https://github.com/ganyao114/SandHook) source (it's the engine). |
| Reading malware that ships its own hook engine | Compare against [YAHFA](https://github.com/rk700/YAHFA) / [AndHook](https://github.com/asLody/AndHook) source; most rolled-their-own engines are copies. |
| In-process instrumentation from a non-rooted app | [Epic](https://github.com/tiann/epic), designed for this use case. |
| Hooking `@FastNative` / `@CriticalNative` methods that ART hook frameworks skip | [Whale](https://github.com/asLody/whale) or a native inline hook library (e.g., [Dobby](https://github.com/jmpews/Dobby)). |
| Academic paper references a hook framework you've never heard of | Likely one of the archived libraries above; check author and approach to map it to a current equivalent. |

## Relationship to Frida

Frida does not use any of these libraries. It implements its own Stalker-based instrumentation and PLT/GOT hooking, and for Java it interacts with ART directly through Frida's `Java.use()` machinery. The libraries on this page are relevant when:

- The target uses Xposed-style modules (Frida is process-scoped; Xposed/LSPosed is system-wide and persists across process restarts)
- Stealth requirements rule out Frida (Frida's footprint is well-known to anti-instrumentation, while a custom hook engine derived from AndHook/YAHFA can be harder to detect)
- The hook must survive process death without re-injection (Xposed-style hooks are installed by Zygote and inherited)

Malware authors choose Xposed-style engines (or roll their own from YAHFA/AndHook source) for the last two reasons. See [Anti-Frida Detection and Bypass](hooking.md#anti-frida-detection-and-bypass) for the parallel cat-and-mouse on the Frida side.

## Detection from the Defensive Side

Apps that want to detect any of these libraries typically check for:

- `/proc/self/maps` entries for the library's `.so` file
- Specific exported symbols (e.g., `SandHookXposedBridge`, `epic_native`)
- Modified `ArtMethod` entrypoints pointing outside the expected `.oat` / JIT range
- Backup-method artifacts: duplicate `ArtMethod` structs in the class's method array

Offensive tooling responses live in [Hooking § Anti-Frida Detection and Bypass](hooking.md#anti-frida-detection-and-bypass); the same memory-hiding techniques apply when the engine is YAHFA or SandHook rather than Frida-gum.
