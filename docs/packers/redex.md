# Redex (Meta DEX Optimizer)

Redex is Meta's open-source Android DEX bytecode optimizer, [open-sourced under the MIT License in April 2016](https://engineering.fb.com/2016/04/12/android/open-sourcing-redex-making-android-apps-smaller-and-faster/). It is not a packer or RASP; it is a post-build size and performance optimizer. Its transformations (class merging, method inlining, identifier renaming, InterDex layout) incidentally erase the symbols and structural cues that static reverse engineering relies on, which is why Meta apps decompile into walls of `X.A1c`-style classes with collapsed call frames.

## Vendor Information

| Field | Value |
|-------|-------|
| Vendor | Meta Platforms (Facebook) |
| Origin | USA |
| License | MIT ([repo](https://github.com/facebook/redex)) |
| First public discussion | [1 Oct 2015](https://engineering.fb.com/2015/10/01/android/optimizing-android-bytecode-with-redex/) |
| Open source release | [12 Apr 2016](https://engineering.fb.com/2016/04/12/android/open-sourcing-redex-making-android-apps-smaller-and-faster/) |
| Repository | [github.com/facebook/redex](https://github.com/facebook/redex) |
| Documentation | [fbredex.com](https://fbredex.com/) |
| Status | Actively maintained (10,000+ commits, releases through 2025) |
| Build integration | Designed for Buck; consumes ProGuard `-P` rules ([example](https://fbredex.com/docs/examples/proguard/)) |

## Identification

### Naming convention

Redex's [RenameClassesPassV2](https://fbredex.com/docs/help/faq/) produces short obfuscated names with a leading `X.` package prefix, such as `X.A1c`. This convention is documented in the official FAQ and is the strongest single heuristic for spotting Redex output in a target APK.

### InterDex layout

[InterDex](https://fbredex.com/docs/technical_details/interdex/) reorders classes across primary and secondary DEX files based on a cold-start profile, so classes accessed during startup cluster at the head of each DEX. The familiar "alphabetical by package" mental model used when triaging a multidex APK does not apply. When `emit_canaries` is enabled, [each secondary DEX gets a non-functional canary class](https://fbredex.com/docs/technical_details/interdex/) as a layout marker.

### Structural artifacts

Aggressive use of `methodinline`, `final_inline`, `class-merging`, `vertical_merging`, `virtual_merging`, and `singleimpl` ([opt/ tree](https://github.com/facebook/redex/tree/main/opt)) produces decompiled output with disproportionate static-helper density, missing wrapper methods, and single classes holding members from several pre-optimization classes. Decompilers like jadx will surface these patterns even when symbol names happen to survive.

### APKiD coverage

As of the most recent inspection of the [APKiD obfuscator YARA rules](https://github.com/rednaga/APKiD/blob/master/apkid/rules/dex/obfuscators.yara), there is no dedicated Redex signature. Identification is currently a manual exercise based on the artifacts above.

## Transformation Catalog

Every transformation listed below is verifiable in the [`opt/` directory of the Redex repository](https://github.com/facebook/redex/tree/main/opt). Pass names match the directory layout.

### Dead code and structural reduction

| Pass | Effect |
|------|--------|
| `local-dce`, `remove-unreachable`, `object-sensitive-dce` | Remove unreachable methods and classes by entry-point traversal |
| `remove-unused-args`, `remove-unused-fields` | Strip unused method parameters and class fields |
| `remove-builders`, `remove-interfaces`, `remove_redundant_check_casts`, `delsuper` | Eliminate redundant builder objects, dead interfaces, and superfluous casts |

### Inlining and merging

| Pass | Effect |
|------|--------|
| `methodinline`, `final_inline` | Inline small or wrapper methods; destroys original call boundaries |
| `class-merging`, `vertical_merging`, `virtual_merging`, `singleimpl` | Fuse class identities; collapse single-implementation interfaces |
| `class-splitting` | Peel cold methods to separate classes for cold-start layout |

### Code-flow optimization

| Pass | Effect |
|------|--------|
| `peephole`, `reduce-array-literals`, `reduce-boolean-branches`, `reduce-gotos`, `reduce-sparse-switches`, `up-code-motion` | Standard peephole and branch reductions |
| `constant-propagation`, `copy-propagation`, `result-propagation`, `cse`, `type-analysis` | Whole-program data-flow optimizations |
| `regalloc`, `regalloc-fast` | DEX register reallocation |

### Identifier and resource minification

| Pass | Effect |
|------|--------|
| `renameclasses` (RenameClassesPassV2) | Generates short class names like `X.A1c` ([FAQ](https://fbredex.com/docs/help/faq/)) |
| `obfuscate` | Renames fields and methods ([opt/obfuscate](https://github.com/facebook/redex/blob/main/opt/obfuscate/Obfuscate.h)) |
| `optimize_resources`, `dedup_resources`, `obfuscate_resources`, `resource-value-merging-pass` | Optimize, deduplicate, and obfuscate Android resource tables |
| `dedup-strings`, `shorten-srcstrings`, `string_concatenator` | Deduplicate and shorten string pool entries |

### Layout and Kotlin

| Pass | Effect |
|------|--------|
| `interdex` ([InterDex.h](https://github.com/facebook/redex/blob/main/opt/interdex/InterDex.h)) | Reorder classes across DEX files using a cold-start profile |
| `kotlin-lambda` | Kotlin-specific lambda group optimization |

### Not included

Redex does not encrypt DEX, does not add anti-debug, does not implement RASP, and does not perform code virtualization. The [README](https://github.com/facebook/redex) and [FAQ](https://fbredex.com/docs/help/faq/) describe it solely as an optimizer. Any RASP layered on a Meta app comes from a separate component, not Redex.

## Build Pipeline Position

Per the [FAQ](https://fbredex.com/docs/help/faq/), Redex operates on `.dex` bytecode after the Java/Kotlin source has been compiled and (optionally) processed by ProGuard or R8. The intended workflow is to run ProGuard or R8 during the class-to-DEX compile, then Redex on the resulting DEX with the ProGuard keep rules passed through via `-P` ([ProGuard example](https://fbredex.com/docs/examples/proguard/)). Tight Buck integration is documented as the canonical setup ([fbredex.com](https://fbredex.com/)).

## Reverse Engineering Implications

Redex degrades static analysis fidelity even though it is not designed as a protection tool. Renaming replaces meaningful identifiers with short tokens; aggressive inlining collapses wrappers so call graphs no longer match source structure; class merging fuses identities so a single decompiled class may hold methods from several original classes; InterDex reordering scrambles the alphabetical layout used during APK triage.

The project is bidirectionally useful: because Redex provides a robust DEX read/write/IR framework, researchers have repurposed it as a deobfuscation engine. [You et al. (SMA 2020)](https://dl.acm.org/doi/10.1145/3426020.3426089) demonstrated that Redex passes can collapse obfuscated control flow inserted by Obfuscapk on ten open-source Android apps, while noting that Redex did not remove inserted `goto` and `nop` instructions. There is no published Redex-output deobfuscator for Meta apps, and no symbol map.

### Recommended workflow

1. Identify by `X.<short>` naming and InterDex layout artifacts.
2. Decompile with jadx and expect fused class identities, missing call frames, and reordered class layout.
3. Recover semantics that inlining destroyed by hooking API boundaries with Frida rather than chasing decompiled control flow.
4. For comparison and diffing work, consider running additional Redex passes (DCE, simplification) on the target to canonicalize bytecode before diffing two builds.

## Comparison to R8 and ProGuard

Per [Redex's own FAQ](https://fbredex.com/docs/help/faq/): "ReDex is conceptually similar to ProGuard, in that both optimize bytecode. ReDex, however, optimizes .dex bytecode, while ProGuard optimizes .class bytecode before it is lowered to .dex. Operating on .dex is sometimes an advantage: you can consider the number of virtual registers used by a method that is an inlining candidate, and you can control the layout of classes within a dex file. But ProGuard has some capabilities that ReDex does not (for example, ReDex will not remove unused method parameters, which ProGuard does)."

R8 has since absorbed ProGuard's role as the default in the Android Gradle Plugin toolchain. Redex sits at a later, DEX-level stage and adds capabilities R8 lacks: InterDex cold-start layout, aggressive vertical and virtual class merging, and resource-table optimization. See also [R8 / ProGuard](r8-proguard.md) on this site.

## Known Deployments

| App | Source |
|-----|--------|
| Facebook for Android | "In November [2015], we shipped the first ReDex-optimized version of Facebook for Android, which was 25 percent smaller and had up to 30 percent faster start times." ([Meta, Apr 2016](https://engineering.fb.com/2016/04/12/android/open-sourcing-redex-making-android-apps-smaller-and-faster/)) |
| Instagram for Android | "Facebook and Instagram each load more than 20,000 classes on startup. [...] InterdexPass in Redex, our bytecode optimizer." ([Meta, Oct 2025](https://engineering.fb.com/2025/10/01/android/accelerating-our-android-apps-with-baseline-profiles/)) |

WhatsApp, Messenger, and Threads are commonly assumed to use Redex given their Meta provenance, but no primary Meta source surfaced in this research explicitly confirms it. Treat as plausible-but-unsourced. No public confirmation of non-Meta adopters was located, despite the MIT license making external adoption permissible.

## Timeline

| Date | Event |
|------|-------|
| 1 Oct 2015 | [Meta publicly introduces Redex](https://engineering.fb.com/2015/10/01/android/optimizing-android-bytecode-with-redex/) and the first ReDex-optimized Facebook for Android ships in Nov 2015 |
| 12 Apr 2016 | [Redex open-sourced under MIT](https://engineering.fb.com/2016/04/12/android/open-sourcing-redex-making-android-apps-smaller-and-faster/) |
| 2017 | [Redex, Your Build, And You](https://www.youtube.com/watch?v=vtxJvJj6gSE) talk at droidcon SF |
| 2020 | [You et al.](https://dl.acm.org/doi/10.1145/3426020.3426089) repurpose Redex passes as a deobfuscation engine against Obfuscapk-protected apps |
| Oct 2025 | [Meta describes InterDex use on Facebook and Instagram alongside Baseline Profiles](https://engineering.fb.com/2025/10/01/android/accelerating-our-android-apps-with-baseline-profiles/) |

## Talks and References

- [Optimizing Android bytecode with ReDex](https://engineering.fb.com/2015/10/01/android/optimizing-android-bytecode-with-redex/), Engineering at Meta, Oct 2015
- [Open-sourcing ReDex: Making Android apps smaller and faster](https://engineering.fb.com/2016/04/12/android/open-sourcing-redex-making-android-apps-smaller-and-faster/), Engineering at Meta, Apr 2016
- [Accelerating our Android apps with Baseline Profiles](https://engineering.fb.com/2025/10/01/android/accelerating-our-android-apps-with-baseline-profiles/), Engineering at Meta, Oct 2025
- [Redex documentation site](https://fbredex.com/) including [InterDex](https://fbredex.com/docs/technical_details/interdex/), [FAQ](https://fbredex.com/docs/help/faq/), and the [ProGuard example](https://fbredex.com/docs/examples/proguard/)
- [Chris Sarbora, "Redex, Your Build, And You"](https://www.youtube.com/watch?v=vtxJvJj6gSE), droidcon SF 2017
- [Shohei Kawano, Redex: A bytecode optimizer for Android apps](https://speakerdeck.com/shoheikawano/redex-a-bytecode-optimizer-for-android-apps)
- [You et al., Reversing Obfuscated Control Flow Structures in Android Apps using ReDex Optimizer](https://dl.acm.org/doi/10.1145/3426020.3426089), SMA 2020 (ACM DL)
