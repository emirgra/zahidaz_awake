# Tencent Legu

The most widely used Chinese packer. Free protection service integrated with Tencent's app distribution ecosystem. Frequently found on both legitimate Chinese apps and malware. The protection is adequate against automated AV scanning but yields to manual analysis with [Frida](../reversing/hooking.md)-based unpacking.

## Overview

| Property | Value |
|----------|-------|
| **Vendor** | Tencent |
| **Free Tier** | Yes |
| **APKiD Signature** | `packer : Tencent Legu` |
| **Unpacking Difficulty** | Medium |

## Identification

| Artifact | Location | Description |
|----------|----------|-------------|
| Application class | `AndroidManifest.xml` | `com.tencent.StubShell.TxAppEntry` replaces the real Application class |
| Meta-data | `AndroidManifest.xml` | `<meta-data android:name="TxAppEntry" android:value="<real_application_class>"/>` stores the original Application class name |
| Native libraries | `lib/armeabi/` | `libshella-<version>.so` + `libshellx-<version>.so` (versioned by Legu release) |
| DEX stubs | `lib/armeabi/` | `mix.dex` + `mixz.dex` containing a single empty `com.mixClass{}` |
| Older native names | `lib/` | `libshell-super.2019.so`, `libtxoprot.so` in earlier versions |
| Runtime directory | `/data/data/<pkg>/` | `tx_shell/` directory created at runtime containing `libshella.so`, `libshellb.so`, `libshellc.so` |
| Crash reporting | DEX | `com.tencent.bugly.legu.crashreport.CrashReport` with app ID `900015015` |
| Version string | DEX | Static method `c()` on the shell class returns version (e.g., `"2.10.7.1"`); static field `version` holds a hash |

### Version Detection

The Legu version can be determined from the native library filename suffix (`libshella-2.10.7.1.so`) or by calling the version method at runtime:

```javascript
Java.perform(function() {
    var TxAppEntry = Java.use("com.tencent.StubShell.TxAppEntry");
    console.log("Legu version: " + TxAppEntry.c());
});
```

## Protection

### Runtime Loading

`TxAppEntry.attachBaseContext()` loads the native shell library, which decrypts the real DEX from within the outer `classes.dex` using `mmap`/`mprotect`, then calls `load()` to inject the decrypted classes into the running process. `runCreate()` delegates to the real Application's `onCreate()`. The original code exists only in memory and is not extractable statically.

### `getPackageName()` Override

Legu overrides `getPackageName()` with stack trace inspection to manipulate the ContentProvider installation order. This ensures the shell's providers initialize before the real app's providers, which is required for the decryption chain to complete before any app component tries to access protected classes.

### Anti-Analysis

- DEX encryption with AES (decrypted via native library at runtime)
- Native library anti-debugging (ptrace self-attach)
- Emulator detection via hardware properties
- Anti-Frida checks (port scanning, `/proc/maps` inspection, named pipe detection)
- String encryption in native layer
- Code segment checksumming

## Unpacking

Static unpacking is not feasible since the DEX is decrypted in memory by native code. [Dynamic analysis](../reversing/dynamic-analysis.md) is required.

### Standard Approach

1. Hook `DexClassLoader` or `InMemoryDexClassLoader` to intercept DEX loading
2. Dump DEX bytes from memory after native loader decrypts
3. Alternative: use [frida-dexdump](https://github.com/hluwa/frida-dexdump) which scans process memory for DEX headers
4. Memory dump from `/proc/<pid>/maps` to locate decrypted DEX regions

### Anti-Frida Bypass

Tencent Legu checks for Frida by scanning `/proc/self/maps` for `frida-agent` strings, probing port 27042, and checking named pipes in `/proc/self/fd/`. A combined bypass hooks these checks at the native level:

```javascript
var openPtr = Module.findExportByName("libc.so", "open");
Interceptor.attach(openPtr, {
    onEnter: function(args) {
        this.path = args[0].readUtf8String();
    },
    onLeave: function(retval) {
        if (this.path && this.path.indexOf("/proc") !== -1 &&
            this.path.indexOf("/maps") !== -1) {
            this.isMaps = true;
        }
    }
});

var readPtr = Module.findExportByName("libc.so", "read");
Interceptor.attach(readPtr, {
    onLeave: function(retval) {
        if (this.isMaps) {
            var buf = this.context.x1;
            var content = buf.readUtf8String();
            if (content && content.indexOf("frida") !== -1) {
                buf.writeUtf8String(content.replace(/frida/g, "aaaaa"));
            }
        }
    }
});

var connectPtr = Module.findExportByName("libc.so", "connect");
Interceptor.attach(connectPtr, {
    onEnter: function(args) {
        var sockaddr = args[1];
        var port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
        if (port === 27042) {
            args[1] = ptr(0);
        }
    }
});
```

For Legu versions after 2023, the packer also scans for `frida-gadget` in loaded modules. The [Frida naming convention](https://frida.re/docs/gadget/) for renamed gadgets can bypass the string-based check. Using `frida-server` with `--listen 0.0.0.0:1337` on a non-standard port avoids port scanning detection.

## Malware Usage

| Family | Notes |
|--------|-------|
| [Triada](../malware/families/triada.md) | Firmware variants |
| Chinese adware | Most common protection on Chinese-origin adware |

## References

- [APKiD Packer Signatures](https://github.com/rednaga/APKiD)
- [frida-dexdump](https://github.com/hluwa/frida-dexdump)
