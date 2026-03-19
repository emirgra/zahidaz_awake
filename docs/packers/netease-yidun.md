# NetEase YiDun

NetEase's application security service (易盾, "YiDun" = "Easy Shield"), integrated with their gaming ecosystem. Two distinct products: the **App Packer** (full-app encryption) and the **SDK Reinforcement** (method-level VM protection). The app packer is common in Chinese mobile games. The SDK reinforcement variant appears in both legitimate apps and malware, and currently evades APKiD detection.

## Overview

| Property | App Packer | SDK Reinforcement |
|----------|-----------|-------------------|
| **Vendor** | NetEase | NetEase |
| **Package** | `com.netease.nis.wrapper` | `com.netease.nis.sdkwrapper` |
| **Entry class** | `Entry`, `MyJni`, `MyApplication` | `Utils` (native methods `rL()`, `rD()`) |
| **Native library** | `libnesec.so` | `libsecsdk.so` |
| **Assets** | `nedata.db`, `nedig.properties` | Custom-named encrypted blobs |
| **APKiD detection** | Yes (`packer : NetEase`) | No (evades current rules) |
| **Mechanism** | Encrypts entire `classes.dex`, loads at runtime | Extracts individual method bodies, runs in custom native VM |
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

## SDK Reinforcement (SDK加固)

A separate product from the app packer. Instead of encrypting the entire DEX, it extracts individual method bodies from selected classes at build time, encrypts them into asset blobs, and replaces the original methods with JNI dispatch stubs. At runtime, `libsecsdk.so` decrypts and executes the original bytecode through a custom virtual machine embedded in the native library.

Per [NetEase's SDK Reinforcement documentation](https://support.dun.163.com/documents/2017121302?docId=101837745727655936), the required ProGuard keep rule `-keep public class com.netease.nis.sdkwrapper.Utils {public *;}` confirms the SDK variant's namespace.

### Identification

| Artifact | Description |
|----------|-------------|
| Native library | `libsecsdk.so` (stripped ARM64 binary) |
| Package | `com.netease.nis.sdkwrapper.Utils` with native methods `rL()` and `rD()` |
| ProGuard rule | `-keep public class com.netease.nis.sdkwrapper.Utils` in build config |
| Assets | Custom-named encrypted files (randomized English words, `.dat` files) |
| APKiD | Not detected -- existing [yidun rule](https://github.com/rednaga/APKiD/blob/master/apkid/rules/apk/packers.yara) matches only `wrapper`/`libnesec.so` |
| **Common false positive** | MSA OAID SDK (`com.bun.miitmdid`) frequently co-occurs with these artifacts |

### JNI Dispatch Mechanism

Every protected method is replaced with a stub that delegates to `Utils.rL()`:

```java
public class Utils {
    static { System.loadLibrary("secsdk"); }
    public static native Object rL(Object[] objArr);
    public static native String rD(String str, String str2);
}
```

Protected methods become dispatch stubs. All lifecycle methods (`onCreate`, `onStart`, `onBind`) of protected classes delegate to `Utils.rL()`, making DEX-level static analysis see only empty shells.

### Encrypted Assets

The SDK packer stores encrypted VM bytecode in the APK's `assets/` directory as custom-named files. The encrypted payloads are loaded at runtime by `libsecsdk.so` via the NDK `AAssetManager` API.

### OAID SDK False Positives

The MSA OAID SDK (`com.bun.miitmdid`), China's Mobile Security Alliance device identifier SDK, frequently co-occurs with `com.netease.nis.sdkwrapper.Utils` and `libsecsdk.so` in Chinese-market apps. Apps integrating the OAID SDK may contain these artifacts without being intentionally packed by the attacker. Detection rules targeting `sdkwrapper`/`libsecsdk.so` will flag these apps.

To distinguish malicious use from OAID SDK integration: check whether the `Utils.rL()` dispatch protects app-specific classes (malicious) or only `com.bun.miitmdid` classes (OAID). If the only classes calling `Utils.rL()` are in the `miitmdid` namespace, the app is likely just using the OAID SDK, not packed by the attacker.

### Anti-Analysis

- Stripped native binary
- `mmap`/`mprotect` for executable memory mapping (standard for runtime decryption)
- `dlopen`/`dlsym` for dynamic loading

### Unpacking

Static unpacking is not feasible because method bodies only exist as encrypted VM bytecode.

**Hook `Utils.rL()`**: Log all opcode calls, parameters, and return values. This is the single most effective approach -- it captures the VM's input/output for every protected method.

```javascript
Java.perform(function() {
    var Utils = Java.use("com.netease.nis.sdkwrapper.Utils");
    Utils.rL.implementation = function(args) {
        var result = this.rL(args);
        console.log("[rL] opcode=" + args[2] + " result=" + result);
        return result;
    };
});
```

**Hook `mmap`/`mprotect`**: Capture decrypted VM bytecode as it's mapped into executable memory by the native library.

**Hook `AAssetManager_read()`**: Intercept asset decryption at the native layer to capture plaintext of all encrypted assets before VM interpretation.

**frida-dexdump**: If the VM reconstructs DEX structures in memory, scanning for DEX headers may recover partially reconstructed code.

### Comparison with App Packer

| Feature | App Packer | SDK Reinforcement |
|---------|-----------|-------------------|
| Protection granularity | Entire DEX | Individual methods |
| Java-visible code | None (encrypted DEX) | Dispatch stubs visible, logic hidden |
| Native VM | No | Yes (custom bytecode interpreter) |
| APKiD detection | Yes | No |
| Unpacking approach | Dump decrypted DEX from memory | Hook VM dispatch or intercept asset decryption |
| Analysis difficulty | Hard (standard packer) | Very hard (requires VM reversing) |

## References

- [NetEase Yidun SDK Reinforcement documentation](https://support.dun.163.com/documents/2017121302?docId=101837745727655936)
- [NetEase Yidun product page](https://dun.163.com/product/sdk-reinforce)
- [APKiD Packer Signatures](https://github.com/rednaga/APKiD)
- [APKiD Chinese protectors tracking issue](https://github.com/rednaga/APKiD/issues/389)
