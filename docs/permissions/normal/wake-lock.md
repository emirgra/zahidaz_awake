# WAKE_LOCK

Allows preventing the CPU from sleeping. Used by malware to ensure background operations complete without the device entering deep sleep, particularly during [data exfiltration](../../attacks/data-exfiltration.md), [C2](../../attacks/c2-techniques.md) polling, or on-device fraud operations.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.WAKE_LOCK` |
| Protection Level | `normal` |
| Grant Method | Automatically at install time |
| Introduced | API 1 |

## What It Enables

```java
PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
PowerManager.WakeLock wl = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "malware:wakelock");
wl.acquire();
```

Wake lock types:

| Type | Keeps On |
|------|----------|
| `PARTIAL_WAKE_LOCK` | CPU only (screen off, keyboard off) |
| `SCREEN_DIM_WAKE_LOCK` | CPU + screen dim (deprecated API 17) |
| `SCREEN_BRIGHT_WAKE_LOCK` | CPU + screen bright (deprecated API 17) |
| `FULL_WAKE_LOCK` | CPU + screen + keyboard (deprecated API 17) |

`PARTIAL_WAKE_LOCK` is the only non-deprecated type and the one malware uses: it keeps the CPU running while the screen stays off, so the user doesn't notice.

## Abuse in Malware

### Background Operation Completion

Ensure long-running tasks complete:

- Large data uploads (contact database, SMS history, file exfiltration)
- Screen recording and streaming
- Cryptocurrency mining (rare on mobile)
- [ATS](../../attacks/automated-transfer-systems.md) fraud sequences that take multiple steps

### Supporting Role

`WAKE_LOCK` is a supporting permission. It rarely appears alone. Combined with [`FOREGROUND_SERVICE`](foreground-service.md), [`RECEIVE_BOOT_COMPLETED`](receive-boot-completed.md), and [`REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`](request-ignore-battery-optimizations.md), it forms the complete [persistence](../../attacks/persistence-techniques.md) and background execution stack.

## Detection

In the manifest:

```xml
<uses-permission android:name="android.permission.WAKE_LOCK" />
```

Extremely common in legitimate apps (messaging, media, alarm). Not a useful indicator alone. Value is in combination with other persistence and exfiltration permissions.
