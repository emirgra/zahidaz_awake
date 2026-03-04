# INTERACT_ACROSS_USERS_FULL

Signature-level permission that grants full interaction capabilities across all user profiles on a multi-user Android device. This includes managed work profiles, secondary users, and guest accounts. Only system apps signed with the platform key can hold this permission. When a system app or pre-installed component has this permission, it can read data, send broadcasts, start activities, and bind to services in any user profile, bypassing the user isolation boundary that Android enforces by default.

## Technical Details

| Attribute | Value |
|-----------|-------|
| Permission | `android.permission.INTERACT_ACROSS_USERS_FULL` |
| Protection Level | `signature\|installer` |
| Grant Method | Platform signature only (cannot be granted to third-party apps) |
| Introduced | API 17 (Android 4.2, when multi-user was added) |
| User Visibility | None (system-level, not shown in app settings) |

Android 4.2 introduced multi-user support, creating isolated user spaces with separate app data, accounts, and settings. `INTERACT_ACROSS_USERS_FULL` was introduced alongside this feature to allow system components (Settings, SystemUI, device policy controllers) to operate across user boundaries. A weaker variant, `INTERACT_ACROSS_USERS` (protection level `signature|privileged|appop`), provides limited cross-user interaction and is occasionally granted to privileged apps.

## What It Enables

A system app holding this permission can perform any operation in the context of another user profile:

| Capability | API |
|------------|-----|
| Start activities in other profiles | `Context.startActivityAsUser(Intent, UserHandle)` |
| Send broadcasts to other profiles | `Context.sendBroadcastAsUser(Intent, UserHandle)` |
| Bind to services in other profiles | `Context.bindServiceAsUser(Intent, ServiceConnection, int, UserHandle)` |
| Access content providers across profiles | `ContentResolver` queries with cross-profile URI grants |
| Query packages in other profiles | `PackageManager.getInstalledPackagesAsUser()` |

```java
UserManager um = (UserManager) getSystemService(Context.USER_SERVICE);
List<UserHandle> profiles = um.getUserProfiles();
for (UserHandle profile : profiles) {
    context.startActivityAsUser(intent, profile);
}
```

### Relationship to Work Profiles

Android Enterprise work profiles (managed by a Device Policy Controller) create a separate user space on the device. The work profile has its own app data, accounts, and encryption keys. `INTERACT_ACROSS_USERS_FULL` bypasses this separation entirely, allowing a system component to reach into the work profile and access corporate email, managed apps, and enterprise data.

## Abuse Scenarios

### Lateral Movement Across Work Profiles

On a device with an Android Enterprise work profile, a compromised system app with this permission can:

1. Enumerate all user profiles via `UserManager.getUserProfiles()`
2. Query installed packages in the work profile to identify enterprise apps (email, VPN, MDM agent)
3. Read content provider data from work profile apps (contacts, calendar, documents)
4. Send intents to work profile apps to trigger data export or credential capture
5. Bind to services in the work profile to interact with enterprise backends

This effectively defeats the work profile isolation that enterprises rely on to protect corporate data on BYOD devices.

### Pre-installed Malware

On devices with [firmware grayware](../../grayware/firmware-grayware.md) or pre-installed malicious system apps (common on budget devices from certain OEMs), `INTERACT_ACROSS_USERS_FULL` enables surveillance across all user profiles. A pre-installed data harvester with this permission can collect data from the primary user, work profile, and any secondary users simultaneously.

### Device Policy Controller Abuse

A malicious DPC (Device Policy Controller) that also holds `INTERACT_ACROSS_USERS_FULL` can reach beyond its managed profile into the personal profile, inverting the intended security model where the DPC controls only the work profile.

## Android Version Changes

| Version | API | Change |
|---------|-----|--------|
| 4.2 | 17 | Multi-user introduced; `INTERACT_ACROSS_USERS_FULL` added |
| 5.0 | 21 | Work profiles (managed profiles) introduced; cross-user isolation becomes relevant for enterprise |
| 7.0 | 24 | `UserManager.getUserProfiles()` refined; cross-profile intent filters added |
| 11 | 30 | Cross-profile data sharing APIs added (`CrossProfileApps`); provides a controlled alternative to raw cross-user access |
| 14 | 34 | Private Space introduced; adds another user profile type subject to cross-user permissions |

## Detection Indicators

**Manifest signals:**

```xml
<uses-permission android:name="android.permission.INTERACT_ACROSS_USERS_FULL" />
```

This permission in a non-system app's manifest is an immediate red flag. The system will not grant it to apps not signed with the platform key, but its presence indicates the developer intended the app to run as a system component.

**Runtime indicators:**

- Calls to `*AsUser()` API variants (`startActivityAsUser`, `sendBroadcastAsUser`, `bindServiceAsUser`)
- `UserManager.getUserProfiles()` enumeration
- Content provider queries targeting URIs with `userId` parameters

## See Also

- [Work Profile Abuse](../../attacks/work-profile-abuse.md)
- [Firmware Grayware](../../grayware/firmware-grayware.md)
- [Device Admin Abuse](../../attacks/device-admin-abuse.md)
