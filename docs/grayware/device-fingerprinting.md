# Device Fingerprinting Without Permissions

Tracking techniques that require no Android permissions, operating entirely below the permission model.

## Canvas Fingerprinting

A WebView renders a hidden image using the HTML5 Canvas API. The rendering varies subtly based on GPU, graphics driver, font rendering engine, and sub-pixel antialiasing. The pixel data is hashed to produce a device fingerprint. No permission required. Works in any WebView or browser.

## Audio Fingerprinting (AudioContext API)

The [Web Audio API generates and processes a low-frequency audio signal](https://fingerprint.com/blog/audio-fingerprinting/) entirely within the browser -- no speakers used, no microphone accessed. The resulting waveform reflects the device's audio hardware and driver stack, producing a stable identifier across sessions. Safari 17+ injects randomness in Private mode; most other browsers remain unprotected.

## Ultrasonic Cross-Device Tracking

**SilverPush** (exposed 2016): Apps embedded the SilverPush SDK, which used the device microphone to listen for ultrasonic audio beacons (inaudible to humans) embedded in TV commercials, radio broadcasts, or web content. When a beacon was detected, the SDK linked the user's mobile device to the content they were exposed to, enabling cross-device tracking without any network-level correlation. The [FTC issued warning letters to 12 app developers](https://natlawreview.com/article/ultrasonic-cross-device-tracking-consumer-management-tool-ftc-warnings) in March 2016. Security researchers demonstrated that ultrasonic tracking-enabled apps could [deanonymize Tor users](https://www.comparitech.com/blog/information-security/block-ultrasonic-tracking-apps/) by correlating beacons with browsing sessions. SilverPush shut down the Unique Audio Beacon service after FTC pressure.

## Android Advertising ID (GAID)

The Google Advertising ID (GAID) is a user-resettable identifier on every Android device with Google Play Services. It is transmitted in every RTB bid request. Resetting creates a new ID but does not stop tracking -- many SDKs collect Android ID, IMEI (pre-Android 10), and hardware identifiers alongside GAID, enabling re-linking after resets.

Google's [Privacy Sandbox for Android](https://developer.android.com/design-for-safety/privacy-sandbox) (announced 2022) introduces Topics API (replacing the abandoned FLoC), Protected Audiences (on-device retargeting), Attribution Reporting API, and SDK Runtime (isolated sandbox for ad SDKs). GAID deprecation timeline remains uncertain. Google committed to supporting it for at least two years during transition.

## ANDROID_ID and Legacy Fallback Patterns

`Settings.Secure.ANDROID_ID` returns a 64-bit value generated at first boot (per-app on Android 8.0+, per-device before). Apps routinely include it in API calls even when they also declare the user-resettable Advertising ID, providing a stable tracking identifier that survives GAID resets.

A well-known bug on Android 2.1 (Eclair) and 2.2 (Froyo) caused a subset of devices — most commonly cited are the Motorola Droid 2, Droid X, and HTC Nexus One — to [report the same ANDROID_ID value `9774d56d682e549c`](https://issuetracker.google.com/issues/36920653). Long-running Chinese and legacy apps detect this bug and fall back to a different identifier:

```java
String id = Settings.Secure.getString(cr, Settings.Secure.ANDROID_ID);
if ("9774d56d682e549c".equals(id) || id == null) {
    id = ((TelephonyManager) ctx.getSystemService(TELEPHONY_SERVICE))
        .getDeviceId();
}
```

The fallback to `TelephonyManager.getDeviceId()` (which returns the IMEI on GSM devices) is a strong indicator of legacy code originating in China or other markets where Eclair/Froyo devices persisted. On modern Android the fallback is obsolete: Android 10+ restricts `getDeviceId()` to apps holding `READ_PRIVILEGED_PHONE_STATE` (signature-level, granted only to system/carrier apps) and throws `SecurityException` for third-party callers. Per-app ANDROID_ID scoping in Android 8.0+ (values are derived from a tuple of signing key, user, and package) also eliminates the cross-app tracking value that made ANDROID_ID attractive in the first place. The pattern remains in old SDKs and provides a telltale fingerprint for dating code.

## Battery Status API (Historical)

[Research by Olejnik et al. (2015)](https://dl.acm.org/doi/10.1007/978-3-319-29883-2_18) demonstrated that the HTML5 Battery Status API, which reported battery level with double-precision floating point (e.g., `0.9301929625425652`), could fingerprint devices without any permission. Firefox on Linux was particularly vulnerable. Mozilla [removed the Battery Status API from Firefox 52](https://techcrunch.com/2015/08/04/battery-attributes-can-be-used-to-track-web-users/) (March 2017).
