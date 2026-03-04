# Advertising Fraud

Apps that generate fake ad impressions, clicks, or installs in the background to steal advertising revenue. Not data theft but device abuse at the expense of battery, bandwidth, and advertiser budgets.

## Fraud Types

| Type | Mechanism | Detection Signal |
|------|-----------|-----------------|
| Click injection | Listens for `PACKAGE_ADDED` broadcast, injects attribution click before new app finishes installing | `PACKAGE_ADDED` receiver + immediate HTTP request to attribution URL |
| Ad stacking | Multiple invisible ads loaded behind a single visible ad | Multiple ad SDK network calls per visible impression |
| Pixel stuffing | Ads loaded in 1x1 pixel containers, invisible to user | Tiny WebView or ImageView with ad network traffic |
| VirtualDisplay rendering | `DisplayManager.createVirtualDisplay()` creates a 1x1 pixel virtual display; ads render on a `Presentation` targeting that display, invisible to user | `createVirtualDisplay` calls, `Presentation` subclass without corresponding user-visible secondary display |
| Background ad rendering | Hidden [WebView](../attacks/webview-exploitation.md) loads and "views" ads with screen off | WebView activity without corresponding UI, battery drain |
| Fake incoming call interstitial | `TelecomManager.addNewIncomingCall()` with a self-managed `PhoneAccount` (API 26+) triggers incoming call UI; the `Connection.onShowIncomingCallUi()` callback launches an ad activity instead | `MANAGE_OWN_CALLS` permission, `ConnectionService` subclass, immediate `DisconnectCause(LOCAL)` after ad launch |
| Click flooding | Mass generation of fake ad clicks to poison attribution data | High-volume HTTP requests to ad tracking endpoints |
| SDK spoofing | Forge ad impressions by replaying legitimate SDK traffic patterns | Network traffic mimicking ad SDK protocols without actual ad display |

## Notable Cases

**Grabos** (2017): [McAfee discovered 144 trojanized apps on Google Play](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-grabos-exposed-millions-to-pay-per-install-scam-on-google-play/) running a pay-per-install scam. First found in "Aristotle Music audio player 2017," 34 analyzed apps had an average 4.4 rating with 4.2-17.5M downloads. A commercial obfuscator protected the malicious code, making it difficult to detect without runtime analysis.

**Chamois** (2017-2019): Google-discovered ad fraud botnet pre-installed in firmware on 21M+ devices. Operated through the supply chain, with malicious code embedded during manufacturing. Generated fraudulent ad revenue through background ad clicks and premium SMS.

**Judy** (2017): Ad click malware in 41 apps from a Korean developer on Google Play. Used a C2 server to deliver JavaScript payloads that clicked ads via WebView. Estimated 8.5M-36.5M infected devices.

**DrainerBot** (2019): SDK embedded in 10M+ downloads that downloaded video ads in the background, consuming 10GB+ of mobile data per month per device. Users experienced massive data charges and battery drain with no visible cause.

**LeifAccess** (2019): [McAfee documented a trojan](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-leifaccess-a-is-the-silent-fake-reviewer-trojan/) abusing accessibility services to post fake Google Play reviews and simulate legitimate ad clicks. Loaded ads via floating overlays and direct ad-network links, combining ad fraud with review manipulation.

**Tekya** (2020): Auto-clicker malware in 56 Google Play apps (24 children's apps). Used `MotionEvent` API to simulate legitimate ad clicks. Check Point documented the use of Android's `MotionEvent.obtain()` to generate touch events programmatically.

**HiddenAds** (2020-2022): [McAfee tracked multiple HiddenAds campaigns](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/new-hiddenads-malware-that-runs-automatically-and-hides-on-google-play-1m-users-affected/) affecting 1M+ users via Google Play cleaner apps. The malware ran malicious ad services automatically on installation without requiring user launch, then [changed its icon to the Google Play icon](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/hiddenads-spread-via-android-gaming-apps-on-google-play/) and renamed itself "Google Play" or "Setting" to hide from the user. A separate campaign infected 38 games reaching 35M+ users.

**Clicker** (2022): [McAfee found 16 clicker apps on Google Play with 20M+ combined downloads](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/new-malicious-clicker-found-in-apps-installed-by-20m-users/) using the `com.click.cas` and `com.liveposting` libraries. The malware delayed activation by over an hour after installation and paused when the user was actively using the device, making detection through manual testing nearly impossible.

**Invisible Adware** (2023): [McAfee uncovered 43 apps on Google Play](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/invisible-adware-unveiling-ad-fraud-targeting-android-users/) with 2.5M downloads that loaded ads only when the device screen was off. The apps waited multiple weeks after installation before activating and requested "power saving exclusion" and "draw over other apps" permissions to maintain background execution.

## VirtualDisplay Invisible Rendering

A technique where ads render on a virtual display that the user never sees. The app creates a `VirtualDisplay` with 1x1 pixel dimensions via `DisplayManager.createVirtualDisplay()`, then renders a `Presentation` (designed for secondary displays like Chromecast) on that surface. The ad loads, renders, and registers impressions and clicks, but is completely invisible because the display surface is a single pixel.

```java
DisplayManager dm = (DisplayManager) getSystemService(DISPLAY_SERVICE);
VirtualDisplay vd = dm.createVirtualDisplay("ad_surface", 1, 1, 1,
    surface, DisplayManager.VIRTUAL_DISPLAY_FLAG_PRESENTATION);
AdPresentation presentation = new AdPresentation(context, vd.getDisplay());
presentation.show();
```

This is more sophisticated than pixel stuffing because the ad SDK believes it is rendering on a legitimate secondary display at full resolution, generating valid impression metrics. Combined with [HiddenApiBypass](../attacks/anti-analysis-techniques.md#hidden-api-bypass) to instantiate `DisplayManager` directly (avoiding `Context.getSystemService()` which would expose the real package name), it becomes difficult for ad networks to detect programmatically.

## Fake Incoming Calls as Ad Triggers

Adware abusing Android's `TelecomManager` to simulate incoming phone calls, using the call UI as a trigger to display full-screen ad interstitials. The app registers a self-managed `PhoneAccount` (capability `CAPABILITY_SELF_MANAGED` = 2048) and its own `ConnectionService`, then calls `TelecomManager.addNewIncomingCall()` to inject fake calls.

When the system shows the incoming call UI, the malware's `Connection.onShowIncomingCallUi()` callback fires and launches an ad activity. The call is immediately disconnected with `DisconnectCause(LOCAL)` so it never appears in call logs.

Requires only `MANAGE_OWN_CALLS` (a normal permission, no user prompt). Works on Android 8.0+ (API 26, when `CAPABILITY_SELF_MANAGED` was introduced). The user sees a brief incoming call animation, then a full-screen ad appears, designed to confuse the user into thinking the ad is related to the "call."

## Attribution Theft

A distinct fraud category where a malicious SDK embedded in a legitimate-looking app steals attribution data from co-installed analytics SDKs (AppsFlyer, Adjust, Branch, Kochava) to fraudulently claim credit for app installs and user actions.

### How It Works

1. The malicious SDK initializes early (often via a `ContentProvider` with high `initOrder` to run before the app's `Application.onCreate()`)
2. It detects which attribution SDKs are present via reflection or SharedPreferences inspection
3. It reads attribution data: install source, campaign ID, ad group, creative, tracker tokens
4. It exfiltrates this data to its own servers, claiming the install attribution

```java
Object attribution = Adjust.getAttribution();
JSONObject stolen = new JSONObject();
stolen.put("campaign", getField(attribution, "campaign"));
stolen.put("adgroup", getField(attribution, "adgroup"));
stolen.put("network", getField(attribution, "network"));
stolen.put("tracker_token", getField(attribution, "trackerToken"));
exfiltrate(stolen);
```

For AppsFlyer, the SDK reads from SharedPreferences (`appsflyer-data` key) to extract the `attributionId` without calling any AppsFlyer API.

### Grey-Market Ad SDKs

Undocumented ad monetization SDKs with no public website, documentation, or SDK marketplace listing operate as grey-market attribution thieves. They embed in apps distributed through Play Store and third-party markets, providing minimal ad revenue to the host developer while stealing attribution data and injecting their own ads.

Common characteristics:

| Feature | Implementation |
|---------|---------------|
| Early initialization | `ContentProvider` with `initOrder` set high to load before the app |
| Anti-analysis | HTTP proxy detection (`System.getProperty("http.proxyHost")`) -- refuses to initialize if analyst proxy detected |
| Inter-app coordination | Exported `ContentProvider` allows other apps running the same SDK to discover each other on the device |
| Regional endpoints | Separate C2/ad server URLs for China vs. international traffic |
| Remote configuration | Encrypted JSON config fetched periodically, controls ad slots, delay ranges, feature switches |
| Ad format injection | Multiple ad formats (native, HTML interstitial, video, CSS-styled) injected into the host app via reflection-based object graph crawling |
| Coordination broadcast | `BroadcastReceiver` registered with action derived from package name hash, enabling cross-app signaling between SDK instances |

Detection: look for undocumented ContentProviders at high `initOrder`, reflection calls targeting AppsFlyer or Adjust classes, and SharedPreferences files belonging to unknown SDK namespaces.

## Technical Indicators

- `PACKAGE_ADDED` broadcast receiver (click injection vector)
- `MotionEvent.obtain()` or `dispatchTouchEvent()` calls without user interaction
- Hidden or zero-dimension `WebView` instances
- Abnormal battery drain and background data consumption
- Ad SDK network traffic volume disproportionate to app usage
- Wake locks held during screen-off periods for background rendering
- Reflection calls targeting `AppsFlyerLib`, `Adjust`, or other attribution SDK classes
- Unknown ContentProviders with `exported="true"` and `syncable="true"`
- HTTP proxy detection via `System.getProperty("http.proxyHost")`

## Notification & Ad Injection

Apps that monetize by injecting ads outside their own UI context -- into the notification shade, lock screen, or as system-level overlays.

| Technique | Implementation | Android Restrictions |
|-----------|---------------|---------------------|
| Notification ads | High-priority notifications with ad content, mimicking system alerts | Android 8.0+ notification channels; Android 13+ `POST_NOTIFICATIONS` permission |
| Lock screen ads | Custom lock screen replacement or overlay drawn via `SYSTEM_ALERT_WINDOW` | Android 6.0+ requires explicit grant; Android 10+ overlay touch restrictions |
| Full-screen interstitials | `SYSTEM_ALERT_WINDOW` overlays triggered on screen unlock or app switch | Android 12+ overlay deprioritization |
| Foreground service notifications | Persistent notification used as ad surface under the guise of "running service" | Android 14+ foreground service type declarations |

[HiddenAds](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/new-hiddenads-malware-that-runs-automatically-and-hides-on-google-play-1m-users-affected/) campaigns changed their app icon to the Google Play icon and renamed themselves "Google Play" or "Setting" to hide from users while delivering persistent ads. [Invisible Adware](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/invisible-adware-unveiling-ad-fraud-targeting-android-users/) (2023, 43 apps, 2.5M downloads) loaded ads only when the device screen was off, waiting multiple weeks after installation before activating.

## Fleeceware

Apps that exploit free trial mechanics and subscription billing to charge excessive fees for minimal functionality.

### Pattern

1. Offer a "free trial" (typically 3 days) requiring payment method entry
2. Auto-renew at $30-$200/week for commodity functionality (flashlight, QR scanner, wallpaper, horoscope)
3. Make cancellation deliberately confusing: uninstalling the app does not cancel the subscription
4. Target users unfamiliar with app store subscription management
5. Use misleading UI that obscures the subscription cost or implies the trial is truly free

### Scale

Avast identified 200+ fleeceware apps with 1B+ combined downloads in 2020. Sophos coined the term "fleeceware" in 2019 after finding apps charging $100+/month for basic calculator and QR scanner functionality. Apple and Google have both tightened trial disclosure requirements in response, but enforcement remains inconsistent.

### Technical Indicators

- Short trial period (1-3 days) followed by high weekly/monthly charge
- Minimal app functionality relative to subscription cost
- Subscription initiation flow that obscures pricing
- In-app purchase / subscription APIs invoked immediately during onboarding
- No meaningful feature gating between free and paid tiers
