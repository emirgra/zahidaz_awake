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

**CooTek / BeiTaAd** (2019): [Lookout disclosed](https://www.lookout.com/threat-intelligence/article/lookout-discovers-massive-android-ad-fraud) the `BeiTaAd` plugin shipped inside 238 Android apps from Shanghai-based, NYSE-listed CooTek (best known for the TouchPal keyboard), with a combined 440M+ downloads. The plugin sat dormant for ~24 hours after install, then triggered full-screen and audio ads while the device was asleep or locked, tied to no visible app. [BuzzFeed News documented](https://www.buzzfeednews.com/article/craigsilverman/cootek-android-app-ad-fraud-malware) that "clean" updates pushed after the disclosure still carried the code. Google removed every CooTek app from the Play Store and banned the company from its ad platforms in July 2019, the canonical case of an SDK operator getting blacklisted wholesale rather than per-app.

**LeifAccess** (2019): [McAfee documented a trojan](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-leifaccess-a-is-the-silent-fake-reviewer-trojan/) abusing accessibility services to post fake Google Play reviews and simulate legitimate ad clicks. Loaded ads via floating overlays and direct ad-network links, combining ad fraud with review manipulation.

**Tekya** (2020): Auto-clicker malware in 56 Google Play apps (24 children's apps). Used `MotionEvent` API to simulate legitimate ad clicks. Check Point documented the use of Android's `MotionEvent.obtain()` to generate touch events programmatically.

**HiddenAds** (2020-2022): [McAfee tracked multiple HiddenAds campaigns](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/new-hiddenads-malware-that-runs-automatically-and-hides-on-google-play-1m-users-affected/) affecting 1M+ users via Google Play cleaner apps. The malware ran malicious ad services automatically on installation without requiring user launch, then [changed its icon to the Google Play icon](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/hiddenads-spread-via-android-gaming-apps-on-google-play/) and renamed itself "Google Play" or "Setting" to hide from the user. A separate campaign infected 38 games reaching 35M+ users.

**Clicker** (2022): [McAfee found 16 clicker apps on Google Play with 20M+ combined downloads](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/new-malicious-clicker-found-in-apps-installed-by-20m-users/) using the `com.click.cas` and `com.liveposting` libraries. The malware delayed activation by over an hour after installation and paused when the user was actively using the device, making detection through manual testing nearly impossible.

**Invisible Adware** (2023): [McAfee uncovered 43 apps on Google Play](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/invisible-adware-unveiling-ad-fraud-targeting-android-users/) with 2.5M downloads that loaded ads only when the device screen was off. The apps waited multiple weeks after installation before activating and requested "power saving exclusion" and "draw over other apps" permissions to maintain background execution.

## C2-Tasked HTTP Click Fraud

A bot architecture where the compromised device is a dumb executor of tasks issued by a [C2 server](../attacks/c2-techniques.md). Unlike WebView-based ad fraud (which loads pages and relies on the ad SDK), the device makes direct HTTP requests with attacker-supplied URLs, methods, headers, cookies, and bodies — generating clicks, impressions, or attribution events that flow through the attacker's affiliate infrastructure. [Trend Micro](https://www.trendmicro.com/en_us/research/25/j/badbox-2.0.html) and [HUMAN Security](https://www.humansecurity.com/learn/blog/satori-threat-intelligence-alert-badbox-2-0-targets-consumer-devices-with-multiple-fraud-schemes) have documented this pattern at scale in BADBOX 2.0.

### Architecture

```
Device                                    C2 Server
  │                                          │
  ├─ Heartbeat GET /gate ─────────────────>  │
  │  <─ Magic token (activation gate) ───────┤
  │                                          │
  ├─ POST /tasks (device fingerprint JSON)─> │
  │  <─ Task list JSON ──────────────────────┤
  │     { userAgent, secChUa, acceptLanguage,│
  │       reportUrl, requestInterval,        │
  │       tasks: [{ taskId, taskVersion,     │
  │         actions: [...] }] }              │
  │                                          │
  │ For each action:                         │
  │   type 0: HTTP request with spoofed      │
  │           browser headers/cookies/body   │
  │   type 2: WebSocket multi-step chain     │
  │                                          │
  ├─ POST /report (per-step results) ─────>  │
  │     { step, url, reqHeader, reqData,     │
  │       respCode, respHeader, cost, logs } │
```

### Distinguishing Fields

Ad-fraud bot protocols share a vocabulary that distinguishes them from legitimate analytics SDKs:

| Field | Purpose |
|-------|---------|
| `affId`, `subId` | Affiliate and sub-affiliate tracking — ad network attribution |
| `userAgent`, `secChUa`, `acceptLanguage`, `accept` | Browser fingerprint spoofing for clicks — makes requests look like a real desktop/mobile browser |
| `reportUrl` | Back-channel for per-click result reporting, often separate from the task-fetch endpoint |
| `cost` | Per-step impression/click economics tracking |
| `requestInterval` | Server-tunable polling interval (typically 1-1440 minutes) |
| `auto_cookie` | Flag to automatically persist cookies across requests in a session |
| `disconnect_ws`, `async`, `skip_error` | Action-level control flags for chained execution |

`sec-ch-ua` (User-Agent Client Hints) is standardized as the modern successor to `User-Agent`. Ad fraud bots spoof both to match Chrome/Safari/Firefox on desktop or mobile, turning a mobile device into what looks like a browser-based click generator.

### Activation Gate

Some variants check a heartbeat endpoint for a magic response token before entering the tasking loop. If the server does not return the expected token, the bot stays dormant. This gates whether the campaign is active and complicates sandbox analysis — the bot appears benign unless the analyst's traffic reaches the live C2 and receives activation.

### Host App Profile

C2-tasked click fraud frequently ships inside trojanized forks of legitimate open-source apps. The legitimate app code lives in `classes.dex` and provides the cover functionality (keyboard, photo editor, file manager, etc.); the C2 tasking framework resides entirely in `classes2.dex`, wired in through the Application class's `onCreate()`. Multi-DEX is normal for any non-trivial Android app, so the secondary DEX does not trigger heuristic scanners on its own. For example, trojanized keyboard apps have been observed built on top of [FlorisBoard](https://github.com/florisboard/florisboard), an open-source privacy-respecting keyboard available on F-Droid.

Indicators to separate this pattern from legitimate multi-DEX:

- `classes.dex` contains the app's documented functionality and common SDKs (Firebase, AdMob, etc.)
- `classes2.dex` contains a single, self-contained C2 framework (fingerprinting + networking + task executor) with no UI, no integration with the app's own features, and obfuscated class/method names
- The Application class calls into `classes2.dex` from `onCreate()` before any legitimate functionality runs
- No declared purpose for arbitrary HTTP execution in the app's stated use case

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

## WebView Package Name Spoofing

Ad fraud technique where the malware spoofs its identity to the WebView/Chromium engine so that all ad requests appear to come from a different, presumably legitimate app. The attacker controls the ad account for the spoofed package name and collects the revenue.

The spoofing chain:

1. Create a `Proxy` for `android.content.pm.IPackageManager`
2. The proxy intercepts `getInstallerPackageName()` (returns null for the spoofed package) and `getPackageInfo()` (swaps the query package name to make validation succeed)
3. Inject the proxy into `ActivityThread.sPackageManager` (static field) and `PackageManager.mPM` (instance field)
4. Replace the Application's base `Context` with a `ContextWrapper` that overrides `getPackageName()`: when called from `org.chromium.base` frames (detected via stack trace inspection), it returns the fake package name; otherwise returns the real one
5. Create and immediately destroy a WebView to force Chromium to initialize with the spoofed identity
6. Restore the original `IPackageManager` (spoofing only needs to last through WebView init)

After initialization, all ad requests from the WebView claim to come from the spoofed app. Google partially addressed this by [deprecating the X-Requested-With header](https://developer.chrome.com/blog/ppc-deprecating-xrw-header/) in WebView, which previously exposed the host app's package name to ad networks.

Requires [Hidden API Bypass](../attacks/anti-analysis-techniques.md#hidden-api-bypass) to access `ActivityThread.sPackageManager` and other private framework fields.

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

## Lockscreen Ad Bypass

Adware that wakes the screen and dismisses the lock screen to show fullscreen ads, even when the device is idle. The activity calls three APIs in sequence:

```java
setShowWhenLocked(true);
setTurnScreenOn(true);
keyguardManager.requestDismissKeyguard(this, null);
```

`setShowWhenLocked(true)` (API 27+) renders the activity on top of the lock screen. `setTurnScreenOn(true)` powers on the display. `requestDismissKeyguard()` dismisses the keyguard entirely, so the user wakes up to a fullscreen ad with no indication of what triggered it. Combined with `SCREEN_ON`/`SCREEN_OFF` broadcast receivers and exact alarm persistence (e.g., `setExactAndAllowWhileIdle` every 15 minutes), the adware can pop ads at arbitrary intervals around the clock.

The older approach used `WindowManager.LayoutParams` flags (`FLAG_SHOW_WHEN_LOCKED`, `FLAG_DISMISS_KEYGUARD`, `FLAG_TURN_SCREEN_ON`), deprecated in API 27 but still functional on older devices. Modern adware uses both code paths, selecting based on `Build.VERSION.SDK_INT`.

## Fake Notification Impersonation

Adware that creates notification channels mimicking popular apps to lure users into tapping ad-laden overlays. The notification channel uses the impersonated app's branding: channel name, description, and accent color matching the target app's identity.

For example, a channel named `"whatsapp_channel"` with color `#2cb742` (WhatsApp's signature green) and description `"WhatsApp notifications"` makes the notification appear to come from WhatsApp. Tapping the notification opens an ad overlay activity instead. The user sees what looks like a WhatsApp message, taps it, and lands on a fullscreen ad.

This works because Android's notification shade shows the channel name and color set by the posting app, not the actual source app name in a prominent position. Combined with [launcher hiding](../attacks/persistence-techniques.md) (using `category.INFO` instead of `category.LAUNCHER`) and system name impersonation (labeling activities as "Google Play Protect"), the adware becomes difficult for users to identify and uninstall.

## Programmatic Click Simulation

Ad fraud SDKs that programmatically simulate clicks on ads displayed within the app, generating fraudulent click revenue. Unlike [click injection](#fraud-types) (which targets attribution for other apps), this technique clicks on the SDK's own ads.

The fraud logic is controlled by configuration fields:

| Field | Purpose |
|-------|---------|
| `isSimulateClick` | Master toggle for click simulation |
| `secondsOfShowToClick` | Delay between ad display and simulated click (avoids instant-click detection) |
| `clickPositionSelector` | Selects which ad position to click |
| `retryClickWhenProgress100` | Retry click when page finishes loading |

A mask overlay view (`FrameLayout` subclass) covers the ad during the simulated click, hiding any visual feedback (ripple effects, page transitions) from the user. Touch events on the mask are intercepted in native code (JNI), keeping the click simulation logic out of the DEX where it would be visible to static analysis.

Position tracking (`positionShowedList`, `positionClickedList`) ensures the SDK doesn't click the same ad twice and can report clicked/unclicked ratios back to the server, mimicking natural click-through rates.

## Installer-Source Spoofing for CPM Uplift

Ad networks pay materially higher CPM for inventory served inside Play-Store-installed apps than for sideloaded installs. Adware and ad-fraud SDKs forge the install source to capture the uplift.

Two implementations show up in the wild:

```java
PackageInstaller.SessionParams params = new PackageInstaller.SessionParams(
    PackageInstaller.SessionParams.MODE_FULL_INSTALL);
params.getClass()
    .getMethod("setPackageSource", int.class)
    .invoke(params, 1);
params.getClass()
    .getMethod("setInstallReason", int.class)
    .invoke(params, 4);
```

Reflectively setting `PACKAGE_SOURCE_STORE` (1) on the install session and `INSTALL_REASON_POLICY` (4) makes the installed APK report itself as Play-Store-sourced via `PackageManager.getInstallSourceInfo()`. The reflection avoids public API surface that lints would flag.

The runtime variant hooks `PackageManager.getInstallerPackageName(pkg)` (typically through a `Faker.facebook.audience_network`-style namespace, sometimes using the [IPackageManager Binder proxy](../attacks/dynamic-code-loading.md#binder-proxy-system-service-hijack)) to return `"com.android.vending"` for any package the ad SDK queries. Every ad request now claims to come from a Play-Store-installed app regardless of the actual install source.

Hunting tip: any code path that queries `getInstallerPackageName` and unconditionally returns `"com.android.vending"`, `"com.google.android.feedback"`, or `"com.android.packageinstaller"` is forging the install source.

## Probabilistic Close-Button Hijack

A click-fraud variant tuned to evade ad-network click-quality detection. Instead of always converting a close-tap into a click, the SDK rolls a random number against a server-controlled threshold and converts only a fraction of dismissals.

```java
int p = ThreadLocalRandom.current().nextInt(100);
if (p < closeBtnJumpProbability) {
    nativeView.performClick();
} else {
    super.dismiss();
}
```

Aggregate click-quality metrics at the ad network look noisy but not obviously fraudulent — the operator tunes `closeBtnJumpProbability` (and a separate `nativeFullScreenClickProbability` for any-touch-as-click on full-screen ads) to stay under detection thresholds. Both knobs come from the same Remote Config / experiment endpoint that gates the SDK's other behaviors. A constant-100% close-to-click ratio would be flagged immediately; a server-tuned 12-25% blends with real misclick noise.

## TYPE_APPLICATION_PANEL Click-Block Overlays

A no-permission overlay variant: `WindowManager.LayoutParams` with `type = TYPE_APPLICATION_PANEL` (1003) does **not** require `SYSTEM_ALERT_WINDOW`, unlike `TYPE_APPLICATION_OVERLAY` (2038) and the older `TYPE_PHONE` (2002). The adware adds zero-opacity (`alpha = 0`) panel views over specific screen regions inside its own task; touches on those regions are intercepted by the panel's `onTouchEvent` and redirected to `showAdvWithPointName(...)`.

Game touches at the bottom 450×42 dp band (where a virtual control sits) get rerouted to fire ad clicks instead of game input. The panel-type window is invisible, requires no special grant, and is not listed in `Settings > Apps > Display over other apps`. Detection: `WindowManager.addView` with `LayoutParams.type = 1003` (`TYPE_APPLICATION_PANEL`) on transparent / `Color.TRANSPARENT` views with non-zero touch handling.

## Multi-App Background Ad Fleet

A distribution model where the same operator publishes many apps (10+) built from the same codebase with different skins (cleaner, WiFi analyzer, PDF reader, file manager). Each app independently runs an [invisible foreground service](../attacks/persistence-techniques.md#invisible-via-post_notifications-denial-android-13) that periodically attempts to launch fullscreen ad activities from the background.

The apps are not explicitly coordinating with each other. Each independently runs a timer loop that periodically calls `startActivity()` targeting a trampoline activity. The trampoline launches an ad SDK activity (reward video, fullscreen interstitial, companion ad). When many apps from the same operator are installed on one device, their independent timers produce overlapping ad bursts -- multiple fullscreen ads within seconds of each other.

Apps that lack a [BAL bypass](../attacks/anti-analysis-techniques.md#background-activity-launch-bypass-companiondevicemanager) get blocked on Android 10+ but retry on the next interval. The operator relies on volume: if some apps are blocked, others succeed. Each app is a disposable ad launcher in a fleet.

## Notification-Based Ad Triggers

Adware that uses fake system notifications as pretexts to launch fullscreen ad activities. The foreground service creates notifications mimicking system alerts (low battery, WiFi connected, storage full, app update available), and tapping the notification opens a fullscreen ad activity instead of any real settings or system screen.

The notifications use legitimate-sounding channel names (`BatteryStatus`, `WiFiAssistant`, `AppManager`) and system-style icons. Combined with [fake notification impersonation](#fake-notification-impersonation), the user cannot distinguish them from real system notifications.

The ad vector is selected randomly at each timer interval to avoid pattern detection:

| Vector | Notification Pretext | Actual Behavior |
|--------|---------------------|-----------------|
| Battery alert | "Battery optimization available" | Opens fullscreen ad |
| WiFi alert | "WiFi connection secured" | Opens fullscreen ad |
| App status | "Apps need updating" | Opens fullscreen ad |

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

## Out-of-App Push Advertising (OPA)

Server-driven push notification ads delivered via proprietary protocols (often protobuf-based). The server sends structured messages containing notification content and typed action payloads that control what happens when the user taps the notification.

| Action Type | Behavior |
|-------------|----------|
| CUSTOM_TAB | Opens URL in Chrome Custom Tab |
| WEBVIEW | Opens URL in embedded WebView |
| BROWSER | Opens URL in default browser |
| DEEPLINK | Handles deep link URI |
| STORE_LINK | Opens Play Store listing |
| PKG_NAME | Launches any installed app by package name |

The `PKG_NAME` action is particularly notable: the server can silently trigger the launch of any app on the device. Combined with [`REQUEST_INSTALL_PACKAGES`](../permissions/special/request-install-packages.md), this creates a full sideloading pipeline: server pushes a notification with an APK download link, user clicks, APK downloads, install prompt appears. [`SYSTEM_ALERT_WINDOW`](../permissions/special/system-alert-window.md) can overlay UI on top of the install prompt to social-engineer the user into tapping "Install."

OPA systems are typically locale-aware, selecting notification text matching the device's language and country. A `notShowAlive` flag controls whether to display push ads when the app is in the foreground (avoiding annoying active users, saving ads for when they leave the app).

## Exit Interstitials

A fullscreen ad displayed when the user tries to leave the app. The activity overrides `onBackPressed()` to block the back button while the ad is showing, trapping the user until the ad finishes or a countdown timer expires.

The "backable" state is controlled by a server-configurable flag, allowing the ad network to decide per-impression whether the user can skip. Some implementations inject ads at multiple lifecycle points via a configurable "material" system:

| Injection Point | Trigger |
|-----------------|---------|
| Enter | App launch (splash interstitial) |
| EnterSkip | Splash with skip counter |
| Resume | Returning to app from background |
| Exit | Leaving the app (back button trapped) |

Each injection point has server-configurable payloads with local JSON fallback defaults in assets, allowing the server to update ad behavior remotely without app updates.

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
