# Attack Techniques

Documented exploitation techniques targeting Android applications and the OS. Each technique covers what it is, the preconditions required, how it works in practice, real-world malware that uses it, and how it has evolved across Android versions.

Organized by attack surface and offensive objective.

## Techniques

### UI Deception

| Technique | Target Surface | Key Permissions |
|-----------|---------------|-----------------|
| [Overlay Attacks](overlay-attacks.md) | Window Manager | `SYSTEM_ALERT_WINDOW` |
| [Tapjacking](tapjacking.md) | Touch Events | `SYSTEM_ALERT_WINDOW` |
| [Phishing Techniques](phishing-techniques.md) | UI / Social Engineering | `SYSTEM_ALERT_WINDOW` (optional) |
| [Fake Biometric Prompts](fake-biometric-prompts.md) | KeyguardManager / BiometricPrompt | `BIND_ACCESSIBILITY_SERVICE` or `SYSTEM_ALERT_WINDOW` |
| [Launcher Hijacking](launcher-hijacking.md) | HOME Intent / Launcher | None (intent filter) |
| [Task Affinity Attacks](task-affinity-attacks.md) | Activity Stack | None (manifest config) |

### Input, Screen & Sensor Capture

| Technique | Target Surface | Key Permissions |
|-----------|---------------|-----------------|
| [Keylogging](keylogging.md) | InputMethodService / Accessibility | `BIND_ACCESSIBILITY_SERVICE` |
| [Screen Capture](screen-capture.md) | MediaProjection / Accessibility | `FOREGROUND_SERVICE`, `BIND_ACCESSIBILITY_SERVICE` |
| [Clipboard Hijacking](clipboard-hijacking.md) | ClipboardManager | None (foreground) or `BIND_ACCESSIBILITY_SERVICE` |
| [Camera & Mic Surveillance](camera-mic-surveillance.md) | Camera / MediaRecorder / MediaProjection | `CAMERA`, `RECORD_AUDIO` |
| [Location Tracking](location-tracking.md) | LocationManager / FusedLocation | `ACCESS_FINE_LOCATION`, `ACCESS_COARSE_LOCATION` |

### Privilege & Accessibility Abuse

| Technique | Target Surface | Key Permissions |
|-----------|---------------|-----------------|
| [Accessibility Abuse](accessibility-abuse.md) | Accessibility Service | `BIND_ACCESSIBILITY_SERVICE` |
| [Runtime Permission Manipulation](runtime-permission-manipulation.md) | Settings / Accessibility | `BIND_ACCESSIBILITY_SERVICE` |
| [Automated Transfer Systems](automated-transfer-systems.md) | Accessibility + Banking Apps | `BIND_ACCESSIBILITY_SERVICE` |
| [Device Admin Abuse](device-admin-abuse.md) | DevicePolicyManager | `BIND_DEVICE_ADMIN` |
| [Privilege Escalation](privilege-escalation.md) | Kernel / SELinux / Platform | None (exploit) |
| [Work Profile Abuse](work-profile-abuse.md) | Android Enterprise / DPC | Device or Profile Owner |

### Component & IPC Abuse

| Technique | Target Surface | Key Permissions |
|-----------|---------------|-----------------|
| [Intent Hijacking](intent-hijacking.md) | Activities, Services | None (component export) |
| [Broadcast Theft](broadcast-theft.md) | Broadcast Receivers | Varies |
| [Content Provider Attacks](content-provider-attacks.md) | Content Providers | None (provider export) |
| [Deep Link Exploitation](deep-link-exploitation.md) | Activities | None (URI scheme) |
| [WebView Exploitation](webview-exploitation.md) | WebView | Varies |

### Communications Interception

| Technique | Target Surface | Key Permissions |
|-----------|---------------|-----------------|
| [SMS Interception](sms-interception.md) | SMS / BroadcastReceiver | `RECEIVE_SMS`, `READ_SMS` |
| [Notification Listener Abuse](notification-listener-abuse.md) | NotificationListenerService | `BIND_NOTIFICATION_LISTENER_SERVICE` |
| [Notification Suppression](notification-suppression.md) | NotificationListenerService / AudioManager | `BIND_NOTIFICATION_LISTENER_SERVICE` |
| [Call Interception](call-interception.md) | TelecomManager / CallRedirectionService | `CALL_PHONE`, `READ_PHONE_STATE` |
| [SIM & Carrier Attacks](sim-carrier-attacks.md) | SIM Toolkit / SS7 / USSD | Cellular-infrastructure level |
| [Carrier Billing Fraud](carrier-billing-fraud.md) | Direct Carrier Billing portals / OTP / WebView | `RECEIVE_SMS`, `INTERNET` |

### Networking, C2 & Exfiltration

| Technique | Target Surface | Key Permissions |
|-----------|---------------|-----------------|
| [C2 Communication](c2-techniques.md) | Network / IPC | `INTERNET` |
| [Network Traffic Interception](network-traffic-interception.md) | VpnService / DNS / Certificate Store | [`BIND_VPN_SERVICE`](../permissions/special/bind-vpn-service.md) |
| [Data Exfiltration](data-exfiltration.md) | Outbound channels (HTTP, cloud APIs, SMS) | `INTERNET` plus collection permissions |
| [NFC Relay](nfc-relay.md) | NFC / Host Card Emulation | NFC (normal) |

### Persistence & Stealth

| Technique | Target Surface | Key Permissions |
|-----------|---------------|-----------------|
| [Persistence Techniques](persistence-techniques.md) | Services / Receivers / WorkManager | `RECEIVE_BOOT_COMPLETED`, `FOREGROUND_SERVICE` |
| [Anti-Analysis Techniques](anti-analysis-techniques.md) | Emulator / Root / Frida / Debugger | `QUERY_ALL_PACKAGES` |
| [Device Wipe & Ransomware](device-wipe-ransomware.md) | DevicePolicyManager / File System | `BIND_DEVICE_ADMIN`, `MANAGE_EXTERNAL_STORAGE` |

### Distribution & Code Delivery

| Technique | Target Surface | Key Permissions |
|-----------|---------------|-----------------|
| [Play Store Evasion](play-store-evasion.md) | Play Protect / Store Review | None (build and distribution) |
| [Dynamic Code Loading](dynamic-code-loading.md) | ClassLoader / Runtime | None (app-private storage) |
| [Supply Chain Attacks](supply-chain-attacks.md) | SDKs / Build Chain / Firmware | None (pre-install) |
| [Mass Malware Generation](mass-malware-generation.md) | MaaS Builders / Crypters / Repackaging | None (tooling-level) |
| [AI-Assisted Malware](ai-assisted-malware.md) | LLMs / Deepfakes / Adversarial ML | Varies |
| [App Virtualization](app-virtualization.md) | VirtualApp / DroidPlugin | None (app-level) |
| [App Collusion](app-collusion.md) | IPC / Shared Storage / SDKs | Varies (distributed across apps) |

## Kill Chain

How attacks chain together in a typical Android banking trojan or spyware operation. Each stage builds on the previous one. [Anti-Analysis Techniques](anti-analysis-techniques.md) run as a cross-cutting layer at every stage, not as a final step.

| Stage | Objective | Techniques / Permissions | What Happens |
|-------|-----------|--------------------------|-------------|
| **1. Delivery** | Get on device | [Phishing](phishing-techniques.md), sideloading, [Play Store dropper](play-store-evasion.md), [supply chain](supply-chain-attacks.md), smishing link | APK delivered as fake app (Chrome update, Flash Player, bank app), pre-installed in firmware, or pulled in via a poisoned SDK |
| **2. Dropper** | Install payload | [`REQUEST_INSTALL_PACKAGES`](../permissions/special/request-install-packages.md), [Dynamic Code Loading](dynamic-code-loading.md) | Dropper downloads and installs the real malware APK at runtime |
| **3. Persistence** | Survive reboots | [Persistence Techniques](persistence-techniques.md): [`RECEIVE_BOOT_COMPLETED`](../permissions/normal/receive-boot-completed.md) + [`FOREGROUND_SERVICE`](../permissions/normal/foreground-service.md) | Boot receiver re-launches malware; foreground service prevents kill |
| **4. Privilege escalation** | Gain control | [Accessibility Abuse](accessibility-abuse.md), [Runtime Permission Manipulation](runtime-permission-manipulation.md), [Device Admin Abuse](device-admin-abuse.md), [kernel exploits](privilege-escalation.md) | User tricked into enabling accessibility service or device admin; malware auto-grants further permissions, reads screens, injects input, resists uninstall |
| **5. Discovery** | Identify targets | Installed package enumeration (`QUERY_ALL_PACKAGES`), banking app fingerprinting via accessibility, [location checks](location-tracking.md) | Malware enumerates banking, crypto, and authenticator apps; geofences activation to target countries |
| **6. Credential theft** | Steal logins | [Overlay Attacks](overlay-attacks.md), [Keylogging](keylogging.md), [Screen Capture](screen-capture.md), [Clipboard Hijacking](clipboard-hijacking.md), [Fake Biometric Prompts](fake-biometric-prompts.md) | Phishing overlay injected over banking app; keystrokes captured; screen recorded; clipboard monitored for seed phrases; fake lockscreen captures device PIN |
| **7. 2FA bypass** | Intercept OTPs | [SMS Interception](sms-interception.md), [Notification Listener Abuse](notification-listener-abuse.md), [SIM & Carrier Attacks](sim-carrier-attacks.md) | SMS OTPs intercepted via broadcast receiver or read from notification shade; push-based OTPs captured via notification listener; SIM swap defeats SMS 2FA entirely |
| **8. On-device fraud** | Move money | [Automated Transfer Systems](automated-transfer-systems.md), [NFC Relay](nfc-relay.md), [Carrier Billing Fraud](carrier-billing-fraud.md) | ATS fills in transfer fields and confirms transactions; NFC relay clones tap-to-pay; DCB silently subscribes victim to premium services |
| **9. Exfiltration** | Send data to C2 | [C2 Communication](c2-techniques.md): [`INTERNET`](../permissions/normal/internet.md), [Data Exfiltration](data-exfiltration.md), [Network Traffic Interception](network-traffic-interception.md) | Credentials, SMS, contacts, screen recordings sent to C2 over HTTP, WebSocket, or cloud-service tunnels |
| **10. Cleanup** | Destroy evidence | [Notification Suppression](notification-suppression.md), [Device Wipe](device-wipe-ransomware.md) | Transaction alerts hidden; factory reset wipes forensic artifacts post-fraud |

## Technique Combinations

Attacks rarely operate alone. These are the most common pairings observed in active malware families, with citations to the original disclosures.

| Combination | Result | Families Using It |
|-------------|--------|-------------------|
| [Overlay](overlay-attacks.md) + [Accessibility](accessibility-abuse.md) | Credential theft with ATS -- overlay steals creds, accessibility automates transfers | [Cerberus](../malware/families/cerberus.md) ([ThreatFabric](https://www.threatfabric.com/blogs/cerberus-a-new-banking-trojan-from-the-underworld)), [Ermac](../malware/families/ermac.md) ([ThreatFabric](https://www.threatfabric.com/blogs/ermac-another-cerberus-reborn)), [Hook](../malware/families/hook.md) ([ThreatFabric](https://www.threatfabric.com/blogs/hook-a-new-ermac-fork-with-rat-capabilities)), [Xenomorph](../malware/families/xenomorph.md) ([ThreatFabric](https://www.threatfabric.com/blogs/xenomorph-a-newly-hatched-banking-trojan)), [Octo](../malware/families/octo.md) ([ThreatFabric](https://www.threatfabric.com/blogs/octo-new-ondevice-fraud-android-banking-trojan)), [GodFather](../malware/families/godfather.md) ([Group-IB](https://www.group-ib.com/blog/godfather-trojan/)), [TsarBot](../malware/families/tsarbot.md) ([Cyble](https://cyble.com/blog/tsarbot-using-overlay-attacks-targeting-bfsi-sector/)) |
| [Accessibility](accessibility-abuse.md) + [Screen Capture](screen-capture.md) | Remote access / VNC -- accessibility provides input control, screen capture provides visual feed | [Hook](../malware/families/hook.md) ([ThreatFabric](https://www.threatfabric.com/blogs/hook-a-new-ermac-fork-with-rat-capabilities)), [Octo](../malware/families/octo.md) ([ThreatFabric](https://www.threatfabric.com/blogs/octo-new-ondevice-fraud-android-banking-trojan)), [Vultur](../malware/families/vultur.md) ([ThreatFabric](https://www.threatfabric.com/blogs/vultur-v-for-vnc)), [BingoMod](../malware/families/bingomod.md) ([Cleafy](https://www.cleafy.com/cleafy-labs/bingomod-the-new-android-rat-that-steals-money-and-wipes-data)), [Brokewell](../malware/families/brokewell.md) ([ThreatFabric](https://www.threatfabric.com/blogs/brokewell-do-not-go-broke-from-new-banking-trojan)) |
| [Accessibility](accessibility-abuse.md) + [Keylogging](keylogging.md) | Full input capture -- every keystroke and text-field value recorded | [Cerberus](../malware/families/cerberus.md) ([ThreatFabric](https://www.threatfabric.com/blogs/cerberus-a-new-banking-trojan-from-the-underworld)), [Ermac](../malware/families/ermac.md) ([ThreatFabric](https://www.threatfabric.com/blogs/ermac-another-cerberus-reborn)), [TrickMo](../malware/families/trickmo.md) ([Zimperium](https://zimperium.com/blog/unpacking-the-trickmo-banking-trojan-variants)), [SpyNote](../malware/families/spynote.md) ([Cleafy](https://www.cleafy.com/cleafy-labs/spynote-unveiling-the-android-malware-in-an-undetected-campaign-targeting-european-banks)) |
| [Accessibility](accessibility-abuse.md) + [Clipboard Hijacking](clipboard-hijacking.md) | Crypto theft -- accessibility reads screen content, clipboard captures wallet addresses | [SparkCat](../malware/families/sparkcat.md) ([Kaspersky](https://securelist.com/sparkcat-stealer-in-app-store-and-google-play/115385/)), [SpyAgent](../malware/families/spyagent.md) ([McAfee](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/spyagent-android-malware-steals-your-crypto-recovery-phrases/)) |
| [Notification Listener](notification-listener-abuse.md) + [SMS Interception](sms-interception.md) | Complete OTP theft -- SMS receiver grabs text-based codes, notification listener catches push-based codes | [Anatsa](../malware/families/anatsa.md) ([ThreatFabric](https://www.threatfabric.com/blogs/anatsa-trojan-returns-targeting-europe-and-expanding-its-reach)), [Xenomorph](../malware/families/xenomorph.md) ([ThreatFabric](https://www.threatfabric.com/blogs/xenomorph-a-newly-hatched-banking-trojan)), [GodFather](../malware/families/godfather.md) ([Group-IB](https://www.group-ib.com/blog/godfather-trojan/)) |
| [Dynamic Code Loading](dynamic-code-loading.md) + [Phishing](phishing-techniques.md) | Dropper with clean initial scan -- benign APK passes Play Protect, downloads payload post-install | [Anatsa](../malware/families/anatsa.md) ([ThreatFabric](https://www.threatfabric.com/blogs/anatsa-trojan-returns-targeting-europe-and-expanding-its-reach)), [SharkBot](../malware/families/sharkbot.md) ([NCC Group](https://research.nccgroup.com/2022/03/03/sharkbot-a-new-generation-android-banking-trojan-being-distributed-on-google-play-store/)), [Joker](../malware/families/joker.md) ([Zimperium](https://www.zimperium.com/blog/new-joker-variant-hits-google-play-with-an-old-trick/)) |
| [Device Admin](device-admin-abuse.md) + [Persistence](persistence-techniques.md) | Unremovable malware -- device admin blocks uninstall, persistence survives reboots | [BRATA](../malware/families/brata.md) ([Cleafy](https://www.cleafy.com/cleafy-labs/how-brata-is-monitoring-your-bank-account)), [Cerberus](../malware/families/cerberus.md) ([ThreatFabric](https://www.threatfabric.com/blogs/cerberus-a-new-banking-trojan-from-the-underworld)), [Rafel RAT](../malware/families/rafelrat.md) ([Check Point](https://research.checkpoint.com/2024/rafel-rat-android-malware-from-espionage-to-ransomware-operations/)) |
| [Overlay](overlay-attacks.md) + [Tapjacking](tapjacking.md) | Layered UI deception -- overlay captures input while tapjacking forces user interaction | [Anubis](../malware/families/anubis.md) ([Security Intelligence](https://securityintelligence.com/posts/anubis-strikes-again-mobile-malware-continues-to-plague-users-in-campaigns/)), [BankBot](../malware/families/bankbot.md) ([Securelist](https://securelist.com/the-bankbot-trojan-now-with-overlay-for-blockchain/79336/)) (pre-Android 12) |
| [Accessibility](accessibility-abuse.md) + [NFC Relay](nfc-relay.md) | Contactless payment fraud -- accessibility extracts card PINs, NFC relay clones tap-to-pay | [NGate](../malware/families/ngate.md) ([ESET](https://www.welivesecurity.com/en/eset-research/new-ngate-variant-hides-in-a-trojanized-nfc-payment-app/)) |
| [Fake Biometric Prompts](fake-biometric-prompts.md) + [Accessibility](accessibility-abuse.md) | Device unlock theft -- fake lockscreen captures PIN, accessibility downgrades biometric prompts to force PIN entry | [TrickMo](../malware/families/trickmo.md) ([Zimperium](https://zimperium.com/blog/unpacking-the-trickmo-banking-trojan-variants)), [GoldPickaxe](../malware/families/goldpickaxe.md) ([Group-IB](https://www.group-ib.com/blog/goldfactory-ios-trojan/)) |
| [Intent Hijacking](intent-hijacking.md) + [Broadcast Theft](broadcast-theft.md) | SMS interception -- hijack SMS broadcast to steal OTPs before the real app sees them | [FluBot](../malware/families/flubot.md) ([ThreatFabric](https://www.threatfabric.com/blogs/fluBot-the-evolution-of-a-notorious-android-banking-malware)), [Anatsa](../malware/families/anatsa.md) ([ThreatFabric](https://www.threatfabric.com/blogs/anatsa-trojan-returns-targeting-europe-and-expanding-its-reach)) |
| [App Virtualization](app-virtualization.md) + [Accessibility](accessibility-abuse.md) | Overlay-free credential theft -- real banking app runs in hostile sandbox, accessibility redirects launch intents | [GodFather v3](../malware/families/godfather.md) ([Zimperium](https://zimperium.com/blog/your-mobile-app-their-playground-the-dark-side-of-the-virtualization)), FjordPhantom ([Promon](https://promon.io/security-news/fjordphantom-android-malware)) |
| [App Collusion](app-collusion.md) + [Persistence](persistence-techniques.md) | Resilient multi-app architecture -- payload survives deletion of the visible dropper app | [PixPirate](../malware/families/pixpirate.md) ([Cleafy](https://www.cleafy.com/cleafy-labs/pixpirate-a-new-brazilian-banking-trojan)) |
| [Mass Malware Generation](mass-malware-generation.md) + [Play Store Evasion](play-store-evasion.md) | Volume-based evasion -- hundreds of variants submitted across distributed developer accounts overwhelm review | [Vapor 331 apps](https://www.bitdefender.com/en-us/blog/labs/malicious-google-play-apps-bypassed-android-security), [Konfety 250+ apps](https://www.humansecurity.com/learn/blog/satori-threat-intelligence-alert-konfety-spreads-evil-twin-apps-for-multiple-fraud-schemes/), [Joker 1,800+ variants](https://threatpost.com/joker-trojans-android/159595/) |
| [Notification Suppression](notification-suppression.md) + [ATS](automated-transfer-systems.md) | Invisible fraud -- transaction alerts dismissed while ATS moves money | [Cerberus](../malware/families/cerberus.md) ([ThreatFabric](https://www.threatfabric.com/blogs/cerberus-a-new-banking-trojan-from-the-underworld)), [Hook](../malware/families/hook.md) ([ThreatFabric](https://www.threatfabric.com/blogs/hook-a-new-ermac-fork-with-rat-capabilities)), [Octo](../malware/families/octo.md) ([ThreatFabric](https://www.threatfabric.com/blogs/octo-new-ondevice-fraud-android-banking-trojan)), [Xenomorph](../malware/families/xenomorph.md) ([ThreatFabric](https://www.threatfabric.com/blogs/xenomorph-a-newly-hatched-banking-trojan)) |
| [Call Interception](call-interception.md) + [Phishing](phishing-techniques.md) | Voice phishing -- victim calls real bank number but reaches attacker IVR | [Fakecalls](../malware/families/fakecalls.md) ([Kaspersky](https://securelist.com/fakecalls-android-malware-targets-korean-bank-customers/106191/)), Letscall ([ThreatFabric](https://www.threatfabric.com/blogs/letscall-new-sophisticated-vishing-toolset)) |
| [Device Wipe](device-wipe-ransomware.md) + [ATS](automated-transfer-systems.md) | Post-fraud cleanup -- factory reset destroys evidence after money transfer | [BRATA](../malware/families/brata.md) ([The Record](https://therecord.media/android-malware-will-factory-reset-a-phone-after-stealing-a-users-funds)), [BingoMod](../malware/families/bingomod.md) ([Cleafy](https://www.cleafy.com/cleafy-labs/bingomod-the-new-android-rat-that-steals-money-and-wipes-data)) |
| [Camera/Mic Surveillance](camera-mic-surveillance.md) + [Accessibility](accessibility-abuse.md) | Full device surveillance -- camera/mic capture with screen reading and input injection | [SpyNote](../malware/families/spynote.md) ([Cleafy](https://www.cleafy.com/cleafy-labs/spynote-unveiling-the-android-malware-in-an-undetected-campaign-targeting-european-banks)) |
| [Privilege Escalation](privilege-escalation.md) (zero-click exploit chain) | State-sponsored surveillance -- kernel/browser/messenger exploit chains break out of the app sandbox without user interaction | [Pegasus on Android](../malware/families/pegasus.md) ([Google TAG](https://blog.google/threat-analysis-group/pegasus-spyware-and-zero-day-exploits-targeting-android-users/)), [Predator](../malware/families/predator.md) ([Citizen Lab](https://citizenlab.ca/2023/10/predator-in-the-wires-ahmed-eltantawy-targeted-with-predator-spyware-after-announcing-presidential-ambitions/)) |
| [Anti-Analysis](anti-analysis-techniques.md) + [Dynamic Code Loading](dynamic-code-loading.md) | Staged evasion -- environment checks before loading payload; sandbox sees nothing | [Anatsa](../malware/families/anatsa.md) ([ThreatFabric](https://www.threatfabric.com/blogs/anatsa-trojan-returns-targeting-europe-and-expanding-its-reach)), [Mandrake](../malware/families/mandrake.md) ([Kaspersky](https://securelist.com/mandrake-apps-return-to-google-play/113147/)), [Octo](../malware/families/octo.md) ([ThreatFabric](https://www.threatfabric.com/blogs/octo-new-ondevice-fraud-android-banking-trojan)) |
| [Network Interception](network-traffic-interception.md) + [DNS Manipulation](network-traffic-interception.md#dns-manipulation) | Network-level phishing -- DNS hijacking redirects banking domains to credential harvesting | [MoqHao / Roaming Mantis](../malware/families/moqhao.md) ([Kaspersky](https://securelist.com/roaming-mantis-dns-changer-in-malicious-mobile-app/108464/)) |
| [Supply Chain](supply-chain-attacks.md) + [Persistence](persistence-techniques.md) | Pre-installed malware -- payload ships in firmware or in widely-embedded SDK | BADBOX ([HUMAN Security](https://www.humansecurity.com/learn/blog/satori-threat-intelligence-alert-badbox-and-peachpit/)), [Triada firmware](../malware/families/triada.md) ([Kaspersky](https://securelist.com/triada-trojan-in-firmware-of-budget-android-devices/90633/)), [SpinOk SDK](../malware/families/spinok.md) ([Doctor Web](https://news.drweb.com/show/?i=14705&lng=en)), [Necro SDK](../malware/families/necro.md) ([Kaspersky](https://securelist.com/necro-trojan-is-back-on-google-play/113881/)), [Goldoson SDK](../malware/families/goldoson.md) ([McAfee](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/goldoson-privacy-invasive-and-clicker-android-adware-found-in-popular-apps-in-south-korea/)) |
| [SIM Toolkit](sim-carrier-attacks.md) (Simjacker / WIBattack) | Carrier-level location tracking and SMS exfiltration through SIM applets, invisible to the OS | Simjacker ([AdaptiveMobile](https://www.adaptivemobile.com/blog/simjacker-next-generation-spying-over-mobile)) |

## Attacker Priority

Ranked by prevalence in modern (2024-2025) Android malware campaigns. Priority reflects how frequently the technique appears in active operations and how much attacker value it enables. Sources cited where the claim is specific.

| Rank | Technique | Prevalence | Why It Matters |
|-----:|-----------|-----------|----------------|
| 1 | [Accessibility Abuse](accessibility-abuse.md) | Universal in banking trojans | Enables everything: auto-granting permissions, reading screens, performing ATS, bypassing 2FA |
| 2 | [C2 Communication](c2-techniques.md) | Universal | Every malware family needs a command channel; multi-channel C2 is the norm |
| 3 | [Data Exfiltration](data-exfiltration.md) | Universal (operational objective) | The endpoint of every campaign; HTTP, Telegram/Discord, Firebase, SMS all in active use |
| 4 | [Persistence Techniques](persistence-techniques.md) | Universal (supporting) | Required for any long-running operation; boot receivers and foreground services are baseline |
| 5 | [Anti-Analysis Techniques](anti-analysis-techniques.md) | Universal (supporting) | Nearly every family implements emulator/root/Frida detection; determines whether payload executes at all |
| 6 | [Runtime Permission Manipulation](runtime-permission-manipulation.md) | Near-universal once accessibility is granted ([Octo, ThreatFabric](https://www.threatfabric.com/blogs/octo-new-ondevice-fraud-android-banking-trojan)) | Bootstraps every other permission without further user prompts |
| 7 | [Overlay Attacks](overlay-attacks.md) | High (banking trojans) | Primary credential harvesting method; still effective despite Android 12+ restrictions |
| 8 | [Screen Capture](screen-capture.md) | High (banking trojans, RATs -- [Vultur](https://www.threatfabric.com/blogs/vultur-v-for-vnc), [BingoMod](https://www.cleafy.com/cleafy-labs/bingomod-the-new-android-rat-that-steals-money-and-wipes-data)) | Real-time VNC and screen recording for credential theft and remote control |
| 9 | [Keylogging](keylogging.md) | High (banking trojans, spyware) | Captures passwords and OTPs as users type; pairs with accessibility for full coverage |
| 10 | [Automated Transfer Systems](automated-transfer-systems.md) | High (banking trojans) | On-device fraud that bypasses bank-side device fingerprinting and session checks |
| 11 | [Notification Listener Abuse](notification-listener-abuse.md) | High (rising) | Replaced SMS interception as primary OTP theft vector; reads all app notifications |
| 12 | [Notification Suppression](notification-suppression.md) | High (banking trojans) | Hides transaction alerts during fraud; dual-purpose with OTP theft via notification listener |
| 13 | [SMS Interception](sms-interception.md) | High (declining on newer OS) | Original 2FA bypass method; restricted by Play Store policy but still used in sideloaded malware |
| 14 | [Dynamic Code Loading](dynamic-code-loading.md) | High (droppers -- [Anatsa, ThreatFabric](https://www.threatfabric.com/blogs/anatsa-trojan-returns-targeting-europe-and-expanding-its-reach)) | Foundation of Play Store evasion; clean APK downloads malicious payload post-install |
| 15 | [Play Store Evasion](play-store-evasion.md) | High ([Anatsa droppers, ThreatFabric](https://www.threatfabric.com/blogs/anatsa-trojan-returns-targeting-europe-and-expanding-its-reach); [SharkBot, NCC Group](https://research.nccgroup.com/2022/03/03/sharkbot-a-new-generation-android-banking-trojan-being-distributed-on-google-play-store/); [Joker 1,800+ apps](https://threatpost.com/joker-trojans-android/159595/)) | Dropper apps, versioning attacks, and session-based installer abuse reach millions through the official store |
| 16 | [Phishing Techniques](phishing-techniques.md) | High (delivery) | Primary infection vector; smishing, fake Play Store pages, social engineering for permissions |
| 17 | [Mass Malware Generation](mass-malware-generation.md) | High (infrastructure) | MaaS builders, crypter services, and coordinated store submission produce variants faster than detection can scale |
| 18 | [Location Tracking](location-tracking.md) | High in spyware; activation gate in banking trojans | Core spyware capability; banking trojans use it to restrict execution to target countries |
| 19 | [Camera & Mic Surveillance](camera-mic-surveillance.md) | High (spyware, RATs) | Core capability of state-sponsored spyware and surveillance RATs; increasingly restricted by OS |
| 20 | [Clipboard Hijacking](clipboard-hijacking.md) | Rising (crypto-targeting -- [SparkCat](https://securelist.com/sparkcat-stealer-in-app-store-and-google-play/115385/), [SpyAgent](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/spyagent-android-malware-steals-your-crypto-recovery-phrases/)) | Growing alongside cryptocurrency adoption; minimal permissions required from foreground |
| 21 | [Fake Biometric Prompts](fake-biometric-prompts.md) | Rising ([TrickMo](https://zimperium.com/blog/unpacking-the-trickmo-banking-trojan-variants), [GoldPickaxe](https://www.group-ib.com/blog/goldfactory-ios-trojan/)) | Captures device unlock PIN; lets remote-access malware unlock the device |
| 22 | [AI-Assisted Malware](ai-assisted-malware.md) | Rising | LLM-assisted development, deepfake biometric fraud, underground AI tools lowering skill barriers |
| 23 | [NFC Relay](nfc-relay.md) | Emerging ([NGate, ESET](https://www.welivesecurity.com/en/eset-research/new-ngate-variant-hides-in-a-trojanized-nfc-payment-app/)) | Bypasses contactless payment security entirely; hard to detect at the device level |
| 24 | [App Virtualization](app-virtualization.md) | Emerging, high impact ([FjordPhantom, Promon](https://promon.io/security-news/fjordphantom-android-malware); [GodFather v3, Zimperium](https://zimperium.com/blog/your-mobile-app-their-playground-the-dark-side-of-the-virtualization)) | Runs real banking apps inside malware-controlled sandbox; bypasses overlay detection, repackaging checks, root detection |
| 25 | [Device Admin Abuse](device-admin-abuse.md) | Moderate (declining) | Prevents uninstall and enables device wipe; being replaced by accessibility-based persistence |
| 26 | [Intent Hijacking](intent-hijacking.md) | Moderate | Enables SMS/OTP theft and IPC interception; foundational for many attack chains |
| 27 | [WebView Exploitation](webview-exploitation.md) | Moderate | Targets hybrid apps; token theft, JavaScript injection, MITM within the app |
| 28 | [Broadcast Theft](broadcast-theft.md) | Moderate (declining) | SMS interception via broadcast receivers still works but restricted on newer Android versions |
| 29 | [Deep Link Exploitation](deep-link-exploitation.md) | Moderate | OAuth redirect attacks, app navigation hijacking; underestimated in mobile pentests |
| 30 | [App Collusion](app-collusion.md) | Moderate (SDK-mediated; [PixPirate, Cleafy](https://www.cleafy.com/cleafy-labs/pixpirate-a-new-brazilian-banking-trojan)) | SDK-based cross-app data aggregation is the dominant model; multi-app malware architectures emerging |
| 31 | [Network Traffic Interception](network-traffic-interception.md) | Moderate | DNS hijacking, VPN abuse, proxy configuration; [Android 14 APEX certificate store](https://httptoolkit.com/blog/android-14-install-system-ca-certificate/) makes user-CA MITM harder |
| 32 | [Call Interception](call-interception.md) | Moderate (region-specific; [Fakecalls, Kaspersky](https://securelist.com/fakecalls-android-malware-targets-korean-bank-customers/106191/)) | Voice phishing via call redirection; dominant in Korean-targeting campaigns |
| 33 | [Device Wipe & Ransomware](device-wipe-ransomware.md) | Moderate (declining for ransomware, rising for evidence destruction) | File encryption declining due to scoped storage; factory reset as post-fraud cleanup is growing |
| 34 | [Supply Chain Attacks](supply-chain-attacks.md) | Moderate, very high impact ([BADBOX](https://www.humansecurity.com/learn/blog/satori-threat-intelligence-alert-badbox-and-peachpit/), [Triada firmware](https://securelist.com/triada-trojan-in-firmware-of-budget-android-devices/90633/), [SpinOk SDK](https://news.drweb.com/show/?i=14705&lng=en), [Necro](https://securelist.com/necro-trojan-is-back-on-google-play/113881/), [Goldoson](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/goldoson-privacy-invasive-and-clicker-android-adware-found-in-popular-apps-in-south-korea/)) | Pre-install via firmware or poisoned SDKs bypasses the user's trust decision entirely |
| 35 | [Carrier Billing Fraud](carrier-billing-fraud.md) | Moderate (region-dependent) | Joker-class DCB fraud persists in regions with active carrier billing; small per-victim charges hide at scale |
| 36 | [SIM & Carrier Attacks](sim-carrier-attacks.md) | Moderate (region-specific) | SIM swap defeats SMS 2FA at the carrier level; [Simjacker / WIBattack](https://www.adaptivemobile.com/blog/simjacker-next-generation-spying-over-mobile) operate below the OS |
| 37 | [Tapjacking](tapjacking.md) | Low (declining) | Largely mitigated by [`filterTouchesWhenObscured` and Android 12+ untrusted-touch restrictions](https://developer.android.com/privacy-and-security/risks/tapjacking) |
| 38 | [Task Affinity Attacks](task-affinity-attacks.md) | Low | Niche but effective for targeted phishing within the task switcher |
| 39 | [Launcher Hijacking](launcher-hijacking.md) | Low | Niche; mostly seen in lockscreen ransomware and parental-control abuse |
| 40 | [Content Provider Attacks](content-provider-attacks.md) | Low | App-specific; dangerous when providers are exported without proper permissions |
| 41 | [Work Profile Abuse](work-profile-abuse.md) | Low (targeted) | Enterprise-only attack surface; DPC API abuse and cross-profile intent attacks in BYOD environments |
| 42 | [Privilege Escalation](privilege-escalation.md) | Low for commodity malware, defining for commercial spyware ([Pegasus](https://blog.google/threat-analysis-group/pegasus-spyware-and-zero-day-exploits-targeting-android-users/), [Predator](https://citizenlab.ca/2023/10/predator-in-the-wires-ahmed-eltantawy-targeted-with-predator-spyware-after-announcing-presidential-ambitions/)) | Dividing line between sandboxed banking trojans and zero-click surveillance toolkits |
