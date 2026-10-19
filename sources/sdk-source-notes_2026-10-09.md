# SDK documentation and source code – confirmations (accessed 9 Oct 2026 via the GitHub API; versions = tags matching the SDK versions in the HAR headers)

## D17 – Superwall-iOS 4.15.3 (tag `4.15.3`, commit df574161daec2a1410078e6cfc174f05bab020ab)
- `Sources/SuperwallKit/Network/Device Helper/DeviceHelper.swift`, lines 67–68:
  `let vendorId: String = { UIDevice.current.identifierForVendor?.uuidString ?? "" }`
  → **`vendorId` = IDFV** (Apple `identifierForVendor`).
- same file, lines 90–105: `regionCode` = `Locale.autoupdatingCurrent.regionCode`; `preferredRegionCode` = region of the first language in `Locale.preferredLanguages` (or `regionCode`).
- same file, line 171: `isLowPowerModeEnabled` = `ProcessInfo.processInfo.isLowPowerModeEnabled`; line 498: `appInstalledAtString` = installation date; line 626: `deviceDictionary["appTransactionId"] = ReceiptManager.appTransactionId`.
- `Sources/SuperwallKit/Dependencies/DependencyContainer.swift`, lines 642–644:
  `func makeDeviceId() -> String { return "$SuperwallDevice:\(deviceHelper.vendorId)" }`
  → **`deviceId` = `$SuperwallDevice:` + IDFV** (confirms the finding in section 3.3 of the report).
- Permalinks: https://github.com/superwall/Superwall-iOS/blob/4.15.3/Sources/SuperwallKit/Network/Device%20Helper/DeviceHelper.swift , https://github.com/superwall/Superwall-iOS/blob/4.15.3/Sources/SuperwallKit/Dependencies/DependencyContainer.swift

## D18 – purchases-ios (RevenueCat) 5.21.1 (tag `5.21.1`, commit 33cc2cbd324b4bc5d1a72cd3f15df749aa038bc0)
- `Sources/Networking/HTTPClient/HTTPClient.swift`, lines 148–150:
  `if let idfv = self.systemInfo.identifierForVendor { headers["X-Apple-Device-Identifier"] = idfv }`
  → **header `X-Apple-Device-Identifier` = IDFV** in all requests to api.revenuecat.com.
- `Sources/Misc/SystemInfo.swift`, line 129 ff.: `identifierForVendor` from `UIDevice.current.identifierForVendor` (iOS).
- Permalinks: https://github.com/RevenueCat/purchases-ios/blob/5.21.1/Sources/Networking/HTTPClient/HTTPClient.swift , https://github.com/RevenueCat/purchases-ios/blob/5.21.1/Sources/Misc/SystemInfo.swift

## Documentation (fetched 9 Oct 2026)
- Superwall "App Privacy Nutrition Labels" (https://superwall.com/docs/ios/guides/app-privacy-nutrition-labels): the list of collected data includes `vendorId` ("The vendor ID of the device"), `aliases`, `ipRegion`, `ipRegionCode`, `ipCountry`, `ipCity`, `ipContinent`, `ipTimezone` (each "derived from the device's IP address"). `demandScore` and `appTransactionId` are not listed. The page shows no update date.
- RevenueCat "Apple App Privacy" (https://www.revenuecat.com/docs/platform-resources/apple-platform-resources/apple-app-privacy): "Purchases" must be declared; "Identifiers" if purchase history is linked to an identity; "Analytics" and "App Functionality" are required. No mention of IDFV or AdServices. No update date.

## I (inference)
- The value sent as `vendorId` (Superwall) and as `X-Apple-Device-Identifier` (RevenueCat) is the same IDFV; confirmed by the code, not only by observing equal values (section 3.3 of the report).
- `regionCode` comes from `Locale.autoupdatingCurrent`, i.e. from the system Region setting (or, after a change, from the automatically updated value). The region code observed on device B (different from that of A and C), while the authors' account of the device setting is "Region: Poland", remains unresolved.

## D18a – purchases-ios 5.21.1: the AdServices token must be enabled by the app (accessed 9 Oct 2026)
- `Sources/Purchasing/Purchases/Attribution.swift`, line 29: `var automaticAdServicesAttributionTokenCollection: Bool = false`; lines 65–69: `func enableAdServicesAttributionTokenCollection() { self.automaticAdServicesAttributionTokenCollection = true; self.postAdServicesTokenOncePerInstallIfNeeded() }`; lines 71–76: sent only when the flag is `true`.
- `Sources/Purchasing/Purchases/Purchases.swift`, line 1910: the SDK tries to send the token when the app enters the foreground, but the method checks the flag (see above).
- RevenueCat documentation "Apple Search Ads attribution" (https://www.revenuecat.com/docs/integrations/attribution/apple-search-ads, accessed 9 Oct 2026): "The Purchases SDK will collect the attribution token and send it to RevenueCat in the background" after a call to `Purchases.shared.attribution.enableAdServicesAttributionTokenCollection()`.
- I: the observed requests `POST …/adservices_attribution` (6 observations) mean that the app called this method; collecting the token is not the SDK's default behaviour. Permalinks: https://github.com/RevenueCat/purchases-ios/blob/5.21.1/Sources/Purchasing/Purchases/Attribution.swift , https://github.com/RevenueCat/purchases-ios/blob/5.21.1/Sources/Purchasing/Purchases/Purchases.swift
