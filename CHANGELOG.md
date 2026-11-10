# Changelog

All notable changes to `io.ipscope:ipscope-sdk` are documented here. The project follows
[Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-11-10

### Added
- `GeoBlock`: `latitude()`, `longitude()`, `postalCode()`.
- `SecurityBlock`: `isRelay()` (consumer privacy relays such as iCloud Private Relay; not reported as VPN/proxy/hosting).
- `NetworkPrefixLookupResponse`: `matchedNetwork()`, `bgpPrefixLength()`, `lookup()` (full `IpLookupResponse` for the
  prefix base address).
- `CanonicalNetworkPrefixRecord`: `subdivision`, `postalCode`, `latitude`, `longitude`, `timezone`, `geoConfidence`,
  `accuracyRadiusKm`, `isVirtualLocation`, `connectionType`, `isRelay`, `securityConfidence`, `abuseVelocityScore`,
  `isKnownScanner`, `reasonCodes`, `updatedAt` (the API's camelCase keys are read first, snake_case as fallback).
- `FeedbackSubmissionInput`: `evidenceUrl`, `contactConsent`, `contactEmail`, a 4-argument constructor, and
  `withEvidenceUrl(...)` / `withContact(...)`.
- `FeedbackSubmissionResponse`: `evidenceUrl()`, `contactConsent()`, `contactEmail()`.
- `IpScopeModels.FEEDBACK_ROLES` and `IpScopeModels.FEEDBACK_ISSUE_TYPES` listing the values the API accepts.
- `RateLimitMetadata.resetAfterSeconds()` and `RateLimitMetadata.of(...)`.
- `mvn test` / `gradle test` now run the suite with JUnit 5 (test scope only; the runtime jar still has zero
  dependencies). CI runs `mvn verify` and fails if any runtime dependency appears.

### Fixed
- Feedback evidence was sent as `evidence_urls` (array), which the API silently dropped. The SDK now sends
  `evidence_url` (single string).
- Feedback responses default `role` to `user` (was the invalid `end_user`); `createdAt` is read from either casing.
- `X-RateLimit-Reset` is seconds until reset, not a Unix epoch. 429 retry delays derived from it were wrong; they now
  use the relative value.
- `abuseVelocityScore` is documented as a 0-100 score (integer on the wire); fractional legacy values still parse.
- README examples compile against 1.1.0 (the stream example used an undefined variable).
- `User-Agent` is now `ipscope-java/1.1.0`.

### Deprecated
- `FeedbackSubmissionInput(String, String, String, Map, List<String>)` and `FeedbackSubmissionInput.evidenceUrls()`:
  the first non-blank URL is sent as `evidence_url`.
- `RateLimitMetadata.resetEpochSeconds()`: same relative seconds value as `resetAfterSeconds()`.
- `RateLimitMetadata.burstCapacity()` and `rateLimitRps()`: the API sends no such headers; always `null`.

### Compatibility notes
- Records gained components, but every 1.0.x constructor is kept as an overload, so existing source and binaries
  keep working.

## [1.0.0]

- Initial release.
