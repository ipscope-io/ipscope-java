package io.ipscope.sdk;

import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Immutable Java 17 {@code record} models for the IPScope Server-Side Java SDK.
 *
 * <p>Scope Notice: Strictly limited to IP intelligence, network CIDR prefix,
 * dataset metadata, feedback, and service status operations. Contains zero
 * account, wallet, or billing models.
 */
public final class IpScopeModels {

    private IpScopeModels() {}

    /**
     * Geographic classification and confidence returned in {@link IpLookupResponse#geo()}.
     *
     * <p>{@code latitude}/{@code longitude} are representative coordinates (never device GPS);
     * {@code postalCode} is present when the city dataset has one. All three may be {@code null}.
     */
    public record GeoBlock(
            String countryCode,
            String subdivision,
            String city,
            String timezone,
            String locationType,
            double confidence,
            Double accuracyRadiusKm,
            String declaredCountryCode,
            String physicalCountryCode,
            Boolean isVirtualLocation,
            String postalCode,
            Double latitude,
            Double longitude
    ) {
        /** 1.0.x constructor without postal code and coordinates. */
        public GeoBlock(
                String countryCode,
                String subdivision,
                String city,
                String timezone,
                String locationType,
                double confidence,
                Double accuracyRadiusKm,
                String declaredCountryCode,
                String physicalCountryCode,
                Boolean isVirtualLocation
        ) {
            this(countryCode, subdivision, city, timezone, locationType, confidence, accuracyRadiusKm,
                    declaredCountryCode, physicalCountryCode, isVirtualLocation, null, null, null);
        }
    }

    /** Autonomous System and network operator details returned in {@link IpLookupResponse#network()}. */
    public record NetworkBlock(
            Integer asn,
            String organization
    ) {}

    /**
     * Security, hosting, and anonymity classification returned in {@link IpLookupResponse#security()}.
     *
     * <p>{@code isRelay} is {@code true} for a published consumer privacy-relay egress (e.g. Apple
     * iCloud Private Relay). Relay users are not reported as VPN, proxy or hosting. {@code null} when unknown.
     */
    public record SecurityBlock(
            Boolean isVpn,
            Boolean isHosting,
            Boolean isTorExit,
            Boolean isProxy,
            String anonymizerType,
            double confidence,
            List<String> reasonCodes,
            Boolean isRelay
    ) {
        public SecurityBlock {
            reasonCodes = reasonCodes == null ? List.of() : List.copyOf(reasonCodes);
        }

        /** 1.0.x constructor without {@code isRelay}. */
        public SecurityBlock(
                Boolean isVpn,
                Boolean isHosting,
                Boolean isTorExit,
                Boolean isProxy,
                String anonymizerType,
                double confidence,
                List<String> reasonCodes
        ) {
            this(isVpn, isHosting, isTorExit, isProxy, anonymizerType, confidence, reasonCodes, null);
        }
    }

    /** Optional connection context block returned when licensed. */
    public record ConnectionBlock(
            String connectionType,
            Boolean isResidential,
            Boolean isMobile,
            Boolean isBusiness,
            Boolean isHosting
    ) {}

    /**
     * Optional security extensions telemetry block returned when licensed.
     *
     * <p>{@code abuseVelocityScore} is a 0-100 score (an integer on the wire) or {@code null}. It is
     * typed {@link Double} so older fractional payloads still parse.
     */
    public record SecurityExtensionsBlock(
            Double abuseVelocityScore,
            Boolean isKnownScanner,
            Double observationRecencyHours
    ) {}

    /** Canonical single IP lookup response ({@code GET /v1/ip/:ip} and {@code GET /v1/ip/me}). */
    public record IpLookupResponse(
            String ip,
            int ipVersion,
            String matchedNetwork,
            GeoBlock geo,
            NetworkBlock network,
            SecurityBlock security,
            ConnectionBlock connection,
            SecurityExtensionsBlock securityExtensions,
            String datasetVersion,
            String updatedAt
    ) {}

    /** Batch IP lookup response ({@code POST /v1/ip/batch}). */
    public record BatchLookupResponse(
            String datasetVersion,
            int count,
            List<IpLookupResponse> results
    ) {
        public BatchLookupResponse {
            results = results == null ? List.of() : List.copyOf(results);
        }
    }

    /**
     * Canonical network prefix record returned in {@code GET /v1/networks/:prefix/:length}.
     *
     * <p>The API serializes this record in camelCase; camelCase and snake_case keys are both read.
     * {@code abuseVelocityScore} is a 0-100 score or {@code null}.
     */
    public record CanonicalNetworkPrefixRecord(
            String prefix,
            int family,
            Integer asn,
            String organization,
            String countryCode,
            String city,
            String locationType,
            Boolean isVpn,
            Boolean isHosting,
            Boolean isTorExit,
            Boolean isProxy,
            String anonymizerType,
            String subdivision,
            String postalCode,
            Double latitude,
            Double longitude,
            String timezone,
            Double geoConfidence,
            Double accuracyRadiusKm,
            Boolean isVirtualLocation,
            String connectionType,
            Boolean isRelay,
            Double securityConfidence,
            Double abuseVelocityScore,
            Boolean isKnownScanner,
            List<String> reasonCodes,
            String updatedAt
    ) {
        public CanonicalNetworkPrefixRecord {
            reasonCodes = reasonCodes == null ? List.of() : List.copyOf(reasonCodes);
        }

        /** 1.0.x constructor with the original twelve fields. */
        public CanonicalNetworkPrefixRecord(
                String prefix,
                int family,
                Integer asn,
                String organization,
                String countryCode,
                String city,
                String locationType,
                Boolean isVpn,
                Boolean isHosting,
                Boolean isTorExit,
                Boolean isProxy,
                String anonymizerType
        ) {
            this(prefix, family, asn, organization, countryCode, city, locationType, isVpn, isHosting,
                    isTorExit, isProxy, anonymizerType, null, null, null, null, null, null, null, null,
                    null, null, null, null, null, List.of(), null);
        }
    }

    /**
     * Network CIDR prefix lookup response ({@code GET /v1/networks/:prefix/:length}).
     *
     * <p>{@code matchedNetwork} is the most-specific matched prefix, {@code bgpPrefixLength} its length,
     * and {@code lookup} the full IP lookup for the prefix's base address (each may be {@code null}).
     */
    public record NetworkPrefixLookupResponse(
            String queriedCidr,
            int family,
            String datasetVersion,
            CanonicalNetworkPrefixRecord record,
            String matchedNetwork,
            Integer bgpPrefixLength,
            IpLookupResponse lookup
    ) {
        /** 1.0.x constructor without {@code matchedNetwork}, {@code bgpPrefixLength} and {@code lookup}. */
        public NetworkPrefixLookupResponse(
                String queriedCidr,
                int family,
                String datasetVersion,
                CanonicalNetworkPrefixRecord record
        ) {
            this(queriedCidr, family, datasetVersion, record, null, null, null);
        }
    }

    /** Dataset snapshot summary entry returned in {@code GET /v1/metadata/datasets}. */
    public record DatasetSnapshotSummary(
            String snapshotVersion,
            String digest,
            String rulesetVersion,
            String publishedAt,
            int ipv4PrefixCount,
            int ipv6PrefixCount
    ) {}

    /** Datasets metadata response ({@code GET /v1/metadata/datasets}). */
    public record DatasetsMetadataResponse(
            String activeVersion,
            String previousVersion,
            List<DatasetSnapshotSummary> snapshots
    ) {
        public DatasetsMetadataResponse {
            snapshots = snapshots == null ? List.of() : List.copyOf(snapshots);
        }
    }

    /** Reporter roles accepted by {@code POST /v1/feedback}. */
    public static final List<String> FEEDBACK_ROLES = List.of("network_owner", "user", "researcher");

    /** Issue classifications accepted by {@code POST /v1/feedback}. */
    public static final List<String> FEEDBACK_ISSUE_TYPES = List.of(
            "wrong_country",
            "wrong_city",
            "false_positive_vpn",
            "false_positive_hosting",
            "false_positive_tor",
            "virtual_location_mismatch",
            "other"
    );

    /**
     * Input payload for submitting IP/prefix correction feedback ({@code POST /v1/feedback}).
     *
     * <p>{@code role} is one of {@link #FEEDBACK_ROLES}; {@code issueType} one of {@link #FEEDBACK_ISSUE_TYPES}.
     * {@code evidenceUrl}, {@code contactConsent} and {@code contactEmail} are optional ({@code null} = not sent).
     */
    public record FeedbackSubmissionInput(
            String prefixOrIp,
            String role,
            String issueType,
            Map<String, Object> requestedCorrection,
            String evidenceUrl,
            Boolean contactConsent,
            String contactEmail
    ) {
        public FeedbackSubmissionInput {
            requestedCorrection = requestedCorrection == null
                    ? Map.of()
                    : Collections.unmodifiableMap(requestedCorrection);
        }

        /** Creates a payload with only the required fields. */
        public FeedbackSubmissionInput(
                String prefixOrIp,
                String role,
                String issueType,
                Map<String, Object> requestedCorrection
        ) {
            this(prefixOrIp, role, issueType, requestedCorrection, null, null, null);
        }

        /**
         * 1.0.x constructor. The API accepts a single evidence URL, so only the first non-blank entry
         * of {@code evidenceUrls} is sent (as {@code evidence_url}).
         *
         * @deprecated use the constructor taking {@code String evidenceUrl}
         */
        @Deprecated(since = "1.1.0")
        public FeedbackSubmissionInput(
                String prefixOrIp,
                String role,
                String issueType,
                Map<String, Object> requestedCorrection,
                List<String> evidenceUrls
        ) {
            this(prefixOrIp, role, issueType, requestedCorrection, firstNonBlank(evidenceUrls), null, null);
        }

        /** Returns a copy with {@code evidenceUrl} set. */
        public FeedbackSubmissionInput withEvidenceUrl(String url) {
            return new FeedbackSubmissionInput(prefixOrIp, role, issueType, requestedCorrection, url,
                    contactConsent, contactEmail);
        }

        /** Returns a copy with the follow-up contact email and consent flag set. */
        public FeedbackSubmissionInput withContact(String email, boolean consent) {
            return new FeedbackSubmissionInput(prefixOrIp, role, issueType, requestedCorrection, evidenceUrl,
                    consent, email);
        }

        /**
         * 1.0.x accessor.
         *
         * @deprecated use {@link #evidenceUrl()}; returns a one-element list or {@code null}
         */
        @Deprecated(since = "1.1.0")
        public List<String> evidenceUrls() {
            return evidenceUrl == null ? null : List.of(evidenceUrl);
        }

        private static String firstNonBlank(List<String> urls) {
            if (urls == null) {
                return null;
            }
            for (String u : urls) {
                if (u != null && !u.isBlank()) {
                    return u;
                }
            }
            return null;
        }
    }

    /**
     * Response returned when submitting IP/prefix correction feedback ({@code POST /v1/feedback}).
     *
     * <p>{@code createdAt} is read from {@code createdAt} (current API) or {@code created_at}.
     * {@code evidenceUrls} is kept for 1.0.x callers and holds {@code evidenceUrl} as a one-element list.
     */
    public record FeedbackSubmissionResponse(
            String id,
            String prefixOrIp,
            String role,
            String issueType,
            Map<String, Object> requestedCorrection,
            String createdAt,
            String status,
            List<String> evidenceUrls,
            String evidenceUrl,
            Boolean contactConsent,
            String contactEmail
    ) {
        public FeedbackSubmissionResponse {
            requestedCorrection = requestedCorrection == null
                    ? Map.of()
                    : Collections.unmodifiableMap(requestedCorrection);
            evidenceUrls = evidenceUrls == null ? null : List.copyOf(evidenceUrls);
        }

        /** 1.0.x constructor without the evidence URL and contact fields. */
        public FeedbackSubmissionResponse(
                String id,
                String prefixOrIp,
                String role,
                String issueType,
                Map<String, Object> requestedCorrection,
                String createdAt,
                String status,
                List<String> evidenceUrls
        ) {
            this(id, prefixOrIp, role, issueType, requestedCorrection, createdAt, status, evidenceUrls,
                    null, null, null);
        }
    }

    /** Public service health and active snapshot status ({@code GET /v1/status}). */
    public record ServiceStatusResponse(
            String status,
            String currentVersion,
            String previousVersion
    ) {}

    /**
     * Parsed user-scoped rate-limit headers ({@code X-RateLimit-Limit}, {@code -Remaining},
     * {@code -Reset}, {@code -Scope}).
     *
     * <p>{@code resetAfterSeconds} is the number of seconds until the window resets ({@code X-RateLimit-Reset}
     * is relative, not an epoch). {@code resetEpochSeconds} is a deprecated alias holding the same value;
     * {@code burstCapacity} and {@code rateLimitRps} are deprecated and always {@code null} because the API
     * sends no such headers.
     */
    public record RateLimitMetadata(
            Integer limitPerMinute,
            Integer remaining,
            Long resetEpochSeconds,
            String scope,
            Integer burstCapacity,
            Integer rateLimitRps,
            Long resetAfterSeconds
    ) {
        /**
         * Same value as {@link #resetAfterSeconds()}: seconds until reset. It was never an epoch.
         *
         * @deprecated use {@link #resetAfterSeconds()}
         */
        @Deprecated(since = "1.1.0")
        @Override
        public Long resetEpochSeconds() {
            return resetEpochSeconds;
        }

        /**
         * Always {@code null}: the API sends no burst header.
         *
         * @deprecated no replacement
         */
        @Deprecated(since = "1.1.0")
        @Override
        public Integer burstCapacity() {
            return burstCapacity;
        }

        /**
         * Always {@code null}: the API sends no RPS header.
         *
         * @deprecated no replacement
         */
        @Deprecated(since = "1.1.0")
        @Override
        public Integer rateLimitRps() {
            return rateLimitRps;
        }

        public RateLimitMetadata {
            if (resetAfterSeconds == null) {
                resetAfterSeconds = resetEpochSeconds;
            }
            if (resetEpochSeconds == null) {
                resetEpochSeconds = resetAfterSeconds;
            }
        }

        /** 1.0.x constructor; {@code resetEpochSeconds} is treated as seconds until reset. */
        public RateLimitMetadata(
                Integer limitPerMinute,
                Integer remaining,
                Long resetEpochSeconds,
                String scope,
                Integer burstCapacity,
                Integer rateLimitRps
        ) {
            this(limitPerMinute, remaining, resetEpochSeconds, scope, burstCapacity, rateLimitRps, resetEpochSeconds);
        }

        /** Builds metadata from the four headers the API sends. */
        public static RateLimitMetadata of(Integer limitPerMinute, Integer remaining, Long resetAfterSeconds, String scope) {
            return new RateLimitMetadata(limitPerMinute, remaining, resetAfterSeconds, scope, null, null, resetAfterSeconds);
        }

        public static RateLimitMetadata empty() {
            return of(null, null, null, null);
        }
    }

    /** Envelope containing both the typed API response data and HTTP/rate-limit metadata. */
    public record IpScopeResultWithMeta<T>(
            T data,
            int status,
            RateLimitMetadata rateLimit,
            boolean fromCache
    ) {}

    /** Telemetry for the in-memory O(1) LRU + TTL cache. */
    public record CacheStats(
            boolean enabled,
            int size,
            int maxEntries,
            Duration ttl,
            long hits,
            long misses,
            long coalescedInFlightHits
    ) {}

    /** Retry policy configuration for transient network, 5xx, and 429 errors. */
    public record RetryOptions(
            int maxRetries,
            Duration baseDelay,
            Duration maxDelay,
            boolean retryOnRateLimit
    ) {
        public static RetryOptions defaults() {
            return new RetryOptions(2, Duration.ofMillis(150), Duration.ofSeconds(3), true);
        }
    }

    /** In-memory O(1) LRU + TTL cache configuration ({@code < 400 KB} default RAM ceiling). */
    public record CacheOptions(
            boolean enabled,
            int maxEntries,
            Duration ttl
    ) {
        public static CacheOptions defaults() {
            return new CacheOptions(true, 512, Duration.ofSeconds(60));
        }

        public static CacheOptions disabled() {
            return new CacheOptions(false, 512, Duration.ofSeconds(60));
        }
    }

    /** Per-request options for cache bypass and custom headers. */
    public record RequestOptions(
            boolean bypassCache,
            Map<String, String> headers
    ) {
        public static final RequestOptions DEFAULT = new RequestOptions(false, Map.of());

        public RequestOptions {
            headers = headers == null ? Map.of() : Map.copyOf(headers);
        }

        public static RequestOptions withBypassCache() {
            return new RequestOptions(true, Map.of());
        }
    }
}
