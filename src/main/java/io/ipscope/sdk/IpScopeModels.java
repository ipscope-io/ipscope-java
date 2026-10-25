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

    /** Geographic classification and confidence returned in {@link IpLookupResponse#geo()}. */
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
            Boolean isVirtualLocation
    ) {}

    /** Autonomous System and network operator details returned in {@link IpLookupResponse#network()}. */
    public record NetworkBlock(
            Integer asn,
            String organization
    ) {}

    /** Security, hosting, and anonymity classification returned in {@link IpLookupResponse#security()}. */
    public record SecurityBlock(
            Boolean isVpn,
            Boolean isHosting,
            Boolean isTorExit,
            Boolean isProxy,
            String anonymizerType,
            double confidence,
            List<String> reasonCodes
    ) {
        public SecurityBlock {
            reasonCodes = reasonCodes == null ? List.of() : List.copyOf(reasonCodes);
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

    /** Optional security extensions telemetry block returned when licensed. */
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

    /** Canonical network prefix record returned in {@code GET /v1/networks/:prefix/:length}. */
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
            String anonymizerType
    ) {}

    /** Network CIDR prefix lookup response ({@code GET /v1/networks/:prefix/:length}). */
    public record NetworkPrefixLookupResponse(
            String queriedCidr,
            int family,
            String datasetVersion,
            CanonicalNetworkPrefixRecord record
    ) {}

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

    /** Input payload for submitting IP/prefix correction feedback ({@code POST /v1/feedback}). */
    public record FeedbackSubmissionInput(
            String prefixOrIp,
            String role,
            String issueType,
            Map<String, Object> requestedCorrection,
            List<String> evidenceUrls
    ) {
        public FeedbackSubmissionInput {
            requestedCorrection = requestedCorrection == null
                    ? Map.of()
                    : Collections.unmodifiableMap(requestedCorrection);
            evidenceUrls = evidenceUrls == null ? null : List.copyOf(evidenceUrls);
        }
    }

    /** Response returned when submitting IP/prefix correction feedback ({@code POST /v1/feedback}). */
    public record FeedbackSubmissionResponse(
            String id,
            String prefixOrIp,
            String role,
            String issueType,
            Map<String, Object> requestedCorrection,
            String createdAt,
            String status,
            List<String> evidenceUrls
    ) {
        public FeedbackSubmissionResponse {
            requestedCorrection = requestedCorrection == null
                    ? Map.of()
                    : Collections.unmodifiableMap(requestedCorrection);
            evidenceUrls = evidenceUrls == null ? null : List.copyOf(evidenceUrls);
        }
    }

    /** Public service health and active snapshot status ({@code GET /v1/status}). */
    public record ServiceStatusResponse(
            String status,
            String currentVersion,
            String previousVersion
    ) {}

    /** Parsed user-scoped rate-limit headers returned by {@code @ipscope/api}. */
    public record RateLimitMetadata(
            Integer limitPerMinute,
            Integer remaining,
            Long resetEpochSeconds,
            String scope,
            Integer burstCapacity,
            Integer rateLimitRps
    ) {
        public static RateLimitMetadata empty() {
            return new RateLimitMetadata(null, null, null, null, null, null);
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
