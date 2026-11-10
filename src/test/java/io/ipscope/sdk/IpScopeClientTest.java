package io.ipscope.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.ipscope.sdk.IpScopeException.ApiException;
import io.ipscope.sdk.IpScopeException.AuthenticationException;
import io.ipscope.sdk.IpScopeException.ValidationException;
import io.ipscope.sdk.IpScopeModels.BatchLookupResponse;
import io.ipscope.sdk.IpScopeModels.CacheOptions;
import io.ipscope.sdk.IpScopeModels.CanonicalNetworkPrefixRecord;
import io.ipscope.sdk.IpScopeModels.DatasetsMetadataResponse;
import io.ipscope.sdk.IpScopeModels.FeedbackSubmissionInput;
import io.ipscope.sdk.IpScopeModels.FeedbackSubmissionResponse;
import io.ipscope.sdk.IpScopeModels.IpLookupResponse;
import io.ipscope.sdk.IpScopeModels.NetworkPrefixLookupResponse;
import io.ipscope.sdk.IpScopeModels.RateLimitMetadata;
import io.ipscope.sdk.IpScopeModels.RequestOptions;
import io.ipscope.sdk.IpScopeModels.RetryOptions;
import io.ipscope.sdk.IpScopeModels.ServiceStatusResponse;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/**
 * Verification suite for the IPScope Java Server-Side SDK (Sync &amp; Async), run by {@code mvn test}.
 */
class IpScopeClientTest {

    private static final String TEST_KEY =
            "00000000-0000-4000-8000-000000000000:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    private static Map<String, Object> makeMockIpRecord(String ip) {
        int version = ip.contains(":") ? 6 : 4;
        String cidr = version == 6 ? "2001:4860:4860::/48" : "8.8.8.0/24";

        Map<String, Object> geo = new LinkedHashMap<>();
        geo.put("country_code", "US");
        geo.put("subdivision", "California");
        geo.put("city", "Mountain View");
        geo.put("postal_code", "94043");
        geo.put("latitude", 37.422);
        geo.put("longitude", -122.085);
        geo.put("timezone", "America/Los_Angeles");
        geo.put("location_type", "anycast");
        geo.put("confidence", 0.96);
        geo.put("accuracy_radius_km", 20.0);
        geo.put("declared_country_code", "US");
        geo.put("physical_country_code", "US");
        geo.put("is_virtual_location", false);

        Map<String, Object> net = new LinkedHashMap<>();
        net.put("asn", 15169);
        net.put("organization", "Google LLC");

        Map<String, Object> sec = new LinkedHashMap<>();
        sec.put("is_vpn", false);
        sec.put("is_hosting", true);
        sec.put("is_tor_exit", false);
        sec.put("is_proxy", false);
        sec.put("is_relay", false);
        sec.put("anonymizer_type", "none");
        sec.put("confidence", 0.99);
        sec.put("reason_codes", List.of("ASN_HOSTING"));

        Map<String, Object> conn = new LinkedHashMap<>();
        conn.put("connection_type", "hosting");
        conn.put("is_residential", false);
        conn.put("is_mobile", false);
        conn.put("is_business", false);
        conn.put("is_hosting", true);

        Map<String, Object> ext = new LinkedHashMap<>();
        ext.put("abuse_velocity_score", 80);
        ext.put("is_known_scanner", false);
        ext.put("observation_recency_hours", 1.5);

        Map<String, Object> rec = new LinkedHashMap<>();
        rec.put("ip", ip);
        rec.put("ip_version", version);
        rec.put("matched_network", cidr);
        rec.put("geo", geo);
        rec.put("network", net);
        rec.put("security", sec);
        rec.put("connection", conn);
        rec.put("security_extensions", ext);
        rec.put("dataset_version", "2026.10.25-001");
        rec.put("updated_at", "2026-10-25T00:00:00Z");
        return rec;
    }

    private static void sendJson(HttpExchange ex, int status, Map<String, Object> payload) throws IOException {
        byte[] bytes = JsonCodec.toJson(payload).getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.getResponseHeaders().set("X-RateLimit-Limit", "1000");
        ex.getResponseHeaders().set("X-RateLimit-Remaining", "998");
        ex.getResponseHeaders().set("X-RateLimit-Reset", "42");
        ex.getResponseHeaders().set("X-RateLimit-Scope", "user");
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static HttpServer startServer() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(Executors.newCachedThreadPool());
        return server;
    }

    private static String baseUrl(HttpServer server) {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @Test
    void validationAndStrictIpScope() {
        assertEquals(TEST_KEY, IpScopeValidator.validateApiKey("  " + TEST_KEY + "  "));
        assertThrows(ValidationException.class, () -> IpScopeValidator.validateApiKey("   "));
        assertThrows(ValidationException.class, () -> IpScopeValidator.validateApiKey("bad\nheader"));

        var v4 = IpScopeValidator.validateIpAddress(" 8.8.8.8 ");
        assertEquals("8.8.8.8", v4.canonicalIp());
        assertEquals(4, v4.family());

        var v6 = IpScopeValidator.validateIpAddress("2001:0db8:0000:0000:0000:0000:0000:0001");
        assertEquals("2001:db8::1", v6.canonicalIp());
        assertEquals(6, v6.family());

        assertThrows(ValidationException.class, () -> IpScopeValidator.validateIpAddress("999.999.999.999"));
        assertThrows(ValidationException.class, () -> IpScopeValidator.validateIpAddress("example.com"));

        var cidr = IpScopeValidator.validateCidrPrefix("8.8.8.99/24");
        assertEquals("8.8.8.0", cidr.address());
        assertEquals(24, cidr.prefixLength());
        assertEquals("8.8.8.0/24", cidr.canonicalCidr());

        Set<String> forbidden = Set.of(
                "getWallet", "topUpWallet", "createCheckout", "listApiKeys",
                "createApiKey", "revokeApiKey", "login", "register", "getBilling"
        );
        for (Method m : IpScopeClient.class.getDeclaredMethods()) {
            assertFalse(forbidden.contains(m.getName()),
                    "IpScopeClient must not expose account/billing method: " + m.getName());
        }
        assertEquals("ipscope-java/1.1.0", HttpTransport.SDK_USER_AGENT);
    }

    @Test
    void syncLookupCacheAndBatchDeduplication() throws Exception {
        AtomicInteger singleHits = new AtomicInteger();
        List<List<String>> batchSentIps = new CopyOnWriteArrayList<>();

        HttpServer server = startServer();
        server.createContext("/v1/ip/8.8.8.8", ex -> {
            singleHits.incrementAndGet();
            sendJson(ex, 200, makeMockIpRecord("8.8.8.8"));
        });
        server.createContext("/v1/ip/batch", ex -> {
            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            Map<String, Object> parsed = JsonCodec.parseObject(body);
            @SuppressWarnings("unchecked")
            List<Object> rawList = (List<Object>) parsed.get("ips");
            List<String> ips = new ArrayList<>();
            List<Map<String, Object>> results = new ArrayList<>();
            for (Object item : rawList) {
                String ip = String.valueOf(item);
                ips.add(ip);
                results.add(makeMockIpRecord(ip));
            }
            batchSentIps.add(ips);
            sendJson(ex, 200, Map.of(
                    "dataset_version", "2026.10.25-001",
                    "count", results.size(),
                    "results", results
            ));
        });
        server.start();

        try {
            IpScopeClient client = IpScopeClient.builder(TEST_KEY).baseUrl(baseUrl(server)).build();

            IpLookupResponse first = client.lookupIp("8.8.8.8");
            IpLookupResponse second = client.lookupIp("8.8.8.8");
            assertSame(first, second, "Expected cached instance identity");
            assertEquals(1, singleHits.get());
            assertEquals("US", first.geo().countryCode());
            assertEquals(Integer.valueOf(15169), first.network().asn());

            // New 1.1.0 fields
            assertEquals(Double.valueOf(37.422), first.geo().latitude());
            assertEquals(Double.valueOf(-122.085), first.geo().longitude());
            assertEquals("94043", first.geo().postalCode());
            assertEquals(Boolean.FALSE, first.security().isRelay());
            assertEquals(Double.valueOf(80.0), first.securityExtensions().abuseVelocityScore());

            RateLimitMetadata rl = client.getLastRateLimit();
            assertEquals(Integer.valueOf(1000), rl.limitPerMinute());
            assertEquals(Integer.valueOf(998), rl.remaining());
            assertEquals(Long.valueOf(42), rl.resetAfterSeconds());
            assertEquals("user", rl.scope());
            assertDeprecatedRateLimitAliases(rl);

            BatchLookupResponse batch = client.lookupBatch(
                    List.of("8.8.8.8", "1.1.1.1", "8.8.8.8", "1.1.1.1", "9.9.9.9")
            );
            assertEquals(5, batch.count());
            assertEquals(1, batchSentIps.size());
            assertEquals(List.of("1.1.1.1", "9.9.9.9"), batchSentIps.get(0));

            List<String> largeIps = new ArrayList<>(250);
            for (int i = 1; i <= 250; i++) {
                largeIps.add("10.0.0." + i);
            }
            int streamedTotal = client.lookupBatchStream(largeIps, RequestOptions.withBypassCache())
                    .mapToInt(BatchLookupResponse::count)
                    .sum();
            assertEquals(250, streamedTotal);
        } finally {
            server.stop(0);
        }
    }

    @SuppressWarnings("deprecation")
    private static void assertDeprecatedRateLimitAliases(RateLimitMetadata rl) {
        assertEquals(Long.valueOf(42), rl.resetEpochSeconds());
        assertNull(rl.burstCapacity());
        assertNull(rl.rateLimitRps());
        RateLimitMetadata legacy = new RateLimitMetadata(10, 9, 30L, "user", null, null);
        assertEquals(Long.valueOf(30), legacy.resetAfterSeconds());
    }

    @Test
    void asyncSingleflightAndChunkedBatch() throws Exception {
        AtomicInteger singleHits = new AtomicInteger();

        HttpServer server = startServer();
        server.createContext("/v1/ip/8.8.8.8", ex -> {
            singleHits.incrementAndGet();
            try {
                Thread.sleep(25);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
            sendJson(ex, 200, makeMockIpRecord("8.8.8.8"));
        });
        server.createContext("/v1/ip/batch", ex -> {
            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            Map<String, Object> parsed = JsonCodec.parseObject(body);
            @SuppressWarnings("unchecked")
            List<Object> rawList = (List<Object>) parsed.get("ips");
            List<Map<String, Object>> results = new ArrayList<>();
            for (Object item : rawList) {
                results.add(makeMockIpRecord(String.valueOf(item)));
            }
            sendJson(ex, 200, Map.of(
                    "dataset_version", "2026.10.25-001",
                    "count", results.size(),
                    "results", results
            ));
        });
        server.start();

        try {
            IpScopeClient client = IpScopeClient.builder(TEST_KEY).baseUrl(baseUrl(server)).build();

            List<CompletableFuture<IpLookupResponse>> futures = new ArrayList<>();
            for (int i = 0; i < 20; i++) {
                futures.add(client.lookupIpAsync("8.8.8.8"));
            }
            CompletableFuture.allOf(futures.toArray(CompletableFuture<?>[]::new)).join();
            assertEquals(1, singleHits.get());
            assertTrue(client.getCacheStats().coalescedInFlightHits() > 0, "Expected singleflight hits");

            List<String> largeIps = new ArrayList<>(250);
            for (int i = 1; i <= 250; i++) {
                largeIps.add("192.0.2." + i);
            }
            BatchLookupResponse asyncBatch = client.lookupBatchChunkedAsync(
                    largeIps,
                    3,
                    RequestOptions.withBypassCache()
            ).join();
            assertEquals(250, asyncBatch.count());
        } finally {
            server.stop(0);
        }
    }

    @Test
    void networkCallerDatasetsFeedbackAndStatus() throws Exception {
        List<Map<String, Object>> feedbackBodies = new CopyOnWriteArrayList<>();

        Map<String, Object> record = new LinkedHashMap<>();
        record.put("family", 4);
        record.put("prefix", "8.8.8.0/24");
        record.put("asn", 15169);
        record.put("organization", "Google LLC");
        record.put("locations", Map.of());
        record.put("countryCode", "US");
        record.put("subdivision", "California");
        record.put("city", "Mountain View");
        record.put("postalCode", "94043");
        record.put("latitude", 37.422);
        record.put("longitude", -122.085);
        record.put("timezone", "America/Los_Angeles");
        record.put("locationType", "declared");
        record.put("geoConfidence", 0.85);
        record.put("accuracyRadiusKm", 300);
        record.put("isVirtualLocation", null);
        record.put("connectionType", "hosting");
        record.put("isHosting", true);
        record.put("isVpn", false);
        record.put("isTorExit", false);
        record.put("isProxy", false);
        record.put("anonymizerType", "none");
        record.put("securityConfidence", 0.85);
        record.put("abuseVelocityScore", 80);
        record.put("isKnownScanner", false);
        record.put("reasonCodes", List.of("KNOWN_HOSTING_INFRASTRUCTURE_RANGE"));
        record.put("sourceIds", List.of("bgp"));
        record.put("licensePolicyIds", List.of("cc0"));
        record.put("updatedAt", "2026-11-10T03:02:07.437Z");

        Map<String, Object> netPayload = new LinkedHashMap<>();
        netPayload.put("queried_cidr", "8.8.8.0/24");
        netPayload.put("matched_network", "8.8.8.0/24");
        netPayload.put("family", 4);
        netPayload.put("bgp_prefix_length", 24);
        netPayload.put("dataset_version", "2026.10.25-001");
        netPayload.put("record", record);
        netPayload.put("lookup", makeMockIpRecord("8.8.8.0"));

        HttpServer server = startServer();
        server.createContext("/v1/networks/8.8.8.0/24", ex -> sendJson(ex, 200, netPayload));
        server.createContext("/v1/ip/me", ex -> sendJson(ex, 200, makeMockIpRecord("203.0.113.42")));
        server.createContext("/v1/metadata/datasets", ex -> sendJson(ex, 200, Map.of(
                "active_version", "2026.10.25-001",
                "previous_version", "2026.10.24-001",
                "snapshots", List.of(Map.of(
                        "snapshot_version", "2026.10.25-001",
                        "digest", "sha256:abc123",
                        "ruleset_version", "v1",
                        "published_at", "2026-10.25T00:00:00Z",
                        "ipv4_prefix_count", 950000,
                        "ipv6_prefix_count", 220000
                ))
        )));
        server.createContext("/v1/feedback", ex -> {
            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            Map<String, Object> parsed = JsonCodec.parseObject(body);
            feedbackBodies.add(parsed);
            // Echo the payload the way the API does: dto spread + id, camelCase createdAt, status.
            Map<String, Object> echo = new LinkedHashMap<>(parsed);
            echo.put("id", "fb_java_999");
            echo.put("createdAt", "2026-10-25T10:00:00Z");
            echo.put("status", "pending_review");
            sendJson(ex, 201, echo);
        });
        server.createContext("/v1/status", ex -> sendJson(ex, 200, Map.of(
                "status", "ok",
                "snapshot", Map.of(
                        "currentVersion", "2026.10.25-001",
                        "previousVersion", "2026.10.24-001"
                )
        )));
        server.start();

        try {
            IpScopeClient client = IpScopeClient.builder(TEST_KEY).baseUrl(baseUrl(server)).build();

            NetworkPrefixLookupResponse net = client.lookupNetwork("8.8.8.0/24");
            assertEquals("8.8.8.0/24", net.queriedCidr());
            assertEquals("8.8.8.0/24", net.matchedNetwork());
            assertEquals(Integer.valueOf(24), net.bgpPrefixLength());
            assertEquals("8.8.8.0", net.lookup().ip());
            assertEquals(Double.valueOf(37.422), net.lookup().geo().latitude());
            CanonicalNetworkPrefixRecord rec = net.record();
            assertEquals(Integer.valueOf(15169), rec.asn());
            assertEquals("US", rec.countryCode());
            assertEquals("94043", rec.postalCode());
            assertEquals(Double.valueOf(37.422), rec.latitude());
            assertEquals("declared", rec.locationType());
            assertEquals(Double.valueOf(0.85), rec.geoConfidence());
            assertEquals(Double.valueOf(300.0), rec.accuracyRadiusKm());
            assertEquals("hosting", rec.connectionType());
            assertEquals(Boolean.TRUE, rec.isHosting());
            assertEquals(Boolean.FALSE, rec.isVpn());
            assertEquals("none", rec.anonymizerType());
            assertEquals(Double.valueOf(80.0), rec.abuseVelocityScore());
            assertEquals(List.of("KNOWN_HOSTING_INFRASTRUCTURE_RANGE"), rec.reasonCodes());
            assertEquals("2026-11-10T03:02:07.437Z", rec.updatedAt());

            IpLookupResponse caller = client.lookupCallerIp();
            assertEquals("203.0.113.42", caller.ip());

            DatasetsMetadataResponse meta = client.getDatasetsMetadata();
            assertEquals("2026.10.25-001", meta.activeVersion());
            assertEquals(1, meta.snapshots().size());

            FeedbackSubmissionResponse fb = client.submitFeedback(
                    new FeedbackSubmissionInput("8.8.8.8", "network_owner", "wrong_country", Map.of("country_code", "US"))
                            .withEvidenceUrl("https://example.net/geofeed.csv")
                            .withContact("noc@example.net", true)
            );
            assertEquals("fb_java_999", fb.id());
            assertEquals("2026-10-25T10:00:00Z", fb.createdAt());
            assertEquals("network_owner", fb.role());
            assertEquals("https://example.net/geofeed.csv", fb.evidenceUrl());
            assertEquals(Boolean.TRUE, fb.contactConsent());
            assertEquals("noc@example.net", fb.contactEmail());

            Map<String, Object> sent = feedbackBodies.get(0);
            assertEquals("https://example.net/geofeed.csv", sent.get("evidence_url"));
            assertEquals(Boolean.TRUE, sent.get("contact_consent"));
            assertEquals("noc@example.net", sent.get("contact_email"));
            assertFalse(sent.containsKey("evidence_urls"));

            submitLegacyFeedback(client);
            Map<String, Object> legacySent = feedbackBodies.get(1);
            assertEquals("https://example.net/rdap", legacySent.get("evidence_url"));
            assertFalse(legacySent.containsKey("evidence_urls"));
            assertFalse(legacySent.containsKey("contact_email"));
            assertFalse(legacySent.containsKey("contact_consent"));

            ServiceStatusResponse status = client.getStatus();
            assertEquals("ok", status.status());
            assertEquals("2026.10.25-001", status.currentVersion());
        } finally {
            server.stop(0);
        }
    }

    @SuppressWarnings("deprecation")
    private static void submitLegacyFeedback(IpScopeClient client) {
        // 1.0.x constructor: the first evidence URL is sent as `evidence_url`.
        FeedbackSubmissionInput legacy = new FeedbackSubmissionInput(
                "8.8.8.0/24", "researcher", "other", Map.of(), List.of(" ", "https://example.net/rdap"));
        assertEquals(List.of("https://example.net/rdap"), legacy.evidenceUrls());
        client.submitFeedback(legacy);
    }

    @Test
    void wireCompatibilityOfNewFields() {
        // abuse_velocity_score: integer 0-100 (new) and legacy fraction both parse.
        Map<String, Object> raw = makeMockIpRecord("146.75.164.1");
        @SuppressWarnings("unchecked")
        Map<String, Object> ext = (Map<String, Object>) raw.get("security_extensions");
        ext.put("abuse_velocity_score", 0.14);
        assertEquals(Double.valueOf(0.14),
                JsonCodec.toIpLookupResponse(raw).securityExtensions().abuseVelocityScore());
        ext.put("abuse_velocity_score", null);
        assertNull(JsonCodec.toIpLookupResponse(raw).securityExtensions().abuseVelocityScore());

        // Payloads without the new optional fields still parse.
        @SuppressWarnings("unchecked")
        Map<String, Object> geo = (Map<String, Object>) raw.get("geo");
        geo.remove("latitude");
        geo.remove("postal_code");
        @SuppressWarnings("unchecked")
        Map<String, Object> sec = (Map<String, Object>) raw.get("security");
        sec.remove("is_relay");
        IpLookupResponse parsed = JsonCodec.toIpLookupResponse(raw);
        assertNull(parsed.geo().latitude());
        assertNull(parsed.geo().postalCode());
        assertNull(parsed.security().isRelay());

        // Feedback response reads snake_case created_at too.
        FeedbackSubmissionResponse fb = JsonCodec.toFeedbackSubmissionResponse(JsonCodec.parseObject(
                "{\"id\":\"fb_1\",\"prefix_or_ip\":\"8.8.8.8\",\"role\":\"user\",\"issue_type\":\"wrong_city\","
                        + "\"requested_correction\":{},\"created_at\":\"2026-10-25T10:00:00Z\",\"status\":\"pending_review\"}"));
        assertEquals("2026-10-25T10:00:00Z", fb.createdAt());

        // Network record still reads snake_case keys; missing new fields stay null.
        NetworkPrefixLookupResponse net = JsonCodec.toNetworkPrefixLookupResponse(JsonCodec.parseObject(
                "{\"queried_cidr\":\"10.0.0.0/8\",\"family\":4,\"dataset_version\":\"v\","
                        + "\"record\":{\"prefix\":\"10.0.0.0/8\",\"family\":4,\"country_code\":\"ZZ\",\"is_vpn\":false}}"));
        assertEquals("ZZ", net.record().countryCode());
        assertEquals(Boolean.FALSE, net.record().isVpn());
        assertNull(net.matchedNetwork());
        assertNull(net.lookup());

        assertTrue(IpScopeModels.FEEDBACK_ROLES.contains("network_owner"));
        assertTrue(IpScopeModels.FEEDBACK_ISSUE_TYPES.contains("virtual_location_mismatch"));
    }

    @Test
    void retriesAuthErrorOversizedGuardAndLruBounds() throws Exception {
        AtomicInteger attempts = new AtomicInteger();

        HttpServer server = startServer();
        server.createContext("/v1/ip/1.1.1.1", ex -> {
            int n = attempts.incrementAndGet();
            if (n == 1) {
                ex.getResponseHeaders().set("Retry-After", "0.005");
                sendJson(ex, 429, Map.of("message", "Rate limit exceeded"));
                return;
            }
            if (n == 2) {
                sendJson(ex, 503, Map.of("message", "Service unavailable"));
                return;
            }
            sendJson(ex, 200, makeMockIpRecord("1.1.1.1"));
        });
        server.createContext("/v1/ip/8.8.4.4", ex -> sendJson(ex, 401, Map.of("message", "Invalid API Key")));
        server.createContext("/v1/ip/9.9.9.9", ex -> {
            byte[] oversized = new byte[HttpTransport.MAX_RESPONSE_BYTES + 64];
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(200, oversized.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(oversized);
            }
        });
        server.createContext("/v1/ip/", ex -> {
            String path = ex.getRequestURI().getPath();
            String ip = path.substring(path.lastIndexOf('/') + 1);
            sendJson(ex, 200, makeMockIpRecord(ip));
        });
        server.start();

        try {
            IpScopeClient client = IpScopeClient.builder(TEST_KEY)
                    .baseUrl(baseUrl(server))
                    .retry(new RetryOptions(3, Duration.ofMillis(5), Duration.ofMillis(20), true))
                    .cache(new CacheOptions(true, 3, Duration.ofSeconds(60)))
                    .build();

            IpLookupResponse rec = client.lookupIp("1.1.1.1");
            assertEquals("1.1.1.1", rec.ip());
            assertEquals(3, attempts.get());

            assertThrows(AuthenticationException.class, () -> client.lookupIp("8.8.4.4"));

            ApiException sizeErr = assertThrows(ApiException.class, () -> client.lookupIp("9.9.9.9"));
            assertEquals("IPSCOPE_RESPONSE_TOO_LARGE", sizeErr.getCode());

            for (int i = 1; i <= 12; i++) {
                client.lookupIp("10.0.0." + i);
            }
            assertTrue(client.getCacheStats().size() <= 3, "LRU cache must not exceed maxEntries=3");
        } finally {
            server.stop(0);
        }
    }
}
