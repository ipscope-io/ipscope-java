package io.ipscope.sdk;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.ipscope.sdk.IpScopeException.ApiException;
import io.ipscope.sdk.IpScopeException.AuthenticationException;
import io.ipscope.sdk.IpScopeException.ValidationException;
import io.ipscope.sdk.IpScopeModels.BatchLookupResponse;
import io.ipscope.sdk.IpScopeModels.CacheOptions;
import io.ipscope.sdk.IpScopeModels.DatasetsMetadataResponse;
import io.ipscope.sdk.IpScopeModels.FeedbackSubmissionInput;
import io.ipscope.sdk.IpScopeModels.FeedbackSubmissionResponse;
import io.ipscope.sdk.IpScopeModels.IpLookupResponse;
import io.ipscope.sdk.IpScopeModels.NetworkPrefixLookupResponse;
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

/**
 * Comprehensive verification suite for the IPScope Java Server-Side SDK (Sync &amp; Async).
 */
public final class IpScopeClientTest {

    public static void main(String[] args) throws Exception {
        testValidationAndStrictIpScope();
        testSyncLookupCacheAndBatchDeduplication();
        testAsyncSingleflightAndChunkedBatch();
        testNetworkCallerDatasetsFeedbackAndStatus();
        testRetriesAuthErrorOversizedGuardAndLruBounds();
        System.out.println("ALL 5 JAVA SDK TEST SUITES PASSED!");
    }

    private static Map<String, Object> makeMockIpRecord(String ip) {
        int version = ip.contains(":") ? 6 : 4;
        String cidr = version == 6 ? "2001:4860:4860::/48" : "8.8.8.0/24";

        Map<String, Object> geo = new LinkedHashMap<>();
        geo.put("country_code", "US");
        geo.put("subdivision", "California");
        geo.put("city", "Mountain View");
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
        ext.put("abuse_velocity_score", 0.02);
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
        ex.getResponseHeaders().set("X-RateLimit-Reset", "1761350400");
        ex.getResponseHeaders().set("X-RateLimit-Scope", "user");
        ex.getResponseHeaders().set("X-RateLimit-Burst", "100");
        ex.getResponseHeaders().set("X-RateLimit-RPS", "50");
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static void testValidationAndStrictIpScope() {
        assertEquals("ips_live_secret_12345", IpScopeValidator.validateApiKey("  ips_live_secret_12345  "));
        assertThrows(ValidationException.class, () -> IpScopeValidator.validateApiKey("   "));
        assertThrows(ValidationException.class, () -> IpScopeValidator.validateApiKey("ips_live_bad\nheader"));

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
            if (forbidden.contains(m.getName())) {
                throw new AssertionError("IpScopeClient must not expose account/billing method: " + m.getName());
            }
        }
        System.out.println("  [PASS] testValidationAndStrictIpScope");
    }

    private static void testSyncLookupCacheAndBatchDeduplication() throws Exception {
        AtomicInteger singleHits = new AtomicInteger();
        List<List<String>> batchSentIps = new CopyOnWriteArrayList<>();

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(Executors.newCachedThreadPool());
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
            String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
            IpScopeClient client = IpScopeClient.builder("ips_live_valid_key_12345")
                    .baseUrl(baseUrl)
                    .build();

            IpLookupResponse first = client.lookupIp("8.8.8.8");
            IpLookupResponse second = client.lookupIp("8.8.8.8");
            assertTrue(first == second, "Expected cached instance identity");
            assertEquals(1, singleHits.get());
            assertEquals("US", first.geo().countryCode());
            assertEquals(Integer.valueOf(15169), first.network().asn());
            assertEquals(Integer.valueOf(998), client.getLastRateLimit().remaining());

            BatchLookupResponse batch = client.lookupBatch(
                    List.of("8.8.8.8", "1.1.1.1", "8.8.8.8", "1.1.1.1", "9.9.9.9")
            );
            assertEquals(5, batch.count());
            assertEquals(1, batchSentIps.size());
            assertEquals(List.of("1.1.1.1", "9.9.9.9"), batchSentIps.get(0));

            // Streaming batch over 250 IPs
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
        System.out.println("  [PASS] testSyncLookupCacheAndBatchDeduplication");
    }

    private static void testAsyncSingleflightAndChunkedBatch() throws Exception {
        AtomicInteger singleHits = new AtomicInteger();

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(Executors.newCachedThreadPool());
        server.createContext("/v1/ip/8.8.8.8", ex -> {
            singleHits.incrementAndGet();
            try {
                Thread.sleep(25);
            } catch (InterruptedException ignored) {}
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
            String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
            IpScopeClient client = IpScopeClient.builder("ips_live_valid_key_12345")
                    .baseUrl(baseUrl)
                    .build();

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
        System.out.println("  [PASS] testAsyncSingleflightAndChunkedBatch");
    }

    private static void testNetworkCallerDatasetsFeedbackAndStatus() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(Executors.newCachedThreadPool());
        server.createContext("/v1/networks/8.8.8.0/24", ex -> sendJson(ex, 200, Map.of(
                "queried_cidr", "8.8.8.0/24",
                "family", 4,
                "dataset_version", "2026.10.25-001",
                "record", Map.of(
                        "prefix", "8.8.8.0/24",
                        "family", 4,
                        "asn", 15169,
                        "organization", "Google LLC",
                        "country_code", "US"
                )
        )));
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
        server.createContext("/v1/feedback", ex -> sendJson(ex, 201, Map.of(
                "id", "fb_java_999",
                "prefix_or_ip", "8.8.8.8",
                "role", "network_operator",
                "issue_type", "wrong_country",
                "requested_correction", Map.of("country_code", "US"),
                "created_at", "2026-10-25T10:00:00Z",
                "status", "pending_review"
        )));
        server.createContext("/v1/status", ex -> sendJson(ex, 200, Map.of(
                "status", "ok",
                "snapshot", Map.of(
                        "currentVersion", "2026.10.25-001",
                        "previousVersion", "2026.10.24-001"
                )
        )));
        server.start();

        try {
            String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
            IpScopeClient client = IpScopeClient.builder("ips_live_valid_key_12345")
                    .baseUrl(baseUrl)
                    .build();

            NetworkPrefixLookupResponse net = client.lookupNetwork("8.8.8.0/24");
            assertEquals("8.8.8.0/24", net.queriedCidr());
            assertEquals(Integer.valueOf(15169), net.record().asn());

            IpLookupResponse caller = client.lookupCallerIp();
            assertEquals("203.0.113.42", caller.ip());

            DatasetsMetadataResponse meta = client.getDatasetsMetadata();
            assertEquals("2026.10.25-001", meta.activeVersion());
            assertEquals(1, meta.snapshots().size());

            FeedbackSubmissionResponse fb = client.submitFeedback(new FeedbackSubmissionInput(
                    "8.8.8.8",
                    "network_operator",
                    "wrong_country",
                    Map.of("country_code", "US"),
                    null
            ));
            assertEquals("fb_java_999", fb.id());

            ServiceStatusResponse status = client.getStatus();
            assertEquals("ok", status.status());
            assertEquals("2026.10.25-001", status.currentVersion());
        } finally {
            server.stop(0);
        }
        System.out.println("  [PASS] testNetworkCallerDatasetsFeedbackAndStatus");
    }

    private static void testRetriesAuthErrorOversizedGuardAndLruBounds() throws Exception {
        AtomicInteger attempts = new AtomicInteger();

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(Executors.newCachedThreadPool());
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
            String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
            IpScopeClient client = IpScopeClient.builder("ips_live_valid_key_12345")
                    .baseUrl(baseUrl)
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
        System.out.println("  [PASS] testRetriesAuthErrorOversizedGuardAndLruBounds");
    }

    private static void assertEquals(Object expected, Object actual) {
        if (expected == null ? actual != null : !expected.equals(actual)) {
            throw new AssertionError("Expected <" + expected + "> but got <" + actual + ">");
        }
    }

    private static void assertTrue(boolean cond, String msg) {
        if (!cond) {
            throw new AssertionError(msg);
        }
    }

    private static <T extends Throwable> T assertThrows(Class<T> expectedType, Runnable runnable) {
        try {
            runnable.run();
        } catch (Throwable t) {
            if (expectedType.isInstance(t)) {
                return expectedType.cast(t);
            }
            throw new AssertionError("Expected exception " + expectedType.getSimpleName() + " but got " + t, t);
        }
        throw new AssertionError("Expected exception " + expectedType.getSimpleName() + " but nothing was thrown");
    }
}
