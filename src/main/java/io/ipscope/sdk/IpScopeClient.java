package io.ipscope.sdk;

import io.ipscope.sdk.HttpTransport.TransportResponse;
import io.ipscope.sdk.IpScopeException.ValidationException;
import io.ipscope.sdk.IpScopeModels.BatchLookupResponse;
import io.ipscope.sdk.IpScopeModels.CacheOptions;
import io.ipscope.sdk.IpScopeModels.CacheStats;
import io.ipscope.sdk.IpScopeModels.DatasetsMetadataResponse;
import io.ipscope.sdk.IpScopeModels.FeedbackSubmissionInput;
import io.ipscope.sdk.IpScopeModels.FeedbackSubmissionResponse;
import io.ipscope.sdk.IpScopeModels.IpLookupResponse;
import io.ipscope.sdk.IpScopeModels.IpScopeResultWithMeta;
import io.ipscope.sdk.IpScopeModels.NetworkPrefixLookupResponse;
import io.ipscope.sdk.IpScopeModels.RateLimitMetadata;
import io.ipscope.sdk.IpScopeModels.RequestOptions;
import io.ipscope.sdk.IpScopeModels.RetryOptions;
import io.ipscope.sdk.IpScopeModels.ServiceStatusResponse;
import io.ipscope.sdk.IpScopeValidator.ValidatedBatch;
import io.ipscope.sdk.IpScopeValidator.ValidatedCidr;
import io.ipscope.sdk.IpScopeValidator.ValidatedIp;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

/**
 * Official thread-safe Sync &amp; Async Server-Side Java Client for the IPScope IP Intelligence API.
 *
 * <p>Scope Notice: Strictly limited to IP intelligence, network CIDR prefix, dataset metadata,
 * feedback, and service status operations. Exposes zero account, wallet, or billing operations.
 */
public final class IpScopeClient implements AutoCloseable {

    private final HttpTransport transport;
    private final LruTtlCache<IpLookupResponse> ipCache;
    private final LruTtlCache<NetworkPrefixLookupResponse> networkCache;

    /** Creates a new {@link IpScopeClient} with default configuration for the given API key. */
    public IpScopeClient(String apiKey) {
        this(builder(apiKey));
    }

    private IpScopeClient(Builder b) {
        this.transport = new HttpTransport(
                b.apiKey,
                b.baseUrl,
                b.timeout,
                b.retry,
                b.userAgent,
                b.httpClient
        );
        CacheOptions cacheOpts = b.cache != null ? b.cache : CacheOptions.defaults();
        this.ipCache = new LruTtlCache<>(cacheOpts);
        this.networkCache = new LruTtlCache<>(new CacheOptions(
                cacheOpts.enabled(),
                Math.min(128, Math.max(1, cacheOpts.maxEntries())),
                cacheOpts.ttl()
        ));
    }

    /** Creates a fluent {@link Builder} for configuring an {@link IpScopeClient}. */
    public static Builder builder(String apiKey) {
        return new Builder(apiKey);
    }

    // =========================================================================
    // Synchronous Operations
    // =========================================================================

    /** Looks up intelligence for a single IPv4 or IPv6 address ({@code GET /v1/ip/:ip}). */
    public IpLookupResponse lookupIp(String rawIp) {
        return lookupIp(rawIp, RequestOptions.DEFAULT);
    }

    /** Looks up intelligence for a single IPv4 or IPv6 address with per-request options. */
    public IpLookupResponse lookupIp(String rawIp, RequestOptions options) {
        return lookupIpWithMeta(rawIp, options).data();
    }

    /** Looks up a single IPv4 or IPv6 address and returns both data and rate-limit metadata. */
    public IpScopeResultWithMeta<IpLookupResponse> lookupIpWithMeta(String rawIp) {
        return lookupIpWithMeta(rawIp, RequestOptions.DEFAULT);
    }

    /** Looks up a single IPv4 or IPv6 address with options and returns both data and rate-limit metadata. */
    public IpScopeResultWithMeta<IpLookupResponse> lookupIpWithMeta(String rawIp, RequestOptions options) {
        RequestOptions opts = options != null ? options : RequestOptions.DEFAULT;
        ValidatedIp vIp = IpScopeValidator.validateIpAddress(rawIp);
        String ipStr = vIp.canonicalIp();

        if (!opts.bypassCache()) {
            IpLookupResponse cached = ipCache.get(ipStr);
            if (cached != null) {
                RateLimitMetadata rl = transport.getLastRateLimit();
                return new IpScopeResultWithMeta<>(
                        cached,
                        200,
                        rl != null ? rl : RateLimitMetadata.empty(),
                        true
                );
            }
        }

        String path = "/v1/ip/" + urlEncodeSegment(ipStr);
        TransportResponse resp = transport.requestSync("GET", path, null, opts.headers(), true);
        IpLookupResponse parsed = JsonCodec.toIpLookupResponse(resp.parsedBody());
        ipCache.set(ipStr, parsed);
        String canonicalLower = parsed.ip().toLowerCase(Locale.ROOT);
        if (!canonicalLower.equals(ipStr)) {
            ipCache.set(canonicalLower, parsed);
        }

        return new IpScopeResultWithMeta<>(parsed, resp.status(), resp.rateLimit(), false);
    }

    /** Looks up intelligence for the caller's own server-observed IP ({@code GET /v1/ip/me}). */
    public IpLookupResponse lookupCallerIp() {
        return lookupCallerIp(RequestOptions.DEFAULT);
    }

    /** Looks up intelligence for the caller's own server-observed IP with options. */
    public IpLookupResponse lookupCallerIp(RequestOptions options) {
        RequestOptions opts = options != null ? options : RequestOptions.DEFAULT;
        TransportResponse resp = transport.requestSync("GET", "/v1/ip/me", null, opts.headers(), true);
        return JsonCodec.toIpLookupResponse(resp.parsedBody());
    }

    /**
     * Performs a batch lookup for 1..100 IPs ({@code POST /v1/ip/batch}), deduplicating wire
     * requests and reusing warm LRU cache entries automatically.
     */
    public BatchLookupResponse lookupBatch(List<String> rawIps) {
        return lookupBatch(rawIps, RequestOptions.DEFAULT);
    }

    /** Performs a batch lookup for 1..100 IPs with per-request options. */
    public BatchLookupResponse lookupBatch(List<String> rawIps, RequestOptions options) {
        RequestOptions opts = options != null ? options : RequestOptions.DEFAULT;
        ValidatedBatch batch = IpScopeValidator.validateAndDeduplicateBatchIps(
                rawIps,
                IpScopeValidator.MAX_SINGLE_BATCH_SIZE
        );

        Map<String, IpLookupResponse> resolvedByIp = new LinkedHashMap<>(batch.uniqueIps().size());
        List<String> missingIps = new ArrayList<>(batch.uniqueIps().size());

        if (!opts.bypassCache()) {
            for (String ipStr : batch.uniqueIps()) {
                IpLookupResponse cached = ipCache.get(ipStr);
                if (cached != null) {
                    resolvedByIp.put(ipStr, cached);
                } else {
                    missingIps.add(ipStr);
                }
            }
        } else {
            missingIps.addAll(batch.uniqueIps());
        }

        String datasetVersion = "";

        if (!missingIps.isEmpty()) {
            TransportResponse resp = transport.requestSync(
                    "POST",
                    "/v1/ip/batch",
                    Map.of("ips", missingIps),
                    opts.headers(),
                    true
            );
            BatchLookupResponse batchParsed = JsonCodec.toBatchLookupResponse(resp.parsedBody());
            datasetVersion = batchParsed.datasetVersion();

            List<IpLookupResponse> results = batchParsed.results();
            for (int i = 0; i < missingIps.size() && i < results.size(); i++) {
                String reqIp = missingIps.get(i);
                IpLookupResponse item = results.get(i);
                resolvedByIp.put(reqIp, item);
                ipCache.set(reqIp, item);
                String canonicalLower = item.ip().toLowerCase(Locale.ROOT);
                if (!canonicalLower.equals(reqIp)) {
                    ipCache.set(canonicalLower, item);
                }
            }
        }

        List<IpLookupResponse> orderedResults = new ArrayList<>(batch.orderedIps().size());
        for (String ipStr : batch.orderedIps()) {
            orderedResults.add(resolvedByIp.get(ipStr));
        }
        if (datasetVersion.isEmpty() && !orderedResults.isEmpty() && orderedResults.get(0) != null) {
            datasetVersion = orderedResults.get(0).datasetVersion();
        }

        return new BatchLookupResponse(datasetVersion, orderedResults.size(), orderedResults);
    }

    /** Performs a chunked batch lookup for &gt;100 IPs by splitting into chunks of up to 100 IPs. */
    public BatchLookupResponse lookupBatchChunked(List<String> rawIps) {
        return lookupBatchChunked(rawIps, RequestOptions.DEFAULT);
    }

    /** Performs a chunked batch lookup for &gt;100 IPs with per-request options. */
    public BatchLookupResponse lookupBatchChunked(List<String> rawIps, RequestOptions options) {
        RequestOptions opts = options != null ? options : RequestOptions.DEFAULT;
        ValidatedBatch batch = IpScopeValidator.validateAndDeduplicateBatchIps(rawIps, 0);

        Map<String, IpLookupResponse> resolvedByIp = new LinkedHashMap<>(batch.uniqueIps().size());
        String datasetVersion = "";

        List<String> unique = batch.uniqueIps();
        for (int i = 0; i < unique.size(); i += IpScopeValidator.MAX_SINGLE_BATCH_SIZE) {
            int end = Math.min(i + IpScopeValidator.MAX_SINGLE_BATCH_SIZE, unique.size());
            List<String> chunk = unique.subList(i, end);
            BatchLookupResponse chunkRes = lookupBatch(chunk, opts);
            if (datasetVersion.isEmpty() && !chunkRes.datasetVersion().isEmpty()) {
                datasetVersion = chunkRes.datasetVersion();
            }
            for (int idx = 0; idx < chunk.size() && idx < chunkRes.results().size(); idx++) {
                resolvedByIp.put(chunk.get(idx), chunkRes.results().get(idx));
            }
        }

        List<IpLookupResponse> orderedResults = new ArrayList<>(batch.orderedIps().size());
        for (String ipStr : batch.orderedIps()) {
            orderedResults.add(resolvedByIp.get(ipStr));
        }
        return new BatchLookupResponse(datasetVersion, orderedResults.size(), orderedResults);
    }

    /**
     * Constant-RAM lazy {@link Stream} yielding {@link BatchLookupResponse} chunks of up to 100 IPs
     * without accumulating the entire result set in memory.
     */
    public Stream<BatchLookupResponse> lookupBatchStream(Iterable<String> rawIps) {
        return lookupBatchStream(rawIps, RequestOptions.DEFAULT);
    }

    /** Constant-RAM lazy {@link Stream} yielding {@link BatchLookupResponse} chunks with options. */
    public Stream<BatchLookupResponse> lookupBatchStream(Iterable<String> rawIps, RequestOptions options) {
        if (rawIps == null) {
            throw new ValidationException("Batch IPs iterable must not be null", "ips");
        }
        RequestOptions opts = options != null ? options : RequestOptions.DEFAULT;
        Iterator<String> source = rawIps.iterator();
        if (!source.hasNext()) {
            throw new ValidationException("Batch IPs iterable must contain at least 1 IP address", "ips");
        }

        Iterator<BatchLookupResponse> chunkIterator = new Iterator<>() {
            @Override
            public boolean hasNext() {
                return source.hasNext();
            }

            @Override
            public BatchLookupResponse next() {
                if (!source.hasNext()) {
                    throw new NoSuchElementException();
                }
                List<String> chunk = new ArrayList<>(IpScopeValidator.MAX_SINGLE_BATCH_SIZE);
                while (source.hasNext() && chunk.size() < IpScopeValidator.MAX_SINGLE_BATCH_SIZE) {
                    chunk.add(source.next());
                }
                return lookupBatch(chunk, opts);
            }
        };

        return StreamSupport.stream(
                Spliterators.spliteratorUnknownSize(chunkIterator, Spliterator.ORDERED | Spliterator.NONNULL),
                false
        );
    }

    /** Inspects canonical network prefix intelligence by CIDR notation ({@code GET /v1/networks/:prefix/:length}). */
    public NetworkPrefixLookupResponse lookupNetwork(String rawCidr) {
        return lookupNetwork(rawCidr, RequestOptions.DEFAULT);
    }

    /** Inspects canonical network prefix intelligence by CIDR notation with options. */
    public NetworkPrefixLookupResponse lookupNetwork(String rawCidr, RequestOptions options) {
        RequestOptions opts = options != null ? options : RequestOptions.DEFAULT;
        ValidatedCidr vCidr = IpScopeValidator.validateCidrPrefix(rawCidr);

        if (!opts.bypassCache()) {
            NetworkPrefixLookupResponse cached = networkCache.get(vCidr.canonicalCidr());
            if (cached != null) {
                return cached;
            }
        }

        String path = "/v1/networks/" + urlEncodeSegment(vCidr.address()) + "/" + vCidr.prefixLength();
        TransportResponse resp = transport.requestSync("GET", path, null, opts.headers(), true);
        NetworkPrefixLookupResponse parsed = JsonCodec.toNetworkPrefixLookupResponse(resp.parsedBody());
        networkCache.set(vCidr.canonicalCidr(), parsed);
        return parsed;
    }

    /** Lists active and historical dataset snapshot versions ({@code GET /v1/metadata/datasets}). */
    public DatasetsMetadataResponse getDatasetsMetadata() {
        return getDatasetsMetadata(RequestOptions.DEFAULT);
    }

    /** Lists active and historical dataset snapshot versions with options. */
    public DatasetsMetadataResponse getDatasetsMetadata(RequestOptions options) {
        RequestOptions opts = options != null ? options : RequestOptions.DEFAULT;
        TransportResponse resp = transport.requestSync("GET", "/v1/metadata/datasets", null, opts.headers(), true);
        return JsonCodec.toDatasetsMetadataResponse(resp.parsedBody());
    }

    /** Submits geolocation, ASN, or anonymity correction feedback ({@code POST /v1/feedback}). */
    public FeedbackSubmissionResponse submitFeedback(FeedbackSubmissionInput feedback) {
        return submitFeedback(feedback, RequestOptions.DEFAULT);
    }

    /** Submits geolocation, ASN, or anonymity correction feedback with options. */
    public FeedbackSubmissionResponse submitFeedback(FeedbackSubmissionInput feedback, RequestOptions options) {
        if (feedback == null) {
            throw new ValidationException("feedback must not be null", "feedback");
        }
        String target = feedback.prefixOrIp() != null ? feedback.prefixOrIp().trim() : "";
        if (target.contains("/")) {
            IpScopeValidator.validateCidrPrefix(target);
        } else {
            IpScopeValidator.validateIpAddress(target);
        }

        RequestOptions opts = options != null ? options : RequestOptions.DEFAULT;
        FeedbackSubmissionInput normalized = new FeedbackSubmissionInput(
                target,
                feedback.role(),
                feedback.issueType(),
                feedback.requestedCorrection(),
                feedback.evidenceUrls()
        );
        TransportResponse resp = transport.requestSync(
                "POST",
                "/v1/feedback",
                JsonCodec.feedbackInputToMap(normalized),
                opts.headers(),
                true
        );
        return JsonCodec.toFeedbackSubmissionResponse(resp.parsedBody());
    }

    /** Fetches public service health and active snapshot status ({@code GET /v1/status}). */
    public ServiceStatusResponse getStatus() {
        return getStatus(RequestOptions.DEFAULT);
    }

    /** Fetches public service health and active snapshot status with options. */
    public ServiceStatusResponse getStatus(RequestOptions options) {
        RequestOptions opts = options != null ? options : RequestOptions.DEFAULT;
        TransportResponse resp = transport.requestSync("GET", "/v1/status", null, opts.headers(), false);
        return JsonCodec.toServiceStatusResponse(resp.parsedBody());
    }

    // =========================================================================
    // Asynchronous Operations (CompletableFuture)
    // =========================================================================

    /** Asynchronously looks up a single IPv4 or IPv6 address with singleflight coalescing. */
    public CompletableFuture<IpLookupResponse> lookupIpAsync(String rawIp) {
        return lookupIpAsync(rawIp, RequestOptions.DEFAULT);
    }

    /** Asynchronously looks up a single IPv4 or IPv6 address with options and singleflight coalescing. */
    public CompletableFuture<IpLookupResponse> lookupIpAsync(String rawIp, RequestOptions options) {
        return lookupIpWithMetaAsync(rawIp, options).thenApply(IpScopeResultWithMeta::data);
    }

    /** Asynchronously looks up a single IPv4 or IPv6 address and returns both data and rate-limit metadata. */
    public CompletableFuture<IpScopeResultWithMeta<IpLookupResponse>> lookupIpWithMetaAsync(
            String rawIp,
            RequestOptions options
    ) {
        RequestOptions opts = options != null ? options : RequestOptions.DEFAULT;
        ValidatedIp vIp;
        try {
            vIp = IpScopeValidator.validateIpAddress(rawIp);
        } catch (RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }
        String ipStr = vIp.canonicalIp();

        return ipCache.getOrComputeAsync(ipStr, opts.bypassCache(), () -> {
            String path = "/v1/ip/" + urlEncodeSegment(ipStr);
            return transport.requestAsync("GET", path, null, opts.headers(), true)
                    .thenApply(resp -> {
                        IpLookupResponse parsed = JsonCodec.toIpLookupResponse(resp.parsedBody());
                        String canonicalLower = parsed.ip().toLowerCase(Locale.ROOT);
                        if (!canonicalLower.equals(ipStr)) {
                            ipCache.set(canonicalLower, parsed);
                        }
                        return parsed;
                    });
        }).thenApply(coalesced -> {
            RateLimitMetadata rl = transport.getLastRateLimit();
            return new IpScopeResultWithMeta<>(
                    coalesced.value(),
                    200,
                    rl != null ? rl : RateLimitMetadata.empty(),
                    coalesced.fromCache()
            );
        });
    }

    /** Asynchronously looks up the caller's own server-observed IP ({@code GET /v1/ip/me}). */
    public CompletableFuture<IpLookupResponse> lookupCallerIpAsync() {
        return lookupCallerIpAsync(RequestOptions.DEFAULT);
    }

    /** Asynchronously looks up the caller's own server-observed IP with options. */
    public CompletableFuture<IpLookupResponse> lookupCallerIpAsync(RequestOptions options) {
        RequestOptions opts = options != null ? options : RequestOptions.DEFAULT;
        return transport.requestAsync("GET", "/v1/ip/me", null, opts.headers(), true)
                .thenApply(resp -> JsonCodec.toIpLookupResponse(resp.parsedBody()));
    }

    /** Asynchronously performs a batch lookup for 1..100 IPs ({@code POST /v1/ip/batch}). */
    public CompletableFuture<BatchLookupResponse> lookupBatchAsync(List<String> rawIps) {
        return lookupBatchAsync(rawIps, RequestOptions.DEFAULT);
    }

    /** Asynchronously performs a batch lookup for 1..100 IPs with options. */
    public CompletableFuture<BatchLookupResponse> lookupBatchAsync(List<String> rawIps, RequestOptions options) {
        RequestOptions opts = options != null ? options : RequestOptions.DEFAULT;
        ValidatedBatch batch;
        try {
            batch = IpScopeValidator.validateAndDeduplicateBatchIps(
                    rawIps,
                    IpScopeValidator.MAX_SINGLE_BATCH_SIZE
            );
        } catch (RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }

        Map<String, IpLookupResponse> resolvedByIp = new ConcurrentHashMap<>(batch.uniqueIps().size());
        List<String> missingIps = new ArrayList<>(batch.uniqueIps().size());

        if (!opts.bypassCache()) {
            for (String ipStr : batch.uniqueIps()) {
                IpLookupResponse cached = ipCache.get(ipStr);
                if (cached != null) {
                    resolvedByIp.put(ipStr, cached);
                } else {
                    missingIps.add(ipStr);
                }
            }
        } else {
            missingIps.addAll(batch.uniqueIps());
        }

        if (missingIps.isEmpty()) {
            List<IpLookupResponse> orderedResults = new ArrayList<>(batch.orderedIps().size());
            for (String ipStr : batch.orderedIps()) {
                orderedResults.add(resolvedByIp.get(ipStr));
            }
            String dsVer = !orderedResults.isEmpty() && orderedResults.get(0) != null
                    ? orderedResults.get(0).datasetVersion()
                    : "";
            return CompletableFuture.completedFuture(
                    new BatchLookupResponse(dsVer, orderedResults.size(), orderedResults)
            );
        }

        return transport.requestAsync(
                "POST",
                "/v1/ip/batch",
                Map.of("ips", missingIps),
                opts.headers(),
                true
        ).thenApply(resp -> {
            BatchLookupResponse batchParsed = JsonCodec.toBatchLookupResponse(resp.parsedBody());
            List<IpLookupResponse> results = batchParsed.results();
            for (int i = 0; i < missingIps.size() && i < results.size(); i++) {
                String reqIp = missingIps.get(i);
                IpLookupResponse item = results.get(i);
                resolvedByIp.put(reqIp, item);
                ipCache.set(reqIp, item);
                String canonicalLower = item.ip().toLowerCase(Locale.ROOT);
                if (!canonicalLower.equals(reqIp)) {
                    ipCache.set(canonicalLower, item);
                }
            }
            List<IpLookupResponse> orderedResults = new ArrayList<>(batch.orderedIps().size());
            for (String ipStr : batch.orderedIps()) {
                orderedResults.add(resolvedByIp.get(ipStr));
            }
            return new BatchLookupResponse(
                    batchParsed.datasetVersion(),
                    orderedResults.size(),
                    orderedResults
            );
        });
    }

    /** Asynchronously performs a chunked batch lookup for &gt;100 IPs with bounded concurrency. */
    public CompletableFuture<BatchLookupResponse> lookupBatchChunkedAsync(
            List<String> rawIps,
            int concurrency
    ) {
        return lookupBatchChunkedAsync(rawIps, concurrency, RequestOptions.DEFAULT);
    }

    /** Asynchronously performs a chunked batch lookup for &gt;100 IPs with bounded concurrency and options. */
    public CompletableFuture<BatchLookupResponse> lookupBatchChunkedAsync(
            List<String> rawIps,
            int concurrency,
            RequestOptions options
    ) {
        RequestOptions opts = options != null ? options : RequestOptions.DEFAULT;
        ValidatedBatch batch;
        try {
            batch = IpScopeValidator.validateAndDeduplicateBatchIps(rawIps, 0);
        } catch (RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }

        int effectiveConcurrency = Math.max(1, Math.min(16, concurrency));
        Semaphore semaphore = new Semaphore(effectiveConcurrency);
        Map<String, IpLookupResponse> resolvedByIp = new ConcurrentHashMap<>(batch.uniqueIps().size());
        List<CompletableFuture<String>> futures = new ArrayList<>();

        List<String> unique = batch.uniqueIps();
        for (int i = 0; i < unique.size(); i += IpScopeValidator.MAX_SINGLE_BATCH_SIZE) {
            int end = Math.min(i + IpScopeValidator.MAX_SINGLE_BATCH_SIZE, unique.size());
            List<String> chunk = List.copyOf(unique.subList(i, end));

            CompletableFuture<String> chunkFuture = CompletableFuture.supplyAsync(() -> {
                try {
                    semaphore.acquire();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new RuntimeException(e);
                }
                return chunk;
            }).thenCompose(ch -> lookupBatchAsync(ch, opts).whenComplete((r, e) -> semaphore.release()))
              .thenApply(res -> {
                  for (int idx = 0; idx < chunk.size() && idx < res.results().size(); idx++) {
                      resolvedByIp.put(chunk.get(idx), res.results().get(idx));
                  }
                  return res.datasetVersion();
              });

            futures.add(chunkFuture);
        }

        return CompletableFuture.allOf(futures.toArray(CompletableFuture<?>[]::new))
                .thenApply(ignored -> {
                    String datasetVersion = "";
                    for (CompletableFuture<String> f : futures) {
                        String ver = f.join();
                        if (datasetVersion.isEmpty() && ver != null && !ver.isEmpty()) {
                            datasetVersion = ver;
                        }
                    }
                    List<IpLookupResponse> orderedResults = new ArrayList<>(batch.orderedIps().size());
                    for (String ipStr : batch.orderedIps()) {
                        orderedResults.add(resolvedByIp.get(ipStr));
                    }
                    return new BatchLookupResponse(datasetVersion, orderedResults.size(), orderedResults);
                });
    }

    /** Asynchronously inspects canonical network prefix intelligence by CIDR notation. */
    public CompletableFuture<NetworkPrefixLookupResponse> lookupNetworkAsync(String rawCidr) {
        return lookupNetworkAsync(rawCidr, RequestOptions.DEFAULT);
    }

    /** Asynchronously inspects canonical network prefix intelligence by CIDR notation with options. */
    public CompletableFuture<NetworkPrefixLookupResponse> lookupNetworkAsync(
            String rawCidr,
            RequestOptions options
    ) {
        RequestOptions opts = options != null ? options : RequestOptions.DEFAULT;
        ValidatedCidr vCidr;
        try {
            vCidr = IpScopeValidator.validateCidrPrefix(rawCidr);
        } catch (RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }

        return networkCache.getOrComputeAsync(vCidr.canonicalCidr(), opts.bypassCache(), () -> {
            String path = "/v1/networks/" + urlEncodeSegment(vCidr.address()) + "/" + vCidr.prefixLength();
            return transport.requestAsync("GET", path, null, opts.headers(), true)
                    .thenApply(resp -> JsonCodec.toNetworkPrefixLookupResponse(resp.parsedBody()));
        }).thenApply(LruTtlCache.CoalescedResult::value);
    }

    /** Asynchronously lists active and historical dataset snapshot versions. */
    public CompletableFuture<DatasetsMetadataResponse> getDatasetsMetadataAsync() {
        return getDatasetsMetadataAsync(RequestOptions.DEFAULT);
    }

    /** Asynchronously lists active and historical dataset snapshot versions with options. */
    public CompletableFuture<DatasetsMetadataResponse> getDatasetsMetadataAsync(RequestOptions options) {
        RequestOptions opts = options != null ? options : RequestOptions.DEFAULT;
        return transport.requestAsync("GET", "/v1/metadata/datasets", null, opts.headers(), true)
                .thenApply(resp -> JsonCodec.toDatasetsMetadataResponse(resp.parsedBody()));
    }

    /** Asynchronously submits geolocation, ASN, or anonymity correction feedback. */
    public CompletableFuture<FeedbackSubmissionResponse> submitFeedbackAsync(FeedbackSubmissionInput feedback) {
        return submitFeedbackAsync(feedback, RequestOptions.DEFAULT);
    }

    /** Asynchronously submits geolocation, ASN, or anonymity correction feedback with options. */
    public CompletableFuture<FeedbackSubmissionResponse> submitFeedbackAsync(
            FeedbackSubmissionInput feedback,
            RequestOptions options
    ) {
        if (feedback == null) {
            return CompletableFuture.failedFuture(new ValidationException("feedback must not be null", "feedback"));
        }
        String target = feedback.prefixOrIp() != null ? feedback.prefixOrIp().trim() : "";
        try {
            if (target.contains("/")) {
                IpScopeValidator.validateCidrPrefix(target);
            } else {
                IpScopeValidator.validateIpAddress(target);
            }
        } catch (RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }

        RequestOptions opts = options != null ? options : RequestOptions.DEFAULT;
        FeedbackSubmissionInput normalized = new FeedbackSubmissionInput(
                target,
                feedback.role(),
                feedback.issueType(),
                feedback.requestedCorrection(),
                feedback.evidenceUrls()
        );
        return transport.requestAsync(
                "POST",
                "/v1/feedback",
                JsonCodec.feedbackInputToMap(normalized),
                opts.headers(),
                true
        ).thenApply(resp -> JsonCodec.toFeedbackSubmissionResponse(resp.parsedBody()));
    }

    /** Asynchronously fetches public service health and active snapshot status. */
    public CompletableFuture<ServiceStatusResponse> getStatusAsync() {
        return getStatusAsync(RequestOptions.DEFAULT);
    }

    /** Asynchronously fetches public service health and active snapshot status with options. */
    public CompletableFuture<ServiceStatusResponse> getStatusAsync(RequestOptions options) {
        RequestOptions opts = options != null ? options : RequestOptions.DEFAULT;
        return transport.requestAsync("GET", "/v1/status", null, opts.headers(), false)
                .thenApply(resp -> JsonCodec.toServiceStatusResponse(resp.parsedBody()));
    }

    // =========================================================================
    // Telemetry & Lifecycle
    // =========================================================================

    /** Returns the most recently observed user-scoped rate-limit headers. */
    public RateLimitMetadata getLastRateLimit() {
        return transport.getLastRateLimit();
    }

    /** Returns current hit/miss/singleflight statistics for the in-memory IP LRU cache. */
    public CacheStats getCacheStats() {
        return ipCache.getStats();
    }

    /** Clears the in-memory IP and network prefix LRU caches. */
    public void clearCache() {
        ipCache.clear();
        networkCache.clear();
    }

    @Override
    public void close() {
        clearCache();
    }

    private static String urlEncodeSegment(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }

    // =========================================================================
    // Builder
    // =========================================================================

    public static final class Builder {
        private final String apiKey;
        private String baseUrl = HttpTransport.DEFAULT_BASE_URL;
        private Duration timeout = HttpTransport.DEFAULT_TIMEOUT;
        private RetryOptions retry = RetryOptions.defaults();
        private CacheOptions cache = CacheOptions.defaults();
        private String userAgent;
        private HttpClient httpClient;

        private Builder(String apiKey) {
            this.apiKey = apiKey;
        }

        public Builder baseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
            return this;
        }

        public Builder timeout(Duration timeout) {
            this.timeout = timeout;
            return this;
        }

        public Builder retry(RetryOptions retry) {
            this.retry = retry;
            return this;
        }

        public Builder cache(CacheOptions cache) {
            this.cache = cache;
            return this;
        }

        public Builder userAgent(String userAgent) {
            this.userAgent = userAgent;
            return this;
        }

        public Builder httpClient(HttpClient httpClient) {
            this.httpClient = httpClient;
            return this;
        }

        public IpScopeClient build() {
            return new IpScopeClient(this);
        }
    }
}
