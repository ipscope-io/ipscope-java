package io.ipscope.sdk;

import io.ipscope.sdk.IpScopeException.ApiException;
import io.ipscope.sdk.IpScopeException.AuthenticationException;
import io.ipscope.sdk.IpScopeException.RateLimitException;
import io.ipscope.sdk.IpScopeException.TimeoutException;
import io.ipscope.sdk.IpScopeModels.RateLimitMetadata;
import io.ipscope.sdk.IpScopeModels.RetryOptions;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Resilient Sync and Async HTTP transport backed by {@link java.net.http.HttpClient}.
 *
 * <p>Enforces a hard 2 MiB ({@link #MAX_RESPONSE_BYTES}) response size ceiling via streaming
 * {@link InputStream} reads in {@code try-with-resources}, parses user-scoped rate-limit headers,
 * and performs exponential backoff with jitter on 429 and transient 502/503/504 responses.
 */
final class HttpTransport {

    public static final String DEFAULT_BASE_URL = "https://api.ipscope.io";
    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(5);
    public static final int MAX_RESPONSE_BYTES = 2 * 1024 * 1024; // 2 MiB hard ceiling
    public static final String SDK_USER_AGENT = "ipscope-java/1.0.0";

    record TransportResponse(Map<String, Object> parsedBody, int status, RateLimitMetadata rateLimit) {}

    private final String apiKey;
    private final String baseUrl;
    private final Duration timeout;
    private final RetryOptions retry;
    private final String userAgent;
    private final HttpClient httpClient;
    private final AtomicReference<RateLimitMetadata> lastRateLimit = new AtomicReference<>();

    HttpTransport(
            String apiKey,
            String baseUrl,
            Duration timeout,
            RetryOptions retry,
            String userAgent,
            HttpClient customClient
    ) {
        this.apiKey = IpScopeValidator.validateApiKey(apiKey);
        String trimmedBase = baseUrl != null ? baseUrl.trim() : DEFAULT_BASE_URL;
        while (trimmedBase.endsWith("/")) {
            trimmedBase = trimmedBase.substring(0, trimmedBase.length() - 1);
        }
        this.baseUrl = trimmedBase.isEmpty() ? DEFAULT_BASE_URL : trimmedBase;
        this.timeout = (timeout != null && !timeout.isNegative() && !timeout.isZero())
                ? timeout
                : DEFAULT_TIMEOUT;
        this.retry = retry != null ? retry : RetryOptions.defaults();
        this.userAgent = (userAgent != null && !userAgent.isBlank())
                ? userAgent.trim() + " " + SDK_USER_AGENT
                : SDK_USER_AGENT;
        this.httpClient = customClient != null
                ? customClient
                : HttpClient.newBuilder()
                        .connectTimeout(this.timeout)
                        .followRedirects(HttpClient.Redirect.NEVER)
                        .version(HttpClient.Version.HTTP_1_1)
                        .build();
    }

    RateLimitMetadata getLastRateLimit() {
        return lastRateLimit.get();
    }

    TransportResponse requestSync(
            String method,
            String path,
            Object bodyObj,
            Map<String, String> extraHeaders,
            boolean requiresAuth
    ) {
        HttpRequest request = buildHttpRequest(method, path, bodyObj, extraHeaders, requiresAuth);
        int maxRetries = Math.max(0, retry.maxRetries());

        for (int attempt = 0; attempt <= maxRetries; attempt++) {
            HttpResponse<InputStream> response;
            try {
                response = httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
            } catch (HttpTimeoutException e) {
                throw new TimeoutException(path, timeout, e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new ApiException(
                        "Request to \"" + path + "\" was interrupted",
                        0,
                        path,
                        "IPSCOPE_INTERRUPTED",
                        null,
                        e
                );
            } catch (IOException e) {
                if (attempt < maxRetries) {
                    sleepSync(computeBackoffMillis(attempt), path);
                    continue;
                }
                throw new ApiException(
                        "Network request to \"" + path + "\" failed: " + e.getMessage(),
                        0,
                        path,
                        "IPSCOPE_NETWORK_ERROR",
                        null,
                        e
                );
            }

            int status = response.statusCode();
            HttpHeaders headers = response.headers();
            String bodyText = readBoundedStream(response.body(), status, headers, path);

            RateLimitMetadata rl = parseRateLimitHeaders(headers);
            lastRateLimit.set(rl);

            if (status >= 200 && status < 300) {
                Map<String, Object> parsed = bodyText.isEmpty() ? Map.of() : JsonCodec.parseObject(bodyText);
                return new TransportResponse(parsed, status, rl);
            }

            String errMsg = JsonCodec.extractErrorMessage(bodyText, status, path);

            if (status == 401 || status == 403) {
                throw new AuthenticationException(errMsg, status, path, rl);
            }

            if (status == 429) {
                Duration retryAfter = computeRetryAfter(headers, rl);
                if (retry.retryOnRateLimit() && attempt < maxRetries) {
                    long delayMs = retryAfter != null
                            ? Math.min(retry.maxDelay().toMillis(), retryAfter.toMillis())
                            : computeBackoffMillis(attempt);
                    sleepSync(delayMs, path);
                    continue;
                }
                throw new RateLimitException(errMsg, path, retryAfter, rl);
            }

            if ((status == 502 || status == 503 || status == 504) && attempt < maxRetries) {
                sleepSync(computeBackoffMillis(attempt), path);
                continue;
            }

            throw new ApiException(errMsg, status, path, "IPSCOPE_HTTP_" + status, rl, null);
        }

        throw new ApiException(
                "Exhausted " + maxRetries + " retries for \"" + path + "\"",
                0,
                path,
                "IPSCOPE_RETRY_EXHAUSTED",
                null,
                null
        );
    }

    CompletableFuture<TransportResponse> requestAsync(
            String method,
            String path,
            Object bodyObj,
            Map<String, String> extraHeaders,
            boolean requiresAuth
    ) {
        HttpRequest request = buildHttpRequest(method, path, bodyObj, extraHeaders, requiresAuth);
        int maxRetries = Math.max(0, retry.maxRetries());
        return executeAsyncAttempt(request, path, 0, maxRetries);
    }

    private CompletableFuture<TransportResponse> executeAsyncAttempt(
            HttpRequest request,
            String path,
            int attempt,
            int maxRetries
    ) {
        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofInputStream())
                .handle((response, throwable) -> {
                    if (throwable != null) {
                        Throwable cause = unwrapCompletionException(throwable);
                        if (cause instanceof HttpTimeoutException) {
                            throw new TimeoutException(path, timeout, cause);
                        }
                        if (attempt < maxRetries) {
                            long delayMs = computeBackoffMillis(attempt);
                            return CompletableFuture.supplyAsync(
                                            () -> null,
                                            CompletableFuture.delayedExecutor(delayMs, TimeUnit.MILLISECONDS)
                                    )
                                    .thenCompose(ignored -> executeAsyncAttempt(request, path, attempt + 1, maxRetries));
                        }
                        throw new ApiException(
                                "Network request to \"" + path + "\" failed: " + cause.getMessage(),
                                0,
                                path,
                                "IPSCOPE_NETWORK_ERROR",
                                null,
                                cause
                        );
                    }

                    int status = response.statusCode();
                    HttpHeaders headers = response.headers();
                    String bodyText = readBoundedStream(response.body(), status, headers, path);

                    RateLimitMetadata rl = parseRateLimitHeaders(headers);
                    lastRateLimit.set(rl);

                    if (status >= 200 && status < 300) {
                        Map<String, Object> parsed = bodyText.isEmpty() ? Map.of() : JsonCodec.parseObject(bodyText);
                        return CompletableFuture.completedFuture(new TransportResponse(parsed, status, rl));
                    }

                    String errMsg = JsonCodec.extractErrorMessage(bodyText, status, path);

                    if (status == 401 || status == 403) {
                        throw new AuthenticationException(errMsg, status, path, rl);
                    }

                    if (status == 429) {
                        Duration retryAfter = computeRetryAfter(headers, rl);
                        if (retry.retryOnRateLimit() && attempt < maxRetries) {
                            long delayMs = retryAfter != null
                                    ? Math.min(retry.maxDelay().toMillis(), retryAfter.toMillis())
                                    : computeBackoffMillis(attempt);
                            return CompletableFuture.supplyAsync(
                                            () -> null,
                                            CompletableFuture.delayedExecutor(delayMs, TimeUnit.MILLISECONDS)
                                    )
                                    .thenCompose(ignored -> executeAsyncAttempt(request, path, attempt + 1, maxRetries));
                        }
                        throw new RateLimitException(errMsg, path, retryAfter, rl);
                    }

                    if ((status == 502 || status == 503 || status == 504) && attempt < maxRetries) {
                        long delayMs = computeBackoffMillis(attempt);
                        return CompletableFuture.supplyAsync(
                                        () -> null,
                                        CompletableFuture.delayedExecutor(delayMs, TimeUnit.MILLISECONDS)
                                )
                                .thenCompose(ignored -> executeAsyncAttempt(request, path, attempt + 1, maxRetries));
                    }

                    throw new ApiException(errMsg, status, path, "IPSCOPE_HTTP_" + status, rl, null);
                })
                .thenCompose(f -> f);
    }

    private HttpRequest buildHttpRequest(
            String method,
            String path,
            Object bodyObj,
            Map<String, String> extraHeaders,
            boolean requiresAuth
    ) {
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + path))
                .timeout(timeout)
                .header("Accept", "application/json")
                .header("User-Agent", userAgent);

        if (requiresAuth) {
            builder.header("x-api-key", apiKey);
            builder.header("Authorization", "Bearer " + apiKey);
        }

        if (extraHeaders != null) {
            for (Map.Entry<String, String> entry : extraHeaders.entrySet()) {
                if (entry.getKey() != null && entry.getValue() != null) {
                    builder.header(entry.getKey(), entry.getValue());
                }
            }
        }

        if (bodyObj != null) {
            String json = JsonCodec.toJson(bodyObj);
            builder.header("Content-Type", "application/json");
            builder.method(method, HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8));
        } else {
            builder.method(method, HttpRequest.BodyPublishers.noBody());
        }

        return builder.build();
    }

    private static String readBoundedStream(
            InputStream stream,
            int status,
            HttpHeaders headers,
            String path
    ) {
        try (InputStream in = stream) {
            Optional<String> clOpt = headers.firstValue("content-length");
            if (clOpt.isPresent()) {
                try {
                    long cl = Long.parseLong(clOpt.get().trim(), 10);
                    if (cl > MAX_RESPONSE_BYTES) {
                        throw new ApiException(
                                "IPScope response payload (" + cl + " bytes) exceeds 2 MiB safety limit",
                                status,
                                path,
                                "IPSCOPE_RESPONSE_TOO_LARGE",
                                null,
                                null
                        );
                    }
                } catch (NumberFormatException ignored) {
                    // Continue to streaming check
                }
            }

            ByteArrayOutputStream out = new ByteArrayOutputStream(1024);
            byte[] buf = new byte[8192];
            int total = 0;
            int n;
            while ((n = in.read(buf)) != -1) {
                total += n;
                if (total > MAX_RESPONSE_BYTES) {
                    throw new ApiException(
                            "IPScope response payload exceeds 2 MiB safety limit",
                            status,
                            path,
                            "IPSCOPE_RESPONSE_TOO_LARGE",
                            null,
                            null
                    );
                }
                out.write(buf, 0, n);
            }
            return out.toString(StandardCharsets.UTF_8);
        } catch (ApiException e) {
            throw e;
        } catch (IOException e) {
            throw new ApiException(
                    "Failed reading response stream from \"" + path + "\": " + e.getMessage(),
                    status,
                    path,
                    "IPSCOPE_NETWORK_ERROR",
                    null,
                    e
            );
        }
    }

    static RateLimitMetadata parseRateLimitHeaders(HttpHeaders headers) {
        return new RateLimitMetadata(
                parseIntHeader(headers, "x-ratelimit-limit"),
                parseIntHeader(headers, "x-ratelimit-remaining"),
                parseLongHeader(headers, "x-ratelimit-reset"),
                headers.firstValue("x-ratelimit-scope").orElse(null),
                parseIntHeader(headers, "x-ratelimit-burst"),
                parseIntHeader(headers, "x-ratelimit-rps")
        );
    }

    private static Integer parseIntHeader(HttpHeaders headers, String name) {
        return headers.firstValue(name)
                .map(String::trim)
                .flatMap(s -> {
                    try {
                        return Optional.of(Integer.parseInt(s, 10));
                    } catch (NumberFormatException e) {
                        return Optional.empty();
                    }
                })
                .orElse(null);
    }

    private static Long parseLongHeader(HttpHeaders headers, String name) {
        return headers.firstValue(name)
                .map(String::trim)
                .flatMap(s -> {
                    try {
                        return Optional.of(Long.parseLong(s, 10));
                    } catch (NumberFormatException e) {
                        return Optional.empty();
                    }
                })
                .orElse(null);
    }

    private static Duration computeRetryAfter(HttpHeaders headers, RateLimitMetadata rl) {
        Optional<String> raOpt = headers.firstValue("retry-after");
        if (raOpt.isPresent()) {
            try {
                double secs = Double.parseDouble(raOpt.get().trim());
                if (secs >= 0) {
                    return Duration.ofMillis((long) (secs * 1000));
                }
            } catch (NumberFormatException ignored) {
                // Fall back to reset epoch
            }
        }
        if (rl.resetEpochSeconds() != null) {
            long deltaMs = (rl.resetEpochSeconds() * 1000L) - Instant.now().toEpochMilli();
            if (deltaMs > 0) {
                return Duration.ofMillis(deltaMs);
            }
        }
        return null;
    }

    private long computeBackoffMillis(int attempt) {
        long baseMs = Math.max(1L, retry.baseDelay().toMillis());
        long maxMs = Math.max(baseMs, retry.maxDelay().toMillis());
        int shift = Math.min(attempt, 10);
        long exp = Math.min(maxMs, baseMs * (1L << shift));
        long jitterBound = Math.max(5L, exp / 4L);
        long jitter = ThreadLocalRandom.current().nextLong(0, jitterBound + 1);
        return Math.min(maxMs, exp + jitter);
    }

    private static void sleepSync(long delayMs, String path) {
        if (delayMs <= 0) {
            return;
        }
        try {
            Thread.sleep(delayMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ApiException(
                    "Retry sleep interrupted for \"" + path + "\"",
                    0,
                    path,
                    "IPSCOPE_INTERRUPTED",
                    null,
                    e
            );
        }
    }

    private static Throwable unwrapCompletionException(Throwable t) {
        Throwable cur = t;
        while (cur instanceof CompletionException && cur.getCause() != null) {
            cur = cur.getCause();
        }
        return cur;
    }
}
