package io.ipscope.sdk;

import io.ipscope.sdk.IpScopeModels.CacheOptions;
import io.ipscope.sdk.IpScopeModels.CacheStats;
import java.time.Duration;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

/**
 * Thread-safe O(1) Least-Recently-Used (LRU) cache with TTL expiration and
 * {@link CompletableFuture} singleflight request coalescing.
 *
 * <p>Strictly bounded by {@code maxEntries} (default: 512, {@code < 400 KB} heap footprint)
 * and guarantees cleanup of in-flight futures in {@code whenComplete}.
 */
public final class LruTtlCache<V> {

    private record CacheEntry<V>(V value, long expiresAtNanos) {}

    public record CoalescedResult<V>(V value, boolean fromCache) {}

    private final boolean enabled;
    private final int maxEntries;
    private final Duration ttl;
    private final long ttlNanos;
    private final LinkedHashMap<String, CacheEntry<V>> map;
    private final ReentrantLock lock = new ReentrantLock();
    private final ConcurrentHashMap<String, CompletableFuture<V>> inFlight = new ConcurrentHashMap<>();

    private final AtomicLong hits = new AtomicLong();
    private final AtomicLong misses = new AtomicLong();
    private final AtomicLong coalescedHits = new AtomicLong();

    public LruTtlCache(CacheOptions options) {
        CacheOptions opts = options != null ? options : CacheOptions.defaults();
        this.enabled = opts.enabled();
        this.maxEntries = Math.max(1, opts.maxEntries());
        this.ttl = (opts.ttl() != null && !opts.ttl().isNegative() && !opts.ttl().isZero())
                ? opts.ttl()
                : Duration.ofSeconds(60);
        this.ttlNanos = this.ttl.toNanos();
        this.map = new LinkedHashMap<>(16, 0.75f, true);
    }

    public V get(String key) {
        if (!enabled) {
            misses.incrementAndGet();
            return null;
        }
        long now = System.nanoTime();
        lock.lock();
        try {
            CacheEntry<V> entry = map.get(key);
            if (entry == null) {
                misses.incrementAndGet();
                return null;
            }
            if (now - entry.expiresAtNanos() >= 0) {
                map.remove(key);
                misses.incrementAndGet();
                return null;
            }
            hits.incrementAndGet();
            return entry.value();
        } finally {
            lock.unlock();
        }
    }

    public void set(String key, V value) {
        if (!enabled || value == null) {
            return;
        }
        long now = System.nanoTime();
        lock.lock();
        try {
            map.remove(key);
            if (map.size() >= maxEntries) {
                Iterator<Map.Entry<String, CacheEntry<V>>> it = map.entrySet().iterator();
                while (it.hasNext() && map.size() >= maxEntries) {
                    it.next();
                    it.remove();
                }
            }
            map.put(key, new CacheEntry<>(value, now + ttlNanos));
        } finally {
            lock.unlock();
        }
    }

    /**
     * Coalesces concurrent requests for the same key into a single in-flight {@link CompletableFuture}.
     */
    public CompletableFuture<CoalescedResult<V>> getOrComputeAsync(
            String key,
            boolean bypassCache,
            Supplier<CompletableFuture<V>> producer
    ) {
        if (!bypassCache) {
            V cached = get(key);
            if (cached != null) {
                return CompletableFuture.completedFuture(new CoalescedResult<>(cached, true));
            }

            AtomicBoolean created = new AtomicBoolean(false);
            CompletableFuture<V> shared = inFlight.computeIfAbsent(key, k -> {
                created.set(true);
                CompletableFuture<V> f;
                try {
                    f = producer.get();
                } catch (Throwable t) {
                    f = CompletableFuture.failedFuture(t);
                }
                return f.whenComplete((val, err) -> {
                    inFlight.remove(k);
                    if (err == null && val != null) {
                        set(k, val);
                    }
                });
            });

            if (!created.get()) {
                coalescedHits.incrementAndGet();
                return shared.thenApply(v -> new CoalescedResult<>(v, true));
            }
            return shared.thenApply(v -> new CoalescedResult<>(v, false));
        }

        return producer.get().thenApply(v -> new CoalescedResult<>(v, false));
    }

    public void clear() {
        lock.lock();
        try {
            map.clear();
        } finally {
            lock.unlock();
        }
        inFlight.clear();
        hits.set(0);
        misses.set(0);
        coalescedHits.set(0);
    }

    public CacheStats getStats() {
        int currentSize;
        lock.lock();
        try {
            currentSize = map.size();
        } finally {
            lock.unlock();
        }
        return new CacheStats(
                enabled,
                currentSize,
                maxEntries,
                ttl,
                hits.get(),
                misses.get(),
                coalescedHits.get()
        );
    }
}
