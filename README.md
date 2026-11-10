# `ipscope-sdk` - Official IPScope Server-Side Java SDK

Official zero-dependency, thread-safe, strictly typed server-side **Java 17+ SDK** (`io.ipscope:ipscope-sdk`) for the **IPScope IP Intelligence Platform**, supporting both **Synchronous** and **Asynchronous (`CompletableFuture`)** execution.

> **Scope Notice:** This SDK is intentionally scoped strictly to **IP intelligence, network prefix, dataset metadata, feedback, and health operations**. It contains **zero account, billing, wallet, or key-management operations**, making it safe to deploy in production backend microservices, workers, and API gateways.

---

## Features

- **Zero External Runtime Dependencies**: Built entirely on Java 17 standard library (`java.net.http.HttpClient`, Java `record` classes, `CompletableFuture`) with a built-in RFC 8259 JSON codec - eliminating Jackson/Gson version conflicts in Spring Boot, Quarkus, Micronaut, or standalone services.
- **Both Sync & Async Operations**:
  - Synchronous methods: `lookupIp`, `lookupIpWithMeta`, `lookupCallerIp`, `lookupBatch`, `lookupBatchChunked`, `lookupBatchStream` (`Stream<BatchLookupResponse>`), `lookupNetwork`, `getDatasetsMetadata`, `submitFeedback`, `getStatus`.
  - Asynchronous methods (`CompletableFuture`): `lookupIpAsync`, `lookupIpWithMetaAsync`, `lookupCallerIpAsync`, `lookupBatchAsync`, `lookupBatchChunkedAsync`, `lookupNetworkAsync`, `getDatasetsMetadataAsync`, `submitFeedbackAsync`, `getStatusAsync`.
- **Low-RAM & Zero Memory Leaks**:
  - Thread-safe O(1) LRU + TTL cache (`maxEntries = 512` default, `< 400 KB` heap footprint) with `CompletableFuture` singleflight request coalescing.
  - Zero-DNS IPv4/IPv6 & CIDR validation (`IpScopeValidator` validates literal syntax before `InetAddress.getByName`, preventing accidental blocking DNS lookups).
  - Hard `2 MiB` (`MAX_RESPONSE_BYTES`) streaming response ceiling in `try-with-resources` prevents OOM on malformed upstream payloads.

---

## Installation

### Maven (`pom.xml`)

```xml
<dependency>
    <groupId>io.ipscope</groupId>
    <artifactId>ipscope-sdk</artifactId>
    <version>1.1.0</version>
</dependency>
```

### Gradle (`build.gradle.kts`)

```kotlin
implementation("io.ipscope:ipscope-sdk:1.1.0")
```

API keys have the form `<public>:<private>` (a UUID, a colon, and a 43-character base64url secret).

---

## Quick Start (Synchronous)

```java
import io.ipscope.sdk.IpScopeClient;
import io.ipscope.sdk.IpScopeModels.BatchLookupResponse;
import io.ipscope.sdk.IpScopeModels.IpLookupResponse;
import io.ipscope.sdk.IpScopeModels.NetworkPrefixLookupResponse;
import java.util.ArrayList;
import java.util.List;

public class Example {
    public static void main(String[] args) {
        IpScopeClient client = new IpScopeClient("<public>:<private>");
        List<String> largeIpList = new ArrayList<>();
        for (int i = 1; i <= 254; i++) {
            largeIpList.add("192.0.2." + i);
        }

        // 1. Single IPv4 or IPv6 lookup (cached automatically in LRU cache)
        IpLookupResponse ipInfo = client.lookupIp("8.8.8.8");
        System.out.println(ipInfo.ip() + " " + ipInfo.geo().countryCode() + " AS" + ipInfo.network().asn());

        // 2. Batch lookup (up to 100 IPs; deduplicates & reuses cached entries automatically)
        BatchLookupResponse batch = client.lookupBatch(
                List.of("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111")
        );
        for (IpLookupResponse record : batch.results()) {
            System.out.println(record.ip() + " -> " + record.network().organization());
        }

        // 3. Lazy constant-RAM Stream for 10,000+ IPs
        client.lookupBatchStream(largeIpList).forEach(chunk -> {
            for (IpLookupResponse record : chunk.results()) {
                System.out.println(record.ip());
            }
        });

        // 4. Network CIDR prefix lookup
        NetworkPrefixLookupResponse prefix = client.lookupNetwork("8.8.8.0/24");
        System.out.println(prefix.queriedCidr() + " matched " + prefix.matchedNetwork()
                + " (/" + prefix.bgpPrefixLength() + ") in " + prefix.datasetVersion());
        if (prefix.record() != null) {
            System.out.println("record: " + prefix.record().countryCode() + " hosting=" + prefix.record().isHosting());
        }
        if (prefix.lookup() != null) {
            System.out.println("base address city: " + prefix.lookup().geo().city());
        }
    }
}
```

---

## Reading the Response

```java
import io.ipscope.sdk.IpScopeClient;
import io.ipscope.sdk.IpScopeModels.IpLookupResponse;

public class ResponseExample {
    public static void main(String[] args) {
        IpScopeClient client = new IpScopeClient("<public>:<private>");
        IpLookupResponse info = client.lookupIp("8.8.8.8");

        // Representative coordinates (never device GPS) and postal code; null when unknown
        System.out.println(info.geo().latitude() + ", " + info.geo().longitude() + " " + info.geo().postalCode());

        // Consumer privacy relays (e.g. iCloud Private Relay) are flagged separately from VPN/proxy
        System.out.println("relay=" + info.security().isRelay() + " vpn=" + info.security().isVpn());

        // Abuse velocity score on a 0-100 scale (present when security_extensions is licensed)
        if (info.securityExtensions() != null) {
            System.out.println("abuse score: " + info.securityExtensions().abuseVelocityScore());
        }
    }
}
```

---

## Rate-Limit Metadata

```java
import io.ipscope.sdk.IpScopeClient;
import io.ipscope.sdk.IpScopeModels.IpLookupResponse;
import io.ipscope.sdk.IpScopeModels.IpScopeResultWithMeta;
import io.ipscope.sdk.IpScopeModels.RateLimitMetadata;

public class RateLimitExample {
    public static void main(String[] args) {
        IpScopeClient client = new IpScopeClient("<public>:<private>");
        IpScopeResultWithMeta<IpLookupResponse> res = client.lookupIpWithMeta("1.1.1.1");

        // X-RateLimit-Limit / -Remaining / -Reset / -Scope.
        // resetAfterSeconds() is the number of seconds until the window resets (not an epoch).
        RateLimitMetadata rl = res.rateLimit();
        System.out.println(rl.remaining() + "/" + rl.limitPerMinute() + " left, resets in "
                + rl.resetAfterSeconds() + "s (scope " + rl.scope() + ")");
    }
}
```

---

## Submitting Feedback

`role` is one of `network_owner`, `user`, `researcher` (`IpScopeModels.FEEDBACK_ROLES`); `issueType` is one of
`wrong_country`, `wrong_city`, `false_positive_vpn`, `false_positive_hosting`, `false_positive_tor`,
`virtual_location_mismatch`, `other` (`IpScopeModels.FEEDBACK_ISSUE_TYPES`).

```java
import io.ipscope.sdk.IpScopeClient;
import io.ipscope.sdk.IpScopeModels.FeedbackSubmissionInput;
import io.ipscope.sdk.IpScopeModels.FeedbackSubmissionResponse;
import java.util.Map;

public class FeedbackExample {
    public static void main(String[] args) {
        IpScopeClient client = new IpScopeClient("<public>:<private>");

        FeedbackSubmissionInput feedback = new FeedbackSubmissionInput(
                "203.0.113.0/24", "network_owner", "wrong_country", Map.of("country_code", "DE"))
                .withEvidenceUrl("https://example.net/geofeed.csv")
                .withContact("noc@example.net", true);

        FeedbackSubmissionResponse receipt = client.submitFeedback(feedback);
        System.out.println(receipt.id() + " " + receipt.status() + " " + receipt.createdAt());
    }
}
```

---

## Quick Start (Asynchronous `CompletableFuture`)

```java
import io.ipscope.sdk.IpScopeClient;
import java.time.Duration;
import java.util.List;

public class AsyncExample {
    public static void main(String[] args) {
        IpScopeClient client = IpScopeClient.builder("<public>:<private>")
                .timeout(Duration.ofSeconds(5))
                .build();

        // 1. Async single lookup (concurrent calls for the same IP are singleflight-coalesced)
        client.lookupIpAsync("1.1.1.1")
                .thenAccept(info -> System.out.println(info.ip() + " -> " + info.network().organization()))
                .join();

        // 2. Async chunked batch lookup with bounded concurrency (max 4 in-flight chunks)
        client.lookupBatchChunkedAsync(List.of("8.8.8.8", "1.1.1.1", "9.9.9.9"), 4)
                .thenAccept(batch -> System.out.println("Resolved: " + batch.count()))
                .join();
    }
}
```
