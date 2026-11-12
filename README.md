<div align="center">
  <br />
  <a href="https://ipscope.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/ipscope-io/.github/main/assets/logo-dark.svg" />
      <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/ipscope-io/.github/main/assets/logo-light.svg" />
      <img alt="ipscope" src="https://raw.githubusercontent.com/ipscope-io/.github/main/assets/logo-light.svg" height="32" />
    </picture>
  </a>
  <h1>ipscope-sdk for Java</h1>
  <p><strong>Official zero-dependency Java 17+ server SDK for ipscope — IP geolocation, BGP ASN, and VPN/proxy detection</strong></p>
  <p>
    <a href="https://central.sonatype.com/artifact/io.ipscope/ipscope-sdk"><img src="https://img.shields.io/maven-central/v/io.ipscope/ipscope-sdk.svg?style=flat-square&label=maven%20central&color=0f172a" alt="Maven Central" /></a>
    <img src="https://img.shields.io/badge/java-%3E%3D17-0f172a?style=flat-square" alt="Java >= 17" />
    <img src="https://img.shields.io/badge/dependencies-zero-0f172a?style=flat-square" alt="Zero dependencies" />
    <a href="LICENSE"><img src="https://img.shields.io/badge/licence-MIT-0f172a?style=flat-square" alt="MIT licence" /></a>
    <a href="https://ipscope.io/docs/sdks/java"><img src="https://img.shields.io/badge/docs-ipscope.io-0f172a?style=flat-square" alt="Documentation" /></a>
  </p>
  <br />
  <a href="https://ipscope.io">
    <img alt="ipscope Java SDK" src="https://raw.githubusercontent.com/ipscope-io/.github/main/assets/banner.webp" width="100%" />
  </a>
</div>

<br />

## What is this

`io.ipscope:ipscope-sdk` is the official, zero-external-dependency Java 17+ server SDK for [ipscope](https://ipscope.io). Built entirely on `java.net.http.HttpClient`, Java `record` types, and a self-contained RFC 8259 JSON parser (with zero Jackson, Gson, or Netty transitive dependencies), it queries the [ipscope REST API](https://ipscope.io/products/api) for physical and declared [IP geolocation](https://ipscope.io/products/geolocation), [BGP origin ASN and prefix routing](https://ipscope.io/products/network), and [VPN, residential proxy, Tor exit, and relay detection](https://ipscope.io/products/privacy).

Every `IpScopeClient` supports both synchronous and asynchronous (`CompletableFuture`) execution, includes a thread-safe `O(1)` LRU + TTL cache (`maxEntries = 512` default, `< 400 KB` heap footprint), singleflight request coalescing, a hard `2 MiB` streaming body guard, and constant-RAM batch streaming for 10,000+ IPs. For offline in-process lookups on the JVM, see our [downloadable MMDB databases](https://ipscope.io/docs/databases/mmdb).

---

## Getting started

### 1. Get an API key

Create a free account at [dashboard.ipscope.io](https://dashboard.ipscope.io/auth/login) and copy your server API key (`<public>:<private>`).

### 2. Add the dependency

**Maven (`pom.xml`):**

```xml
<dependency>
    <groupId>io.ipscope</groupId>
    <artifactId>ipscope-sdk</artifactId>
    <version>1.1.0</version>
</dependency>
```

**Gradle (`build.gradle.kts`):**

```kotlin
implementation("io.ipscope:ipscope-sdk:1.1.0")
```

### 3. Look up an IP address

```java
import io.ipscope.sdk.IpScopeClient;
import io.ipscope.sdk.Models.IpLookupResponse;

try (IpScopeClient client = new IpScopeClient(System.getenv("IPSCOPE_API_KEY"))) {
    IpLookupResponse info = client.lookupIp("8.8.8.8");
    System.out.println(info.ip() + " " + info.geo().countryCode() + " AS" + info.network().asn());
}
```

---

## Contents

- [Synchronous lookups](#synchronous-lookups)
- [Asynchronous lookups (`CompletableFuture`)](#asynchronous-lookups-completablefuture)
- [Network CIDR prefix lookups](#network-cidr-prefix-lookups)
- [Reading the response](#reading-the-response)
- [Rate-limit metadata](#rate-limit-metadata)
- [Submitting feedback](#submitting-feedback)
- [Requirements](#requirements)
- [Documentation](#documentation)
- [Help](#help)
- [Licence](#licence)

---

## Synchronous lookups

Works seamlessly with classic thread pools and Java 21+ Virtual Threads (Project Loom):

```java
import io.ipscope.sdk.IpScopeClient;
import io.ipscope.sdk.Models.BatchLookupResponse;
import io.ipscope.sdk.Models.IpLookupResponse;
import java.util.List;
import java.util.stream.IntStream;

try (IpScopeClient client = new IpScopeClient("<public>:<private>")) {
    // 1. Single IPv4 or IPv6 lookup (cached in LRU & singleflight-coalesced)
    IpLookupResponse ipInfo = client.lookupIp("8.8.8.8");

    // 2. Caller IP lookup (GET /v1/ip/me)
    IpLookupResponse caller = client.lookupCallerIp();

    // 3. Batch lookup (up to 100 IPs; deduplicates & reuses cached entries automatically)
    BatchLookupResponse batch = client.lookupBatch(
        List.of("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111")
    );
    for (IpLookupResponse record : batch.results()) {
        System.out.println(record.ip() + " -> " + record.network().organization());
    }

    // 4. Chunked batch lookup for >100 IPs with bounded concurrency (default: 4)
    BatchLookupResponse largeBatch = client.lookupBatchChunked(
        List.of("8.8.8.8", "1.1.1.1", "9.9.9.9"),
        4
    );

    // 5. Constant-RAM streaming batch lookup for 10,000+ IPs
    List<String> largeIpList = IntStream.rangeClosed(1, 254)
        .mapToObj(i -> "192.0.2." + i)
        .toList();
    client.lookupBatchStream(largeIpList, chunk -> {
        for (IpLookupResponse record : chunk.results()) {
            System.out.println(record.ip());
        }
    });
}
```

---

## Asynchronous lookups (`CompletableFuture`)

```java
import io.ipscope.sdk.IpScopeClient;

try (IpScopeClient client = new IpScopeClient("<public>:<private>")) {
    client.lookupIpAsync("8.8.8.8")
        .thenAccept(info -> System.out.println(info.ip() + " -> " + info.network().organization()))
        .join();
}
```

---

## Network CIDR prefix lookups

Inspect the longest-matching routed BGP prefix and its base address intelligence via `lookupNetwork`:

```java
var prefix = client.lookupNetwork("8.8.8.0/24");
System.out.println(prefix.queriedCidr() + " matched " + prefix.matchedNetwork()
    + " (/" + prefix.bgpPrefixLength() + ") in " + prefix.datasetVersion());
if (prefix.record() != null) {
    System.out.println("record: " + prefix.record().countryCode() + " hosting=" + prefix.record().isHosting());
}
if (prefix.lookup() != null) {
    System.out.println("base address city: " + prefix.lookup().geo().city());
}
```

---

## Reading the response

```java
IpLookupResponse info = client.lookupIp("8.8.8.8");

// Representative coordinates (never device GPS) and postal code; null when unknown
System.out.println(info.geo().latitude() + ", " + info.geo().longitude() + " " + info.geo().postalCode());

// Consumer privacy relays (e.g. iCloud Private Relay) are flagged separately from VPN/proxy
System.out.println("relay=" + info.security().isRelay() + " vpn=" + info.security().isVpn());

// Abuse velocity score on a 0-100 scale (present when security_extensions is licensed)
if (info.securityExtensions() != null) {
    System.out.println("abuse score: " + info.securityExtensions().abuseVelocityScore());
}
```

---

## Rate-limit metadata

Use `lookupIpWithMeta` (or any `*WithMeta` method) to inspect the parsed `X-RateLimit-*` headers:

```java
import io.ipscope.sdk.Models.IpScopeResultWithMeta;
import io.ipscope.sdk.Models.RateLimitMetadata;

IpScopeResultWithMeta<IpLookupResponse> res = client.lookupIpWithMeta("1.1.1.1");
RateLimitMetadata rl = res.rateLimit();
System.out.println(rl.remaining() + "/" + rl.limitPerMinute()
    + " left, resets in " + rl.resetAfterSeconds() + "s (scope " + rl.scope() + ")");
```

---

## Submitting feedback

Report outdated geolocation or anonymity classifications directly via `submitFeedback`:

```java
import io.ipscope.sdk.Models.FeedbackSubmissionInput;
import io.ipscope.sdk.Models.FeedbackSubmissionResponse;
import java.util.Map;

var feedback = new FeedbackSubmissionInput(
    "203.0.113.0/24",
    "network_owner", // FeedbackValues.ROLES: network_owner | user | researcher
    "wrong_country", // FeedbackValues.ISSUE_TYPES
    Map.of("country_code", "DE"),
    "https://example.net/geofeed.csv",
    true,
    "noc@example.net"
);

FeedbackSubmissionResponse receipt = client.submitFeedback(feedback);
System.out.println(receipt.id() + " " + receipt.status() + " " + receipt.createdAt());
```

---

## Requirements

- Java 17 or later (zero external runtime dependencies).

---

## Documentation

| Topic | Link |
| :--- | :--- |
| Java SDK guide | [ipscope.io/docs/sdks/java](https://ipscope.io/docs/sdks/java) |
| REST API overview | [ipscope.io/docs/api/overview](https://ipscope.io/docs/api/overview) |
| Single & batch IP lookups | [ipscope.io/docs/api/single-ip](https://ipscope.io/docs/api/single-ip) |
| Network CIDR prefix lookups | [ipscope.io/docs/api/network-prefix](https://ipscope.io/docs/api/network-prefix) |
| Errors & rate limits | [ipscope.io/docs/api/errors](https://ipscope.io/docs/api/errors) |
| Downloadable MMDB databases | [ipscope.io/docs/databases/mmdb](https://ipscope.io/docs/databases/mmdb) |

---

## Help

- Bugs and feature requests: [open an issue](https://github.com/ipscope-io/ipscope-java/issues)
- Account, billing and integration questions: [contact@ipscope.io](mailto:contact@ipscope.io)
- Security vulnerabilities: see the [security policy](https://github.com/ipscope-io/.github/blob/main/SECURITY.md)

---

## Licence

[MIT](LICENSE). Made by [ipscope](https://ipscope.io).
