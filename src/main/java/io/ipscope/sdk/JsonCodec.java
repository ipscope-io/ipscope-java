package io.ipscope.sdk;

import io.ipscope.sdk.IpScopeModels.BatchLookupResponse;
import io.ipscope.sdk.IpScopeModels.CanonicalNetworkPrefixRecord;
import io.ipscope.sdk.IpScopeModels.ConnectionBlock;
import io.ipscope.sdk.IpScopeModels.DatasetSnapshotSummary;
import io.ipscope.sdk.IpScopeModels.DatasetsMetadataResponse;
import io.ipscope.sdk.IpScopeModels.FeedbackSubmissionInput;
import io.ipscope.sdk.IpScopeModels.FeedbackSubmissionResponse;
import io.ipscope.sdk.IpScopeModels.GeoBlock;
import io.ipscope.sdk.IpScopeModels.IpLookupResponse;
import io.ipscope.sdk.IpScopeModels.NetworkBlock;
import io.ipscope.sdk.IpScopeModels.NetworkPrefixLookupResponse;
import io.ipscope.sdk.IpScopeModels.SecurityBlock;
import io.ipscope.sdk.IpScopeModels.SecurityExtensionsBlock;
import io.ipscope.sdk.IpScopeModels.ServiceStatusResponse;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Zero-dependency RFC 8259 JSON parser, serializer, and typed mapper for IPScope models.
 *
 * <p>Eliminates external Jackson/Gson runtime dependencies so {@code io.ipscope:ipscope-sdk}
 * never causes classpath conflicts in Spring Boot, Quarkus, Micronaut, or standalone JVM apps.
 */
final class JsonCodec {

    private JsonCodec() {}

    @SuppressWarnings("unchecked")
    static Map<String, Object> parseObject(String json) {
        Object parsed = new Parser(json).parseValue();
        if (parsed instanceof Map<?, ?> map) {
            return (Map<String, Object>) map;
        }
        throw new IllegalArgumentException("Expected JSON object at root");
    }

    static String toJson(Object value) {
        StringBuilder sb = new StringBuilder(128);
        writeJson(sb, value);
        return sb.toString();
    }

    private static void writeJson(StringBuilder sb, Object value) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof String s) {
            writeEscapedString(sb, s);
        } else if (value instanceof Number || value instanceof Boolean) {
            sb.append(value);
        } else if (value instanceof Map<?, ?> map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                writeEscapedString(sb, String.valueOf(entry.getKey()));
                sb.append(':');
                writeJson(sb, entry.getValue());
            }
            sb.append('}');
        } else if (value instanceof Collection<?> col) {
            sb.append('[');
            boolean first = true;
            for (Object item : col) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                writeJson(sb, item);
            }
            sb.append(']');
        } else {
            writeEscapedString(sb, String.valueOf(value));
        }
    }

    private static void writeEscapedString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }

    // =========================================================================
    // Typed Mappers
    // =========================================================================

    static IpLookupResponse toIpLookupResponse(Map<String, Object> raw) {
        Map<String, Object> geoRaw = asMap(raw.get("geo"));
        Map<String, Object> netRaw = asMap(raw.get("network"));
        Map<String, Object> secRaw = asMap(raw.get("security"));
        Map<String, Object> connRaw = asNullableMap(raw.get("connection"));
        Map<String, Object> extRaw = asNullableMap(raw.get("security_extensions"));

        GeoBlock geo = new GeoBlock(
                asString(geoRaw.get("country_code")),
                asString(geoRaw.get("subdivision")),
                asString(geoRaw.get("city")),
                asString(geoRaw.get("timezone")),
                asStringOrDefault(geoRaw.get("location_type"), "unknown"),
                asDoubleOrDefault(geoRaw.get("confidence"), 0.0),
                asNullableDouble(geoRaw.get("accuracy_radius_km")),
                asString(geoRaw.get("declared_country_code")),
                asString(geoRaw.get("physical_country_code")),
                asNullableBoolean(geoRaw.get("is_virtual_location"))
        );

        NetworkBlock network = new NetworkBlock(
                asNullableInt(netRaw.get("asn")),
                asString(netRaw.get("organization"))
        );

        SecurityBlock security = new SecurityBlock(
                asNullableBoolean(secRaw.get("is_vpn")),
                asNullableBoolean(secRaw.get("is_hosting")),
                asNullableBoolean(secRaw.get("is_tor_exit")),
                asNullableBoolean(secRaw.get("is_proxy")),
                asStringOrDefault(secRaw.get("anonymizer_type"), "unknown"),
                asDoubleOrDefault(secRaw.get("confidence"), 0.0),
                asStringList(secRaw.get("reason_codes"))
        );

        ConnectionBlock connection = connRaw == null ? null : new ConnectionBlock(
                asStringOrDefault(connRaw.get("connection_type"), "unknown"),
                asNullableBoolean(connRaw.get("is_residential")),
                asNullableBoolean(connRaw.get("is_mobile")),
                asNullableBoolean(connRaw.get("is_business")),
                asNullableBoolean(connRaw.get("is_hosting"))
        );

        SecurityExtensionsBlock securityExtensions = extRaw == null ? null : new SecurityExtensionsBlock(
                asNullableDouble(extRaw.get("abuse_velocity_score")),
                asNullableBoolean(extRaw.get("is_known_scanner")),
                asNullableDouble(extRaw.get("observation_recency_hours"))
        );

        int ipVersion = asIntOrDefault(raw.get("ip_version"), 4) == 6 ? 6 : 4;
        return new IpLookupResponse(
                asStringOrDefault(raw.get("ip"), ""),
                ipVersion,
                asString(raw.get("matched_network")),
                geo,
                network,
                security,
                connection,
                securityExtensions,
                asStringOrDefault(raw.get("dataset_version"), ""),
                asString(raw.get("updated_at"))
        );
    }

    static BatchLookupResponse toBatchLookupResponse(Map<String, Object> raw) {
        List<Object> itemsRaw = asList(raw.get("results"));
        List<IpLookupResponse> results = new ArrayList<>(itemsRaw.size());
        for (Object item : itemsRaw) {
            if (item instanceof Map<?, ?>) {
                results.add(toIpLookupResponse(asMap(item)));
            }
        }
        return new BatchLookupResponse(
                asStringOrDefault(raw.get("dataset_version"), ""),
                asIntOrDefault(raw.get("count"), results.size()),
                results
        );
    }

    static NetworkPrefixLookupResponse toNetworkPrefixLookupResponse(Map<String, Object> raw) {
        Map<String, Object> recRaw = asNullableMap(raw.get("record"));
        CanonicalNetworkPrefixRecord record = null;
        if (recRaw != null) {
            int recFamily = asIntOrDefault(recRaw.get("family"), asIntOrDefault(raw.get("family"), 4)) == 6 ? 6 : 4;
            record = new CanonicalNetworkPrefixRecord(
                    asStringOrDefault(recRaw.get("prefix"), asStringOrDefault(raw.get("queried_cidr"), "")),
                    recFamily,
                    asNullableInt(recRaw.get("asn")),
                    asString(recRaw.get("organization")),
                    firstNonNullString(recRaw.get("country_code"), recRaw.get("countryCode")),
                    asString(recRaw.get("city")),
                    firstNonNullString(recRaw.get("location_type"), recRaw.get("locationType")),
                    firstNonNullBoolean(recRaw.get("is_vpn"), recRaw.get("isVpn")),
                    firstNonNullBoolean(recRaw.get("is_hosting"), recRaw.get("isHosting")),
                    firstNonNullBoolean(recRaw.get("is_tor_exit"), recRaw.get("isTorExit")),
                    firstNonNullBoolean(recRaw.get("is_proxy"), recRaw.get("isProxy")),
                    firstNonNullString(recRaw.get("anonymizer_type"), recRaw.get("anonymizerType"))
            );
        }
        int family = asIntOrDefault(raw.get("family"), 4) == 6 ? 6 : 4;
        return new NetworkPrefixLookupResponse(
                asStringOrDefault(raw.get("queried_cidr"), ""),
                family,
                asStringOrDefault(raw.get("dataset_version"), ""),
                record
        );
    }

    static DatasetsMetadataResponse toDatasetsMetadataResponse(Map<String, Object> raw) {
        List<Object> snapsRaw = asList(raw.get("snapshots"));
        List<DatasetSnapshotSummary> snapshots = new ArrayList<>(snapsRaw.size());
        for (Object item : snapsRaw) {
            Map<String, Object> s = asMap(item);
            snapshots.add(new DatasetSnapshotSummary(
                    asStringOrDefault(s.get("snapshot_version"), ""),
                    asStringOrDefault(s.get("digest"), ""),
                    asStringOrDefault(s.get("ruleset_version"), ""),
                    asStringOrDefault(s.get("published_at"), ""),
                    asIntOrDefault(s.get("ipv4_prefix_count"), 0),
                    asIntOrDefault(s.get("ipv6_prefix_count"), 0)
            ));
        }
        return new DatasetsMetadataResponse(
                asStringOrDefault(raw.get("active_version"), ""),
                asString(raw.get("previous_version")),
                snapshots
        );
    }

    static Map<String, Object> feedbackInputToMap(FeedbackSubmissionInput input) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("prefix_or_ip", input.prefixOrIp());
        map.put("role", input.role());
        map.put("issue_type", input.issueType());
        map.put("requested_correction", input.requestedCorrection());
        if (input.evidenceUrls() != null) {
            map.put("evidence_urls", input.evidenceUrls());
        }
        return map;
    }

    static FeedbackSubmissionResponse toFeedbackSubmissionResponse(Map<String, Object> raw) {
        Object evRaw = raw.get("evidence_urls");
        List<String> evUrls = evRaw == null ? null : asStringList(evRaw);
        return new FeedbackSubmissionResponse(
                asStringOrDefault(raw.get("id"), ""),
                asStringOrDefault(raw.get("prefix_or_ip"), ""),
                asStringOrDefault(raw.get("role"), "end_user"),
                asStringOrDefault(raw.get("issue_type"), "other"),
                asMap(raw.get("requested_correction")),
                firstNonNullString(raw.get("created_at"), raw.get("createdAt")) != null
                        ? firstNonNullString(raw.get("created_at"), raw.get("createdAt"))
                        : "",
                asStringOrDefault(raw.get("status"), "pending_review"),
                evUrls
        );
    }

    static ServiceStatusResponse toServiceStatusResponse(Map<String, Object> raw) {
        Map<String, Object> snap = asNullableMap(raw.get("snapshot"));
        String curVer = snap == null ? null : asString(snap.get("currentVersion"));
        String prevVer = snap == null ? null : asString(snap.get("previousVersion"));
        return new ServiceStatusResponse(
                asStringOrDefault(raw.get("status"), "unknown"),
                curVer,
                prevVer
        );
    }

    static String extractErrorMessage(String bodyText, int status, String path) {
        if (bodyText != null && !bodyText.isBlank()) {
            try {
                Map<String, Object> map = parseObject(bodyText);
                Object msg = map.get("message");
                if (msg instanceof String s && !s.isBlank()) {
                    return s.trim();
                }
                if (msg instanceof List<?> list && !list.isEmpty()) {
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < list.size(); i++) {
                        if (i > 0) {
                            sb.append("; ");
                        }
                        sb.append(list.get(i));
                    }
                    return sb.toString();
                }
            } catch (Exception ignored) {
                // Fall back to default status message
            }
        }
        return "IPScope API error (" + status + ") on " + path;
    }

    // =========================================================================
    // Helper Coercions
    // =========================================================================

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object obj) {
        if (obj instanceof Map<?, ?> m) {
            return (Map<String, Object>) m;
        }
        return Map.of();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asNullableMap(Object obj) {
        if (obj instanceof Map<?, ?> m) {
            return (Map<String, Object>) m;
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> asList(Object obj) {
        if (obj instanceof List<?> l) {
            return (List<Object>) l;
        }
        return List.of();
    }

    private static List<String> asStringList(Object obj) {
        if (!(obj instanceof List<?> list)) {
            return List.of();
        }
        List<String> res = new ArrayList<>(list.size());
        for (Object item : list) {
            if (item != null) {
                res.add(String.valueOf(item));
            }
        }
        return res;
    }

    private static String asString(Object obj) {
        return obj == null ? null : String.valueOf(obj);
    }

    private static String asStringOrDefault(Object obj, String def) {
        return obj == null ? def : String.valueOf(obj);
    }

    private static String firstNonNullString(Object a, Object b) {
        if (a != null) {
            return String.valueOf(a);
        }
        return b == null ? null : String.valueOf(b);
    }

    private static Boolean asNullableBoolean(Object obj) {
        if (obj instanceof Boolean b) {
            return b;
        }
        return null;
    }

    private static Boolean firstNonNullBoolean(Object a, Object b) {
        Boolean ba = asNullableBoolean(a);
        return ba != null ? ba : asNullableBoolean(b);
    }

    private static Integer asNullableInt(Object obj) {
        if (obj instanceof Number n) {
            return n.intValue();
        }
        return null;
    }

    private static int asIntOrDefault(Object obj, int def) {
        if (obj instanceof Number n) {
            return n.intValue();
        }
        return def;
    }

    private static Double asNullableDouble(Object obj) {
        if (obj instanceof Number n) {
            return n.doubleValue();
        }
        return null;
    }

    private static double asDoubleOrDefault(Object obj, double def) {
        if (obj instanceof Number n) {
            return n.doubleValue();
        }
        return def;
    }

    // =========================================================================
    // RFC 8259 Recursive-Descent JSON Parser
    // =========================================================================

    private static final class Parser {
        private final String s;
        private final int len;
        private int pos;

        Parser(String s) {
            this.s = s != null ? s : "";
            this.len = this.s.length();
            this.pos = 0;
        }

        Object parseValue() {
            skipWhitespace();
            if (pos >= len) {
                throw new IllegalArgumentException("Unexpected end of JSON input");
            }
            char c = s.charAt(pos);
            return switch (c) {
                case '{' -> parseObjectInternal();
                case '[' -> parseArrayInternal();
                case '"' -> parseStringInternal();
                case 't', 'f' -> parseBooleanInternal();
                case 'n' -> parseNullInternal();
                default -> {
                    if (c == '-' || (c >= '0' && c <= '9')) {
                        yield parseNumberInternal();
                    }
                    throw new IllegalArgumentException("Unexpected character '" + c + "' at position " + pos);
                }
            };
        }

        private Map<String, Object> parseObjectInternal() {
            pos++; // skip '{'
            skipWhitespace();
            Map<String, Object> map = new LinkedHashMap<>();
            if (pos < len && s.charAt(pos) == '}') {
                pos++;
                return map;
            }
            while (pos < len) {
                skipWhitespace();
                if (s.charAt(pos) != '"') {
                    throw new IllegalArgumentException("Expected string key at position " + pos);
                }
                String key = parseStringInternal();
                skipWhitespace();
                if (pos >= len || s.charAt(pos) != ':') {
                    throw new IllegalArgumentException("Expected ':' after key at position " + pos);
                }
                pos++; // skip ':'
                Object val = parseValue();
                map.put(key, val);
                skipWhitespace();
                if (pos < len && s.charAt(pos) == ',') {
                    pos++;
                    continue;
                }
                if (pos < len && s.charAt(pos) == '}') {
                    pos++;
                    return map;
                }
                throw new IllegalArgumentException("Expected ',' or '}' in object at position " + pos);
            }
            throw new IllegalArgumentException("Unterminated JSON object");
        }

        private List<Object> parseArrayInternal() {
            pos++; // skip '['
            skipWhitespace();
            List<Object> list = new ArrayList<>();
            if (pos < len && s.charAt(pos) == ']') {
                pos++;
                return list;
            }
            while (pos < len) {
                Object val = parseValue();
                list.add(val);
                skipWhitespace();
                if (pos < len && s.charAt(pos) == ',') {
                    pos++;
                    continue;
                }
                if (pos < len && s.charAt(pos) == ']') {
                    pos++;
                    return list;
                }
                throw new IllegalArgumentException("Expected ',' or ']' in array at position " + pos);
            }
            throw new IllegalArgumentException("Unterminated JSON array");
        }

        private String parseStringInternal() {
            pos++; // skip '"'
            StringBuilder sb = new StringBuilder();
            while (pos < len) {
                char c = s.charAt(pos++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c == '\\') {
                    if (pos >= len) {
                        throw new IllegalArgumentException("Unterminated escape sequence");
                    }
                    char esc = s.charAt(pos++);
                    switch (esc) {
                        case '"', '\\', '/' -> sb.append(esc);
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case 'u' -> {
                            if (pos + 4 > len) {
                                throw new IllegalArgumentException("Invalid unicode escape");
                            }
                            int code = Integer.parseInt(s.substring(pos, pos + 4), 16);
                            sb.append((char) code);
                            pos += 4;
                        }
                        default -> sb.append(esc);
                    }
                } else {
                    sb.append(c);
                }
            }
            throw new IllegalArgumentException("Unterminated string literal");
        }

        private Boolean parseBooleanInternal() {
            if (s.startsWith("true", pos)) {
                pos += 4;
                return Boolean.TRUE;
            }
            if (s.startsWith("false", pos)) {
                pos += 5;
                return Boolean.FALSE;
            }
            throw new IllegalArgumentException("Invalid boolean token at position " + pos);
        }

        private Object parseNullInternal() {
            if (s.startsWith("null", pos)) {
                pos += 4;
                return null;
            }
            throw new IllegalArgumentException("Invalid null token at position " + pos);
        }

        private Number parseNumberInternal() {
            int start = pos;
            boolean isFloat = false;
            if (s.charAt(pos) == '-') {
                pos++;
            }
            while (pos < len && Character.isDigit(s.charAt(pos))) {
                pos++;
            }
            if (pos < len && s.charAt(pos) == '.') {
                isFloat = true;
                pos++;
                while (pos < len && Character.isDigit(s.charAt(pos))) {
                    pos++;
                }
            }
            if (pos < len && (s.charAt(pos) == 'e' || s.charAt(pos) == 'E')) {
                isFloat = true;
                pos++;
                if (pos < len && (s.charAt(pos) == '+' || s.charAt(pos) == '-')) {
                    pos++;
                }
                while (pos < len && Character.isDigit(s.charAt(pos))) {
                    pos++;
                }
            }
            String numStr = s.substring(start, pos);
            if (isFloat) {
                return Double.parseDouble(numStr);
            }
            long l = Long.parseLong(numStr);
            if (l >= Integer.MIN_VALUE && l <= Integer.MAX_VALUE) {
                return (int) l;
            }
            return l;
        }

        private void skipWhitespace() {
            while (pos < len) {
                char c = s.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    pos++;
                } else {
                    break;
                }
            }
        }
    }
}
