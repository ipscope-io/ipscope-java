package io.ipscope.sdk;

import io.ipscope.sdk.IpScopeException.ValidationException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Zero-DNS client-side IPv4/IPv6, CIDR prefix, and API key validation utilities.
 *
 * <p>Guarantees that {@link InetAddress#getByName(String)} is only called after verifying
 * that the string contains strictly IPv4 or IPv6 literal characters, preventing any
 * accidental blocking DNS resolution on malformed inputs.
 */
public final class IpScopeValidator {

    public static final int MAX_SINGLE_BATCH_SIZE = 100;

    private IpScopeValidator() {}

    public record ValidatedIp(String canonicalIp, int family) {}

    public record ValidatedCidr(String address, int prefixLength, int family, String canonicalCidr) {}

    public record ValidatedBatch(List<String> orderedIps, List<String> uniqueIps) {}

    /** Validates and trims an IPScope API key, rejecting null, empty, and control characters. */
    public static String validateApiKey(String rawApiKey) {
        if (rawApiKey == null) {
            throw new ValidationException("API key must be a non-empty string", "apiKey");
        }
        String trimmed = rawApiKey.trim();
        if (trimmed.isEmpty()) {
            throw new ValidationException("API key cannot be empty", "apiKey");
        }
        for (int i = 0; i < trimmed.length(); i++) {
            char c = trimmed.charAt(i);
            if (c == '\r' || c == '\n' || c == '\0') {
                throw new ValidationException("API key contains invalid control characters", "apiKey");
            }
        }
        return trimmed;
    }

    /**
     * Validates an IPv4 or IPv6 literal string without triggering DNS resolution.
     */
    public static ValidatedIp validateIpAddress(String rawIp) {
        if (rawIp == null) {
            throw new ValidationException("IP address must be a string", "ip");
        }
        String trimmed = rawIp.trim();
        if (trimmed.isEmpty() || trimmed.indexOf('%') >= 0 || trimmed.indexOf('/') >= 0) {
            throw new ValidationException("Invalid IPv4 or IPv6 address: \"" + trimmed + "\"", "ip");
        }

        boolean looksLikeV6 = trimmed.indexOf(':') >= 0;
        if (looksLikeV6) {
            if (!isSyntacticallyValidIpv6Literal(trimmed)) {
                throw new ValidationException("Invalid IPv4 or IPv6 address: \"" + trimmed + "\"", "ip");
            }
        } else {
            if (!isStrictIpv4DottedQuad(trimmed)) {
                throw new ValidationException("Invalid IPv4 or IPv6 address: \"" + trimmed + "\"", "ip");
            }
        }

        try {
            InetAddress addr = InetAddress.getByName(trimmed);
            byte[] rawBytes = addr.getAddress();
            int family = (addr instanceof Inet6Address || rawBytes.length == 16) ? 6 : 4;
            String canonical = formatCanonicalIp(rawBytes, family);
            return new ValidatedIp(canonical, family);
        } catch (UnknownHostException e) {
            throw new ValidationException("Invalid IPv4 or IPv6 address: \"" + trimmed + "\"", "ip");
        }
    }

    /**
     * Validates a CIDR prefix ({@code <ip>/<prefixLength>}), masks host bits to the canonical
     * network address, and returns {@link ValidatedCidr}.
     */
    public static ValidatedCidr validateCidrPrefix(String rawCidr) {
        if (rawCidr == null) {
            throw new ValidationException("CIDR prefix must be a string", "cidr");
        }
        String trimmed = rawCidr.trim();
        int slashIdx = trimmed.indexOf('/');
        if (slashIdx <= 0 || slashIdx != trimmed.lastIndexOf('/') || slashIdx == trimmed.length() - 1) {
            throw new ValidationException(
                    "Invalid CIDR notation \"" + trimmed + "\". Expected \"<ip>/<prefixLength>\" (e.g. \"1.1.1.0/24\")",
                    "cidr"
            );
        }

        String addrPart = trimmed.substring(0, slashIdx);
        String lenPart = trimmed.substring(slashIdx + 1).trim();
        ValidatedIp vIp = validateIpAddress(addrPart);

        for (int i = 0; i < lenPart.length(); i++) {
            if (!Character.isDigit(lenPart.charAt(i))) {
                throw new ValidationException(
                        "Invalid prefix length \"" + lenPart + "\" in CIDR \"" + trimmed + "\"",
                        "cidr"
                );
            }
        }

        int prefixLen;
        try {
            prefixLen = Integer.parseInt(lenPart, 10);
        } catch (NumberFormatException e) {
            throw new ValidationException(
                    "Invalid prefix length \"" + lenPart + "\" in CIDR \"" + trimmed + "\"",
                    "cidr"
            );
        }

        int maxBits = vIp.family() == 4 ? 32 : 128;
        if (prefixLen < 0 || prefixLen > maxBits) {
            throw new ValidationException(
                    "Prefix length " + prefixLen + " out of range [0.." + maxBits + "] for IPv" + vIp.family() + " CIDR \"" + trimmed + "\"",
                    "cidr"
            );
        }

        try {
            byte[] bytes = InetAddress.getByName(vIp.canonicalIp()).getAddress();
            maskNetworkBytes(bytes, prefixLen);
            String maskedAddr = formatCanonicalIp(bytes, vIp.family());
            return new ValidatedCidr(
                    maskedAddr,
                    prefixLen,
                    vIp.family(),
                    maskedAddr + "/" + prefixLen
            );
        } catch (UnknownHostException e) {
            throw new ValidationException("Invalid CIDR prefix: \"" + trimmed + "\"", "cidr");
        }
    }

    /**
     * Validates a list of 1..maxBatchSize IPs and returns both the ordered normalized IPs
     * and the deduplicated unique IPs.
     */
    public static ValidatedBatch validateAndDeduplicateBatchIps(List<String> rawIps, int maxBatchSize) {
        if (rawIps == null || rawIps.isEmpty()) {
            throw new ValidationException("Batch IPs list must contain at least 1 IP address", "ips");
        }
        if (maxBatchSize > 0 && rawIps.size() > maxBatchSize) {
            throw new ValidationException(
                    "Batch IPs length (" + rawIps.size() + ") exceeds maximum single-request batch size ("
                            + maxBatchSize + "). Use lookupBatchChunked() or lookupBatchStream() for larger lists.",
                    "ips"
            );
        }

        List<String> ordered = new ArrayList<>(rawIps.size());
        Set<String> unique = new LinkedHashSet<>();

        for (String raw : rawIps) {
            ValidatedIp v = validateIpAddress(raw);
            ordered.add(v.canonicalIp());
            unique.add(v.canonicalIp());
        }

        return new ValidatedBatch(List.copyOf(ordered), List.copyOf(unique));
    }

    private static boolean isStrictIpv4DottedQuad(String s) {
        String[] parts = s.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3) {
                return false;
            }
            if (part.length() > 1 && part.charAt(0) == '0') {
                return false;
            }
            for (int i = 0; i < part.length(); i++) {
                if (!Character.isDigit(part.charAt(i))) {
                    return false;
                }
            }
            int val = Integer.parseInt(part, 10);
            if (val < 0 || val > 255) {
                return false;
            }
        }
        return true;
    }

    private static boolean isSyntacticallyValidIpv6Literal(String s) {
        if (s.length() < 2 || s.length() > 45) {
            return false;
        }
        int colonCount = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == ':') {
                colonCount++;
            } else if (c == '.') {
                // IPv4-embedded IPv6 allowed
            } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                return false;
            }
        }
        return colonCount >= 2 && colonCount <= 7;
    }

    private static void maskNetworkBytes(byte[] bytes, int prefixLen) {
        int fullBytes = prefixLen / 8;
        int remBits = prefixLen % 8;
        if (fullBytes < bytes.length) {
            if (remBits > 0) {
                int mask = (0xFF << (8 - remBits)) & 0xFF;
                bytes[fullBytes] = (byte) (bytes[fullBytes] & mask);
                fullBytes++;
            }
            for (int i = fullBytes; i < bytes.length; i++) {
                bytes[i] = 0;
            }
        }
    }

    private static String formatCanonicalIp(byte[] bytes, int family) {
        if (family == 4 && bytes.length == 4) {
            return (bytes[0] & 0xFF) + "."
                    + (bytes[1] & 0xFF) + "."
                    + (bytes[2] & 0xFF) + "."
                    + (bytes[3] & 0xFF);
        }
        // RFC 5952 canonical IPv6 compression (shortest zero run -> "::", lowercase hex)
        int[] groups = new int[8];
        for (int i = 0; i < 8; i++) {
            groups[i] = ((bytes[i * 2] & 0xFF) << 8) | (bytes[i * 2 + 1] & 0xFF);
        }
        int bestStart = -1;
        int bestLen = 0;
        int curStart = -1;
        int curLen = 0;
        for (int i = 0; i < 8; i++) {
            if (groups[i] == 0) {
                if (curStart == -1) {
                    curStart = i;
                    curLen = 1;
                } else {
                    curLen++;
                }
                if (curLen > bestLen && curLen >= 2) {
                    bestLen = curLen;
                    bestStart = curStart;
                }
            } else {
                curStart = -1;
                curLen = 0;
            }
        }

        StringBuilder sb = new StringBuilder(39);
        for (int i = 0; i < 8; i++) {
            if (bestStart != -1 && i >= bestStart && i < bestStart + bestLen) {
                if (i == bestStart) {
                    sb.append("::");
                }
                continue;
            }
            if (i > 0 && !(bestStart != -1 && i == bestStart + bestLen)) {
                sb.append(':');
            }
            sb.append(Integer.toHexString(groups[i]).toLowerCase(Locale.ROOT));
        }
        return sb.toString();
    }
}
