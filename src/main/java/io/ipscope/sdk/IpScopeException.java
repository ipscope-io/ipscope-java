package io.ipscope.sdk;

import io.ipscope.sdk.IpScopeModels.RateLimitMetadata;
import java.time.Duration;

/**
 * Base runtime exception for all errors thrown by the IPScope Java SDK.
 */
public class IpScopeException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final String code;

    public IpScopeException(String message, String code) {
        super(message);
        this.code = code;
    }

    public IpScopeException(String message, String code, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public String getCode() {
        return code;
    }

    /** Thrown when client-side validation fails before making an HTTP request. */
    public static final class ValidationException extends IpScopeException {
        private static final long serialVersionUID = 1L;
        private final String field;

        public ValidationException(String message, String field) {
            super(message, "IPSCOPE_VALIDATION_ERROR");
            this.field = field;
        }

        public String getField() {
            return field;
        }
    }

    /** Thrown when an HTTP request exceeds the configured timeout. */
    public static final class TimeoutException extends IpScopeException {
        private static final long serialVersionUID = 1L;
        private final String path;
        private final Duration timeout;

        public TimeoutException(String path, Duration timeout, Throwable cause) {
            super(
                    "IPScope request to \"" + path + "\" timed out after " + timeout.toMillis() + "ms",
                    "IPSCOPE_TIMEOUT_ERROR",
                    cause
            );
            this.path = path;
            this.timeout = timeout;
        }

        public String getPath() {
            return path;
        }

        public Duration getTimeout() {
            return timeout;
        }
    }

    /** Thrown when the IPScope API returns a non-2xx HTTP status or transport failure. */
    public static class ApiException extends IpScopeException {
        private static final long serialVersionUID = 1L;
        private final int status;
        private final String path;
        private final RateLimitMetadata rateLimit;

        public ApiException(
                String message,
                int status,
                String path,
                String code,
                RateLimitMetadata rateLimit,
                Throwable cause
        ) {
            super(message, code != null ? code : "IPSCOPE_HTTP_" + status, cause);
            this.status = status;
            this.path = path;
            this.rateLimit = rateLimit;
        }

        public int getStatus() {
            return status;
        }

        public String getPath() {
            return path;
        }

        public RateLimitMetadata getRateLimit() {
            return rateLimit;
        }
    }

    /** Thrown on HTTP 401 Unauthorized or 403 Forbidden. */
    public static final class AuthenticationException extends ApiException {
        private static final long serialVersionUID = 1L;

        public AuthenticationException(
                String message,
                int status,
                String path,
                RateLimitMetadata rateLimit
        ) {
            super(
                    message,
                    status,
                    path,
                    status == 401 ? "IPSCOPE_UNAUTHORIZED" : "IPSCOPE_FORBIDDEN_SCOPE",
                    rateLimit,
                    null
            );
        }
    }

    /** Thrown on HTTP 429 Too Many Requests when retries are exhausted or disabled. */
    public static final class RateLimitException extends ApiException {
        private static final long serialVersionUID = 1L;
        private final Duration retryAfter;

        public RateLimitException(
                String message,
                String path,
                Duration retryAfter,
                RateLimitMetadata rateLimit
        ) {
            super(message, 429, path, "IPSCOPE_RATE_LIMITED", rateLimit, null);
            this.retryAfter = retryAfter;
        }

        public Duration getRetryAfter() {
            return retryAfter;
        }
    }
}
