package io.nothingdns.sdk;

/**
 * The single error type raised by the NothingDNS SDK.
 *
 * <p>It represents two failure modes:</p>
 * <ul>
 *   <li>An HTTP 4xx/5xx response from the server. {@link #getStatusCode()}
 *       carries the status, {@link #getPayload()} the raw response body.</li>
 *   <li>A transport-level failure or an undecodable body, surfaced as
 *       {@link NothingDnsConnectionException} or as this type with a
 *       non-HTTP status code of {@code 0}.</li>
 * </ul>
 *
 * <p>The server reports failures as {@code {"error": "…"}}. When that field is
 * present it becomes the exception message; otherwise the raw body (truncated)
 * is used, so the server's explanation is never lost.</p>
 *
 * <p>All SDK methods throw this type unchecked, so callers are not forced to
 * declare it — but they should still handle it.</p>
 */
public class NothingDnsException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /** Status used when the failure did not come from an HTTP response. */
    public static final int NO_STATUS = 0;

    private final int statusCode;
    private final String payload;

    /**
     * Create an exception for an HTTP error response.
     *
     * @param statusCode the HTTP status code returned by the server
     * @param message    a human-readable description of the failure
     * @param payload    the raw (undecoded) response body, may be {@code null}
     */
    public NothingDnsException(int statusCode, String message, String payload) {
        this(statusCode, message, payload, null);
    }

    /**
     * Create an exception for an HTTP error response, keeping an underlying cause.
     *
     * @param statusCode the HTTP status code returned by the server
     * @param message    a human-readable description of the failure
     * @param payload    the raw (undecoded) response body, may be {@code null}
     * @param cause      the underlying error, may be {@code null}
     */
    public NothingDnsException(int statusCode, String message, String payload, Throwable cause) {
        super("NothingDNS API error " + statusCode + ": " + message, cause);
        this.statusCode = statusCode;
        this.payload = payload;
    }

    /**
     * Create an exception for a failure that produced no HTTP response.
     *
     * @param message a human-readable description of the failure
     * @param cause   the underlying error, may be {@code null}
     */
    public NothingDnsException(String message, Throwable cause) {
        this(NO_STATUS, message, null, cause);
    }

    /**
     * The HTTP status code that produced this error, or {@link #NO_STATUS}
     * when the failure was not an HTTP response.
     *
     * @return the status code
     */
    public int getStatusCode() {
        return statusCode;
    }

    /**
     * The raw, undecoded response body, when one was received.
     *
     * @return the response body, or {@code null}
     */
    public String getPayload() {
        return payload;
    }

    /**
     * Whether this error represents an HTTP 404 (missing zone, record, user, …).
     *
     * @param error the error to test, may be {@code null}
     * @return true when {@code error} is a 404
     */
    public static boolean isNotFound(NothingDnsException error) {
        return statusOf(error) == 404;
    }

    /**
     * Whether this error represents an HTTP 401 (missing or expired token).
     *
     * @param error the error to test, may be {@code null}
     * @return true when {@code error} is a 401
     */
    public static boolean isUnauthorized(NothingDnsException error) {
        return statusOf(error) == 401;
    }

    /**
     * Whether this error represents an HTTP 403 (insufficient role).
     *
     * <p>The server's role hierarchy is viewer &lt; operator &lt; admin.</p>
     *
     * @param error the error to test, may be {@code null}
     * @return true when {@code error} is a 403
     */
    public static boolean isForbidden(NothingDnsException error) {
        return statusOf(error) == 403;
    }

    /**
     * Whether this error represents an HTTP 429 (rate limited).
     *
     * @param error the error to test, may be {@code null}
     * @return true when {@code error} is a 429
     */
    public static boolean isRateLimited(NothingDnsException error) {
        return statusOf(error) == 429;
    }

    private static int statusOf(NothingDnsException error) {
        return error == null ? -1 : error.getStatusCode();
    }
}
