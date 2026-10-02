package io.nothingdns.sdk;

/**
 * The server could not be reached: DNS resolution failure, refused connection,
 * TLS handshake error or a request that exceeded its timeout.
 *
 * <p>No HTTP response was produced, so {@link #getStatusCode()} is
 * {@link NothingDnsException#NO_STATUS} and {@link #getPayload()} is
 * {@code null}. The original I/O or interrupt error is kept as the cause.</p>
 */
public class NothingDnsConnectionException extends NothingDnsException {

    private static final long serialVersionUID = 1L;

    /**
     * Create a connection failure.
     *
     * @param message a human-readable description, ideally including the URL
     * @param cause   the underlying I/O or interrupt error, may be {@code null}
     */
    public NothingDnsConnectionException(String message, Throwable cause) {
        super(NO_STATUS, message, null, cause);
    }

    /**
     * Create a connection failure without an underlying cause.
     *
     * @param message a human-readable description, ideally including the URL
     */
    public NothingDnsConnectionException(String message) {
        this(message, null);
    }
}
