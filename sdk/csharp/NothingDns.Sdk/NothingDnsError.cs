using System.Text.Json;

namespace NothingDns.Sdk;

/// <summary>
/// Base class for every error raised by the NothingDNS SDK.
/// </summary>
/// <remarks>
/// Catch this type to handle any SDK failure without also catching unrelated
/// exceptions. Cancellation surfaces as the standard
/// <see cref="OperationCanceledException"/> and is deliberately not wrapped.
/// </remarks>
public class NothingDnsException : Exception
{
    /// <summary>Initializes a new instance of the <see cref="NothingDnsException"/> class.</summary>
    /// <param name="message">Human-readable description of the failure.</param>
    public NothingDnsException(string message)
        : base(message)
    {
    }

    /// <summary>Initializes a new instance of the <see cref="NothingDnsException"/> class with an inner cause.</summary>
    /// <param name="message">Human-readable description of the failure.</param>
    /// <param name="innerException">The underlying cause.</param>
    public NothingDnsException(string message, Exception? innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// An HTTP 4xx/5xx response returned by the NothingDNS server.
/// </summary>
/// <remarks>
/// <para>
/// The NothingDNS API reports failures as <c>{"error": "…"}</c>. This exception
/// surfaces the server's own text through the inherited
/// <see cref="Exception.Message"/> property, so <c>ex.Message</c> is the most
/// useful single thing to log.
/// </para>
/// <para>
/// Use the <see cref="IsNotFound"/>, <see cref="IsUnauthorized"/>,
/// <see cref="IsForbidden"/> and <see cref="IsRateLimited"/> properties in an
/// exception filter:
/// </para>
/// <code>
/// try
/// {
///     var detail = await client.Zones.GetAsync("nope.example.com", ct);
/// }
/// catch (NothingDnsApiException ex) when (ex.IsNotFound)
/// {
///     // the zone does not exist
/// }
/// </code>
/// </remarks>
public sealed class NothingDnsApiException : NothingDnsException
{
    /// <summary>Initializes a new instance of the <see cref="NothingDnsApiException"/> class.</summary>
    /// <param name="statusCode">HTTP status code returned by the server.</param>
    /// <param name="message">The server's error text, or the raw body when the payload is not JSON.</param>
    /// <param name="payload">The decoded JSON body, when the response was valid JSON.</param>
    /// <param name="rawBody">The untruncated response body exactly as received.</param>
    public NothingDnsApiException(
        int statusCode,
        string message,
        JsonElement? payload = null,
        string rawBody = "")
        : base(message)
    {
        StatusCode = statusCode;
        Payload = payload;
        RawBody = rawBody ?? string.Empty;
    }

    /// <summary>Gets the HTTP status code returned by the server.</summary>
    public int StatusCode { get; }

    /// <summary>
    /// Gets the decoded JSON body of the error response, or <see langword="null"/>
    /// when the body was absent or not valid JSON.
    /// </summary>
    public JsonElement? Payload { get; }

    /// <summary>Gets the untruncated response body exactly as received.</summary>
    public string RawBody { get; }

    /// <summary>Gets a value indicating whether the status code was 404 (resource not found).</summary>
    public bool IsNotFound => StatusCode == 404;

    /// <summary>Gets a value indicating whether the status code was 401 (missing, invalid or expired token).</summary>
    public bool IsUnauthorized => StatusCode == 401;

    /// <summary>Gets a value indicating whether the status code was 403 (the caller's role is insufficient).</summary>
    public bool IsForbidden => StatusCode == 403;

    /// <summary>Gets a value indicating whether the status code was 429 (rate limited).</summary>
    public bool IsRateLimited => StatusCode == 429;

    /// <summary>Gets a value indicating whether the status code was in the 5xx range.</summary>
    public bool IsServerError => StatusCode >= 500 && StatusCode <= 599;

    /// <summary>Returns a diagnostic string including the status code and message.</summary>
    /// <returns>A string in the form <c>NothingDNS API error {status}: {message}</c>.</returns>
    public override string ToString() => $"NothingDNS API error {StatusCode}: {Message}";
}

/// <summary>
/// The NothingDNS server could not be reached: DNS failure, refused connection,
/// TLS handshake error or a request that exceeded the configured timeout.
/// </summary>
public sealed class NothingDnsConnectionException : NothingDnsException
{
    /// <summary>Initializes a new instance of the <see cref="NothingDnsConnectionException"/> class.</summary>
    /// <param name="message">Human-readable description of the connectivity failure.</param>
    /// <param name="innerException">The underlying transport exception, when available.</param>
    public NothingDnsConnectionException(string message, Exception? innerException = null)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// A response body could not be decoded, or an argument failed local validation
/// before any request was sent.
/// </summary>
public sealed class NothingDnsValidationException : NothingDnsException
{
    /// <summary>Initializes a new instance of the <see cref="NothingDnsValidationException"/> class.</summary>
    /// <param name="message">Human-readable description of the validation failure.</param>
    public NothingDnsValidationException(string message)
        : base(message)
    {
    }

    /// <summary>Initializes a new instance of the <see cref="NothingDnsValidationException"/> class with an inner cause.</summary>
    /// <param name="message">Human-readable description of the validation failure.</param>
    /// <param name="innerException">The underlying cause, typically a <see cref="System.Text.Json.JsonException"/>.</param>
    public NothingDnsValidationException(string message, Exception? innerException)
        : base(message, innerException)
    {
    }
}

/// <summary>
/// Status-code predicates for catch blocks that handle a broad exception type.
/// </summary>
/// <remarks>
/// The same predicates are available as instance properties on
/// <see cref="NothingDnsApiException"/>; use these overloads when you catch
/// <see cref="Exception"/> or <see cref="NothingDnsException"/>.
/// </remarks>
public static class NothingDnsErrors
{
    /// <summary>Determines whether <paramref name="exception"/> is the API error raised for HTTP 404.</summary>
    /// <param name="exception">The exception to inspect; may be <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the exception is a 404 <see cref="NothingDnsApiException"/>.</returns>
    public static bool IsNotFound(Exception? exception)
        => exception is NothingDnsApiException api && api.IsNotFound;

    /// <summary>Determines whether <paramref name="exception"/> is the API error raised for HTTP 401.</summary>
    /// <param name="exception">The exception to inspect; may be <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the exception is a 401 <see cref="NothingDnsApiException"/>.</returns>
    public static bool IsUnauthorized(Exception? exception)
        => exception is NothingDnsApiException api && api.IsUnauthorized;

    /// <summary>Determines whether <paramref name="exception"/> is the API error raised for HTTP 403.</summary>
    /// <param name="exception">The exception to inspect; may be <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the exception is a 403 <see cref="NothingDnsApiException"/>.</returns>
    public static bool IsForbidden(Exception? exception)
        => exception is NothingDnsApiException api && api.IsForbidden;

    /// <summary>Determines whether <paramref name="exception"/> is the API error raised for HTTP 429.</summary>
    /// <param name="exception">The exception to inspect; may be <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the exception is a 429 <see cref="NothingDnsApiException"/>.</returns>
    public static bool IsRateLimited(Exception? exception)
        => exception is NothingDnsApiException api && api.IsRateLimited;
}
