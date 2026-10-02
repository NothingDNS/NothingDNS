using System.Text.Json;

namespace NothingDns.Sdk;

/// <summary>
/// The log levels accepted by <see cref="NothingDnsConfig.SetLoggingAsync"/>.
/// </summary>
public static class NothingDnsLogLevels
{
    /// <summary>Verbose diagnostic logging.</summary>
    public const string Debug = "debug";

    /// <summary>Normal operational logging.</summary>
    public const string Info = "info";

    /// <summary>Warning-level logging.</summary>
    public const string Warn = "warn";

    /// <summary>Warning-level logging, alternative spelling.</summary>
    public const string Warning = "warning";

    /// <summary>Error-level logging.</summary>
    public const string Error = "error";

    /// <summary>Fatal-only logging.</summary>
    public const string Fatal = "fatal";

    /// <summary>All accepted log levels.</summary>
    public static readonly IReadOnlyList<string> All = new[] { Debug, Info, Warn, Warning, Error, Fatal };
}

/// <summary>
/// Configuration inspection and runtime tunables (<c>/api/v1/config</c>).
/// </summary>
/// <remarks>
/// <para>
/// Runtime changes are persisted to <c>runtime_overrides.json</c> in the data
/// directory and re-applied over the YAML section on every config reload, so they
/// survive a restart. Reading the effective configuration needs the operator
/// role; every setter needs admin.
/// </para>
/// <para>
/// The setters are partial updates: an argument left <see langword="null"/> is
/// omitted from the request body and therefore left unchanged on the server.
/// </para>
/// </remarks>
public sealed class NothingDnsConfig
{
    private readonly NothingDnsTransport _transport;

    /// <summary>Initializes a new instance of the <see cref="NothingDnsConfig"/> class.</summary>
    /// <param name="transport">The shared transport used to reach the server.</param>
    /// <exception cref="ArgumentNullException"><paramref name="transport"/> is <see langword="null"/>.</exception>
    public NothingDnsConfig(NothingDnsTransport transport)
    {
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
    }

    /// <summary>Read the effective configuration with secrets redacted.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>
    /// The merged configuration as a JSON document. Secrets are replaced with a
    /// redaction marker by the server.
    /// </returns>
    /// <exception cref="NothingDnsApiException">401 or 403 when the caller's role is insufficient.</exception>
    public async Task<JsonElement> GetAsync(CancellationToken cancellationToken = default)
        => await _transport
            .GetAsync("/api/v1/config", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

    /// <summary>Reload the configuration file from disk without restarting.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The server's confirmation message.</returns>
    /// <exception cref="NothingDnsApiException">401 or 403 when the caller is not an admin, or 500 when the file is invalid.</exception>
    public async Task<string> ReloadAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .PostAsync("/api/v1/config/reload", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.MessageOf(payload);
    }

    /// <summary>Change the log level at runtime.</summary>
    /// <param name="level">One of the <see cref="NothingDnsLogLevels"/> values. Matched case-insensitively and sent lowercased.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The server's confirmation message.</returns>
    /// <exception cref="ArgumentException"><paramref name="level"/> is empty.</exception>
    /// <exception cref="NothingDnsValidationException"><paramref name="level"/> is not a known level.</exception>
    /// <exception cref="NothingDnsApiException">400 for an invalid level, or 403 when the caller is not an admin.</exception>
    public async Task<string> SetLoggingAsync(
        string level,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(level);

        if (!NothingDnsLogLevels.All.Contains(level, StringComparer.OrdinalIgnoreCase))
        {
            throw new NothingDnsValidationException(
                $"level must be one of {string.Join(", ", NothingDnsLogLevels.All)}, but was '{level}'.");
        }

        var body = NothingDnsTransport.Body(("level", level.ToLowerInvariant()));
        var payload = await _transport
            .PutAsync("/api/v1/config/logging", body, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.MessageOf(payload);
    }

    /// <summary>Change the per-client DNS rate limiter at runtime.</summary>
    /// <param name="enabled">Turn the limiter on or off. Omit to leave unchanged.</param>
    /// <param name="rate">Sustained queries per second per client. Omit to leave unchanged.</param>
    /// <param name="burst">Token bucket burst size. Omit to leave unchanged.</param>
    /// <param name="maxBuckets">Maximum number of tracked client buckets. Omit to leave unchanged.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The server's confirmation message.</returns>
    /// <exception cref="NothingDnsApiException">401 or 403 when the caller is not an admin.</exception>
    public async Task<string> SetRrlAsync(
        bool? enabled = null,
        double? rate = null,
        long? burst = null,
        long? maxBuckets = null,
        CancellationToken cancellationToken = default)
    {
        var body = NothingDnsTransport.Body(
            ("enabled", enabled),
            ("rate", rate),
            ("burst", burst),
            ("max_buckets", maxBuckets));

        var payload = await _transport
            .PutAsync("/api/v1/config/rrl", body, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.MessageOf(payload);
    }

    /// <summary>Change cache settings at runtime.</summary>
    /// <param name="enabled">Turn caching on or off. Omit to leave unchanged.</param>
    /// <param name="size">Maximum number of cache entries. Omit to leave unchanged.</param>
    /// <param name="defaultTtl">Default TTL in seconds applied to cached answers.</param>
    /// <param name="maxTtl">Upper bound on any cached TTL.</param>
    /// <param name="minTtl">Lower bound on any cached TTL.</param>
    /// <param name="negativeTtl">TTL in seconds for negative (NXDOMAIN/NODATA) answers.</param>
    /// <param name="prefetch">Refresh popular entries shortly before expiry.</param>
    /// <param name="prefetchThreshold">Remaining TTL in seconds below which prefetching starts.</param>
    /// <param name="serveStale">Serve expired entries while a refresh is in flight (RFC 8767).</param>
    /// <param name="staleGraceSecs">How long a stale answer may still be served.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The server's confirmation message.</returns>
    /// <exception cref="NothingDnsApiException">400 for inconsistent TTL bounds, or 403 when the caller is not an admin.</exception>
    public async Task<string> SetCacheAsync(
        bool? enabled = null,
        long? size = null,
        long? defaultTtl = null,
        long? maxTtl = null,
        long? minTtl = null,
        long? negativeTtl = null,
        bool? prefetch = null,
        long? prefetchThreshold = null,
        bool? serveStale = null,
        long? staleGraceSecs = null,
        CancellationToken cancellationToken = default)
    {
        var body = NothingDnsTransport.Body(
            ("enabled", enabled),
            ("size", size),
            ("default_ttl", defaultTtl),
            ("max_ttl", maxTtl),
            ("min_ttl", minTtl),
            ("negative_ttl", negativeTtl),
            ("prefetch", prefetch),
            ("prefetch_threshold", prefetchThreshold),
            ("serve_stale", serveStale),
            ("stale_grace_secs", staleGraceSecs));

        var payload = await _transport
            .PutAsync("/api/v1/config/cache", body, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.MessageOf(payload);
    }

    /// <summary>Change resolution settings at runtime.</summary>
    /// <param name="recursive">Turn recursive resolution on or off. Omit to leave unchanged.</param>
    /// <param name="authoritativeOnly">Refuse queries for names outside configured zones.</param>
    /// <param name="maxDepth">Maximum recursion depth.</param>
    /// <param name="timeout">Per-query timeout as a Go-style duration string, for example <c>5s</c>.</param>
    /// <param name="edns0BufferSize">EDNS0 UDP payload size advertised to upstreams.</param>
    /// <param name="qnameMinimization">Use QNAME minimisation (RFC 9156).</param>
    /// <param name="use0x20">Randomise query name case as a 0x20 defence.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The server's confirmation message.</returns>
    /// <exception cref="NothingDnsApiException">400 for an invalid duration or value, or 403 when the caller is not an admin.</exception>
    public async Task<string> SetResolutionAsync(
        bool? recursive = null,
        bool? authoritativeOnly = null,
        long? maxDepth = null,
        string? timeout = null,
        long? edns0BufferSize = null,
        bool? qnameMinimization = null,
        bool? use0x20 = null,
        CancellationToken cancellationToken = default)
    {
        var body = NothingDnsTransport.Body(
            ("recursive", recursive),
            ("authoritative_only", authoritativeOnly),
            ("max_depth", maxDepth),
            ("timeout", timeout),
            ("edns0_buffer_size", edns0BufferSize),
            ("qname_minimization", qnameMinimization),
            ("use_0x20", use0x20));

        var payload = await _transport
            .PutAsync("/api/v1/config/resolution", body, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.MessageOf(payload);
    }

    /// <summary>Enable or disable DNS64 synthesis at runtime (RFC 6147).</summary>
    /// <param name="enabled">Whether synthesis is active.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The server's confirmation message.</returns>
    /// <exception cref="NothingDnsApiException">401 or 403 when the caller is not an admin.</exception>
    public async Task<string> SetDns64Async(bool enabled, CancellationToken cancellationToken = default)
    {
        var body = NothingDnsTransport.Body(("enabled", enabled));
        var payload = await _transport
            .PutAsync("/api/v1/config/dns64", body, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.MessageOf(payload);
    }

    /// <summary>Enable or disable DNS Cookies at runtime (RFC 7873).</summary>
    /// <param name="enabled">Whether DNS Cookies are active.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The server's confirmation message.</returns>
    /// <exception cref="NothingDnsApiException">401 or 403 when the caller is not an admin.</exception>
    public async Task<string> SetCookieAsync(bool enabled, CancellationToken cancellationToken = default)
    {
        var body = NothingDnsTransport.Body(("enabled", enabled));
        var payload = await _transport
            .PutAsync("/api/v1/config/cookie", body, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.MessageOf(payload);
    }
}
