namespace NothingDns.Sdk;

/// <summary>
/// Query log, top domains and the metrics history ring buffer.
/// </summary>
public sealed class NothingDnsMetrics
{
    private readonly NothingDnsTransport _transport;

    /// <summary>Initializes a new instance of the <see cref="NothingDnsMetrics"/> class.</summary>
    /// <param name="transport">The shared transport used to reach the server.</param>
    /// <exception cref="ArgumentNullException"><paramref name="transport"/> is <see langword="null"/>.</exception>
    public NothingDnsMetrics(NothingDnsTransport transport)
    {
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
    }

    /// <summary>Read a page of the query log.</summary>
    /// <param name="offset">Number of rows to skip. Omit to start at the first row.</param>
    /// <param name="limit">Maximum number of rows to return. Omit to use the server default.</param>
    /// <param name="q">Optional free-text filter matched against the domain and client address.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>One page of query log rows plus the total match count.</returns>
    /// <exception cref="NothingDnsApiException">
    /// 401 or 403 when the caller's role is insufficient, or 503 when the query log
    /// is not available.
    /// </exception>
    public async Task<QueryLogPage> QueryLogAsync(
        long? offset = null,
        long? limit = null,
        string? q = null,
        CancellationToken cancellationToken = default)
    {
        var query = new[]
        {
            new KeyValuePair<string, object?>("offset", offset),
            new KeyValuePair<string, object?>("limit", limit),
            new KeyValuePair<string, object?>("q", q),
        };

        var payload = await _transport
            .GetAsync("/api/v1/queries", query, cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.Model<QueryLogPage>(payload);
    }

    /// <summary>Read the most-queried domains.</summary>
    /// <param name="limit">Maximum number of domains to return. Omit to use the server default.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The domains ordered by query count, highest first.</returns>
    /// <exception cref="NothingDnsApiException">
    /// 401 or 403 when the caller's role is insufficient, or 503 when statistics
    /// are not available.
    /// </exception>
    public async Task<TopDomains> TopDomainsAsync(
        long? limit = null,
        CancellationToken cancellationToken = default)
    {
        var query = new[] { new KeyValuePair<string, object?>("limit", limit) };

        var payload = await _transport
            .GetAsync("/api/v1/topdomains", query, cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.Model<TopDomains>(payload);
    }

    /// <summary>Read the metrics history ring buffer.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>Parallel arrays of timestamps, query counts, cache hits, cache misses and latencies.</returns>
    /// <exception cref="NothingDnsApiException">
    /// 401 or 403 when the caller's role is insufficient, or 503 when the ring buffer
    /// is not available.
    /// </exception>
    public async Task<MetricsHistory> HistoryAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .GetAsync("/api/v1/metrics/history", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.Model<MetricsHistory>(payload);
    }
}
