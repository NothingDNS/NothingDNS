namespace NothingDns.Sdk;

/// <summary>
/// The DNS response cache (<c>/api/v1/cache</c>).
/// </summary>
public sealed class NothingDnsCache
{
    private readonly NothingDnsTransport _transport;

    /// <summary>Initializes a new instance of the <see cref="NothingDnsCache"/> class.</summary>
    /// <param name="transport">The shared transport used to reach the server.</param>
    /// <exception cref="ArgumentNullException"><paramref name="transport"/> is <see langword="null"/>.</exception>
    public NothingDnsCache(NothingDnsTransport transport)
    {
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
    }

    /// <summary>Read the cache counters.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>Current size, capacity, hit and miss counters and the hit ratio.</returns>
    /// <exception cref="NothingDnsApiException">401 or 403 when the caller's role is insufficient (operator required).</exception>
    public async Task<CacheStats> StatsAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .GetAsync("/api/v1/cache/stats", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.Model<CacheStats>(payload);
    }

    /// <summary>Flush every entry from the cache.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The server's confirmation message.</returns>
    /// <exception cref="NothingDnsApiException">401 or 403 when the caller is not an admin.</exception>
    public async Task<string> FlushAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .PostAsync("/api/v1/cache/flush", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.MessageOf(payload);
    }

    /// <summary>Flush the cached entries of one name only, every type.</summary>
    /// <param name="name">The owner name to drop from the cache.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The server's message, which carries the number of entries removed.</returns>
    /// <exception cref="ArgumentException">
    /// <paramref name="name"/> is empty; use <see cref="FlushAsync"/> to clear the whole cache.
    /// </exception>
    /// <exception cref="NothingDnsApiException">401 or 403 when the caller is not an admin.</exception>
    public async Task<string> FlushNameAsync(string name, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        var query = new[] { new KeyValuePair<string, object?>("name", name) };
        var payload = await _transport
            .PostAsync("/api/v1/cache/flush", query: query, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.MessageOf(payload);
    }
}
