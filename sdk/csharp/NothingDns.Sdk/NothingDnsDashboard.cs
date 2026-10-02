namespace NothingDns.Sdk;

/// <summary>
/// Dashboard counters and live query events (<c>/api/dashboard</c>).
/// </summary>
/// <remarks>
/// These endpoints back the embedded dashboard and use camelCase field names,
/// which the models in this SDK preserve on the wire while exposing idiomatic
/// PascalCase properties.
/// </remarks>
public sealed class NothingDnsDashboard
{
    private readonly NothingDnsTransport _transport;

    /// <summary>Initializes a new instance of the <see cref="NothingDnsDashboard"/> class.</summary>
    /// <param name="transport">The shared transport used to reach the server.</param>
    /// <exception cref="ArgumentNullException"><paramref name="transport"/> is <see langword="null"/>.</exception>
    public NothingDnsDashboard(NothingDnsTransport transport)
    {
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
    }

    /// <summary>Read the dashboard counters.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>Uptime, query totals and rate, cache hit rate, blocked queries, active clients and zone count.</returns>
    /// <exception cref="NothingDnsApiException">401 or 403 when the caller's role is insufficient.</exception>
    public async Task<DashboardStats> StatsAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .GetAsync("/api/dashboard/stats", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.Model<DashboardStats>(payload);
    }

    /// <summary>Read the most recent query events.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The last 100 query events, newest first.</returns>
    /// <exception cref="NothingDnsApiException">
    /// 401 or 403 when the caller's role is insufficient, or 503 when the live query
    /// buffer is not available.
    /// </exception>
    public async Task<IReadOnlyList<QueryEvent>> QueriesAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .GetAsync("/api/dashboard/queries", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.ListOf<QueryEvent>(payload);
    }

    /// <summary>Read the zone summary shown on the dashboard.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>Each zone's name, record count and serial.</returns>
    /// <exception cref="NothingDnsApiException">401 or 403 when the caller's role is insufficient.</exception>
    public async Task<IReadOnlyList<Zone>> ZonesAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .GetAsync("/api/dashboard/zones", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.ListOf<Zone>(payload);
    }
}
