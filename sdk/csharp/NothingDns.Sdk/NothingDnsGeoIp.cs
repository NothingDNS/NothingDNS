namespace NothingDns.Sdk;

/// <summary>
/// GeoDNS statistics (<c>/api/v1/geoip</c>).
/// </summary>
public sealed class NothingDnsGeoIp
{
    private readonly NothingDnsTransport _transport;

    /// <summary>Initializes a new instance of the <see cref="NothingDnsGeoIp"/> class.</summary>
    /// <param name="transport">The shared transport used to reach the server.</param>
    /// <exception cref="ArgumentNullException"><paramref name="transport"/> is <see langword="null"/>.</exception>
    public NothingDnsGeoIp(NothingDnsTransport transport)
    {
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
    }

    /// <summary>Read GeoDNS statistics.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>Whether GeoDNS is on, the rule count, MaxMind database state and lookup counters.</returns>
    /// <exception cref="NothingDnsApiException">401 or 403 when the caller's role is insufficient.</exception>
    public async Task<GeoIpStats> StatsAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .GetAsync("/api/v1/geoip/stats", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.Model<GeoIpStats>(payload);
    }
}
