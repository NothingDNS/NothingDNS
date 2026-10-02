namespace NothingDns.Sdk;

/// <summary>
/// DNSSEC validation status and signing keys (<c>/api/v1/dnssec</c>).
/// </summary>
public sealed class NothingDnsDnssec
{
    private readonly NothingDnsTransport _transport;

    /// <summary>Initializes a new instance of the <see cref="NothingDnsDnssec"/> class.</summary>
    /// <param name="transport">The shared transport used to reach the server.</param>
    /// <exception cref="ArgumentNullException"><paramref name="transport"/> is <see langword="null"/>.</exception>
    public NothingDnsDnssec(NothingDnsTransport transport)
    {
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
    }

    /// <summary>Read the DNSSEC validation status.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>Whether validation is enabled and whether it is mandatory.</returns>
    /// <exception cref="NothingDnsApiException">401 or 403 when the caller's role is insufficient.</exception>
    public async Task<DnssecStatus> StatusAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .GetAsync("/api/v1/dnssec/status", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.Model<DnssecStatus>(payload);
    }

    /// <summary>List the published DNSSEC signing keys.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>Public key metadata grouped by zone. Private key material is never returned.</returns>
    /// <exception cref="NothingDnsApiException">401 or 403 when the caller is not an admin.</exception>
    public async Task<DnssecKeyList> KeysAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .GetAsync("/api/v1/dnssec/keys", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.Model<DnssecKeyList>(payload);
    }
}
