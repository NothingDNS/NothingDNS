namespace NothingDns.Sdk;

/// <summary>
/// The upstream resolver pool (<c>/api/v1/upstreams</c>).
/// </summary>
public sealed class NothingDnsUpstreams
{
    private readonly NothingDnsTransport _transport;

    /// <summary>Initializes a new instance of the <see cref="NothingDnsUpstreams"/> class.</summary>
    /// <param name="transport">The shared transport used to reach the server.</param>
    /// <exception cref="ArgumentNullException"><paramref name="transport"/> is <see langword="null"/>.</exception>
    public NothingDnsUpstreams(NothingDnsTransport transport)
    {
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
    }

    /// <summary>Read upstream health and counters.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>Per-upstream pool counters and per-server health and latency.</returns>
    /// <exception cref="NothingDnsApiException">401 or 403 when the caller's role is insufficient.</exception>
    public async Task<Upstreams> ListAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .GetAsync("/api/v1/upstreams", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.Model<Upstreams>(payload);
    }

    /// <summary>Add one upstream server to the pool at runtime.</summary>
    /// <param name="server">The server address, for example <c>9.9.9.9:53</c> or <c>https://dns.example.com/dns-query</c>.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The server's confirmation message.</returns>
    /// <exception cref="ArgumentException"><paramref name="server"/> is empty.</exception>
    /// <exception cref="NothingDnsApiException">
    /// 400 for an unparsable address, 404 when the server is unknown, or 409 when it
    /// is already configured. Admin role required.
    /// </exception>
    public async Task<string> AddAsync(string server, CancellationToken cancellationToken = default)
        => await ChangeAsync("add", server, cancellationToken).ConfigureAwait(false);

    /// <summary>Remove one upstream server from the pool at runtime.</summary>
    /// <param name="server">The server address to remove.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The server's confirmation message.</returns>
    /// <exception cref="ArgumentException"><paramref name="server"/> is empty.</exception>
    /// <exception cref="NothingDnsApiException">404 when the server is not configured. Admin role required.</exception>
    public async Task<string> RemoveAsync(string server, CancellationToken cancellationToken = default)
        => await ChangeAsync("remove", server, cancellationToken).ConfigureAwait(false);

    private async Task<string> ChangeAsync(
        string action,
        string server,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(server);

        var body = NothingDnsTransport.Body(("action", action), ("server", server));

        var payload = await _transport
            .PutAsync("/api/v1/upstreams", body, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.MessageOf(payload);
    }
}
