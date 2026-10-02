namespace NothingDns.Sdk;

/// <summary>
/// Gossip membership and Raft consensus (<c>/api/v1/cluster</c>).
/// </summary>
public sealed class NothingDnsCluster
{
    private readonly NothingDnsTransport _transport;

    /// <summary>Initializes a new instance of the <see cref="NothingDnsCluster"/> class.</summary>
    /// <param name="transport">The shared transport used to reach the server.</param>
    /// <exception cref="ArgumentNullException"><paramref name="transport"/> is <see langword="null"/>.</exception>
    public NothingDnsCluster(NothingDnsTransport transport)
    {
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
    }

    /// <summary>Read the cluster status.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>Node counts, gossip counters, Raft state and cluster-wide metrics.</returns>
    /// <exception cref="NothingDnsApiException">401 or 403 when the caller's role is insufficient.</exception>
    public async Task<ClusterStatus> StatusAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .GetAsync("/api/v1/cluster/status", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.Model<ClusterStatus>(payload);
    }

    /// <summary>List the cluster nodes.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>Every known node with its membership state, health and load.</returns>
    /// <exception cref="NothingDnsApiException">401 or 403 when the caller's role is insufficient.</exception>
    public async Task<IReadOnlyList<ClusterNode>> NodesAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .GetAsync("/api/v1/cluster/nodes", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.ListOf<ClusterNode>(payload, "nodes");
    }

    /// <summary>Join a cluster through a seed node.</summary>
    /// <param name="seedAddress">The address of an existing cluster member, for example <c>10.0.0.5:7946</c>.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The server's confirmation message.</returns>
    /// <exception cref="ArgumentException"><paramref name="seedAddress"/> is empty.</exception>
    /// <exception cref="NothingDnsApiException">
    /// 400 for an unparsable address, or 503 when the seed node is unreachable. Admin role required.
    /// </exception>
    public async Task<string> JoinAsync(string seedAddress, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(seedAddress);

        var body = NothingDnsTransport.Body(("seed_address", seedAddress));

        var payload = await _transport
            .PostAsync("/api/v1/cluster/join", body, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.MessageOf(payload);
    }

    /// <summary>Drain and leave the cluster.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The server's confirmation message.</returns>
    /// <exception cref="NothingDnsApiException">
    /// 500 when the drain does not complete cleanly, or 503 when the consensus layer
    /// is unavailable. Admin role required.
    /// </exception>
    public async Task<string> LeaveAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .DeleteAsync("/api/v1/cluster/leave", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.MessageOf(payload);
    }
}
