namespace NothingDns.Sdk;

/// <summary>
/// Client ACLs and the recursion allow list (<c>/api/v1/acl</c>).
/// </summary>
/// <remarks>
/// Rules are evaluated in configuration order and the first match wins. Once any
/// rule exists, a client matching none of them is refused. Changes made through
/// the API are written to <c>access_policy.json</c>, which replaces the YAML
/// <c>acl</c> section at start-up and on every reload.
/// </remarks>
public sealed class NothingDnsAcl
{
    private readonly NothingDnsTransport _transport;

    /// <summary>Initializes a new instance of the <see cref="NothingDnsAcl"/> class.</summary>
    /// <param name="transport">The shared transport used to reach the server.</param>
    /// <exception cref="ArgumentNullException"><paramref name="transport"/> is <see langword="null"/>.</exception>
    public NothingDnsAcl(NothingDnsTransport transport)
    {
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
    }

    /// <summary>Read the ACL rules together with the recursion allow list.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>
    /// The current ACL. When <see cref="AclConfig.Persistent"/> is true the list is
    /// served from <c>access_policy.json</c> rather than the configuration file.
    /// </returns>
    /// <exception cref="NothingDnsApiException">401 or 403 when the caller's role is insufficient.</exception>
    public async Task<AclConfig> GetAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .GetAsync("/api/v1/acl", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.Model<AclConfig>(payload);
    }

    /// <summary>Replace the full ACL rule list.</summary>
    /// <param name="rules">The complete new rule list, in evaluation order.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The server's confirmation message.</returns>
    /// <exception cref="NothingDnsValidationException"><paramref name="rules"/> is empty.</exception>
    /// <exception cref="NothingDnsApiException">400 for an invalid rule, or 403 when the caller is not an admin.</exception>
    /// <remarks>
    /// This is a replace, not a merge. To change a single rule, read the current
    /// list, edit it in memory and send the whole thing back:
    /// <code>
    /// var current = (await client.Acl.GetAsync(ct)).Rules;
    /// current.Add(new AclRule { Name = "office", Networks = { "10.0.0.0/8" }, Action = "allow" });
    /// await client.Acl.SetAsync(current, ct);
    /// </code>
    /// An empty list is refused deliberately rather than sent, because it would
    /// silently open the server to every client that matches no rule.
    /// </remarks>
    public async Task<string> SetAsync(
        IEnumerable<AclRule> rules,
        CancellationToken cancellationToken = default)
    {
        var materialized = rules?.ToList() ?? new List<AclRule>();
        if (materialized.Count == 0)
        {
            throw new NothingDnsValidationException(
                "refusing to send an empty rule list; the server refuses every unmatched client once any rule exists");
        }

        var body = NothingDnsTransport.Body(("rules", materialized.Select(rule => rule.ToPayload()).ToList()));

        var payload = await _transport
            .PutAsync("/api/v1/acl", body, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.MessageOf(payload);
    }

    /// <summary>Read the recursion allow list.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>Which clients may send recursive queries.</returns>
    /// <exception cref="NothingDnsApiException">401 or 403 when the caller's role is insufficient.</exception>
    public async Task<RecursionAllowList> RecursionAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .GetAsync("/api/v1/acl/recursion", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.Model<RecursionAllowList>(payload);
    }

    /// <summary>Replace the recursion allow list.</summary>
    /// <param name="networks">CIDR networks allowed to send recursive queries.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The stored list as the server returned it.</returns>
    /// <exception cref="NothingDnsApiException">400 for an invalid network, or 403 when the caller is not an admin.</exception>
    /// <remarks>
    /// An empty list denies recursion to every client, which is the safe default
    /// for a server that also answers authoritatively.
    /// </remarks>
    public async Task<RecursionAllowList> SetRecursionAsync(
        IEnumerable<string> networks,
        CancellationToken cancellationToken = default)
    {
        var body = NothingDnsTransport.Body(("networks", networks?.ToList() ?? new List<string>()));

        var payload = await _transport
            .PutAsync("/api/v1/acl/recursion", body, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.Model<RecursionAllowList>(payload);
    }
}
