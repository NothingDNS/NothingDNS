namespace NothingDns.Sdk;

/// <summary>
/// The policy actions accepted by <see cref="NothingDnsRpz.AddRuleAsync"/>.
/// </summary>
public static class NothingDnsRpzActions
{
    /// <summary>Answer with NXDOMAIN.</summary>
    public const string Nxdomain = "NXDOMAIN";

    /// <summary>Answer with an empty NOERROR response.</summary>
    public const string Nodata = "NODATA";

    /// <summary>Rewrite the answer to a CNAME.</summary>
    public const string Cname = "CNAME";

    /// <summary>Rewrite the answer to fixed data.</summary>
    public const string Override = "OVERRIDE";

    /// <summary>Drop the response entirely.</summary>
    public const string Drop = "DROP";

    /// <summary>Ignore the policy and resolve normally.</summary>
    public const string Passthrough = "PASSTHROUGH";

    /// <summary>Refuse over UDP and require TCP.</summary>
    public const string Tcponly = "TCPONLY";

    /// <summary>All accepted policy actions.</summary>
    public static readonly IReadOnlyList<string> All =
        new[] { Nxdomain, Nodata, Cname, Override, Drop, Passthrough, Tcponly };
}

/// <summary>
/// Response Policy Zones (<c>/api/v1/rpz</c>).
/// </summary>
public sealed class NothingDnsRpz
{
    private readonly NothingDnsTransport _transport;

    /// <summary>Initializes a new instance of the <see cref="NothingDnsRpz"/> class.</summary>
    /// <param name="transport">The shared transport used to reach the server.</param>
    /// <exception cref="ArgumentNullException"><paramref name="transport"/> is <see langword="null"/>.</exception>
    public NothingDnsRpz(NothingDnsTransport transport)
    {
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
    }

    /// <summary>Read RPZ statistics.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>Rule counts per trigger type, plus lifetime match and lookup counters.</returns>
    /// <exception cref="NothingDnsApiException">401 or 403 when the caller's role is insufficient.</exception>
    public async Task<RpzStats> StatsAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .GetAsync("/api/v1/rpz", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.Model<RpzStats>(payload);
    }

    /// <summary>List the QNAME policy rules.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The rules in priority order. Check <see cref="RpzRuleList.Truncated"/> for a capped response.</returns>
    /// <exception cref="NothingDnsApiException">401 or 403 when the caller's role is insufficient.</exception>
    public async Task<RpzRuleList> RulesAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .GetAsync("/api/v1/rpz/rules", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.Model<RpzRuleList>(payload);
    }

    /// <summary>Add a QNAME policy rule.</summary>
    /// <param name="pattern">The domain pattern the rule matches, for example <c>ads.example.net</c>.</param>
    /// <param name="action">One of the <see cref="NothingDnsRpzActions"/> values. Defaults to <c>NXDOMAIN</c>.</param>
    /// <param name="overrideData">Replacement data for rewriting actions such as <c>CNAME</c> or <c>OVERRIDE</c>.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The server's confirmation message.</returns>
    /// <exception cref="ArgumentException"><paramref name="pattern"/> is empty.</exception>
    /// <exception cref="NothingDnsValidationException"><paramref name="action"/> is not a known action.</exception>
    /// <exception cref="NothingDnsApiException">400 for an invalid pattern, or 403 when the caller is not an admin.</exception>
    public async Task<string> AddRuleAsync(
        string pattern,
        string action = NothingDnsRpzActions.Nxdomain,
        string? overrideData = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(pattern);

        if (!NothingDnsRpzActions.All.Contains(action, StringComparer.OrdinalIgnoreCase))
        {
            throw new NothingDnsValidationException(
                $"action must be one of {string.Join(", ", NothingDnsRpzActions.All)}, but was '{action}'.");
        }

        var body = NothingDnsTransport.Body(
            ("pattern", pattern),
            ("action", action.ToUpperInvariant()),
            ("override_data", overrideData));

        var payload = await _transport
            .PostAsync("/api/v1/rpz/rules", body, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.MessageOf(payload);
    }

    /// <summary>Delete a QNAME policy rule.</summary>
    /// <param name="pattern">The exact domain pattern to remove.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The server's confirmation message.</returns>
    /// <exception cref="ArgumentException"><paramref name="pattern"/> is empty.</exception>
    /// <exception cref="NothingDnsApiException">401 or 403 when the caller is not an admin.</exception>
    public async Task<string> DeleteRuleAsync(string pattern, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(pattern);

        var query = new[] { new KeyValuePair<string, object?>("pattern", pattern) };
        var payload = await _transport
            .DeleteAsync("/api/v1/rpz/rules", query: query, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.MessageOf(payload);
    }

    /// <summary>Toggle RPZ filtering on or off for the whole server.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The server's confirmation message.</returns>
    /// <exception cref="NothingDnsApiException">401 or 403 when the caller is not an admin.</exception>
    public async Task<string> ToggleAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .PostAsync("/api/v1/rpz/toggle", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.MessageOf(payload);
    }
}
