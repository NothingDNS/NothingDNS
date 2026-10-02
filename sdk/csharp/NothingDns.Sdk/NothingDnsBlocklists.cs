namespace NothingDns.Sdk;

/// <summary>
/// Blocklist sources and global filtering (<c>/api/v1/blocklists</c>).
/// </summary>
public sealed class NothingDnsBlocklists
{
    private readonly NothingDnsTransport _transport;

    /// <summary>Initializes a new instance of the <see cref="NothingDnsBlocklists"/> class.</summary>
    /// <param name="transport">The shared transport used to reach the server.</param>
    /// <exception cref="ArgumentNullException"><paramref name="transport"/> is <see langword="null"/>.</exception>
    public NothingDnsBlocklists(NothingDnsTransport transport)
    {
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
    }

    /// <summary>Read blocklist statistics.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>Whether filtering is on, plus rule and source counts.</returns>
    /// <exception cref="NothingDnsApiException">401 or 403 when the caller's role is insufficient.</exception>
    public async Task<BlocklistStats> StatsAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .GetAsync("/api/v1/blocklists", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.Model<BlocklistStats>(payload);
    }

    /// <summary>Add a blocklist source from a local file or a remote URL.</summary>
    /// <param name="file">Path of a hosts-format file to load.</param>
    /// <param name="url">URL of a hosts-format list to fetch.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The server's confirmation message.</returns>
    /// <exception cref="NothingDnsValidationException">
    /// Neither <paramref name="file"/> nor <paramref name="url"/> was supplied, or both were.
    /// </exception>
    /// <exception cref="NothingDnsApiException">
    /// 400 when the source is unreadable, or 403 when the caller is not an admin.
    /// </exception>
    public async Task<string> AddAsync(
        string? file = null,
        string? url = null,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(file) && string.IsNullOrWhiteSpace(url))
        {
            throw new NothingDnsValidationException("supply either a file path or a url to add");
        }

        if (!string.IsNullOrWhiteSpace(file) && !string.IsNullOrWhiteSpace(url))
        {
            throw new NothingDnsValidationException("pass either a file path or a url, not both");
        }

        var body = NothingDnsTransport.Body(("file", file), ("url", url));

        var payload = await _transport
            .PostAsync("/api/v1/blocklists", body, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.MessageOf(payload);
    }

    /// <summary>List the configured blocklist sources.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>Each source with its type, enabled state and domain count.</returns>
    /// <exception cref="NothingDnsApiException">401 or 403 when the caller's role is insufficient.</exception>
    public async Task<IReadOnlyList<BlocklistSource>> SourcesAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .GetAsync("/api/v1/blocklists/sources", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.ListOf<BlocklistSource>(payload);
    }

    /// <summary>Toggle blocklist filtering on or off for the whole server.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The server's confirmation message.</returns>
    /// <exception cref="NothingDnsApiException">401 or 403 when the caller is not an admin.</exception>
    public async Task<string> ToggleAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .PostAsync("/api/v1/blocklists/toggle", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.MessageOf(payload);
    }

    /// <summary>Remove one blocklist source.</summary>
    /// <param name="source">The source identifier, as reported by <see cref="SourcesAsync"/>.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The server's confirmation message.</returns>
    /// <exception cref="ArgumentException"><paramref name="source"/> is empty.</exception>
    /// <exception cref="NothingDnsApiException">400 when the source cannot be removed, or 403 when the caller is not an admin.</exception>
    public async Task<string> RemoveAsync(string source, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(source);

        var payload = await _transport
            .DeleteAsync(
                $"/api/v1/blocklists/{NothingDnsTransport.Escape(source)}",
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.MessageOf(payload);
    }

    /// <summary>Enable or disable one blocklist source.</summary>
    /// <param name="source">The source identifier, as reported by <see cref="SourcesAsync"/>.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The server's confirmation message.</returns>
    /// <exception cref="ArgumentException"><paramref name="source"/> is empty.</exception>
    /// <exception cref="NothingDnsApiException">404 when the source does not exist, or 403 when the caller is not an admin.</exception>
    public async Task<string> ToggleSourceAsync(string source, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(source);

        var payload = await _transport
            .PostAsync(
                $"/api/v1/blocklists/{NothingDnsTransport.Escape(source)}/toggle",
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.MessageOf(payload);
    }
}
