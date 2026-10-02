using System.Text.Json;

namespace NothingDns.Sdk;

/// <summary>
/// Client for the NothingDNS management API.
/// </summary>
/// <remarks>
/// <para>
/// The client mirrors the server's API groups as properties:
/// </para>
/// <list type="bullet">
///   <item><description><see cref="Auth"/> — login, bootstrap, session, users, roles</description></item>
///   <item><description><see cref="Zones"/> — zones, records, export, bulk PTR</description></item>
///   <item><description><see cref="Cache"/> — cache statistics and flush</description></item>
///   <item><description><see cref="Config"/> — effective config and runtime tunables</description></item>
///   <item><description><see cref="Acl"/> — ACL rules and the recursion allow list</description></item>
///   <item><description><see cref="Blocklists"/> — blocklist sources and filtering</description></item>
///   <item><description><see cref="Rpz"/> — response policy zones</description></item>
///   <item><description><see cref="Dnssec"/> — validation status and signing keys</description></item>
///   <item><description><see cref="Upstreams"/> — upstream pool health</description></item>
///   <item><description><see cref="GeoIp"/> — GeoDNS statistics</description></item>
///   <item><description><see cref="Cluster"/> — gossip and Raft cluster management</description></item>
///   <item><description><see cref="Dashboard"/> — dashboard counters, query events, zone summary</description></item>
///   <item><description><see cref="Metrics"/> — query log, top domains, metrics history</description></item>
/// </list>
/// <para>
/// Health probes, status, the server configuration summary and the OpenAPI document
/// live on the client itself. Every method returns a typed model from
/// <c>Models.cs</c> and throws <see cref="NothingDnsApiException"/> for any non-2xx
/// response.
/// </para>
/// <para>
/// Dispose the client when you are finished, or use
/// <c>await using</c>. Give each thread its own client when you also share an
/// injected <see cref="HttpClient"/>; otherwise a single client is safe to use
/// concurrently because the transport keeps no mutable per-request state.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// await using var client = new NothingDnsClient("http://dns.example.com:8080");
/// var session = await client.Auth.LoginAsync(user, password, cancellationToken: ct);
/// var zones = await client.Zones.ListAsync(ct);
/// Console.WriteLine($"{zones.Total} zones as {session.Username}");
/// </code>
/// </example>
public sealed class NothingDnsClient : IAsyncDisposable
{
    private readonly NothingDnsTransport _transport;

    /// <summary>Initializes a new instance of the <see cref="NothingDnsClient"/> class.</summary>
    /// <param name="baseUrl">
    /// Base URL of the server's HTTP listener, the <c>server.http</c> section of its
    /// configuration. Defaults to <see cref="NothingDnsTransport.DefaultBaseUrl"/>.
    /// </param>
    /// <param name="token">
    /// Bearer token to start with — a JWT from
    /// <see cref="NothingDnsAuth.LoginAsync"/>, or the static
    /// <c>server.http.auth_token</c> value. May also be set later with
    /// <see cref="SetToken"/>.
    /// </param>
    /// <param name="timeout">Per-request timeout. Defaults to 30 seconds.</param>
    /// <param name="httpClient">
    /// An existing <see cref="HttpClient"/> to reuse, for example to share a proxy or
    /// connection pool. The SDK never disposes a client it did not create.
    /// </param>
    /// <param name="headers">Extra headers merged into every request.</param>
    /// <exception cref="ArgumentException"><paramref name="baseUrl"/> is empty or not an absolute URI.</exception>
    public NothingDnsClient(
        string baseUrl = NothingDnsTransport.DefaultBaseUrl,
        string? token = null,
        TimeSpan? timeout = null,
        HttpClient? httpClient = null,
        IDictionary<string, string>? headers = null)
    {
        _transport = new NothingDnsTransport(baseUrl, token, timeout, httpClient, headers);

        Auth = new NothingDnsAuth(_transport);
        Zones = new NothingDnsZones(_transport);
        Cache = new NothingDnsCache(_transport);
        Config = new NothingDnsConfig(_transport);
        Acl = new NothingDnsAcl(_transport);
        Blocklists = new NothingDnsBlocklists(_transport);
        Rpz = new NothingDnsRpz(_transport);
        Dnssec = new NothingDnsDnssec(_transport);
        Upstreams = new NothingDnsUpstreams(_transport);
        GeoIp = new NothingDnsGeoIp(_transport);
        Cluster = new NothingDnsCluster(_transport);
        Dashboard = new NothingDnsDashboard(_transport);
        Metrics = new NothingDnsMetrics(_transport);
    }

    /// <summary>Gets authentication, user management and the role table.</summary>
    public NothingDnsAuth Auth { get; }

    /// <summary>Gets the zones, records, export and bulk PTR namespace.</summary>
    public NothingDnsZones Zones { get; }

    /// <summary>Gets the DNS response cache namespace.</summary>
    public NothingDnsCache Cache { get; }

    /// <summary>Gets the configuration and runtime tunables namespace.</summary>
    public NothingDnsConfig Config { get; }

    /// <summary>Gets the ACL and recursion allow list namespace.</summary>
    public NothingDnsAcl Acl { get; }

    /// <summary>Gets the blocklist namespace.</summary>
    public NothingDnsBlocklists Blocklists { get; }

    /// <summary>Gets the response policy zone namespace.</summary>
    public NothingDnsRpz Rpz { get; }

    /// <summary>Gets the DNSSEC namespace.</summary>
    public NothingDnsDnssec Dnssec { get; }

    /// <summary>Gets the upstream resolver pool namespace.</summary>
    public NothingDnsUpstreams Upstreams { get; }

    /// <summary>Gets the GeoDNS namespace.</summary>
    public NothingDnsGeoIp GeoIp { get; }

    /// <summary>Gets the cluster namespace.</summary>
    public NothingDnsCluster Cluster { get; }

    /// <summary>Gets the dashboard namespace.</summary>
    public NothingDnsDashboard Dashboard { get; }

    /// <summary>Gets the query log and metrics history namespace.</summary>
    public NothingDnsMetrics Metrics { get; }

    /// <summary>Gets the underlying transport for endpoints the SDK does not model directly.</summary>
    public NothingDnsTransport Transport => _transport;

    /// <summary>Gets the base URL of the server, without a trailing slash.</summary>
    public string BaseUrl => _transport.BaseUri.ToString().TrimEnd('/');

    /// <summary>Gets the bearer token currently in use, or <see langword="null"/> when anonymous.</summary>
    public string? Token => _transport.Token;

    /// <summary>Set the bearer token used by every namespace.</summary>
    /// <param name="token">
    /// A JWT from <see cref="NothingDnsAuth.LoginAsync"/> or
    /// <see cref="NothingDnsAuth.BootstrapAsync"/>, the static
    /// <c>server.http.auth_token</c> value, or <see langword="null"/> to continue
    /// unauthenticated.
    /// </param>
    public void SetToken(string? token) => _transport.SetToken(token);

    /// <summary>Run the health check.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The reported state and server timestamp.</returns>
    /// <exception cref="NothingDnsApiException">429 when the endpoint's own rate limit is hit.</exception>
    public async Task<HealthResponse> HealthAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .GetAsync("/health", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.Model<HealthResponse>(payload);
    }

    /// <summary>Run the readiness probe.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The reported state and server timestamp.</returns>
    /// <exception cref="NothingDnsApiException">
    /// 503 when the server is not ready to answer queries. Treat that as "not ready"
    /// rather than as a hard failure, for example in a start-up gate.
    /// </exception>
    public async Task<HealthResponse> ReadyAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .GetAsync("/readyz", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.Model<HealthResponse>(payload);
    }

    /// <summary>Run the liveness probe.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The reported state and server timestamp.</returns>
    /// <exception cref="NothingDnsApiException">429 when the endpoint's own rate limit is hit.</exception>
    public async Task<HealthResponse> LiveAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .GetAsync("/livez", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.Model<HealthResponse>(payload);
    }

    /// <summary>Read the server status, version, cache and cluster summary.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>
    /// The status. Any authenticated user may call this, but
    /// <see cref="StatusResponse.Cache"/> is only present for operators and admins.
    /// </returns>
    /// <exception cref="NothingDnsApiException">401 when no valid token was sent.</exception>
    public async Task<StatusResponse> StatusAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .GetAsync("/api/v1/status", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.Model<StatusResponse>(payload);
    }

    /// <summary>Read the server configuration summary.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>Listen port, log level and the DNS64 and DNS Cookies configuration.</returns>
    /// <exception cref="NothingDnsApiException">401 or 403 when the caller's role is insufficient.</exception>
    public async Task<ServerConfig> ServerConfigAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .GetAsync("/api/v1/server/config", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.Model<ServerConfig>(payload);
    }

    /// <summary>Fetch the server's OpenAPI document.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>
    /// The document as a <see cref="JsonElement"/>. Useful for detecting server
    /// capabilities that this SDK version predates.
    /// </returns>
    /// <exception cref="NothingDnsApiException">401 when authentication is required but absent.</exception>
    public async Task<JsonElement> OpenApiSpecAsync(CancellationToken cancellationToken = default)
        => await _transport
            .GetAsync("/api/openapi.json", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

    /// <summary>Fetch the interactive API explorer page.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The HTML of the explorer page.</returns>
    public async Task<string> ApiDocsAsync(CancellationToken cancellationToken = default)
        => await _transport
            .GetTextAsync("/api/docs", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

    /// <summary>Fetch the API explorer script.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The JavaScript source of the explorer.</returns>
    public async Task<string> ApiDocsScriptAsync(CancellationToken cancellationToken = default)
        => await _transport
            .GetTextAsync("/api/docs/app.js", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

    /// <summary>
    /// Submit a Content-Security-Policy violation report to the server's report sink.
    /// </summary>
    /// <param name="report">The report body, normally a <c>{"csp-report": …}</c> document sent by the browser.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>A task that completes when the report has been accepted. The server answers 204 No Content.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="report"/> is <see langword="null"/>.</exception>
    /// <exception cref="NothingDnsApiException">429 when the endpoint's own rate limit is hit.</exception>
    /// <remarks>
    /// This endpoint is unauthenticated by design so the browser can post to it
    /// after a policy violation. It is exposed for completeness and for tests; an
    /// ordinary management tool has no reason to call it.
    /// </remarks>
    public async Task ReportCspAsync(
        IReadOnlyDictionary<string, object?> report,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(report);

        await _transport
            .PostAsync("/api/v1/csp-report", report, expectJson: false, cancellationToken: cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Release the underlying connection pool. An injected <see cref="HttpClient"/>
    /// is left open for its owner. Safe to call more than once.
    /// </summary>
    /// <returns>A completed task.</returns>
    public ValueTask DisposeAsync() => _transport.DisposeAsync();
}
