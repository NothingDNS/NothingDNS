using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NothingDns.Sdk;

/// <summary>
/// The HTTP core shared by every NothingDNS resource namespace.
/// </summary>
/// <remarks>
/// <para>
/// The transport owns URL construction, the <c>Authorization</c> bearer header,
/// query serialisation, JSON encoding, per-request timeouts and the translation
/// of HTTP failures into SDK errors. Resource namespaces describe only
/// <em>what</em> to call; this type decides <em>how</em> the request is made.
/// </para>
/// <para>
/// Credential <em>acquisition</em> (the login and bootstrap password payloads)
/// lives in <see cref="NothingDnsAuth"/>, deliberately in a different file, so
/// that the code which sends a password and the code that constructs the bearer
/// header never appear together.
/// </para>
/// <para>
/// The transport holds no mutable per-request state other than the bearer token,
/// which is read exactly once at the start of each request. Swapping the token
/// with <see cref="SetToken"/> is therefore safe while other requests are in
/// flight: each request keeps whichever token it observed. Give each thread its
/// own <see cref="NothingDnsClient"/> if you also need isolation of the injected
/// <see cref="System.Net.Http.HttpClient"/>.
/// </para>
/// </remarks>
public sealed class NothingDnsTransport : IAsyncDisposable
{
    /// <summary>The base URL used when none is supplied, matching the server's default HTTP listener.</summary>
    public const string DefaultBaseUrl = "http://localhost:8080";

    /// <summary>The per-request timeout used when none is supplied.</summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Options used to serialise request bodies. Null properties are omitted so a
    /// partial update leaves unspecified settings untouched.
    /// </summary>
    private static readonly JsonSerializerOptions WriteOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <summary>
    /// Options used to deserialise response bodies. Case-insensitive matching and
    /// lenient number parsing keep the SDK working against server builds that
    /// quote numbers or vary casing.
    /// </summary>
    private static readonly JsonSerializerOptions ReadOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        NumberHandling = JsonNumberHandling.AllowReadingFromString,
    };

    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;
    private readonly Dictionary<string, string> _defaultHeaders = new(StringComparer.OrdinalIgnoreCase);
    private string? _token;
    private bool _disposed;

    /// <summary>Initializes a new instance of the <see cref="NothingDnsTransport"/> class.</summary>
    /// <param name="baseUrl">
    /// Base URL of the server's HTTP listener, for example
    /// <c>http://dns.example.com:8080</c>. A trailing slash is optional.
    /// </param>
    /// <param name="token">
    /// Bearer token to send with every request, or <see langword="null"/> for an
    /// unauthenticated client. Accepts a JWT returned by
    /// <see cref="NothingDnsAuth.LoginAsync"/> or the static
    /// <c>server.http.auth_token</c> value from the server configuration.
    /// </param>
    /// <param name="timeout">Per-request timeout. Defaults to <see cref="DefaultTimeout"/>.</param>
    /// <param name="httpClient">
    /// An existing <see cref="HttpClient"/> to reuse, for example to share a
    /// connection pool or proxy configuration. When supplied, the SDK never
    /// disposes it and never mutates its <see cref="HttpClient.Timeout"/>; the
    /// timeout is instead enforced per request.
    /// </param>
    /// <param name="headers">Extra default headers merged into every request.</param>
    /// <exception cref="ArgumentException"><paramref name="baseUrl"/> is empty or not an absolute URI.</exception>
    public NothingDnsTransport(
        string baseUrl = DefaultBaseUrl,
        string? token = null,
        TimeSpan? timeout = null,
        HttpClient? httpClient = null,
        IDictionary<string, string>? headers = null)
    {
        if (string.IsNullOrWhiteSpace(baseUrl))
        {
            throw new ArgumentException("baseUrl must not be empty.", nameof(baseUrl));
        }

        var normalized = baseUrl.TrimEnd('/') + "/";
        if (!Uri.TryCreate(normalized, UriKind.Absolute, out var parsed))
        {
            throw new ArgumentException(
                $"baseUrl must be an absolute URI such as http://host:8080, but was '{baseUrl}'.",
                nameof(baseUrl));
        }

        BaseUri = parsed;
        Timeout = timeout ?? DefaultTimeout;

        if (httpClient is null)
        {
            _httpClient = new HttpClient();
            _ownsHttpClient = true;
        }
        else
        {
            _httpClient = httpClient;
            _ownsHttpClient = false;
        }

        _defaultHeaders["Accept"] = "application/json";
        if (headers is not null)
        {
            foreach (var (name, value) in headers)
            {
                if (!string.IsNullOrWhiteSpace(name))
                {
                    _defaultHeaders[name] = value;
                }
            }
        }

        _token = string.IsNullOrEmpty(token) ? null : token;
    }

    /// <summary>Gets the normalised base URI, always ending with a single trailing slash.</summary>
    public Uri BaseUri { get; }

    /// <summary>Gets the per-request timeout applied to every call.</summary>
    public TimeSpan Timeout { get; }

    /// <summary>Gets the bearer token currently sent with requests, or <see langword="null"/> when anonymous.</summary>
    public string? Token => Volatile.Read(ref _token);

    /// <summary>
    /// Use <paramref name="token"/> for all subsequent requests.
    /// </summary>
    /// <param name="token">
    /// A JWT from <see cref="NothingDnsAuth.LoginAsync"/> or
    /// <see cref="NothingDnsAuth.BootstrapAsync"/>, the static
    /// <c>server.http.auth_token</c> value, or <see langword="null"/> to continue
    /// unauthenticated.
    /// </param>
    public void SetToken(string? token)
        => Interlocked.Exchange(ref _token, string.IsNullOrEmpty(token) ? null : token);

    /// <summary>Forget the bearer token; subsequent requests are sent unauthenticated.</summary>
    public void ClearToken() => Interlocked.Exchange(ref _token, null);

    /// <summary>
    /// Percent-encode a single path segment such as a zone name, blocklist source
    /// id or username, so that dots, slashes and other reserved characters cannot
    /// alter the shape of the URL.
    /// </summary>
    /// <param name="segment">The raw, unescaped path segment.</param>
    /// <returns>The escaped segment, safe to interpolate into a request path.</returns>
    public static string Escape(string segment)
    {
        ArgumentNullException.ThrowIfNull(segment);
        return Uri.EscapeDataString(segment);
    }

    /// <summary>
    /// Build a JSON request body from explicit wire field names, dropping entries
    /// whose value is <see langword="null"/> so that a partial update leaves
    /// unspecified settings unchanged.
    /// </summary>
    /// <param name="fields">Wire field name and value pairs.</param>
    /// <returns>A dictionary that serialises to the desired request body.</returns>
    internal static Dictionary<string, object?> Body(params (string Key, object? Value)[] fields)
    {
        var body = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var (key, value) in fields)
        {
            if (value is not null)
            {
                body[key] = value;
            }
        }

        return body;
    }

    /// <summary>Serialise query parameters, skipping entries with a null value.</summary>
    /// <param name="query">Name and value pairs; null values are omitted.</param>
    /// <returns>The query string including its leading <c>?</c>, or an empty string when there is nothing to send.</returns>
    internal static string BuildQuery(IEnumerable<KeyValuePair<string, object?>>? query)
    {
        if (query is null)
        {
            return string.Empty;
        }

        var builder = new StringBuilder();
        foreach (var (name, value) in query)
        {
            if (string.IsNullOrEmpty(name) || value is null)
            {
                continue;
            }

            if (builder.Length > 0)
            {
                builder.Append('&');
            }

            builder.Append(Uri.EscapeDataString(name))
                   .Append('=')
                   .Append(Uri.EscapeDataString(Stringify(value)));
        }

        return builder.Length == 0 ? string.Empty : "?" + builder.ToString();
    }

    private static string Stringify(object value) => value switch
    {
        string text => text,
        bool flag => flag ? "true" : "false",
        IFormattable formattable => formattable.ToString(null, CultureInfo.InvariantCulture),
        _ => value.ToString() ?? string.Empty,
    };

    /// <summary>Compose the absolute request URL for an API path plus optional query parameters.</summary>
    /// <param name="path">API path beginning with <c>/</c>.</param>
    /// <param name="query">Optional query parameters.</param>
    /// <returns>The fully-qualified request URL.</returns>
    private string BuildUrl(string path, IEnumerable<KeyValuePair<string, object?>>? query)
    {
        if (string.IsNullOrEmpty(path))
        {
            throw new ArgumentException("path must not be empty.", nameof(path));
        }

        var suffix = path[0] == '/' ? path : "/" + path;
        return BaseUri.ToString().TrimEnd('/') + suffix + BuildQuery(query);
    }

    /// <summary>
    /// Send one request and return the raw response body.
    /// </summary>
    /// <param name="method">HTTP verb.</param>
    /// <param name="path">API path beginning with <c>/</c>.</param>
    /// <param name="query">Optional query parameters; null values are skipped.</param>
    /// <param name="body">Optional request body, serialised as JSON.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The untruncated response body on success.</returns>
    /// <exception cref="NothingDnsApiException">The server answered with a 4xx or 5xx status.</exception>
    /// <exception cref="NothingDnsConnectionException">The server could not be reached or the request timed out.</exception>
    private async Task<string> SendCoreAsync(
        HttpMethod method,
        string path,
        IEnumerable<KeyValuePair<string, object?>>? query,
        object? body,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();

        var url = BuildUrl(path, query);
        using var request = new HttpRequestMessage(method, url);
        request.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));

        foreach (var (name, value) in _defaultHeaders)
        {
            request.Headers.TryAddWithoutValidation(name, value);
        }

        // Read the token once so a concurrent SetToken cannot tear this request.
        var token = Volatile.Read(ref _token);
        if (!string.IsNullOrEmpty(token))
        {
            request.Headers.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        }

        if (body is not null)
        {
            var json = JsonSerializer.Serialize(body, body.GetType(), WriteOptions);
            request.Content = new StringContent(json, Encoding.UTF8, "application/json");
        }

        HttpResponseMessage response;
        using (var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            timeoutSource.CancelAfter(Timeout);
            try
            {
                response = await _httpClient
                    .SendAsync(request, HttpCompletionOption.ResponseContentRead, timeoutSource.Token)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                throw new NothingDnsConnectionException(
                    $"NothingDNS did not respond within {Timeout.TotalSeconds:0.##}s for {method} {url}.");
            }
            catch (HttpRequestException ex)
            {
                throw new NothingDnsConnectionException(
                    $"Could not reach NothingDNS at {url}: {ex.Message}", ex);
            }
        }

        using (response)
        {
            var text = response.Content is null
                ? string.Empty
                : await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                throw BuildApiError(response.StatusCode, text);
            }

            return text;
        }
    }

    private static NothingDnsApiException BuildApiError(System.Net.HttpStatusCode status, string body)
    {
        var statusCode = (int)status;
        var fallback = $"HTTP {statusCode}";
        var message = fallback;
        JsonElement? payload = null;
        body ??= string.Empty;

        if (!string.IsNullOrWhiteSpace(body))
        {
            try
            {
                using var document = JsonDocument.Parse(body);
                payload = document.RootElement.Clone();

                if (payload.Value.ValueKind == JsonValueKind.Object)
                {
                    foreach (var name in (string[])["error", "message", "detail"])
                    {
                        if (payload.Value.TryGetProperty(name, out var reported) &&
                            reported.ValueKind == JsonValueKind.String)
                        {
                            var text = reported.GetString();
                            if (!string.IsNullOrEmpty(text))
                            {
                                message = text;
                                break;
                            }
                        }
                    }
                }
            }
            catch (JsonException)
            {
                // Not JSON; fall through to the raw-body message below.
            }

            if (message == fallback)
            {
                var trimmed = body.Trim();
                if (trimmed.Length > 0)
                {
                    message = trimmed.Length > 500 ? trimmed[..500] : trimmed;
                }
            }
        }

        return new NothingDnsApiException(statusCode, message, payload, body);
    }

    private static string Truncate(string text, int max)
        => text.Length <= max ? text : text[..max];

    private async Task<JsonElement> SendJsonAsync(
        HttpMethod method,
        string path,
        IEnumerable<KeyValuePair<string, object?>>? query,
        object? body,
        bool expectJson,
        CancellationToken cancellationToken)
    {
        var text = await SendCoreAsync(method, path, query, body, cancellationToken).ConfigureAwait(false);
        if (!expectJson || string.IsNullOrWhiteSpace(text))
        {
            return default;
        }

        try
        {
            using var document = JsonDocument.Parse(text);
            return document.RootElement.Clone();
        }
        catch (JsonException ex)
        {
            throw new NothingDnsValidationException(
                $"NothingDNS returned a non-JSON body for {method} {BuildUrl(path, query)}: {Truncate(text, 200)}",
                ex);
        }
    }

    /// <summary>Send a GET request and return the decoded JSON body.</summary>
    /// <param name="path">API path beginning with <c>/</c>.</param>
    /// <param name="query">Optional query parameters; null values are skipped.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The decoded JSON body.</returns>
    public Task<JsonElement> GetAsync(
        string path,
        IEnumerable<KeyValuePair<string, object?>>? query = null,
        CancellationToken cancellationToken = default)
        => SendJsonAsync(HttpMethod.Get, path, query, null, true, cancellationToken);

    /// <summary>Send a POST request and return the decoded JSON body.</summary>
    /// <param name="path">API path beginning with <c>/</c>.</param>
    /// <param name="body">Optional request body, serialised as JSON.</param>
    /// <param name="query">Optional query parameters; null values are skipped.</param>
    /// <param name="expectJson">Set to <see langword="false"/> for endpoints that answer with no body or a bare acknowledgement.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The decoded JSON body, or <see cref="JsonElement.ValueKind"/> <c>Undefined</c> when <paramref name="expectJson"/> is <see langword="false"/>.</returns>
    public Task<JsonElement> PostAsync(
        string path,
        object? body = null,
        IEnumerable<KeyValuePair<string, object?>>? query = null,
        bool expectJson = true,
        CancellationToken cancellationToken = default)
        => SendJsonAsync(HttpMethod.Post, path, query, body, expectJson, cancellationToken);

    /// <summary>Send a PUT request and return the decoded JSON body.</summary>
    /// <param name="path">API path beginning with <c>/</c>.</param>
    /// <param name="body">Optional request body, serialised as JSON.</param>
    /// <param name="query">Optional query parameters; null values are skipped.</param>
    /// <param name="expectJson">Set to <see langword="false"/> for endpoints that answer with no body or a bare acknowledgement.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The decoded JSON body, or <see cref="JsonElement.ValueKind"/> <c>Undefined</c> when <paramref name="expectJson"/> is <see langword="false"/>.</returns>
    public Task<JsonElement> PutAsync(
        string path,
        object? body = null,
        IEnumerable<KeyValuePair<string, object?>>? query = null,
        bool expectJson = true,
        CancellationToken cancellationToken = default)
        => SendJsonAsync(HttpMethod.Put, path, query, body, expectJson, cancellationToken);

    /// <summary>Send a DELETE request and return the decoded JSON body.</summary>
    /// <param name="path">API path beginning with <c>/</c>.</param>
    /// <param name="body">Optional request body, serialised as JSON.</param>
    /// <param name="query">Optional query parameters; null values are skipped.</param>
    /// <param name="expectJson">Set to <see langword="false"/> for endpoints that answer with no body or a bare acknowledgement.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The decoded JSON body, or <see cref="JsonElement.ValueKind"/> <c>Undefined</c> when <paramref name="expectJson"/> is <see langword="false"/>.</returns>
    public Task<JsonElement> DeleteAsync(
        string path,
        object? body = null,
        IEnumerable<KeyValuePair<string, object?>>? query = null,
        bool expectJson = true,
        CancellationToken cancellationToken = default)
        => SendJsonAsync(HttpMethod.Delete, path, query, body, expectJson, cancellationToken);

    /// <summary>
    /// Send a GET request and return the raw response text instead of decoded
    /// JSON, used by the zone export endpoint which serves a BIND zone file.
    /// </summary>
    /// <param name="path">API path beginning with <c>/</c>.</param>
    /// <param name="query">Optional query parameters; null values are skipped.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The response body exactly as received.</returns>
    public Task<string> GetTextAsync(
        string path,
        IEnumerable<KeyValuePair<string, object?>>? query = null,
        CancellationToken cancellationToken = default)
        => SendCoreAsync(HttpMethod.Get, path, query, null, cancellationToken);

    /// <summary>Extract the server's plain <c>message</c> acknowledgement from a decoded body.</summary>
    /// <param name="payload">The decoded JSON body.</param>
    /// <returns>The message text, or an empty string when the body carries none.</returns>
    internal static string MessageOf(JsonElement payload)
    {
        if (payload.ValueKind == JsonValueKind.Object &&
            payload.TryGetProperty("message", out var message) &&
            message.ValueKind == JsonValueKind.String)
        {
            return message.GetString() ?? string.Empty;
        }

        return string.Empty;
    }

    /// <summary>Deserialise a decoded JSON object into a model, tolerating missing fields.</summary>
    /// <typeparam name="T">The model type to construct.</typeparam>
    /// <param name="element">The decoded JSON element.</param>
    /// <returns>The deserialised model, or a default-constructed one when the payload is not an object.</returns>
    internal static T Model<T>(JsonElement element) where T : class, new()
        => element.ValueKind == JsonValueKind.Object
            ? element.Deserialize<T>(ReadOptions) ?? new T()
            : new T();

    /// <summary>Deserialise a JSON array into a list of models.</summary>
    /// <typeparam name="T">The model type to construct for each element.</typeparam>
    /// <param name="element">The decoded JSON element, expected to be an array.</param>
    /// <returns>The deserialised list, empty when the payload is not an array.</returns>
    internal static List<T> ListOf<T>(JsonElement element) where T : class, new()
        => element.ValueKind == JsonValueKind.Array
            ? element.Deserialize<List<T>>(ReadOptions) ?? new List<T>()
            : new List<T>();

    /// <summary>Deserialise a JSON array nested under a named property into a list of models.</summary>
    /// <typeparam name="T">The model type to construct for each element.</typeparam>
    /// <param name="element">The decoded JSON object containing the array.</param>
    /// <param name="key">The property holding the array, for example <c>zones</c>.</param>
    /// <returns>The deserialised list, empty when the property is absent or not an array.</returns>
    internal static List<T> ListOf<T>(JsonElement element, string key) where T : class, new()
        => element.ValueKind == JsonValueKind.Object && element.TryGetProperty(key, out var nested)
            ? ListOf<T>(nested)
            : new List<T>();

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(NothingDnsTransport));
        }
    }

    /// <summary>
    /// Release the underlying <see cref="HttpClient"/> when this transport created
    /// it. An injected <see cref="HttpClient"/> is left open for its owner to
    /// dispose. Safe to call more than once.
    /// </summary>
    /// <returns>A completed task.</returns>
    public ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return ValueTask.CompletedTask;
        }

        _disposed = true;
        if (_ownsHttpClient)
        {
            _httpClient.Dispose();
        }

        return ValueTask.CompletedTask;
    }
}
