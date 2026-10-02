using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;

namespace NothingDns.Sdk.Tests;

/// <summary>
/// A recorded request: HTTP method, the raw request-target (path plus query,
/// percent-encoding preserved), the decoded request body text and the
/// Authorization header exactly as received.
/// </summary>
public sealed record RecordedRequest(string Method, string Path, string? BodyText, string? Auth)
{
    /// <summary>The request body parsed as JSON, or <see langword="null"/> when the body was absent or not JSON.</summary>
    public JsonNode? BodyJson => BodyText is null ? null : JsonNode.Parse(BodyText);
}

/// <summary>
/// In-process stand-in for the NothingDNS management API, mirroring the mock
/// server of the Python suite (<c>sdk/python/tests/conftest.py</c>).
/// </summary>
/// <remarks>
/// <para>
/// A raw <see cref="TcpListener"/> loopback server is used instead of
/// <see cref="System.Net.HttpListener"/> so the suite behaves identically on
/// every OS without URL ACL registration, and so the recorded request-target
/// keeps the client's percent-encoding intact (<c>%2F</c>, <c>%20</c>) — the
/// same trick Go's <c>httptest</c> server enables. Each connection serves one
/// request and is closed (<c>Connection: close</c>), which keeps the HTTP
/// parsing trivial and side-effect free.
/// </para>
/// <para>
/// Every request is recorded so tests can assert on methods, paths, bodies and
/// headers, exactly like the Python and Go suites do.
/// </para>
/// </remarks>
public sealed class MockApi : IDisposable
{
    public const string Username = "admin";
    public const string Password = "correct";
    public const string Token = "tok-123";

    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly object _lock = new();
    private readonly List<RecordedRequest> _requests = new();
    private string _lastResponseContentType = string.Empty;
    private readonly Task _acceptLoop;

    public MockApi()
    {
        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start();
        _acceptLoop = Task.Run(AcceptLoopAsync);
    }

    /// <summary>Base URL of the mock server, without a trailing slash.</summary>
    public string Base => $"http://127.0.0.1:{Port}";

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;

    /// <summary>All requests received so far, in arrival order.</summary>
    public IReadOnlyList<RecordedRequest> Requests
    {
        get
        {
            lock (_lock)
            {
                return _requests.ToList();
            }
        }
    }

    /// <summary>The most recent request; fails the test when nothing was sent.</summary>
    public RecordedRequest Last
    {
        get
        {
            lock (_lock)
            {
                if (_requests.Count == 0)
                {
                    throw new InvalidOperationException("the mock server has not received any request");
                }

                return _requests[^1];
            }
        }
    }

    /// <summary>An unauthenticated SDK client bound to this mock, with a short timeout.</summary>
    public NothingDnsClient CreateClient() =>
        new(Base, timeout: TimeSpan.FromSeconds(5));

    /// <summary>The Content-Type header of the most recent response this mock actually served.</summary>
    public string LastResponseContentType
    {
        get
        {
            lock (_lock)
            {
                return _lastResponseContentType;
            }
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        try
        {
            _listener.Stop();
        }
        catch
        {
            // already stopped — nothing to do
        }

        try
        {
            _acceptLoop.Wait(TimeSpan.FromSeconds(5));
        }
        catch
        {
            // accept loop failures after shutdown are expected
        }

        _cts.Dispose();
        GC.SuppressFinalize(this);
    }

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            TcpClient tcp;
            try
            {
                tcp = await _listener.AcceptTcpClientAsync(_cts.Token).ConfigureAwait(false);
            }
            catch
            {
                // listener stopped — shutdown path
                return;
            }

            _ = Task.Run(() => ServeOneAsync(tcp));
        }
    }

    private async Task ServeOneAsync(TcpClient tcp)
    {
        using (tcp)
        {
            NetworkStream stream;
            try
            {
                stream = tcp.GetStream();
            }
            catch
            {
                return;
            }

            try
            {
                var request = await ReadRequestAsync(stream, _cts.Token).ConfigureAwait(false);
                if (request is null)
                {
                    return;
                }

                lock (_lock)
                {
                    _requests.Add(request.Recorded);
                }

                var (status, contentType, body) = Route(request.Method, request.Route, request.BodyText);
                lock (_lock)
                {
                    _lastResponseContentType = contentType;
                }

                await WriteResponseAsync(stream, status, contentType, body).ConfigureAwait(false);
            }
            catch
            {
                // a broken request or a client that hung up mid-flight must not
                // destabilise the suite; the test asserts on what it needs.
            }
        }
    }

    private static async Task<IncomingRequest?> ReadRequestAsync(NetworkStream stream, CancellationToken ct)
    {
        var headerBytes = new List<byte>(1024);
        var buffer = new byte[4096];
        var terminatorIndex = -1;
        while ((terminatorIndex = IndexOfDoubleCrlf(headerBytes)) < 0)
        {
            var read = await stream.ReadAsync(buffer, ct).ConfigureAwait(false);
            if (read == 0)
            {
                return null;
            }

            headerBytes.AddRange(buffer.AsMemory(0, read).Span.ToArray());
        }

        var headerEnd = terminatorIndex + 4; // bytes consumed by the header block, including the blank line
        var headerText = Encoding.ASCII.GetString(headerBytes.ToArray(), 0, headerEnd);
        var lines = headerText.Split("\r\n");
        var requestLine = lines[0].Split(' ');
        if (requestLine.Length < 2)
        {
            return null;
        }

        string? contentLengthHeader = null;
        string? authHeader = null;
        foreach (var line in lines.Skip(1))
        {
            var colon = line.IndexOf(':');
            if (colon <= 0)
            {
                continue;
            }

            var name = line[..colon].Trim();
            var value = line[(colon + 1)..].Trim();
            if (string.Equals(name, "Content-Length", StringComparison.OrdinalIgnoreCase))
            {
                contentLengthHeader = value;
            }
            else if (string.Equals(name, "Authorization", StringComparison.OrdinalIgnoreCase))
            {
                authHeader = value;
            }
        }

        string? bodyText = null;
        if (contentLengthHeader is not null
            && long.TryParse(contentLengthHeader, out var contentLength)
            && contentLength > 0)
        {
            var body = new byte[contentLength];
            // Bytes that arrived attached to the header block belong to the body.
            var leftover = Math.Min(Math.Max(headerBytes.Count - headerEnd, 0), body.Length);
            headerBytes.CopyTo(headerEnd, body, 0, leftover);

            var filled = leftover;
            while (filled < body.Length)
            {
                var read = await stream.ReadAsync(body.AsMemory(filled), ct).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                filled += read;
            }

            bodyText = Encoding.UTF8.GetString(body, 0, filled);
        }

        var target = requestLine[1];
        var route = target.Split('?', 2)[0];
        return new IncomingRequest(
            requestLine[0],
            route,
            bodyText,
            new RecordedRequest(requestLine[0], target, bodyText, authHeader));
    }

    private static int IndexOfDoubleCrlf(List<byte> bytes)
    {
        for (var i = 0; i + 3 < bytes.Count; i++)
        {
            if (bytes[i] == (byte)'\r'
                && bytes[i + 1] == (byte)'\n'
                && bytes[i + 2] == (byte)'\r'
                && bytes[i + 3] == (byte)'\n')
            {
                return i;
            }
        }

        return -1;
    }

    private static async Task WriteResponseAsync(NetworkStream stream, int status, string contentType, string body)
    {
        var payload = Encoding.UTF8.GetBytes(body);
        var head = Encoding.ASCII.GetBytes(
            $"HTTP/1.1 {status} {Reason(status)}\r\n" +
            "Content-Type: " + contentType + "\r\n" +
            $"Content-Length: {payload.Length}\r\n" +
            "Connection: close\r\n" +
            "\r\n");
        await stream.WriteAsync(head).ConfigureAwait(false);
        await stream.WriteAsync(payload).ConfigureAwait(false);
        await stream.FlushAsync().ConfigureAwait(false);
    }

    private static string Reason(int status) => status switch
    {
        200 => "OK",
        201 => "Created",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        _ => "OK",
    };

    private static (int Status, string ContentType, string Body) Route(string method, string route, string? bodyText)
    {
        var body = JsonNode.Parse(bodyText ?? "null") as JsonObject;

        switch (route)
        {
            case "/health":
            case "/readyz":
            case "/livez":
                return (200, "application/json", """{"status":"healthy","timestamp":"2026-10-02T11:00:00Z"}""");

            case "/api/v1/auth/login":
            {
                var password = body?["password"]?.GetValue<string>();
                if (password != Password)
                {
                    return (401, "application/json", """{"error":"invalid credentials"}""");
                }

                return (200, "application/json",
                    $$"""{"token":"{{Token}}","username":"{{Username}}","role":"admin","expires":"2026-10-02T12:00:00Z"}""");
            }

            case "/api/v1/auth/logout":
                return (200, "application/json", """{"message":"logged out"}""");

            case "/api/v1/status":
                return (200, "application/json",
                    """
                    {"status":"running","timestamp":"t","version":"1.2.17","cache":{"size":3,"capacity":100,"hits":9,"misses":1,"hit_ratio":0.9},"cluster":{"enabled":false,"node_id":"n1","node_count":1,"alive_count":1,"healthy":true}}
                    """);

            case "/api/v1/zones":
                if (method == "POST")
                {
                    return (201, "application/json", """{"message":"zone created"}""");
                }

                return (200, "application/json",
                    """{"zones":[{"name":"example.com","serial":7,"records":3}],"total":1,"truncated":false}""");

            case "/api/v1/zones/example.com":
                return (200, "application/json", """{"message":"zone deleted"}""");

            case "/api/v1/zones/example.com/records":
                return method switch
                {
                    "GET" => (200, "application/json",
                        """{"records":[{"name":"www","type":"A","ttl":300,"class":"IN","data":"192.0.2.1"}],"total":1,"truncated":false}"""),
                    "POST" => (201, "application/json", """{"message":"record added"}"""),
                    "PUT" => (200, "application/json", """{"message":"record replaced"}"""),
                    _ => (200, "application/json", """{"message":"records deleted"}"""),
                };

            case "/api/v1/zones/example.com/export":
                return (200, "text/plain", "$ORIGIN example.com.\n@ IN SOA ns1 hostmaster 7 3600 600 86400 300\n");

            case "/api/v1/zones/missing.com":
                return (404, "application/json", """{"error":"Zone missing.com not found"}""");

            case "/api/v1/zones/2.0.192.in-addr.arpa/ptr-bulk":
                return (200, "application/json",
                    """
                    {"preview":true,"total":256,"willAdd":256,"willAddA":0,"willSkip":0,"willOverride":0,"changes":[{"name":"1","type":"PTR","ttl":300,"data":"host-192-0-2-1.example.com","action":"add"}]}
                    """);

            case "/api/v1/zones/8.b.d.0.1.0.0.2.ip6.arpa/ptr6-lookup":
                return (200, "application/json",
                    """{"ip":"2001:db8::1","ptr":"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0","ptrFQDN":"host.example.com","target":"host.example.com","ttl":300,"found":true}""");

            case "/api/v1/zones/transfers":
                return (200, "application/json",
                    """{"slave_zones":[{"zone":"sub.example.com","masters":"192.0.2.53","serial":3,"last_transfer":"2026-10-01T00:00:00Z","status":"synced","records":12}]}""");

            case "/api/v1/acl":
                if (method == "PUT")
                {
                    return (200, "application/json", """{"message":"acl updated"}""");
                }

                return (200, "application/json",
                    """
                    {"rules":[{"name":"office","networks":["10.0.0.0/8"],"action":"allow","types":["A"],"redirect":""}],"allow_recursion":{"allow_all":false,"networks":["10.0.0.0/8"]},"persistent":true,"policy_file":"/var/lib/nothingdns/access_policy.json"}
                    """);

            case "/api/v1/acl/recursion":
                return (200, "application/json", """{"allow_all":false,"networks":["10.0.0.0/8"]}""");

            case "/api/v1/config/logging":
                return (200, "application/json", """{"message":"log level updated"}""");

            case var config when config.StartsWith("/api/v1/config/", StringComparison.Ordinal):
                return (200, "application/json", """{"message":"config updated"}""");

            case "/api/dashboard/stats":
                return (200, "application/json",
                    """
                    {"uptime":7200,"queriesTotal":42,"queriesPerSec":1.5,"cacheHitRate":0.75,"blockedQueries":3,"activeClients":2,"zoneCount":1,"upstreamLatency":12}
                    """);

            case "/api/dashboard/queries":
                return (200, "application/json",
                    """
                    [{"timestamp":"t","clientIp":"10.0.0.5","countryCode":"NL","domain":"example.com","queryType":"A","responseCode":"NOERROR","answers":["192.0.2.1"],"duration":1,"cached":true,"blocked":false,"protocol":"udp"}]
                    """);

            case "/api/v1/queries":
                return (200, "application/json",
                    """
                    {"queries":[{"timestamp":"t","client_ip":"10.0.0.5","domain":"example.com","query_type":"A","response_code":"NOERROR","answers":["192.0.2.1"],"duration_ms":1,"cached":true,"blocked":false,"protocol":"udp"}],"total":1,"offset":0,"limit":50}
                    """);

            case "/api/v1/upstreams":
                if (method == "PUT")
                {
                    return (200, "application/json", """{"message":"upstream added"}""");
                }

                return (200, "application/json",
                    """{"upstreams":[{"address":"9.9.9.9:53","healthy":true,"queries":5,"failed":0,"failovers":0}],"servers":[{"address":"9.9.9.9:53","healthy":true,"latency_ms":12.5}]}""");

            case "/api/v1/dnssec/keys":
                return (403, "application/json", """{"error":"admin role required"}""");

            case "/api/v1/cache/flush":
                return (429, "application/json", """{"error":"rate limited"}""");

            default:
                return (404, "application/json", """{"error":"not found"}""");
        }
    }

    private sealed record IncomingRequest(string Method, string Route, string? BodyText, RecordedRequest Recorded);
}
