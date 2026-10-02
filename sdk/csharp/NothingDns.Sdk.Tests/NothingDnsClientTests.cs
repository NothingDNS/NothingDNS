using System.Text.Json.Nodes;
using Xunit;

namespace NothingDns.Sdk.Tests;

/// <summary>
/// Behavioural tests for the NothingDNS C# client against the loopback mock,
/// mirroring the request-level contract of the Python suite
/// (<c>sdk/python/tests/test_client.py</c>) and <c>sdk/go/client_test.go</c>:
/// paths, methods, query strings, JSON bodies, bearer-auth propagation and
/// typed model decoding.
/// </summary>
public sealed class NothingDnsClientTests
{
    // ------------------------------------------------------------------
    // Health & authentication
    // ------------------------------------------------------------------

    [Fact]
    public async Task HealthEndpointsNeedNoAuth()
    {
        using var mock = new MockApi();
        await using var client = mock.CreateClient();

        var endpoints = new (string ExpectedPath, Func<Task<HealthResponse>> Call)[]
        {
            ("/health", () => client.HealthAsync()),
            ("/readyz", () => client.ReadyAsync()),
            ("/livez", () => client.LiveAsync()),
        };

        foreach (var (expectedPath, call) in endpoints)
        {
            var health = await call();

            Assert.Equal("healthy", health.Status);
            Assert.Equal(expectedPath, mock.Last.Path);
            Assert.Null(mock.Last.Auth);
        }
    }

    [Fact]
    public async Task LoginStoresTokenAndNextRequestCarriesIt()
    {
        using var mock = new MockApi();
        await using var client = mock.CreateClient();

        var session = await client.Auth.LoginAsync(MockApi.Username, MockApi.Password);

        Assert.Equal("admin", session.Role);
        Assert.Equal("2026-10-02T12:00:00Z", session.Expires);
        Assert.Equal(MockApi.Token, client.Token);
        // The login request itself must not carry a token; the next one must.
        Assert.Null(mock.Last.Auth);
        await client.StatusAsync();
        Assert.Equal($"Bearer {MockApi.Token}", mock.Last.Auth);
    }

    [Fact]
    public async Task LoginSendsTheUsernameAndPasswordBody()
    {
        using var mock = new MockApi();
        await using var client = mock.CreateClient();

        await client.Auth.LoginAsync(MockApi.Username, MockApi.Password);

        Assert.Equal("POST", mock.Last.Method);
        Assert.Equal("/api/v1/auth/login", mock.Last.Path);
        var expected = new JsonObject { ["username"] = MockApi.Username, ["password"] = MockApi.Password };
        Assert.True(JsonNode.DeepEquals(expected, mock.Last.BodyJson), $"body was {mock.Last.BodyText}");
    }

    [Fact]
    public async Task LoginCanSkipStoringTheToken()
    {
        using var mock = new MockApi();
        await using var client = mock.CreateClient();

        var session = await client.Auth.LoginAsync(
            MockApi.Username, MockApi.Password, storeToken: false);

        Assert.Equal(MockApi.Token, session.Token);
        Assert.Null(client.Token);
    }

    [Fact]
    public async Task SetTokenIsUsedForRequests()
    {
        using var mock = new MockApi();
        await using var client = mock.CreateClient();

        const string serviceToken = $"{MockApi.Token}-service";
        client.SetToken(serviceToken);

        await client.StatusAsync();

        Assert.Equal($"Bearer {serviceToken}", mock.Last.Auth);
    }

    [Fact]
    public async Task LogoutInvalidatesAndReturnsMessage()
    {
        using var mock = new MockApi();
        await using var client = mock.CreateClient();
        client.SetToken(MockApi.Token);

        var message = await client.Auth.LogoutAsync();

        Assert.Equal("logged out", message);
        Assert.Equal("POST", mock.Last.Method);
    }

    // ------------------------------------------------------------------
    // Status & models
    // ------------------------------------------------------------------

    [Fact]
    public async Task StatusDecodesNestedModels()
    {
        using var mock = new MockApi();
        await using var client = mock.CreateClient();

        var status = await client.StatusAsync();

        Assert.Equal("1.2.17", status.Version);
        Assert.Equal(0.9, status.Cache!.HitRatio);
        Assert.False(status.Cluster!.Enabled);
        Assert.Equal("n1", status.Cluster.NodeId);
    }

    // ------------------------------------------------------------------
    // Zones & records
    // ------------------------------------------------------------------

    [Fact]
    public async Task ZoneListDecodesZones()
    {
        using var mock = new MockApi();
        await using var client = mock.CreateClient();

        var zones = await client.Zones.ListAsync();

        Assert.Equal(1, zones.Total);
        Assert.False(zones.Truncated);
        Assert.Equal("example.com", zones.Zones[0].Name);
        Assert.Equal(7, zones.Zones[0].Serial);
    }

    [Fact]
    public async Task RecordCrudMethodsPathsAndBodies()
    {
        using var mock = new MockApi();
        await using var client = mock.CreateClient();

        var records = await client.Zones.ListRecordsAsync("example.com");
        Assert.Equal("GET", mock.Last.Method);
        Assert.Equal("/api/v1/zones/example.com/records", mock.Last.Path);
        Assert.Equal("192.0.2.1", records.Records[0].Data);
        Assert.Equal("IN", records.Records[0].Class); // wire field "class"

        var added = await client.Zones.AddRecordAsync("example.com", "api", "A", "192.0.2.9", ttl: 60);
        Assert.Equal("POST", mock.Last.Method);
        Assert.Equal("/api/v1/zones/example.com/records", mock.Last.Path);
        Assert.True(
            JsonNode.DeepEquals(
                new JsonObject { ["name"] = "api", ["type"] = "A", ["data"] = "192.0.2.9", ["ttl"] = 60 },
                mock.Last.BodyJson),
            $"add body was {mock.Last.BodyText}");
        Assert.Equal("record added", added);

        var replaced = await client.Zones.ReplaceRecordAsync("example.com", "api", "A", "192.0.2.9", "192.0.2.10");
        Assert.Equal("PUT", mock.Last.Method);
        Assert.Equal("192.0.2.9", mock.Last.BodyJson?["old_data"]?.GetValue<string>());
        Assert.Equal("record replaced", replaced);

        var deleted = await client.Zones.DeleteRecordsAsync("example.com", "api", "A");
        Assert.Equal("DELETE", mock.Last.Method);
        Assert.True(
            JsonNode.DeepEquals(
                new JsonObject { ["name"] = "api", ["type"] = "A" },
                mock.Last.BodyJson),
            $"delete body was {mock.Last.BodyText}");
        Assert.Equal("records deleted", deleted);
    }

    [Fact]
    public async Task ZoneCreateSendsNameServersAndReturnsMessage()
    {
        using var mock = new MockApi();
        await using var client = mock.CreateClient();

        var message = await client.Zones.CreateAsync(
            "example.com",
            new[] { "ns1.example.com", "ns2.example.com" },
            adminEmail: "hostmaster@example.com",
            ttl: 3600);

        Assert.Equal("POST", mock.Last.Method);
        Assert.Equal("/api/v1/zones", mock.Last.Path);
        Assert.True(
            JsonNode.DeepEquals(
                new JsonObject
                {
                    ["name"] = "example.com",
                    ["nameservers"] = new JsonArray("ns1.example.com", "ns2.example.com"),
                    ["admin_email"] = "hostmaster@example.com",
                    ["ttl"] = 3600,
                },
                mock.Last.BodyJson),
            $"create body was {mock.Last.BodyText}");
        Assert.Equal("zone created", message);
    }

    [Fact]
    public async Task ZoneDeleteReturnsMessage()
    {
        using var mock = new MockApi();
        await using var client = mock.CreateClient();

        var message = await client.Zones.DeleteAsync("example.com");

        Assert.Equal("DELETE", mock.Last.Method);
        Assert.Equal("/api/v1/zones/example.com", mock.Last.Path);
        Assert.Equal("zone deleted", message);
    }

    [Fact]
    public async Task ZoneExportReturnsRawZoneFile()
    {
        using var mock = new MockApi();
        await using var client = mock.CreateClient();
        client.SetToken(MockApi.Token);

        var text = await client.Zones.ExportAsync("example.com");

        Assert.StartsWith("$ORIGIN example.com.", text);
        Assert.Equal("text/plain", mock.LastResponseContentType);
    }

    [Fact]
    public async Task ZoneTransfersDecodeSlaveZones()
    {
        using var mock = new MockApi();
        await using var client = mock.CreateClient();

        var slaves = await client.Zones.TransfersAsync();

        Assert.Equal("sub.example.com", slaves[0].Zone);
        Assert.Equal("synced", slaves[0].Status);
        Assert.Equal(12, slaves[0].Records);
    }

    [Fact]
    public async Task PtrBulkPreviewWireKeysAndDecoding()
    {
        using var mock = new MockApi();
        await using var client = mock.CreateClient();

        var preview = await client.Zones.PtrBulkAsync(
            "2.0.192.in-addr.arpa", "192.0.2.0/24", "host-{ip}.example.com");

        Assert.Equal("POST", mock.Last.Method);
        Assert.Equal("/api/v1/zones/2.0.192.in-addr.arpa/ptr-bulk", mock.Last.Path);
        // The result decodes the wire's camelCase keys.
        Assert.True(preview.Preview);
        Assert.Equal(256, preview.WillAdd);
        Assert.Equal("host-192-0-2-1.example.com", preview.Changes[0].Data);
        // The request keeps the wire's camelCase keys.
        Assert.True(
            JsonNode.DeepEquals(
                new JsonObject
                {
                    ["cidr"] = "192.0.2.0/24",
                    ["pattern"] = "host-{ip}.example.com",
                    ["override"] = false,
                    ["addA"] = false,
                    ["preview"] = true,
                },
                mock.Last.BodyJson),
            $"ptr-bulk body was {mock.Last.BodyText}");
    }

    [Fact]
    public async Task Ptr6LookupSendsIpQueryParam()
    {
        using var mock = new MockApi();
        await using var client = mock.CreateClient();

        var lookup = await client.Zones.Ptr6LookupAsync(
            "8.b.d.0.1.0.0.2.ip6.arpa", "2001:db8::1");

        Assert.StartsWith("/api/v1/zones/8.b.d.0.1.0.0.2.ip6.arpa/ptr6-lookup?", mock.Last.Path);
        Assert.Contains("ip=2001%3Adb8%3A%3A1", mock.Last.Path);
        Assert.True(lookup.Found);
        Assert.Equal("host.example.com", lookup.Target);
    }

    // ------------------------------------------------------------------
    // ACL
    // ------------------------------------------------------------------

    [Fact]
    public async Task AclRoundTrip()
    {
        using var mock = new MockApi();
        await using var client = mock.CreateClient();

        var acl = await client.Acl.GetAsync();
        Assert.Equal("allow", acl.Rules[0].Action);
        Assert.Equal(["10.0.0.0/8"], acl.Rules[0].Networks);
        Assert.False(acl.AllowRecursion!.AllowAll);
        Assert.True(acl.Persistent);

        var message = await client.Acl.SetAsync(
        [
            new AclRule { Name = "vpn", Networks = { "10.1.0.0/16" }, Action = "deny" },
            new AclRule
            {
                Name = "lan",
                Networks = { "192.168.0.0/16" },
                Action = "redirect",
                Types = { "A", "AAAA" },
                Redirect = "127.0.0.1",
            },
        ]);
        Assert.Equal("PUT", mock.Last.Method);
        // Mirrors the Python SDK's ACLRule.to_dict: types and redirect are omitted
        // when empty and included when set.
        Assert.True(
            JsonNode.DeepEquals(
                new JsonObject
                {
                    ["rules"] = new JsonArray(
                        new JsonObject
                        {
                            ["name"] = "vpn",
                            ["networks"] = new JsonArray("10.1.0.0/16"),
                            ["action"] = "deny",
                        },
                        new JsonObject
                        {
                            ["name"] = "lan",
                            ["networks"] = new JsonArray("192.168.0.0/16"),
                            ["action"] = "redirect",
                            ["types"] = new JsonArray("A", "AAAA"),
                            ["redirect"] = "127.0.0.1",
                        }),
                },
                mock.Last.BodyJson),
            $"acl body was {mock.Last.BodyText}");
        Assert.Equal("acl updated", message);

        var recursion = await client.Acl.SetRecursionAsync(["10.0.0.0/8"]);
        Assert.Equal(["10.0.0.0/8"], recursion.Networks);
    }

    // ------------------------------------------------------------------
    // Configuration
    // ------------------------------------------------------------------

    [Fact]
    public async Task ConfigPartialUpdatesDropNullFieldsAndParseMessage()
    {
        using var mock = new MockApi();
        await using var client = mock.CreateClient();

        var message = await client.Config.SetLoggingAsync("debug");
        Assert.Equal("PUT", mock.Last.Method);
        Assert.Equal("/api/v1/config/logging", mock.Last.Path);
        Assert.True(
            JsonNode.DeepEquals(new JsonObject { ["level"] = "debug" }, mock.Last.BodyJson),
            $"logging body was {mock.Last.BodyText}");
        Assert.Equal("log level updated", message);

        await client.Config.SetCacheAsync(size: 5000, serveStale: true);
        Assert.Equal("/api/v1/config/cache", mock.Last.Path);
        Assert.True(
            JsonNode.DeepEquals(
                new JsonObject { ["size"] = 5000, ["serve_stale"] = true },
                mock.Last.BodyJson),
            $"cache body was {mock.Last.BodyText}");

        await client.Config.SetRrlAsync(enabled: true);
        Assert.True(
            JsonNode.DeepEquals(new JsonObject { ["enabled"] = true }, mock.Last.BodyJson),
            $"rrl body was {mock.Last.BodyText}");
    }

    // ------------------------------------------------------------------
    // Dashboard & metrics
    // ------------------------------------------------------------------

    [Fact]
    public async Task DashboardDecodesCamelCaseKeys()
    {
        using var mock = new MockApi();
        await using var client = mock.CreateClient();

        var stats = await client.Dashboard.StatsAsync();
        Assert.Equal(42, stats.QueriesTotal);
        Assert.Equal(0.75, stats.CacheHitRate);
        Assert.Equal(1, stats.ZoneCount);

        var events = await client.Dashboard.QueriesAsync();
        Assert.Equal("10.0.0.5", events[0].ClientIp);
        Assert.Equal("NL", events[0].CountryCode);
        Assert.True(events[0].Cached);
    }

    [Fact]
    public async Task QueryLogParamsAndSnakeCasePayload()
    {
        using var mock = new MockApi();
        await using var client = mock.CreateClient();

        var page = await client.Metrics.QueryLogAsync(limit: 50, q: "example");
        Assert.Equal("/api/v1/queries?limit=50&q=example", mock.Last.Path);
        Assert.Equal("10.0.0.5", page.Queries[0].ClientIp);
        Assert.Equal(1, page.Total);

        await client.Metrics.QueryLogAsync(offset: 100, limit: 50);
        Assert.Equal("/api/v1/queries?offset=100&limit=50", mock.Last.Path);

        await client.Metrics.QueryLogAsync();
        Assert.Equal("/api/v1/queries", mock.Last.Path);
    }

    // ------------------------------------------------------------------
    // Upstreams
    // ------------------------------------------------------------------

    [Fact]
    public async Task UpstreamsListAndAdd()
    {
        using var mock = new MockApi();
        await using var client = mock.CreateClient();

        var pool = await client.Upstreams.ListAsync();
        Assert.Equal(12.5, pool.Servers[0].LatencyMs);

        var message = await client.Upstreams.AddAsync("1.1.1.1:53");
        Assert.Equal("PUT", mock.Last.Method);
        Assert.True(
            JsonNode.DeepEquals(
                new JsonObject { ["action"] = "add", ["server"] = "1.1.1.1:53" },
                mock.Last.BodyJson),
            $"upstream body was {mock.Last.BodyText}");
        Assert.Equal("upstream added", message);
    }

    // ------------------------------------------------------------------
    // Local validation
    // ------------------------------------------------------------------

    [Fact]
    public async Task LocalValidationRejectsBeforeAnyRequest()
    {
        using var mock = new MockApi();
        await using var client = mock.CreateClient();

        var cases = new (string Name, Func<Task> Call)[]
        {
            ("empty-acl", () => client.Acl.SetAsync([])),
            ("bad-log-level", () => client.Config.SetLoggingAsync("loud")),
            ("blocklist-without-source", () => client.Blocklists.AddAsync()),
            ("blocklist-with-both-sources", () => client.Blocklists.AddAsync("/etc/hosts", "https://example.com/hosts")),
            ("unknown-role", () => client.Auth.CreateUserAsync("ops", "pw-op-1", role: "root")),
            ("unknown-rpz-action", () => client.Rpz.AddRuleAsync("ads.example.com", action: "DENY")),
            ("zone-without-nameservers", () => client.Zones.CreateAsync("example.com", [])),
        };

        foreach (var (name, call) in cases)
        {
            var exception = await Record.ExceptionAsync(call);
            Assert.True(
                exception is NothingDnsValidationException,
                $"{name}: expected NothingDnsValidationException but was {exception?.GetType().Name}: {exception?.Message}");
        }

        // Nothing was sent for any of the rejected calls.
        Assert.Empty(mock.Requests);
    }

    [Fact]
    public async Task EmptyRequiredArgumentsAreRejectedBeforeAnyRequest()
    {
        using var mock = new MockApi();
        await using var client = mock.CreateClient();

        await Assert.ThrowsAsync<ArgumentException>(() => client.Zones.GetAsync(""));
        await Assert.ThrowsAsync<ArgumentException>(() => client.Zones.AddRecordAsync("example.com", "", "A", "1.2.3.4"));
        await Assert.ThrowsAsync<ArgumentException>(() => client.Auth.LoginAsync("", "pw"));

        Assert.Empty(mock.Requests);
    }

    // ------------------------------------------------------------------
    // Request mechanics
    // ------------------------------------------------------------------

    [Fact]
    public async Task PathSegmentsAreEscaped()
    {
        using var mock = new MockApi();
        await using var client = mock.CreateClient();

        await Assert.ThrowsAsync<NothingDnsApiException>(
            () => client.Zones.GetAsync("weird zone/name"));

        var path = mock.Last.Path;
        Assert.Contains("%20", path);
        Assert.Contains("%2F", path);
    }

    [Fact]
    public async Task TrailingSlashInBaseUrlIsNormalised()
    {
        using var mock = new MockApi();
        await using var client = new NothingDnsClient(mock.Base + "/", timeout: TimeSpan.FromSeconds(5));

        Assert.Equal(mock.Base, client.BaseUrl);

        var health = await client.HealthAsync();
        Assert.Equal("healthy", health.Status);
    }
}
