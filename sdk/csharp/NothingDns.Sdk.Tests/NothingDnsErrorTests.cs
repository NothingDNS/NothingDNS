using Xunit;

namespace NothingDns.Sdk.Tests;

/// <summary>
/// Error translation and predicate tests, mirroring
/// <c>sdk/python/tests/test_errors.py</c>.
/// </summary>
public sealed class NothingDnsErrorTests
{
    [Fact]
    public async Task UnauthorizedPredicateSurfacesTheServerMessage()
    {
        using var mock = new MockApi();
        await using var client = mock.CreateClient();

        var exception = await Assert.ThrowsAsync<NothingDnsApiException>(
            () => client.Auth.LoginAsync(MockApi.Username, "wrong"));

        Assert.Equal(401, exception.StatusCode);
        Assert.Equal("invalid credentials", exception.Message);
        Assert.True(exception.IsUnauthorized);
        Assert.False(exception.IsForbidden);
    }

    [Fact]
    public async Task ForbiddenPredicate()
    {
        using var mock = new MockApi();
        await using var client = mock.CreateClient();

        var exception = await Assert.ThrowsAsync<NothingDnsApiException>(
            () => client.Dnssec.KeysAsync());

        Assert.Equal(403, exception.StatusCode);
        Assert.True(exception.IsForbidden);
    }

    [Fact]
    public async Task RateLimitedPredicate()
    {
        using var mock = new MockApi();
        await using var client = mock.CreateClient();

        var exception = await Assert.ThrowsAsync<NothingDnsApiException>(
            () => client.Cache.FlushAsync());

        Assert.Equal(429, exception.StatusCode);
        Assert.True(exception.IsRateLimited);
    }

    [Fact]
    public async Task NotFoundPredicateCarriesThePayload()
    {
        using var mock = new MockApi();
        await using var client = mock.CreateClient();

        var exception = await Assert.ThrowsAsync<NothingDnsApiException>(
            () => client.Zones.GetAsync("missing.com"));

        Assert.Equal(404, exception.StatusCode);
        Assert.True(exception.IsNotFound);
        Assert.Contains("missing.com", exception.Message);
        Assert.Equal(
            "Zone missing.com not found",
            exception.Payload!.Value.GetProperty("error").GetString());
        Assert.Contains("Zone missing.com not found", exception.RawBody);
    }

    [Fact]
    public void PredicatesRejectNonApiErrors()
    {
        Assert.False(NothingDnsErrors.IsNotFound(new InvalidOperationException("nope")));
        Assert.False(NothingDnsErrors.IsUnauthorized(new InvalidOperationException("nope")));
        Assert.False(NothingDnsErrors.IsForbidden(null));
        Assert.False(NothingDnsErrors.IsRateLimited(null));
        Assert.False(NothingDnsErrors.IsNotFound(new NothingDnsConnectionException("nope")));
    }

    [Fact]
    public void ApiErrorStringIncludesStatusAndMessage()
    {
        var error = new NothingDnsApiException(409, "zone already exists");

        Assert.Contains("409", error.ToString());
        Assert.Contains("zone already exists", error.ToString());
    }

    [Fact]
    public async Task UnreachableServerRaisesConnectionError()
    {
        // Bind a port, note it, then close it so connections are refused.
        var probe = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        probe.Start();
        var deadPort = ((System.Net.IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();

        await using var client = new NothingDnsClient(
            $"http://127.0.0.1:{deadPort}", timeout: TimeSpan.FromSeconds(2));

        var exception = await Assert.ThrowsAnyAsync<NothingDnsException>(
            () => client.HealthAsync());

        Assert.IsType<NothingDnsConnectionException>(exception);
    }
}
