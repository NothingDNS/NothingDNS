using NothingDns.Sdk;

namespace NothingDns.QuickStart;

/// <summary>
/// A runnable tour of the NothingDNS C# SDK.
/// </summary>
/// <remarks>
/// <para>
/// The example logs in, lists every zone, makes sure the demo zone and its A
/// record exist, reads the cache statistics and prints a zone export. It is
/// written so that a second run is idempotent: the zone is created only when it
/// is missing, and the A record is replaced rather than duplicated.
/// </para>
/// <para>
/// Credentials are read from the environment and are never hardcoded or echoed:
/// <list type="bullet">
///   <item><description><c>NDNS_URL</c> — base URL, default <c>http://localhost:8080</c></description></item>
///   <item><description><c>NDNS_USER</c> — account name (required)</description></item>
///   <item><description><c>NDNS_PASSWORD</c> — account password (required)</description></item>
/// </list>
/// Run it with:
/// <code>
/// export NDNS_URL=http://dns.example.com:8080
/// export NDNS_USER=admin
/// export NDNS_PASSWORD=...          # or: read -rs NDNS_PASSWORD
/// dotnet run --project NothingDns.Sdk/Examples
/// </code>
/// </para>
/// </remarks>
internal static class Program
{
    private const string ZoneName = "example.com";
    private const string RecordName = "www";
    private const string RecordAddress = "203.0.113.10";

    private static async Task<int> Main()
    {
        var baseUrl = Environment.GetEnvironmentVariable("NDNS_URL") ?? "http://localhost:8080";
        var username = Environment.GetEnvironmentVariable("NDNS_USER");
        var password = Environment.GetEnvironmentVariable("NDNS_PASSWORD");

        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
        {
            Console.Error.WriteLine("Set NDNS_USER and NDNS_PASSWORD before running this example.");
            return 2;
        }

        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        var role = "unknown";

        try
        {
            await using var client = new NothingDnsClient(baseUrl);

            // 1. Log in. The token is stored on the client, so every later call is
            //    authenticated without passing the token around.
            var session = await client.Auth.LoginAsync(
                username,
                password,
                cancellationToken: cancellation.Token);

            role = session.Role;
            Console.WriteLine($"Logged in as {session.Username} ({session.Role}) against {client.BaseUrl}");

            // 2. List every zone served by this node.
            var zones = await client.Zones.ListAsync(cancellation.Token);
            Console.WriteLine(
                $"\n{zones.Zones.Count} of {zones.Total} zone(s) loaded"
                + (zones.Truncated ? " (response was truncated)" : string.Empty));

            foreach (var zone in zones.Zones)
            {
                Console.WriteLine($"  {zone.Name,-32} serial {zone.Serial,-10} {zone.Records} record(s)");
            }

            // 3. Make sure the demo zone exists before touching its records.
            await EnsureZoneAsync(client, cancellation.Token);

            // 4. Add the A record, replacing it when a previous run already created it.
            await EnsureRecordAsync(client, cancellation.Token);

            // 5. Read the cache counters.
            var cache = await client.Cache.StatsAsync(cancellation.Token);
            Console.WriteLine(
                $"\nCache: {cache.Size}/{cache.Capacity} entries, "
                + $"{cache.Hits} hits / {cache.Misses} misses, hit ratio {cache.HitRatio:P1}");

            // 6. Print the zone export.
            var export = await client.Zones.ExportAsync(ZoneName, cancellation.Token);
            Console.WriteLine($"\n----- {ZoneName} -----");
            Console.WriteLine(export.TrimEnd());
            Console.WriteLine($"----- end of {ZoneName} -----");

            // 7. Leave the session tidy.
            Console.WriteLine($"\nLogging out: {await client.Auth.LogoutAsync(cancellation.Token)}");
            return 0;
        }
        catch (NothingDnsApiException ex)
        {
            // The server answered with a 4xx/5xx status.
            Console.Error.WriteLine($"NothingDNS returned HTTP {ex.StatusCode}: {ex.Message}");

            if (ex.IsUnauthorized)
            {
                Console.Error.WriteLine("The credentials were rejected, or the session expired.");
            }
            else if (ex.IsForbidden)
            {
                Console.Error.WriteLine(
                    $"The '{role}' role is not enough for this call; zone changes need operator or admin.");
            }
            else if (ex.IsNotFound)
            {
                Console.Error.WriteLine($"The resource '{ZoneName}' does not exist on this server.");
            }

            return 1;
        }
        catch (NothingDnsConnectionException ex)
        {
            Console.Error.WriteLine($"Could not reach the server: {ex.Message}");
            return 1;
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("The example timed out.");
            return 1;
        }
    }

    private static async Task EnsureZoneAsync(NothingDnsClient client, CancellationToken cancellationToken)
    {
        try
        {
            await client.Zones.GetAsync(ZoneName, cancellationToken);
            Console.WriteLine($"\nZone {ZoneName} already exists.");
        }
        catch (NothingDnsApiException ex) when (ex.IsNotFound)
        {
            var message = await client.Zones.CreateAsync(
                ZoneName,
                new[] { "ns1.example.com", "ns2.example.com" },
                adminEmail: "hostmaster@example.com",
                ttl: 3600,
                cancellationToken: cancellationToken);

            Console.WriteLine($"\nCreated {ZoneName}: {message}");
        }
    }

    private static async Task EnsureRecordAsync(NothingDnsClient client, CancellationToken cancellationToken)
    {
        var records = await client.Zones.ListRecordsAsync(ZoneName, RecordName, cancellationToken);

        foreach (var record in records.Records)
        {
            if (record.Type == "A" && record.Data == RecordAddress)
            {
                Console.WriteLine($"Record {RecordName}.{ZoneName} A {RecordAddress} already exists.");
                return;
            }
        }

        var existing = records.Records.Find(record => record.Type == "A");

        if (existing is not null)
        {
            // Replace the first existing A record so repeated runs converge.
            var message = await client.Zones.ReplaceRecordAsync(
                ZoneName,
                RecordName,
                "A",
                existing.Data,
                RecordAddress,
                ttl: 300,
                cancellationToken: cancellationToken);

            Console.WriteLine($"Updated {RecordName}.{ZoneName} A {existing.Data} -> {RecordAddress}: {message}");
            return;
        }

        var added = await client.Zones.AddRecordAsync(
            ZoneName,
            RecordName,
            "A",
            RecordAddress,
            ttl: 300,
            cancellationToken: cancellationToken);

        Console.WriteLine($"Added {RecordName}.{ZoneName} A {RecordAddress}: {added}");
    }
}
