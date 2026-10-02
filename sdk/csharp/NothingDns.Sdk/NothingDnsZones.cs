namespace NothingDns.Sdk;

/// <summary>
/// Zones, records, export and bulk PTR generation (<c>/api/v1/zones</c>).
/// </summary>
/// <remarks>
/// Every method requires at least the operator role. Zone names, owner names and
/// other user-supplied path segments are percent-encoded by the SDK, so a name
/// containing a slash or a space cannot alter the shape of the request URL.
/// </remarks>
public sealed class NothingDnsZones
{
    private readonly NothingDnsTransport _transport;

    /// <summary>Initializes a new instance of the <see cref="NothingDnsZones"/> class.</summary>
    /// <param name="transport">The shared transport used to reach the server.</param>
    /// <exception cref="ArgumentNullException"><paramref name="transport"/> is <see langword="null"/>.</exception>
    public NothingDnsZones(NothingDnsTransport transport)
    {
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
    }

    /// <summary>List every zone served by this node.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The zone list. When <see cref="ZoneList.Truncated"/> is true the server capped the response.</returns>
    /// <exception cref="NothingDnsApiException">401 or 403 when the caller's role is insufficient.</exception>
    public async Task<ZoneList> ListAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .GetAsync("/api/v1/zones", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.Model<ZoneList>(payload);
    }

    /// <summary>Create a new authoritative zone.</summary>
    /// <param name="name">Zone name, for example <c>example.com</c>. A trailing dot is optional.</param>
    /// <param name="nameservers">NS hostnames written into the zone's SOA record. At least one is required.</param>
    /// <param name="adminEmail">Zone admin e-mail; the server derives the SOA <c>rname</c> from it.</param>
    /// <param name="ttl">Default TTL in seconds for records in the new zone.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The server's confirmation message.</returns>
    /// <exception cref="ArgumentException"><paramref name="name"/> is empty or <paramref name="nameservers"/> is empty.</exception>
    /// <exception cref="NothingDnsApiException">
    /// 409 when the zone already exists, or 421 when the name cannot become its own
    /// zone because it is a subdomain of an existing one.
    /// </exception>
    public async Task<string> CreateAsync(
        string name,
        IEnumerable<string> nameservers,
        string? adminEmail = null,
        long? ttl = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        var servers = nameservers?.ToList() ?? new List<string>();
        if (servers.Count == 0)
        {
            throw new NothingDnsValidationException(
                "nameservers must contain at least one hostname.");
        }

        var body = NothingDnsTransport.Body(
            ("name", name),
            ("nameservers", servers),
            ("admin_email", adminEmail),
            ("ttl", ttl));

        var payload = await _transport
            .PostAsync("/api/v1/zones", body, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.MessageOf(payload);
    }

    /// <summary>Get one zone with its SOA record and NS set.</summary>
    /// <param name="zone">The zone name.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The zone detail.</returns>
    /// <exception cref="ArgumentException"><paramref name="zone"/> is empty.</exception>
    /// <exception cref="NothingDnsApiException">404 when the zone does not exist.</exception>
    public async Task<ZoneDetail> GetAsync(string zone, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(zone);

        var payload = await _transport
            .GetAsync($"/api/v1/zones/{NothingDnsTransport.Escape(zone)}", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.Model<ZoneDetail>(payload);
    }

    /// <summary>Delete a zone.</summary>
    /// <param name="zone">The zone name.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The server's confirmation message.</returns>
    /// <exception cref="ArgumentException"><paramref name="zone"/> is empty.</exception>
    /// <exception cref="NothingDnsApiException">
    /// 404 when the zone does not exist, or 421 when other zones still live beneath it.
    /// </exception>
    public async Task<string> DeleteAsync(string zone, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(zone);

        var payload = await _transport
            .DeleteAsync($"/api/v1/zones/{NothingDnsTransport.Escape(zone)}", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.MessageOf(payload);
    }

    /// <summary>Reload one zone from its zone file on disk.</summary>
    /// <param name="zone">The zone name.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The server's confirmation message.</returns>
    /// <exception cref="ArgumentException"><paramref name="zone"/> is empty.</exception>
    /// <exception cref="NothingDnsApiException">
    /// 400 when the zone name is invalid, or 500 when the file could not be parsed. Admin role required.
    /// </exception>
    public async Task<string> ReloadAsync(string zone, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(zone);

        var query = new[] { new KeyValuePair<string, object?>("zone", zone) };
        var payload = await _transport
            .PostAsync("/api/v1/zones/reload", query: query, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.MessageOf(payload);
    }

    /// <summary>List secondary (slave) zones and their transfer state.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The secondary zones, each with its serial and sync status.</returns>
    /// <exception cref="NothingDnsApiException">401 or 403 when the caller's role is insufficient.</exception>
    public async Task<IReadOnlyList<SlaveZone>> TransfersAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .GetAsync("/api/v1/zones/transfers", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.ListOf<SlaveZone>(payload, "slave_zones");
    }

    /// <summary>List the records in a zone.</summary>
    /// <param name="zone">The zone name.</param>
    /// <param name="name">Optional owner-name filter, for example <c>www</c> or <c>@</c> for the apex.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The matching records. Check <see cref="RecordList.Truncated"/> for a capped response.</returns>
    /// <exception cref="ArgumentException"><paramref name="zone"/> is empty.</exception>
    /// <exception cref="NothingDnsApiException">404 when the zone does not exist.</exception>
    public async Task<RecordList> ListRecordsAsync(
        string zone,
        string? name = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(zone);

        var query = new[] { new KeyValuePair<string, object?>("name", name) };
        var payload = await _transport
            .GetAsync(
                $"/api/v1/zones/{NothingDnsTransport.Escape(zone)}/records",
                query,
                cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.Model<RecordList>(payload);
    }

    /// <summary>Add a record to a zone.</summary>
    /// <param name="zone">The zone name.</param>
    /// <param name="name">Owner name relative to the zone; <c>@</c> is the apex.</param>
    /// <param name="type">Record type, for example <c>A</c>, <c>AAAA</c>, <c>CNAME</c>, <c>MX</c>, <c>TXT</c>, <c>SRV</c>, <c>CAA</c> or <c>PTR</c>.</param>
    /// <param name="data">
    /// Record data in zone-file presentation format: a bare address for <c>A</c>,
    /// the target host for <c>MX</c>/<c>SRV</c>, quoted text for <c>TXT</c>.
    /// </param>
    /// <param name="ttl">Record TTL in seconds; the zone default is used when omitted.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The server's confirmation message.</returns>
    /// <exception cref="ArgumentException">A required argument is empty.</exception>
    /// <exception cref="NothingDnsApiException">
    /// 400 for invalid record data, 404 when the zone does not exist, or 421 when
    /// the record conflicts with one that already exists.
    /// </exception>
    public async Task<string> AddRecordAsync(
        string zone,
        string name,
        string type,
        string data,
        long? ttl = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(zone);
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentException.ThrowIfNullOrEmpty(type);
        ArgumentException.ThrowIfNullOrEmpty(data);

        var body = NothingDnsTransport.Body(
            ("name", name),
            ("type", type),
            ("data", data),
            ("ttl", ttl));

        var payload = await _transport
            .PostAsync(
                $"/api/v1/zones/{NothingDnsTransport.Escape(zone)}/records",
                body,
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.MessageOf(payload);
    }

    /// <summary>Replace an existing record, identified by its current data.</summary>
    /// <param name="zone">The zone name.</param>
    /// <param name="name">Owner name relative to the zone.</param>
    /// <param name="type">Record type.</param>
    /// <param name="oldData">The record's current data, used to locate it.</param>
    /// <param name="data">The replacement data.</param>
    /// <param name="ttl">New TTL in seconds; the zone default is used when omitted.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The server's confirmation message.</returns>
    /// <exception cref="ArgumentException">A required argument is empty.</exception>
    /// <exception cref="NothingDnsApiException">
    /// 400 for invalid data, 404 when the zone or the record does not exist, or 421
    /// when the replacement conflicts with another record.
    /// </exception>
    public async Task<string> ReplaceRecordAsync(
        string zone,
        string name,
        string type,
        string oldData,
        string data,
        long? ttl = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(zone);
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentException.ThrowIfNullOrEmpty(type);
        ArgumentException.ThrowIfNullOrEmpty(oldData);
        ArgumentException.ThrowIfNullOrEmpty(data);

        var body = NothingDnsTransport.Body(
            ("name", name),
            ("type", type),
            ("old_data", oldData),
            ("data", data),
            ("ttl", ttl));

        var payload = await _transport
            .PutAsync(
                $"/api/v1/zones/{NothingDnsTransport.Escape(zone)}/records",
                body,
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.MessageOf(payload);
    }

    /// <summary>Delete records from a zone by owner name and type.</summary>
    /// <param name="zone">The zone name.</param>
    /// <param name="name">Owner name relative to the zone; <c>@</c> is the apex.</param>
    /// <param name="type">Record type.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The server's confirmation message.</returns>
    /// <exception cref="ArgumentException">A required argument is empty.</exception>
    /// <exception cref="NothingDnsApiException">
    /// 404 when the zone does not exist, or 421 when the deletion would leave a
    /// delegated or otherwise required record dangling.
    /// </exception>
    public async Task<string> DeleteRecordsAsync(
        string zone,
        string name,
        string type,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(zone);
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentException.ThrowIfNullOrEmpty(type);

        var body = NothingDnsTransport.Body(("name", name), ("type", type));

        var payload = await _transport
            .DeleteAsync(
                $"/api/v1/zones/{NothingDnsTransport.Escape(zone)}/records",
                body,
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.MessageOf(payload);
    }

    /// <summary>Export a zone as a BIND-format zone file.</summary>
    /// <param name="zone">The zone name.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The zone file contents exactly as served.</returns>
    /// <exception cref="ArgumentException"><paramref name="zone"/> is empty.</exception>
    /// <exception cref="NothingDnsApiException">404 when the zone does not exist.</exception>
    public async Task<string> ExportAsync(string zone, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(zone);

        return await _transport
            .GetTextAsync(
                $"/api/v1/zones/{NothingDnsTransport.Escape(zone)}/export",
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);
    }

    /// <summary>Generate PTR and optionally forward-confirmed A records for an IPv4 range.</summary>
    /// <param name="zone">The reverse zone, for example <c>2.0.192.in-addr.arpa</c>.</param>
    /// <param name="cidr">IPv4 CIDR to cover, for example <c>192.0.2.0/24</c>. Ranges larger than a /16 are rejected by the server.</param>
    /// <param name="pattern">Target host template; <c>{ip}</c> is replaced with the address, for example <c>host-{ip}.example.com</c>.</param>
    /// <param name="override">Replace records that already exist instead of skipping them.</param>
    /// <param name="addA">Also create the matching A records.</param>
    /// <param name="preview">
    /// When <see langword="true"/> (the default) nothing is written and the planned
    /// changes are returned instead.
    /// </param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>
    /// The result. Check <see cref="PtrBulkResult.Preview"/> to tell the dry run
    /// apart from the applied run.
    /// </returns>
    /// <exception cref="ArgumentException">A required argument is empty.</exception>
    /// <exception cref="NothingDnsApiException">
    /// 400 for an invalid CIDR, a non-IPv4 range or an oversized range, or 404 when
    /// the zone does not exist.
    /// </exception>
    public async Task<PtrBulkResult> PtrBulkAsync(
        string zone,
        string cidr,
        string pattern,
        bool @override = false,
        bool addA = false,
        bool preview = true,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(zone);
        ArgumentException.ThrowIfNullOrEmpty(cidr);
        ArgumentException.ThrowIfNullOrEmpty(pattern);

        var body = NothingDnsTransport.Body(
            ("cidr", cidr),
            ("pattern", pattern),
            ("override", @override),
            ("addA", addA),
            ("preview", preview));

        var result = await _transport
            .PostAsync(
                $"/api/v1/zones/{NothingDnsTransport.Escape(zone)}/ptr-bulk",
                body,
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.Model<PtrBulkResult>(result);
    }

    /// <summary>Look up the PTR record for an IPv6 address in a zone.</summary>
    /// <param name="zone">The IPv6 reverse zone, for example <c>8.b.d.0.1.0.0.2.ip6.arpa</c>.</param>
    /// <param name="ip">The IPv6 address to resolve.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The lookup result. Check <see cref="PtrLookup.Found"/> before reading the other fields.</returns>
    /// <exception cref="ArgumentException">A required argument is empty.</exception>
    /// <exception cref="NothingDnsApiException">404 when the zone does not exist.</exception>
    public async Task<PtrLookup> Ptr6LookupAsync(
        string zone,
        string ip,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(zone);
        ArgumentException.ThrowIfNullOrEmpty(ip);

        var query = new[] { new KeyValuePair<string, object?>("ip", ip) };
        var payload = await _transport
            .GetAsync(
                $"/api/v1/zones/{NothingDnsTransport.Escape(zone)}/ptr6-lookup",
                query,
                cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.Model<PtrLookup>(payload);
    }
}
