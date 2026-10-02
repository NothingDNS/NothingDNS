package io.nothingdns.sdk.resources;

import com.google.gson.JsonElement;
import io.nothingdns.sdk.NothingDnsTransport;
import io.nothingdns.sdk.model.PtrModels;
import io.nothingdns.sdk.model.RecordList;
import io.nothingdns.sdk.model.SlaveZone;
import io.nothingdns.sdk.model.ZoneDetail;
import io.nothingdns.sdk.model.ZoneList;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Zones, records, export and bulk PTR generation ({@code /api/v1/zones}).
 *
 * <p>Obtained from {@code client.zones()}. Every method except
 * {@link #list()} needs at least the operator role; the mutating methods need
 * admin for the reload.</p>
 */
public final class ZonesResource extends ApiResource {

    /**
     * Create the zones namespace.
     *
     * @param transport the shared transport
     */
    public ZonesResource(NothingDnsTransport transport) {
        super(transport);
    }

    /**
     * List every zone served by this node (operator+).
     *
     * @return the zone list; when it reports truncation the server capped the
     *         response
     * @throws io.nothingdns.sdk.NothingDnsException 401 or 403 when the caller
     *                                                is below operator
     */
    public ZoneList list() {
        return model(transport.get("/api/v1/zones"), ZoneList.class);
    }

    /**
     * Create a zone (operator+).
     *
     * @param name        the zone name, e.g. {@code example.com}
     * @param nameservers the zone's nameserver hostnames; must have at least
     *                    one entry
     * @param adminEmail  the responsible email, optional
     * @param ttl         the default record TTL, optional
     * @return the server's confirmation message
     * @throws io.nothingdns.sdk.NothingDnsException 400 for a bad name, 409
     *                                                when the zone already
     *                                                exists, 421 when the name
     *                                                is out of range
     */
    public String create(String name, List<String> nameservers, String adminEmail, Integer ttl) {
        Map<String, Object> payload = body();
        payload.put("name", name);
        payload.put("nameservers", nameservers);
        put(payload, "admin_email", adminEmail);
        put(payload, "ttl", ttl);
        return message(transport.post("/api/v1/zones", payload));
    }

    /**
     * Create a zone with no admin email or default TTL (operator+).
     *
     * @param name        the zone name
     * @param nameservers the zone's nameserver hostnames
     * @return the server's confirmation message
     */
    public String create(String name, List<String> nameservers) {
        return create(name, nameservers, null, null);
    }

    /**
     * Get a zone's details, including its SOA record (operator+).
     *
     * @param zone the zone name
     * @return the zone details
     * @throws io.nothingdns.sdk.NothingDnsException 404 when the zone is unknown
     */
    public ZoneDetail get(String zone) {
        return model(transport.get("/api/v1/zones/" + escape(zone)), ZoneDetail.class);
    }

    /**
     * Delete a zone (operator+).
     *
     * @param zone the zone name
     * @return the server's confirmation message
     * @throws io.nothingdns.sdk.NothingDnsException 404 when the zone is unknown
     */
    public String delete(String zone) {
        return message(transport.delete("/api/v1/zones/" + escape(zone)));
    }

    /**
     * Reload one zone from its file on disk (admin).
     *
     * @param zone the zone name
     * @return the server's confirmation message
     * @throws io.nothingdns.sdk.NothingDnsException 500 when the zone file
     *                                                cannot be reloaded
     */
    public String reload(String zone) {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("zone", zone);
        return message(transport.post("/api/v1/zones/reload", params, null));
    }

    /**
     * List the secondary (slave) zones and their transfer state (operator+).
     *
     * @return the slave zones
     */
    public List<SlaveZone> transfers() {
        return list(transport.get("/api/v1/zones/transfers"), "slave_zones", SlaveZone.class);
    }

    /**
     * List a zone's records (operator+).
     *
     * @param zone the zone name
     * @param name an optional owner name to filter by; {@code null} lists all
     * @return the record list
     * @throws io.nothingdns.sdk.NothingDnsException 404 when the zone is unknown
     */
    public RecordList listRecords(String zone, String name) {
        Map<String, Object> params = new LinkedHashMap<>();
        put(params, "name", name);
        return model(transport.get("/api/v1/zones/" + escape(zone) + "/records", params),
                RecordList.class);
    }

    /**
     * List every record in a zone (operator+).
     *
     * @param zone the zone name
     * @return the record list
     */
    public RecordList listRecords(String zone) {
        return listRecords(zone, null);
    }

    /**
     * Add a record to a zone (operator+).
     *
     * @param zone the zone name
     * @param name the owner name
     * @param type the record type, e.g. {@code A}
     * @param data the record data
     * @param ttl  the record TTL, optional
     * @return the server's confirmation message
     * @throws io.nothingdns.sdk.NothingDnsException 400 for an invalid record,
     *                                                404 for an unknown zone
     */
    public String addRecord(String zone, String name, String type, String data, Integer ttl) {
        Map<String, Object> payload = body();
        payload.put("name", name);
        payload.put("type", type);
        payload.put("data", data);
        put(payload, "ttl", ttl);
        return message(transport.post("/api/v1/zones/" + escape(zone) + "/records", payload));
    }

    /**
     * Add a record with the zone's default TTL (operator+).
     *
     * @param zone the zone name
     * @param name the owner name
     * @param type the record type
     * @param data the record data
     * @return the server's confirmation message
     */
    public String addRecord(String zone, String name, String type, String data) {
        return addRecord(zone, name, type, data, null);
    }

    /**
     * Replace an existing record (operator+).
     *
     * @param zone    the zone name
     * @param name    the owner name
     * @param type    the record type
     * @param oldData the current record data, used to identify the record
     * @param data    the new record data
     * @param ttl     the new TTL, optional
     * @return the server's confirmation message
     * @throws io.nothingdns.sdk.NothingDnsException 400 when no record matches
     *                                                {@code oldData}
     */
    public String replaceRecord(String zone,
                                String name,
                                String type,
                                String oldData,
                                String data,
                                Integer ttl) {
        Map<String, Object> payload = body();
        payload.put("name", name);
        payload.put("type", type);
        payload.put("old_data", oldData);
        payload.put("data", data);
        put(payload, "ttl", ttl);
        return message(transport.put("/api/v1/zones/" + escape(zone) + "/records", payload));
    }

    /**
     * Delete the records matching an owner name and type (operator+).
     *
     * @param zone the zone name
     * @param name the owner name
     * @param type the record type
     * @return the server's confirmation message
     * @throws io.nothingdns.sdk.NothingDnsException 404 when nothing matched
     */
    public String deleteRecords(String zone, String name, String type) {
        Map<String, Object> payload = body();
        payload.put("name", name);
        payload.put("type", type);
        return message(transport.delete("/api/v1/zones/" + escape(zone) + "/records", payload));
    }

    /**
     * Export a zone as a BIND zone file (operator+).
     *
     * @param zone the zone name
     * @return the zone file, as text
     * @throws io.nothingdns.sdk.NothingDnsException 404 when the zone is unknown
     */
    public String export(String zone) {
        return transport.getRaw("/api/v1/zones/" + escape(zone) + "/export", null);
    }

    /**
     * Preview a bulk PTR generation without writing anything (operator+).
     *
     * @param zone     the reverse zone, e.g. {@code 2.0.192.in-addr.arpa}
     * @param cidr     the IPv4 CIDR to cover; ranges larger than a /16 are rejected
     * @param pattern  the target hostname template; {@code {ip}} is replaced with
     *                 the address, e.g. {@code host-{ip}.example.com}
     * @param override replace records that already exist instead of skipping
     * @param addA     also create the matching A records (forward-confirmed PTR)
     * @return the planned changes
     * @throws io.nothingdns.sdk.NothingDnsException 400 for an invalid CIDR or
     *                                                an oversized range
     */
    public PtrModels.PtrBulkPreview ptrBulkPreview(String zone,
                                                   String cidr,
                                                   String pattern,
                                                   boolean override,
                                                   boolean addA) {
        return model(ptrBulk(zone, cidr, pattern, override, addA, true),
                PtrModels.PtrBulkPreview.class);
    }

    /**
     * Generate PTR (and optionally forward-confirmed A) records for an IPv4
     * range (operator+).
     *
     * @param zone     the reverse zone
     * @param cidr     the IPv4 CIDR to cover
     * @param pattern  the target hostname template
     * @param override replace records that already exist instead of skipping
     * @param addA     also create the matching A records
     * @return the applied counts
     * @throws io.nothingdns.sdk.NothingDnsException 400 for an invalid CIDR or
     *                                                an oversized range
     */
    public PtrModels.PtrBulkResult ptrBulk(String zone,
                                           String cidr,
                                           String pattern,
                                           boolean override,
                                           boolean addA) {
        return model(ptrBulk(zone, cidr, pattern, override, addA, false),
                PtrModels.PtrBulkResult.class);
    }

    private JsonElement ptrBulk(String zone,
                                String cidr,
                                String pattern,
                                boolean override,
                                boolean addA,
                                boolean preview) {
        Map<String, Object> payload = body();
        payload.put("cidr", cidr);
        payload.put("pattern", pattern);
        payload.put("override", override);
        payload.put("addA", addA);
        payload.put("preview", preview);
        return transport.post("/api/v1/zones/" + escape(zone) + "/ptr-bulk", payload);
    }

    /**
     * Look up the PTR record for an IPv6 address in a zone (operator+).
     *
     * @param zone the IPv6 reverse zone, e.g. {@code 8.b.d.0.1.0.0.2.ip6.arpa}
     * @param ip   the IPv6 address to resolve
     * @return the lookup; check {@link PtrModels.PtrLookup#isFound()} before
     *         reading the record
     * @throws io.nothingdns.sdk.NothingDnsException 400 for a malformed address
     */
    public PtrModels.PtrLookup ptr6Lookup(String zone, String ip) {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("ip", ip);
        return model(transport.get("/api/v1/zones/" + escape(zone) + "/ptr6-lookup", params),
                PtrModels.PtrLookup.class);
    }
}
