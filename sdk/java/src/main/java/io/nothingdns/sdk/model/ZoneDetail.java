package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.List;

/**
 * Full details of one zone.
 *
 * <p>Returned by {@code GET /api/v1/zones/{zone}} (operator+).</p>
 */
public final class ZoneDetail {

    private String name;
    private int serial;
    private int records;
    private Soa soa;
    private List<String> nameservers;

    private ZoneDetail() {
        this.nameservers = new java.util.ArrayList<>();
    }

    /**
     * Decode zone details.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the details, never {@code null}
     */
    public static ZoneDetail from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        ZoneDetail z = new ZoneDetail();
        z.name = Json.str(o, "name");
        z.serial = Json.integer(o, "serial");
        z.records = Json.integer(o, "records");
        z.soa = Soa.from(o.get("soa"), gson);
        z.nameservers = Json.stringList(o, "nameservers");
        return z;
    }

    /**
     * @return the zone name
     */
    public String getName() {
        return name;
    }

    /**
     * @return the zone's SOA serial
     */
    public int getSerial() {
        return serial;
    }

    /**
     * @return the number of records in the zone
     */
    public int getRecords() {
        return records;
    }

    /**
     * @return the zone's SOA record, never {@code null}
     */
    public Soa getSoa() {
        return soa;
    }

    /**
     * @return the zone's nameservers, never {@code null}
     */
    public List<String> getNameservers() {
        return nameservers;
    }

    @Override
    public String toString() {
        return "ZoneDetail{name='" + name + "', serial=" + serial
                + ", records=" + records + "}";
    }
}
