package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * A zone summary: name, serial and record count.
 *
 * <p>Appears in the {@code zones} array of {@code GET /api/v1/zones}, in the
 * dashboard zone summary, and is the per-zone item of the dashboard listing.</p>
 */
public final class Zone {

    private String name;
    private int serial;
    private int records;

    private Zone() {
    }

    /**
     * Decode a zone summary.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the zone, never {@code null}
     */
    public static Zone from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        Zone z = new Zone();
        z.name = Json.str(o, "name");
        z.serial = Json.integer(o, "serial");
        z.records = Json.integer(o, "records");
        return z;
    }

    /**
     * @return the zone name, e.g. {@code example.com}
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

    @Override
    public String toString() {
        return "Zone{name='" + name + "', serial=" + serial + ", records=" + records + "}";
    }
}
