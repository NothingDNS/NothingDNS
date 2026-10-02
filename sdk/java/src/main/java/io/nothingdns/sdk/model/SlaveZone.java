package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.annotations.SerializedName;

import java.util.List;

/**
 * A secondary (slave) zone and its transfer state.
 *
 * <p>Returned inside the {@code slave_zones} array of
 * {@code GET /api/v1/zones/transfers} (operator+).</p>
 */
public final class SlaveZone {

    private String zone;
    private String masters;
    private int serial;
    @SerializedName("last_transfer")
    private String lastTransfer;
    private String status;
    private int records;

    private SlaveZone() {
    }

    /**
     * Decode a secondary zone.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the zone, never {@code null}
     */
    public static SlaveZone from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        SlaveZone s = new SlaveZone();
        s.zone = Json.str(o, "zone");
        s.masters = Json.str(o, "masters");
        s.serial = Json.integer(o, "serial");
        s.lastTransfer = Json.str(o, "last_transfer");
        s.status = Json.str(o, "status");
        s.records = Json.integer(o, "records");
        return s;
    }

    /**
     * Decode the list of secondary zones nested under {@code key}.
     *
     * @param element the decoded body, may be {@code null}
     * @param key     the wrapper field
     * @param gson    the codec
     * @return the zones, never {@code null}
     */
    public static List<SlaveZone> listFrom(JsonElement element, String key, Gson gson) {
        return Json.list(element, key, SlaveZone.class, gson);
    }

    /**
     * @return the zone name
     */
    public String getZone() {
        return zone;
    }

    /**
     * @return the configured master server(s)
     */
    public String getMasters() {
        return masters;
    }

    /**
     * @return the last transferred serial
     */
    public int getSerial() {
        return serial;
    }

    /**
     * @return when the last transfer completed, as an ISO-8601 timestamp
     */
    public String getLastTransfer() {
        return lastTransfer;
    }

    /**
     * @return the transfer state: {@code pending} or {@code synced}
     */
    public String getStatus() {
        return status;
    }

    /**
     * @return the number of records in the zone
     */
    public int getRecords() {
        return records;
    }

    @Override
    public String toString() {
        return "SlaveZone{zone='" + zone + "', serial=" + serial
                + ", status='" + status + "', records=" + records + "}";
    }
}
