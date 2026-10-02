package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.List;

/**
 * The paginated/truncated list of zones served by a node.
 *
 * <p>Returned by {@code GET /api/v1/zones} (operator+). When
 * {@link #isTruncated()} is true the server capped the response and
 * {@link #getTotal()} may be larger than {@link #getZones()}.size()}.</p>
 */
public final class ZoneList {

    private List<Zone> zones;
    private int total;
    private boolean truncated;

    private ZoneList() {
        this.zones = new java.util.ArrayList<>();
    }

    /**
     * Decode a zone list.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the zone list, never {@code null}
     */
    public static ZoneList from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        ZoneList z = new ZoneList();
        z.zones = Json.list(o.get("zones"), null, Zone.class, gson);
        z.total = Json.integer(o, "total");
        z.truncated = Json.bool(o, "truncated");
        return z;
    }

    /**
     * @return the zones in this page, never {@code null}
     */
    public List<Zone> getZones() {
        return zones;
    }

    /**
     * @return the total number of zones known to the server
     */
    public int getTotal() {
        return total;
    }

    /**
     * @return whether the server capped the list
     */
    public boolean isTruncated() {
        return truncated;
    }

    @Override
    public String toString() {
        return "ZoneList{total=" + total + ", truncated=" + truncated
                + ", zones=" + zones.size() + "}";
    }
}
