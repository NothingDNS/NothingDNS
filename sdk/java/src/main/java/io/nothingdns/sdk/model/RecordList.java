package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.List;

/**
 * A page of resource records in a zone.
 *
 * <p>Returned by {@code GET /api/v1/zones/{zone}/records} (operator+).</p>
 */
public final class RecordList {

    private List<Record> records;
    private int total;
    private boolean truncated;

    private RecordList() {
        this.records = new ArrayList<>();
    }

    /**
     * Decode a record list.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the record list, never {@code null}
     */
    public static RecordList from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        RecordList r = new RecordList();
        r.records = Json.list(o.get("records"), null, Record.class, gson);
        r.total = Json.integer(o, "total");
        r.truncated = Json.bool(o, "truncated");
        return r;
    }

    /**
     * @return the records in this page, never {@code null}
     */
    public List<Record> getRecords() {
        return records;
    }

    /**
     * @return the total number of records in the zone
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
        return "RecordList{total=" + total + ", truncated=" + truncated
                + ", records=" + records.size() + "}";
    }
}
