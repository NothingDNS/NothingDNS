package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.annotations.SerializedName;

/**
 * One resource record.
 *
 * <p>Returned inside the {@code records} array of
 * {@code GET /api/v1/zones/{zone}/records}.</p>
 */
public final class Record {

    private String name;
    private String type;
    private int ttl;
    @SerializedName("class")
    private String recordClass;
    private String data;

    private Record() {
    }

    /**
     * Decode a record.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the record, never {@code null}
     */
    public static Record from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        Record r = new Record();
        r.name = Json.str(o, "name");
        r.type = Json.str(o, "type");
        r.ttl = Json.integer(o, "ttl");
        r.recordClass = Json.str(o, "class");
        r.data = Json.str(o, "data");
        return r;
    }

    /**
     * @return the owner name
     */
    public String getName() {
        return name;
    }

    /**
     * @return the record type, e.g. {@code A}, {@code MX}, {@code TXT}
     */
    public String getType() {
        return type;
    }

    /**
     * @return the record TTL, in seconds
     */
    public int getTtl() {
        return ttl;
    }

    /**
     * @return the record class, usually {@code IN}
     */
    public String getRecordClass() {
        return recordClass;
    }

    /**
     * @return the record data (rdata), e.g. {@code 192.0.2.1}
     */
    public String getData() {
        return data;
    }

    @Override
    public String toString() {
        return "Record{name='" + name + "', type='" + type + "', ttl=" + ttl
                + ", data='" + data + "'}";
    }
}
