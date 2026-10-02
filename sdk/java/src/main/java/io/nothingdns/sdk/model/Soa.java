package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * The start-of-authority record of a zone.
 *
 * <p>Embedded in the {@code soa} block of {@code GET /api/v1/zones/{zone}}.</p>
 */
public final class Soa {

    private String mname;
    private String rname;
    private int serial;
    private int refresh;
    private int retry;
    private int expire;
    private int minimum;

    private Soa() {
    }

    /**
     * Decode an SOA record.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the record, never {@code null}
     */
    public static Soa from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        Soa s = new Soa();
        s.mname = Json.str(o, "mname");
        s.rname = Json.str(o, "rname");
        s.serial = Json.integer(o, "serial");
        s.refresh = Json.integer(o, "refresh");
        s.retry = Json.integer(o, "retry");
        s.expire = Json.integer(o, "expire");
        s.minimum = Json.integer(o, "minimum");
        return s;
    }

    /**
     * @return the primary master server name
     */
    public String getMname() {
        return mname;
    }

    /**
     * @return the responsible email, in DNS form (the first label holds an {@code @})
     */
    public String getRname() {
        return rname;
    }

    /**
     * @return the zone serial
     */
    public int getSerial() {
        return serial;
    }

    /**
     * @return the refresh interval, in seconds
     */
    public int getRefresh() {
        return refresh;
    }

    /**
     * @return the retry interval, in seconds
     */
    public int getRetry() {
        return retry;
    }

    /**
     * @return the expire interval, in seconds
     */
    public int getExpire() {
        return expire;
    }

    /**
     * @return the minimum TTL / negative caching interval, in seconds
     */
    public int getMinimum() {
        return minimum;
    }

    @Override
    public String toString() {
        return "Soa{mname='" + mname + "', serial=" + serial + "}";
    }
}
