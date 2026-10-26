package io.nothingdns.sdk.model;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The SOA fields to change with {@code client.zones().updateSoa(...)}.
 *
 * <p>Fields left unset keep their value. The serial is not settable: the
 * server bumps it, so secondaries are notified and transfer the change.</p>
 *
 * <pre>{@code
 * client.zones().updateSoa("example.com", new SoaUpdate().rname("dns@example.com").minimum(300));
 * }</pre>
 */
public final class SoaUpdate {

    private final Map<String, Object> fields = new LinkedHashMap<>();

    /**
     * @param mname the primary nameserver
     * @return this update
     */
    public SoaUpdate mname(String mname) {
        fields.put("mname", mname);
        return this;
    }

    /**
     * @param rname the admin address, as {@code user@domain} or in DNS form
     * @return this update
     */
    public SoaUpdate rname(String rname) {
        fields.put("rname", rname);
        return this;
    }

    /**
     * @param ttl the TTL of the SOA record, in seconds
     * @return this update
     */
    public SoaUpdate ttl(int ttl) {
        fields.put("ttl", ttl);
        return this;
    }

    /**
     * @param refresh the secondary refresh interval, in seconds
     * @return this update
     */
    public SoaUpdate refresh(int refresh) {
        fields.put("refresh", refresh);
        return this;
    }

    /**
     * @param retry the secondary retry interval, in seconds; shorter than refresh
     * @return this update
     */
    public SoaUpdate retry(int retry) {
        fields.put("retry", retry);
        return this;
    }

    /**
     * @param expire when a secondary stops serving the zone, in seconds;
     *               longer than refresh
     * @return this update
     */
    public SoaUpdate expire(int expire) {
        fields.put("expire", expire);
        return this;
    }

    /**
     * @param minimum the negative-caching TTL, in seconds
     * @return this update
     */
    public SoaUpdate minimum(int minimum) {
        fields.put("minimum", minimum);
        return this;
    }

    /**
     * @return {@code true} when no field is set
     */
    public boolean isEmpty() {
        return fields.isEmpty();
    }

    /**
     * @return the request body: the set fields, in the order they were set
     */
    public Map<String, Object> toBody() {
        return new LinkedHashMap<>(fields);
    }
}
