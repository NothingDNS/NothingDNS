package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.List;

/**
 * Public metadata for one DNSSEC signing key, and the list that contains them.
 *
 * <p>Returned by {@code GET /api/v1/dnssec/keys} (admin). The wire format for
 * this group is camelCase ({@code keyTag}, {@code isKSK}, {@code isZSK}), so the
 * Java field names match the wire directly.</p>
 */
public final class DnssecKey {

    private int keyTag;
    private int algorithm;
    private int flags;
    private boolean isKSK;
    private boolean isZSK;
    private String zone;

    private DnssecKey() {
    }

    /**
     * Decode a key.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the key, never {@code null}
     */
    public static DnssecKey from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        DnssecKey k = new DnssecKey();
        k.keyTag = Json.integer(o, "keyTag");
        k.algorithm = Json.integer(o, "algorithm");
        k.flags = Json.integer(o, "flags");
        k.isKSK = Json.bool(o, "isKSK");
        k.isZSK = Json.bool(o, "isZSK");
        k.zone = Json.str(o, "zone");
        return k;
    }

    /**
     * @return the DNSKEY key tag
     */
    public int getKeyTag() {
        return keyTag;
    }

    /**
     * @return the DNSSEC algorithm number (e.g. 13 for Ed25519)
     */
    public int getAlgorithm() {
        return algorithm;
    }

    /**
     * @return the DNSKEY flags
     */
    public int getFlags() {
        return flags;
    }

    /**
     * @return whether this is a key-signing key
     */
    public boolean isKSK() {
        return isKSK;
    }

    /**
     * @return whether this is a zone-signing key
     */
    public boolean isZSK() {
        return isZSK;
    }

    /**
     * @return the zone the key signs
     */
    public String getZone() {
        return zone;
    }

    @Override
    public String toString() {
        return "DnssecKey{zone='" + zone + "', keyTag=" + keyTag
                + ", algorithm=" + algorithm + "}";
    }

    /**
     * The set of keys, grouped under the {@code zones} field of the response.
     */
    public static final class DnssecKeyList {
        private List<DnssecKey> zones;

        private DnssecKeyList() {
            this.zones = new ArrayList<>();
        }

        /**
         * Decode a key list.
         *
         * @param element the decoded body, may be {@code null}
         * @param gson    the codec
         * @return the key list, never {@code null}
         */
        public static DnssecKeyList from(JsonElement element, Gson gson) {
            JsonObject o = Json.obj(element);
            DnssecKeyList l = new DnssecKeyList();
            l.zones = Json.list(o.get("zones"), null, DnssecKey.class, gson);
            return l;
        }

        /**
         * @return the keys, never {@code null}
         */
        public List<DnssecKey> getZones() {
            return zones;
        }

        @Override
        public String toString() {
            return "DnssecKeyList{keys=" + zones.size() + "}";
        }
    }
}
