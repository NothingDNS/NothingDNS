package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.annotations.SerializedName;

/**
 * DNSSEC validation status.
 *
 * <p>Returned by {@code GET /api/v1/dnssec/status} (operator+).</p>
 */
public final class DnssecStatus {

    private boolean enabled;
    @SerializedName("require_dnssec")
    private boolean requireDnssec;

    private DnssecStatus() {
    }

    /**
     * Decode a DNSSEC status.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the status, never {@code null}
     */
    public static DnssecStatus from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        DnssecStatus s = new DnssecStatus();
        s.enabled = Json.bool(o, "enabled");
        s.requireDnssec = Json.bool(o, "require_dnssec");
        return s;
    }

    /**
     * @return whether DNSSEC validation is on
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * @return whether validation failures are fatal (the server refuses
     *         answers it cannot validate)
     */
    public boolean isRequireDnssec() {
        return requireDnssec;
    }

    @Override
    public String toString() {
        return "DnssecStatus{enabled=" + enabled + ", requireDnssec=" + requireDnssec + "}";
    }
}
