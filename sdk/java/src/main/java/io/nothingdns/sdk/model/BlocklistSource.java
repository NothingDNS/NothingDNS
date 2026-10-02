package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * One configured blocklist source.
 *
 * <p>Returned in the array of {@code GET /api/v1/blocklists/sources}
 * (operator+).</p>
 */
public final class BlocklistSource {

    private String id;
    private String type;
    private boolean enabled;
    private long domains;

    private BlocklistSource() {
    }

    /**
     * Decode a blocklist source.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the source, never {@code null}
     */
    public static BlocklistSource from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        BlocklistSource s = new BlocklistSource();
        s.id = Json.str(o, "id");
        s.type = Json.str(o, "type");
        s.enabled = Json.bool(o, "enabled");
        s.domains = Json.integer(o, "domains");
        return s;
    }

    /**
     * @return the source's identifier, used to remove or toggle it
     */
    public String getId() {
        return id;
    }

    /**
     * @return {@code file} or {@code url}
     */
    public String getType() {
        return type;
    }

    /**
     * @return whether this source is currently active
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * @return the number of domains this source contributed
     */
    public long getDomains() {
        return domains;
    }

    @Override
    public String toString() {
        return "BlocklistSource{id='" + id + "', type='" + type
                + "', enabled=" + enabled + ", domains=" + domains + "}";
    }
}
