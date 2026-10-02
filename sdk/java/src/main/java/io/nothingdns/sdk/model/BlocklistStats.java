package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.annotations.SerializedName;

/**
 * Blocklist engine statistics.
 *
 * <p>Returned by {@code GET /api/v1/blocklists} (operator+).</p>
 */
public final class BlocklistStats {

    private boolean enabled;
    @SerializedName("total_rules")
    private long totalRules;
    @SerializedName("files_count")
    private int filesCount;
    @SerializedName("urls_count")
    private int urlsCount;

    private BlocklistStats() {
    }

    /**
     * Decode blocklist statistics.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the statistics, never {@code null}
     */
    public static BlocklistStats from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        BlocklistStats b = new BlocklistStats();
        b.enabled = Json.bool(o, "enabled");
        b.totalRules = Json.integer(o, "total_rules");
        b.filesCount = Json.integer(o, "files_count");
        b.urlsCount = Json.integer(o, "urls_count");
        return b;
    }

    /**
     * @return whether blocklist filtering is on
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * @return the total number of blocked domains loaded
     */
    public long getTotalRules() {
        return totalRules;
    }

    /**
     * @return the number of file-based sources
     */
    public int getFilesCount() {
        return filesCount;
    }

    /**
     * @return the number of URL-based sources
     */
    public int getUrlsCount() {
        return urlsCount;
    }

    @Override
    public String toString() {
        return "BlocklistStats{enabled=" + enabled + ", totalRules=" + totalRules
                + ", filesCount=" + filesCount + ", urlsCount=" + urlsCount + "}";
    }
}
