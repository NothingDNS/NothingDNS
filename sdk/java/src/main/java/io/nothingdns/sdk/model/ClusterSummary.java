package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

/**
 * The cluster summary embedded in {@code GET /api/v1/status}.
 *
 * <p>A trimmed-down view of {@link ClusterStatus}: membership counts and
 * health, without the gossip, raft and metrics blocks.</p>
 */
public final class ClusterSummary {

    private boolean enabled;
    private String nodeId;
    private int nodeCount;
    private int aliveCount;
    private boolean healthy;

    private ClusterSummary() {
    }

    /**
     * Decode a cluster summary.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the summary, never {@code null}
     */
    public static ClusterSummary from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        ClusterSummary c = new ClusterSummary();
        c.enabled = Json.bool(o, "enabled");
        c.nodeId = Json.str(o, "node_id");
        c.nodeCount = Json.integer(o, "node_count");
        c.aliveCount = Json.integer(o, "alive_count");
        c.healthy = Json.bool(o, "healthy");
        return c;
    }

    /**
     * @return whether clustering is enabled on this node
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * @return this node's identifier
     */
    public String getNodeId() {
        return nodeId;
    }

    /**
     * @return the total number of known nodes
     */
    public int getNodeCount() {
        return nodeCount;
    }

    /**
     * @return the number of nodes currently considered alive
     */
    public int getAliveCount() {
        return aliveCount;
    }

    /**
     * @return whether the cluster reports itself healthy
     */
    public boolean isHealthy() {
        return healthy;
    }

    @Override
    public String toString() {
        return "ClusterSummary{enabled=" + enabled + ", nodeId='" + nodeId
                + "', nodeCount=" + nodeCount + ", aliveCount=" + aliveCount
                + ", healthy=" + healthy + "}";
    }
}
