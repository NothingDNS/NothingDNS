package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.annotations.SerializedName;

/**
 * One node in the cluster.
 *
 * <p>Returned in the {@code nodes} array of {@code GET /api/v1/cluster/nodes}
 * (operator+).</p>
 */
public final class ClusterNode {

    private String id;
    private String addr;
    private int port;
    private String state;
    private String role;
    private String region;
    private String zone;
    private int weight;
    @SerializedName("http_addr")
    private String httpAddr;
    private long version;
    @SerializedName("health_score")
    private int healthScore;
    @SerializedName("queries_per_second")
    private double queriesPerSecond;
    @SerializedName("latency_ms")
    private double latencyMs;
    @SerializedName("cpu_percent")
    private double cpuPercent;
    @SerializedName("memory_percent")
    private double memoryPercent;
    @SerializedName("active_connections")
    private long activeConnections;

    private ClusterNode() {
    }

    /**
     * Decode a cluster node.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the node, never {@code null}
     */
    public static ClusterNode from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        ClusterNode n = new ClusterNode();
        n.id = Json.str(o, "id");
        n.addr = Json.str(o, "addr");
        n.port = Json.integer(o, "port");
        n.state = Json.str(o, "state");
        n.role = Json.str(o, "role");
        n.region = Json.str(o, "region");
        n.zone = Json.str(o, "zone");
        n.weight = Json.integer(o, "weight");
        n.httpAddr = Json.str(o, "http_addr");
        n.version = Json.integer(o, "version");
        n.healthScore = Json.integer(o, "health_score");
        n.queriesPerSecond = Json.dbl(o, "queries_per_second");
        n.latencyMs = Json.dbl(o, "latency_ms");
        n.cpuPercent = Json.dbl(o, "cpu_percent");
        n.memoryPercent = Json.dbl(o, "memory_percent");
        n.activeConnections = Json.integer(o, "active_connections");
        return n;
    }

    /**
     * @return the node's identifier
     */
    public String getId() {
        return id;
    }

    /**
     * @return the node's gossip address
     */
    public String getAddr() {
        return addr;
    }

    /**
     * @return the gossip port
     */
    public int getPort() {
        return port;
    }

    /**
     * @return the node's state, e.g. {@code alive}
     */
    public String getState() {
        return state;
    }

    /**
     * @return the node's raft role, e.g. {@code leader}
     */
    public String getRole() {
        return role;
    }

    /**
     * @return the node's region label
     */
    public String getRegion() {
        return region;
    }

    /**
     * @return the node's zone label
     */
    public String getZone() {
        return zone;
    }

    /**
     * @return the load-balancing weight
     */
    public int getWeight() {
        return weight;
    }

    /**
     * @return the node's HTTP management address
     */
    public String getHttpAddr() {
        return httpAddr;
    }

    /**
     * @return the node's software version
     */
    public long getVersion() {
        return version;
    }

    /**
     * @return the node's health score
     */
    public int getHealthScore() {
        return healthScore;
    }

    /**
     * @return the node's current query rate, per second
     */
    public double getQueriesPerSecond() {
        return queriesPerSecond;
    }

    /**
     * @return the node's query latency, in milliseconds
     */
    public double getLatencyMs() {
        return latencyMs;
    }

    /**
     * @return the node's CPU usage, as a percentage
     */
    public double getCpuPercent() {
        return cpuPercent;
    }

    /**
     * @return the node's memory usage, as a percentage
     */
    public double getMemoryPercent() {
        return memoryPercent;
    }

    /**
     * @return the number of active connections
     */
    public long getActiveConnections() {
        return activeConnections;
    }

    @Override
    public String toString() {
        return "ClusterNode{id='" + id + "', addr='" + addr + "', state='" + state
                + "', role='" + role + "'}";
    }
}
