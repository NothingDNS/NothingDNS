package io.nothingdns.sdk.resources;

import com.google.gson.JsonElement;
import io.nothingdns.sdk.NothingDnsTransport;
import io.nothingdns.sdk.model.ClusterNode;
import io.nothingdns.sdk.model.ClusterStatus;

import java.util.List;
import java.util.Map;

/**
 * Gossip membership and Raft consensus management ({@code /api/v1/cluster}).
 *
 * <p>Obtained from {@code client.cluster()}. Reading needs operator; joining
 * and leaving need admin.</p>
 */
public final class ClusterResource extends ApiResource {

    /**
     * Create the cluster namespace.
     *
     * @param transport the shared transport
     */
    public ClusterResource(NothingDnsTransport transport) {
        super(transport);
    }

    /**
     * Read cluster status: membership, consensus state and metrics (operator+).
     *
     * @return the status
     * @throws io.nothingdns.sdk.NothingDnsException 401 or 403 when the caller
     *                                                is below operator
     */
    public ClusterStatus status() {
        return model(transport.get("/api/v1/cluster/status"), ClusterStatus.class);
    }

    /**
     * List the cluster's nodes (operator+).
     *
     * @return the nodes
     */
    public List<ClusterNode> nodes() {
        return list(transport.get("/api/v1/cluster/nodes"), "nodes", ClusterNode.class);
    }

    /**
     * Join a cluster through a seed node (admin).
     *
     * @param seedAddress the address of an existing cluster member
     * @return the server's confirmation message
     * @throws io.nothingdns.sdk.NothingDnsException 400 when the seed is
     *                                                unreachable
     */
    public String join(String seedAddress) {
        Map<String, Object> payload = body();
        payload.put("seed_address", seedAddress);
        return message(transport.post("/api/v1/cluster/join", payload));
    }

    /**
     * Drain this node and leave the cluster (admin).
     *
     * @return the server's confirmation message
     * @throws io.nothingdns.sdk.NothingDnsException 500 when the node cannot be
     *                                                drained cleanly
     */
    public String leave() {
        JsonElement data = transport.delete("/api/v1/cluster/leave");
        return message(data);
    }
}
