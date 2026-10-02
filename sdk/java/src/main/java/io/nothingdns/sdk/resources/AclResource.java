package io.nothingdns.sdk.resources;

import io.nothingdns.sdk.NothingDnsTransport;
import io.nothingdns.sdk.model.AclConfig;
import io.nothingdns.sdk.model.AclRule;
import io.nothingdns.sdk.model.RecursionAllowList;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Access-control rules and the recursion allow list ({@code /api/v1/acl}).
 *
 * <p>Obtained from {@code client.acl()}. Rules apply to every query, first
 * match wins; a client matched by no rule is refused once any rule exists.
 * Reads need operator, writes need admin.</p>
 */
public final class AclResource extends ApiResource {

    /**
     * Create the ACL namespace.
     *
     * @param transport the shared transport
     */
    public AclResource(NothingDnsTransport transport) {
        super(transport);
    }

    /**
     * Read the ACL rules and the recursion allow list (operator+).
     *
     * @return the configuration
     * @throws io.nothingdns.sdk.NothingDnsException 401 or 403 when the caller
     *                                                is below operator
     */
    public AclConfig get() {
        return model(transport.get("/api/v1/acl"), AclConfig.class);
    }

    /**
     * Replace the ACL rules (admin).
     *
     * <p>This is a full replacement, not a merge: the rules you send become
     * the complete rule set. Read with {@link #get()} first, edit the list,
     * and send it back.</p>
     *
     * @param rules the complete, ordered rule set
     * @return the server's confirmation message
     * @throws io.nothingdns.sdk.NothingDnsException 400 for an invalid rule
     */
    public String set(List<AclRule> rules) {
        Map<String, Object> payload = body();
        payload.put("rules", rules == null ? new ArrayList<>() : rules);
        return message(transport.put("/api/v1/acl", payload));
    }

    /**
     * Read the recursion allow list (operator+).
     *
     * @return the allow list
     */
    public RecursionAllowList recursion() {
        return model(transport.get("/api/v1/acl/recursion"), RecursionAllowList.class);
    }

    /**
     * Replace the recursion allow list (admin).
     *
     * <p>Also a full replacement. The server returns the resulting policy,
     * which reflects the effective {@code allow_all} setting.</p>
     *
     * @param networks the networks allowed to recurse
     * @return the resulting allow list
     * @throws io.nothingdns.sdk.NothingDnsException 400 for an invalid network
     */
    public RecursionAllowList setRecursion(List<String> networks) {
        Map<String, Object> payload = body();
        payload.put("networks", networks == null ? new ArrayList<>() : networks);
        return model(transport.put("/api/v1/acl/recursion", payload),
                RecursionAllowList.class);
    }
}
