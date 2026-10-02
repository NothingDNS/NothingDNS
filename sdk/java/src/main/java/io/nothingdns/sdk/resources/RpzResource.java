package io.nothingdns.sdk.resources;

import io.nothingdns.sdk.NothingDnsTransport;
import io.nothingdns.sdk.model.RpzRule;
import io.nothingdns.sdk.model.RpzStats;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Response Policy Zones ({@code /api/v1/rpz}).
 *
 * <p>Obtained from {@code client.rpz()}. RPZ rewrites answers for policy
 * domains — typically advertising or malware block lists. Reads need operator;
 * rule changes and toggling need admin.</p>
 */
public final class RpzResource extends ApiResource {

    /**
     * Actions accepted by {@link #addRule(String, String, String)}.
     */
    public static final List<String> ACTIONS =
            java.util.Collections.unmodifiableList(java.util.Arrays.asList(
                    "NXDOMAIN", "NODATA", "CNAME", "OVERRIDE", "DROP", "PASSTHROUGH", "TCPONLY"));

    /**
     * Create the RPZ namespace.
     *
     * @param transport the shared transport
     */
    public RpzResource(NothingDnsTransport transport) {
        super(transport);
    }

    /**
     * Read RPZ engine statistics (operator+).
     *
     * @return the statistics
     */
    public RpzStats stats() {
        return model(transport.get("/api/v1/rpz"), RpzStats.class);
    }

    /**
     * List the QNAME rules (operator+).
     *
     * @return a page of rules
     */
    public RpzRule.RpzRuleList rules() {
        return model(transport.get("/api/v1/rpz/rules"), RpzRule.RpzRuleList.class);
    }

    /**
     * Add a QNAME rule (admin).
     *
     * @param pattern      the domain pattern the rule matches
     * @param action       one of {@link #ACTIONS}, or {@code null} for the
     *                     server default
     * @param overrideData the replacement data for {@code CNAME} and
     *                     {@code OVERRIDE}, or {@code null}
     * @return the server's confirmation message
     * @throws IllegalArgumentException when {@code action} is not a known action
     * @throws io.nothingdns.sdk.NothingDnsException 400 when the server rejects
     *                                                the rule
     */
    public String addRule(String pattern, String action, String overrideData) {
        if (action != null && !ACTIONS.contains(action)) {
            throw new IllegalArgumentException(
                    "action must be one of " + String.join(", ", ACTIONS));
        }
        Map<String, Object> payload = body();
        payload.put("pattern", pattern);
        put(payload, "action", action);
        put(payload, "override_data", overrideData);
        return message(transport.post("/api/v1/rpz/rules", payload));
    }

    /**
     * Add a QNAME rule with the default action (admin).
     *
     * @param pattern the domain pattern the rule matches
     * @return the server's confirmation message
     */
    public String addRule(String pattern) {
        return addRule(pattern, null, null);
    }

    /**
     * Delete a QNAME rule by pattern (admin).
     *
     * @param pattern the pattern of the rule to remove
     * @return the server's confirmation message
     */
    public String deleteRule(String pattern) {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("pattern", pattern);
        return message(transport.delete("/api/v1/rpz/rules", null, params));
    }

    /**
     * Toggle RPZ filtering on or off for the whole engine (admin).
     *
     * @return the server's confirmation message
     */
    public String toggle() {
        return message(transport.post("/api/v1/rpz/toggle", null));
    }
}
