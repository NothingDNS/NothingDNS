package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.annotations.SerializedName;

import java.util.ArrayList;
import java.util.List;

/**
 * The full ACL configuration: rules, recursion allow list and where it lives.
 *
 * <p>Returned by {@code GET /api/v1/acl} (operator+).</p>
 */
public final class AclConfig {

    private List<AclRule> rules;
    @SerializedName("allow_recursion")
    private RecursionAllowList allowRecursion;
    private boolean persistent;
    @SerializedName("policy_file")
    private String policyFile;

    private AclConfig() {
        this.rules = new ArrayList<>();
    }

    /**
     * Decode an ACL configuration.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the configuration, never {@code null}
     */
    public static AclConfig from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        AclConfig c = new AclConfig();
        c.rules = Json.list(o.get("rules"), null, AclRule.class, gson);
        c.allowRecursion = RecursionAllowList.from(o.get("allow_recursion"), gson);
        c.persistent = Json.bool(o, "persistent");
        c.policyFile = Json.str(o, "policy_file");
        return c;
    }

    /**
     * @return the rules, in evaluation order, never {@code null}
     */
    public List<AclRule> getRules() {
        return rules;
    }

    /**
     * @return the recursion allow list, never {@code null}
     */
    public RecursionAllowList getAllowRecursion() {
        return allowRecursion;
    }

    /**
     * @return whether the policy is persisted to disk
     */
    public boolean isPersistent() {
        return persistent;
    }

    /**
     * @return the file the policy is persisted to
     */
    public String getPolicyFile() {
        return policyFile;
    }

    @Override
    public String toString() {
        return "AclConfig{rules=" + rules.size() + ", persistent=" + persistent
                + ", policyFile='" + policyFile + "'}";
    }
}
