package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.List;

/**
 * One access-control rule.
 *
 * <p>Rules are evaluated in order, first match wins, against every query. A
 * client matched by no rule is refused once any rule exists. The wire fields
 * are all single words, so no name mapping is needed.</p>
 */
public final class AclRule {

    private String name;
    private List<String> networks;
    private String action;
    private List<String> types;
    private String redirect;

    private AclRule() {
        this.networks = new ArrayList<>();
        this.types = new ArrayList<>();
    }

    /**
     * Build a rule. The instance is sent as-is by
     * {@code client.acl().set(List)}.
     *
     * @param name     a human-readable label for the rule
     * @param networks the source networks the rule matches, e.g. {@code 10.0.0.0/8}
     * @param action   {@code allow}, {@code deny} or {@code redirect}
     * @return the rule
     */
    public static AclRule of(String name, List<String> networks, String action) {
        AclRule r = new AclRule();
        r.name = name;
        if (networks != null) {
            r.networks = new ArrayList<>(networks);
        }
        r.action = action;
        return r;
    }

    /**
     * Decode a rule.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the rule, never {@code null}
     */
    public static AclRule from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        AclRule r = new AclRule();
        r.name = Json.str(o, "name");
        r.networks = Json.stringList(o, "networks");
        r.action = Json.str(o, "action");
        r.types = Json.stringList(o, "types");
        r.redirect = Json.str(o, "redirect");
        return r;
    }

    /**
     * @return the rule's label
     */
    public String getName() {
        return name;
    }

    /**
     * Set the rule's label.
     *
     * @param name the label
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * @return the source networks the rule matches, never {@code null}
     */
    public List<String> getNetworks() {
        return networks;
    }

    /**
     * @return {@code allow}, {@code deny} or {@code redirect}
     */
    public String getAction() {
        return action;
    }

    /**
     * @return the DNS types the rule is limited to, or empty for all types
     */
    public List<String> getTypes() {
        return types;
    }

    /**
     * @return the redirect target when the action is {@code redirect}
     */
    public String getRedirect() {
        return redirect;
    }

    @Override
    public String toString() {
        return "AclRule{name='" + name + "', action='" + action
                + "', networks=" + networks + "}";
    }
}
