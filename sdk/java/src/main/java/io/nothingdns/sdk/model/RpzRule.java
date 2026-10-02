package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.annotations.SerializedName;

import java.util.ArrayList;
import java.util.List;

/**
 * One QNAME response policy rule, and the page of rules that contains it.
 *
 * <p>The rule itself comes from {@code GET /api/v1/rpz/rules} (operator+); a
 * rule is added with {@code POST /api/v1/rpz/rules} (admin) and removed with
 * {@code DELETE /api/v1/rpz/rules} (admin).</p>
 */
public final class RpzRule {

    private String pattern;
    private String action;
    private String trigger;
    @SerializedName("override_data")
    private String overrideData;
    @SerializedName("policy_name")
    private String policyName;
    private int priority;

    private RpzRule() {
    }

    /**
     * Decode a rule.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the rule, never {@code null}
     */
    public static RpzRule from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        RpzRule r = new RpzRule();
        r.pattern = Json.str(o, "pattern");
        r.action = Json.str(o, "action");
        r.trigger = Json.str(o, "trigger");
        r.overrideData = Json.str(o, "override_data");
        r.policyName = Json.str(o, "policy_name");
        r.priority = Json.integer(o, "priority");
        return r;
    }

    /**
     * @return the domain pattern the rule matches
     */
    public String getPattern() {
        return pattern;
    }

    /**
     * @return the action taken on a match, e.g. {@code NXDOMAIN}
     */
    public String getAction() {
        return action;
    }

    /**
     * @return the RPZ trigger that activated this rule
     */
    public String getTrigger() {
        return trigger;
    }

    /**
     * @return the replacement data for {@code CNAME} / {@code OVERRIDE} actions
     */
    public String getOverrideData() {
        return overrideData;
    }

    /**
     * @return the name of the policy the rule came from
     */
    public String getPolicyName() {
        return policyName;
    }

    /**
     * @return the rule's evaluation priority
     */
    public int getPriority() {
        return priority;
    }

    @Override
    public String toString() {
        return "RpzRule{pattern='" + pattern + "', action='" + action + "'}";
    }

    /**
     * A page of QNAME rules.
     */
    public static final class RpzRuleList {
        private List<RpzRule> rules;
        private int total;
        private boolean truncated;

        private RpzRuleList() {
            this.rules = new ArrayList<>();
        }

        /**
         * Decode a rule list.
         *
         * @param element the decoded body, may be {@code null}
         * @param gson    the codec
         * @return the rule list, never {@code null}
         */
        public static RpzRuleList from(JsonElement element, Gson gson) {
            JsonObject o = Json.obj(element);
            RpzRuleList l = new RpzRuleList();
            l.rules = Json.list(o.get("rules"), null, RpzRule.class, gson);
            l.total = Json.integer(o, "total");
            l.truncated = Json.bool(o, "truncated");
            return l;
        }

        /**
         * @return the rules in this page, never {@code null}
         */
        public List<RpzRule> getRules() {
            return rules;
        }

        /**
         * @return the total number of rules the server holds
         */
        public int getTotal() {
            return total;
        }

        /**
         * @return whether the server capped the list
         */
        public boolean isTruncated() {
            return truncated;
        }

        @Override
        public String toString() {
            return "RpzRuleList{total=" + total + ", truncated=" + truncated
                    + ", rules=" + rules.size() + "}";
        }
    }
}
