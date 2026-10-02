package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.List;

/**
 * The recursion allow list: which clients may issue recursive queries.
 *
 * <p>Returned by {@code GET /api/v1/acl/recursion} and
 * {@code PUT /api/v1/acl/recursion}, and embedded in {@link AclConfig}.</p>
 */
public final class RecursionAllowList {

    @com.google.gson.annotations.SerializedName("allow_all")
    private boolean allowAll;
    private List<String> networks;

    private RecursionAllowList() {
        this.networks = new ArrayList<>();
    }

    /**
     * Decode a recursion allow list.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the list, never {@code null}
     */
    public static RecursionAllowList from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        RecursionAllowList r = new RecursionAllowList();
        r.allowAll = Json.bool(o, "allow_all");
        r.networks = Json.stringList(o, "networks");
        return r;
    }

    /**
     * @return whether every client may recurse
     */
    public boolean isAllowAll() {
        return allowAll;
    }

    /**
     * @return the networks allowed to recurse, never {@code null}
     */
    public List<String> getNetworks() {
        return networks;
    }

    @Override
    public String toString() {
        return "RecursionAllowList{allowAll=" + allowAll + ", networks=" + networks + "}";
    }
}
