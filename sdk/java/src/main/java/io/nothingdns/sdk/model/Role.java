package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.List;

/**
 * One entry in the server's role table.
 *
 * <p>Returned inside {@code GET /api/v1/auth/roles} (operator+).</p>
 */
public final class Role {

    private String name;
    private String description;

    private Role() {
    }

    /**
     * Decode a role.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the role, never {@code null}
     */
    public static Role from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        Role r = new Role();
        r.name = Json.str(o, "name");
        r.description = Json.str(o, "description");
        return r;
    }

    /**
     * Decode a list of roles nested under {@code key}.
     *
     * @param element the decoded body, may be {@code null}
     * @param key     the wrapper field, or {@code null} for a bare array
     * @param gson    the codec
     * @return the roles, never {@code null}
     */
    public static List<Role> listFrom(JsonElement element, String key, Gson gson) {
        return Json.list(element, key, Role.class, gson);
    }

    /**
     * @return the role name: {@code viewer}, {@code operator} or {@code admin}
     */
    public String getName() {
        return name;
    }

    /**
     * @return a human-readable description of what the role may do
     */
    public String getDescription() {
        return description;
    }

    @Override
    public String toString() {
        return "Role{name='" + name + "', description='" + description + "'}";
    }
}
