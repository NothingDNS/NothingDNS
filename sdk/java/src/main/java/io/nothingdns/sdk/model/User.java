package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.annotations.SerializedName;

import java.util.List;

/**
 * A user account.
 *
 * <p>Returned by {@code GET /api/v1/auth/users} and
 * {@code POST /api/v1/auth/users}. Passwords are never returned by the API.</p>
 */
public final class User {

    private String username;
    private String role;
    @SerializedName("created_at")
    private String createdAt;
    @SerializedName("updated_at")
    private String updatedAt;

    private User() {
    }

    /**
     * Decode a user account.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the account, never {@code null}
     */
    public static User from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        User u = new User();
        u.username = Json.str(o, "username");
        u.role = Json.str(o, "role");
        u.createdAt = Json.str(o, "created_at");
        u.updatedAt = Json.str(o, "updated_at");
        return u;
    }

    /**
     * Decode a list of user accounts, from either a bare array or one nested
     * under {@code key}.
     *
     * @param element the decoded body, may be {@code null}
     * @param key     the wrapper field, or {@code null} for a bare array
     * @param gson    the codec
     * @return the accounts, never {@code null}
     */
    public static List<User> listFrom(JsonElement element, String key, Gson gson) {
        return Json.list(element, key, User.class, gson);
    }

    /**
     * @return the account name
     */
    public String getUsername() {
        return username;
    }

    /**
     * @return the role: {@code viewer}, {@code operator} or {@code admin}
     */
    public String getRole() {
        return role;
    }

    /**
     * @return when the account was created, as an ISO-8601 timestamp
     */
    public String getCreatedAt() {
        return createdAt;
    }

    /**
     * @return when the account was last changed, as an ISO-8601 timestamp
     */
    public String getUpdatedAt() {
        return updatedAt;
    }

    @Override
    public String toString() {
        return "User{username='" + username + "', role='" + role + "'}";
    }
}
