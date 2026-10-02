package io.nothingdns.sdk;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import io.nothingdns.sdk.model.Role;
import io.nothingdns.sdk.model.Session;
import io.nothingdns.sdk.model.User;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Authentication, users and roles ({@code /api/v1/auth}).
 *
 * <p>This class owns credential <em>acquisition</em>: it builds the login and
 * bootstrap <em>password</em> payloads. Credential <em>transmission</em> — the
 * {@code Authorization: Bearer …} header — is handled by
 * {@link NothingDnsTransport}, which every namespace shares. Keeping the two
 * concerns in separate files means this one never assembles the bearer header
 * and the transport never sees a password.</p>
 *
 * <p>The server's role hierarchy is {@code viewer < operator < admin}.</p>
 */
public final class NothingDnsAuth {

    /** Roles a user account can hold, ordered viewer &lt; operator &lt; admin. */
    public static final List<String> ROLES =
            java.util.Collections.unmodifiableList(Arrays.asList("viewer", "operator", "admin"));

    private final NothingDnsTransport transport;

    /**
     * Create the auth namespace.
     *
     * @param transport the shared transport
     */
    public NothingDnsAuth(NothingDnsTransport transport) {
        this.transport = transport;
    }

    /**
     * Log in and receive a bearer token.
     *
     * @param username   the account name
     * @param password   the account password
     * @param storeToken keep the returned token on the transport so later calls
     *                   are authenticated automatically
     * @return the session (token, username, role, expiry)
     * @throws NothingDnsException 400 for a malformed request, 401 for bad
     *                             credentials, 429 when the login rate limit
     *                             is hit
     */
    public Session login(String username, String password, boolean storeToken) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("username", username);
        payload.put("password", password);
        return storeSession(
                transport.post("/api/v1/auth/login", payload), storeToken);
    }

    /**
     * Log in and keep the token on the transport.
     *
     * @param username the account name
     * @param password the account password
     * @return the session
     * @throws NothingDnsException 400, 401 or 429 as for
     *                              {@link #login(String, String, boolean)}
     */
    public Session login(String username, String password) {
        return login(username, password, true);
    }

    /**
     * Create the first admin account, or reset an existing account's password.
     *
     * <p>Use this to provision the very first admin on a fresh server, or to
     * recover access when the current password is known.</p>
     *
     * @param username    the new (or first) admin account name
     * @param password    the new password for the account
     * @param oldPassword the current password of the account being reset; required
     *                    when resetting an account that is not the initial
     *                    bootstrap. May be {@code null}.
     * @param storeToken  keep the returned token on the transport
     * @return the session for the new password
     * @throws NothingDnsException 401 when {@code oldPassword} is wrong, 403
     *                             when the change is not permitted for this
     *                             caller, 409 when the server already has an
     *                             admin and no {@code oldPassword} was given
     */
    public Session bootstrap(String username,
                             String password,
                             String oldPassword,
                             boolean storeToken) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("username", username);
        payload.put("password", password);
        if (oldPassword != null) {
            payload.put("old_password", oldPassword);
        }
        return storeSession(
                transport.post("/api/v1/auth/bootstrap", payload), storeToken);
    }

    /**
     * Create the first admin account and keep the returned token.
     *
     * @param username the new (or first) admin account name
     * @param password the new password for the account
     * @return the session
     * @throws NothingDnsException as for
     *                              {@link #bootstrap(String, String, String, boolean)}
     */
    public Session bootstrap(String username, String password) {
        return bootstrap(username, password, null, true);
    }

    /**
     * Return the current session: token, username and role.
     *
     * <p>The dashboard calls this to rebuild its in-memory bearer after a page
     * reload without persisting the token in the browser. The server rejects
     * the legacy shared {@code auth_token} for this call — a real login session
     * is required.</p>
     *
     * @return the current session
     * @throws NothingDnsException 401 when no valid session token is presented
     */
    public Session session() {
        JsonElement data = transport.get("/api/v1/auth/session");
        return Session.from(data, transport.gson());
    }

    /**
     * Invalidate the current session.
     *
     * @return the server's confirmation message
     * @throws NothingDnsException 401 when no valid session token is presented
     */
    public String logout() {
        JsonElement data = transport.post("/api/v1/auth/logout", null);
        return messageOf(data);
    }

    /**
     * List the roles the server knows about (operator+).
     *
     * @return the role table, in the server's own order
     * @throws NothingDnsException 401 or 403 when the caller is not an operator
     */
    public List<Role> roles() {
        JsonElement data = transport.get("/api/v1/auth/roles");
        return Role.listFrom(data, "roles", transport.gson());
    }

    /**
     * List every user account (operator+).
     *
     * <p>Passwords are never returned by the API.</p>
     *
     * @return the accounts, in the server's own order
     * @throws NothingDnsException 401 or 403 when the caller is not an operator
     */
    public List<User> listUsers() {
        JsonElement data = transport.get("/api/v1/auth/users");
        return User.listFrom(data, null, transport.gson());
    }

    /**
     * Create a user account (admin only).
     *
     * @param username the new account name; must be unique on this server
     * @param password the password for the new account
     * @param role     {@code viewer} (read-only), {@code operator} (zones,
     *                 cache, config reads) or {@code admin} (everything,
     *                 including users and runtime config changes)
     * @return the created account
     * @throws NothingDnsException 409 when the username already exists, or
     *                              {@link IllegalArgumentException} when
     *                              {@code role} is not a known role
     */
    public User createUser(String username, String password, String role) {
        if (role == null || !ROLES.contains(role)) {
            throw new IllegalArgumentException(
                    "role must be one of " + String.join(", ", ROLES));
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("username", username);
        payload.put("password", password);
        payload.put("role", role);
        JsonElement data = transport.post("/api/v1/auth/users", payload);
        return User.from(data, transport.gson());
    }

    /**
     * Create a viewer account (admin only).
     *
     * @param username the new account name
     * @param password the password for the new account
     * @return the created account
     * @throws NothingDnsException 409 when the username already exists
     */
    public User createUser(String username, String password) {
        return createUser(username, password, "viewer");
    }

    /**
     * Delete a user account by name (admin only).
     *
     * <p>Uses the path form of the endpoint,
     * {@code DELETE /api/v1/auth/users/{username}}.</p>
     *
     * @param username the account to remove
     * @return the server's confirmation message
     * @throws NothingDnsException 404 when the account does not exist
     */
    public String deleteUser(String username) {
        JsonElement data = transport.delete(
                "/api/v1/auth/users/" + NothingDnsTransport.escape(username));
        return messageOf(data);
    }

    /**
     * Delete a user account by name using the query-parameter form of the
     * endpoint (admin only).
     *
     * <p>Prefer {@link #deleteUser(String)}, which uses the path form. Both
     * forms are documented by the server and behave identically; this one is
     * here for parity with the contract and for gateways that only route the
     * query form.</p>
     *
     * @param username the account to remove
     * @return the server's confirmation message
     * @throws NothingDnsException 400 when no username was given, 404 when the
     *                             account does not exist
     */
    public String deleteUserByQuery(String username) {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("username", username);
        JsonElement data = transport.delete("/api/v1/auth/users", params, null);
        return messageOf(data);
    }

    // -- helpers -----------------------------------------------------------

    private Session storeSession(JsonElement data, boolean storeToken) {
        Session session = Session.from(data, transport.gson());
        if (storeToken && session.getToken() != null && !session.getToken().isEmpty()) {
            transport.setToken(session.getToken());
        }
        return session;
    }

    private static String messageOf(JsonElement data) {
        if (data == null || !data.isJsonObject()) {
            return "";
        }
        JsonObject object = data.getAsJsonObject();
        if (object.has("message") && object.get("message").isJsonPrimitive()) {
            return object.get("message").getAsString();
        }
        return "";
    }

    /**
     * A defensive copy helper kept package-private for the resource classes.
     *
     * @param <T> the element type
     * @param in  the source list, may be {@code null}
     * @return a mutable copy, never {@code null}
     */
    static <T> List<T> copyOf(List<T> in) {
        return in == null ? new ArrayList<>() : new ArrayList<>(in);
    }
}
