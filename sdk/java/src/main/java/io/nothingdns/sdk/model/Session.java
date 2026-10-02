package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.List;

/**
 * An authenticated session: the bearer token plus who it belongs to.
 *
 * <p>Returned by {@code POST /api/v1/auth/login},
 * {@code POST /api/v1/auth/bootstrap} and {@code GET /api/v1/auth/session}.</p>
 */
public final class Session {

    private String token;
    private String username;
    private String role;
    private String expires;

    private Session() {
    }

    /**
     * Decode a session.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the session, never {@code null}
     */
    public static Session from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        Session s = new Session();
        s.token = Json.str(o, "token");
        s.username = Json.str(o, "username");
        s.role = Json.str(o, "role");
        s.expires = Json.str(o, "expires");
        return s;
    }

    /**
     * The bearer token. Pass it to
     * {@code client.setToken(String)} or keep it for a later process.
     *
     * @return the token, or {@code ""} when the server returned none
     */
    public String getToken() {
        return token;
    }

    /**
     * @return the account name this token belongs to
     */
    public String getUsername() {
        return username;
    }

    /**
     * @return the account role: {@code viewer}, {@code operator} or {@code admin}
     */
    public String getRole() {
        return role;
    }

    /**
     * @return when the token expires, as an ISO-8601 timestamp, or {@code ""}
     *         when the server did not say
     */
    public String getExpires() {
        return expires;
    }

    /**
     * Whether this token has the given role or a higher one.
     *
     * <p>Uses the server's hierarchy {@code viewer < operator < admin}.</p>
     *
     * @param required the required role
     * @return true when this session's role is at least {@code required}
     */
    public boolean hasRole(String required) {
        return rank(role) >= rank(required);
    }

    private static int rank(String role) {
        if ("admin".equalsIgnoreCase(role)) {
            return 3;
        }
        if ("operator".equalsIgnoreCase(role)) {
            return 2;
        }
        if ("viewer".equalsIgnoreCase(role)) {
            return 1;
        }
        return 0;
    }

    /**
     * An empty, defensive list — used by callers that need a mutable list.
     *
     * @param <T> the element type
     * @return a new empty list
     */
    static <T> List<T> emptyList() {
        return new ArrayList<>();
    }

    @Override
    public String toString() {
        // The token is deliberately not printed.
        return "Session{username='" + username + "', role='" + role + "', expires='" + expires + "'}";
    }
}
