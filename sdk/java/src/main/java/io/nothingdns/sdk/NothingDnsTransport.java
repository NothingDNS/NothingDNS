package io.nothingdns.sdk;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The HTTP core shared by every NothingDNS resource namespace.
 *
 * <p>The transport owns URL construction, the {@code Authorization: Bearer …}
 * header, query serialisation, JSON encoding, timeouts, and the translation of
 * HTTP failures into {@link NothingDnsException}. Resource namespaces only
 * describe <em>what</em> to call; this class decides <em>how</em> the request
 * is made.</p>
 *
 * <p>Credential <em>transmission</em> lives here. Credential <em>acquisition</em>
 * (the login and bootstrap password payloads) lives in {@link NothingDnsAuth},
 * deliberately kept in a separate file.</p>
 *
 * <p>This class is safe to share between threads: the only mutable state is the
 * bearer token, which is {@code volatile}.</p>
 */
public class NothingDnsTransport implements AutoCloseable {

    /** Base URL used when the caller does not supply one. */
    public static final String DEFAULT_BASE_URL = "http://localhost:8080";

    /** Per-request timeout used when the caller does not supply one. */
    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);

    private static final int MAX_TEXT_IN_MESSAGE = 500;

    private final String baseUrl;
    private final Duration timeout;
    private final HttpClient httpClient;
    private final Gson gson;
    private final Map<String, String> defaultHeaders;

    private volatile String token;

    /**
     * Create a transport with default settings.
     *
     * @param baseUrl the base URL of the server's HTTP listener
     * @param token   the bearer token to send, or {@code null} for an
     *                unauthenticated client
     */
    public NothingDnsTransport(String baseUrl, String token) {
        this(baseUrl, token, DEFAULT_TIMEOUT, null, null);
    }

    /**
     * Create a transport.
     *
     * @param baseUrl       the base URL of the server's HTTP listener, e.g.
     *                      {@code http://dns.example.com:8080}
     * @param token         the bearer token to send, or {@code null}
     * @param timeout       the per-request timeout, or {@code null} for
     *                      {@link #DEFAULT_TIMEOUT}
     * @param headers       extra headers merged into every request, or {@code null}
     * @param httpClient    an {@link HttpClient} to reuse, or {@code null} to
     *                      create one (useful to share a connection pool, a
     *                      proxy or a custom TLS context)
     */
    public NothingDnsTransport(String baseUrl,
                               String token,
                               Duration timeout,
                               Map<String, String> headers,
                               HttpClient httpClient) {
        String trimmed = (baseUrl == null || baseUrl.isBlank())
                ? DEFAULT_BASE_URL
                : baseUrl.trim();
        while (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        this.baseUrl = trimmed;
        this.timeout = timeout == null ? DEFAULT_TIMEOUT : timeout;
        this.token = (token == null || token.isBlank()) ? null : token;
        this.gson = new GsonBuilder().disableHtmlEscaping().create();
        this.defaultHeaders = new LinkedHashMap<>();
        if (headers != null) {
            this.defaultHeaders.putAll(headers);
        }
        this.httpClient = httpClient != null
                ? httpClient
                : HttpClient.newBuilder()
                        .connectTimeout(this.timeout)
                        .followRedirects(HttpClient.Redirect.NORMAL)
                        .build();
    }

    // -- accessors ---------------------------------------------------------

    /**
     * The base URL of the server, without a trailing slash.
     *
     * @return the base URL
     */
    public String getBaseUrl() {
        return baseUrl;
    }

    /**
     * The bearer token currently sent with requests.
     *
     * @return the token, or {@code null} when unauthenticated
     */
    public String getToken() {
        return token;
    }

    /**
     * Use {@code newToken} for all subsequent requests.
     *
     * <p>Accepts a JWT returned by {@code auth.login} / {@code auth.bootstrap},
     * or the static {@code server.http.auth_token} value from the server
     * config. Pass {@code null} to go anonymous.</p>
     *
     * @param newToken the token to send, or {@code null}
     */
    public void setToken(String newToken) {
        this.token = (newToken == null || newToken.isBlank()) ? null : newToken;
    }

    /**
     * Forget the bearer token; subsequent requests are sent unauthenticated.
     */
    public void clearToken() {
        this.token = null;
    }

    /**
     * The per-request timeout in force.
     *
     * @return the timeout
     */
    public Duration getTimeout() {
        return timeout;
    }

    /**
     * The JSON codec used to (de)serialise every request and response.
     *
     * @return the shared {@link Gson} instance
     */
    public Gson gson() {
        return gson;
    }

    // -- URL helpers -------------------------------------------------------

    /**
     * Percent-encode one path segment (a zone name, source id or username).
     *
     * <p>Every character outside the RFC 3986 unreserved set is escaped, so a
     * zone name or username can never break out of its path position.</p>
     *
     * @param segment the raw segment, may be {@code null}
     * @return the escaped segment
     */
    public static String escape(String segment) {
        return segment == null ? "" : percentEncode(segment);
    }

    /**
     * Serialise query parameters into a {@code ?a=1&b=2} suffix, skipping
     * entries whose value is {@code null}.
     *
     * <p>Skipping nulls is what makes the partial-update endpoints safe: an
     * omitted optional argument means "leave unchanged" rather than "send
     * null".</p>
     *
     * @param params the parameters, may be {@code null} or empty
     * @return the query string, including the leading {@code ?}, or an empty
     *         string when there is nothing to send
     */
    public static String buildQuery(Map<String, ?> params) {
        if (params == null || params.isEmpty()) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, ?> entry : params.entrySet()) {
            if (entry.getKey() == null || entry.getValue() == null) {
                continue;
            }
            sb.append(sb.length() == 0 ? "?" : "&")
              .append(percentEncode(entry.getKey()))
              .append('=')
              .append(percentEncode(String.valueOf(entry.getValue())));
        }
        return sb.toString();
    }

    private static String percentEncode(String value) {
        StringBuilder sb = new StringBuilder();
        for (byte b : value.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xFF;
            boolean unreserved = (c >= 'A' && c <= 'Z')
                    || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9')
                    || c == '-' || c == '_' || c == '.' || c == '~';
            if (unreserved) {
                sb.append((char) c);
            } else {
                sb.append('%');
                sb.append(Character.toUpperCase(Character.forDigit(c >> 4, 16)));
                sb.append(Character.toUpperCase(Character.forDigit(c & 0x0F, 16)));
            }
        }
        return sb.toString();
    }

    // -- verbs -------------------------------------------------------------

    /**
     * Send a {@code GET} and return the decoded body.
     *
     * @param path   the API path, starting with {@code /}
     * @param params query parameters; null values are dropped, may be {@code null}
     * @return the decoded body, or {@code null} for an empty response
     */
    public JsonElement get(String path, Map<String, ?> params) {
        return json("GET", path, params, null);
    }

    /**
     * Send a {@code GET} with no query parameters.
     *
     * @param path the API path, starting with {@code /}
     * @return the decoded body, or {@code null} for an empty response
     */
    public JsonElement get(String path) {
        return json("GET", path, null, null);
    }

    /**
     * Send a {@code POST} with a JSON body and return the decoded response.
     *
     * @param path the API path, starting with {@code /}
     * @param body the request body, serialised as JSON, may be {@code null}
     * @return the decoded body, or {@code null} for an empty response
     */
    public JsonElement post(String path, Object body) {
        return json("POST", path, null, body);
    }

    /**
     * Send a {@code POST} with query parameters and a JSON body.
     *
     * @param path   the API path, starting with {@code /}
     * @param params query parameters; null values are dropped, may be {@code null}
     * @param body   the request body, serialised as JSON, may be {@code null}
     * @return the decoded body, or {@code null} for an empty response
     */
    public JsonElement post(String path, Map<String, ?> params, Object body) {
        return json("POST", path, params, body);
    }

    /**
     * Send a {@code PUT} with a JSON body and return the decoded response.
     *
     * @param path the API path, starting with {@code /}
     * @param body the request body, serialised as JSON, may be {@code null}
     * @return the decoded body, or {@code null} for an empty response
     */
    public JsonElement put(String path, Object body) {
        return json("PUT", path, null, body);
    }

    /**
     * Send a {@code DELETE} with a JSON body and return the decoded response.
     *
     * @param path the API path, starting with {@code /}
     * @param body the request body, serialised as JSON, may be {@code null}
     * @return the decoded body, or {@code null} for an empty response
     */
    public JsonElement delete(String path, Object body) {
        return json("DELETE", path, null, body);
    }

    /**
     * Send a {@code DELETE} with no body and return the decoded response.
     *
     * @param path the API path, starting with {@code /}
     * @return the decoded body, or {@code null} for an empty response
     */
    public JsonElement delete(String path) {
        return json("DELETE", path, null, null);
    }

    /**
     * Send a {@code DELETE} with query parameters and an optional body.
     *
     * <p>The RPZ rule endpoint takes its pattern as a query parameter on a
     * {@code DELETE}, which this overload exists to support.</p>
     *
     * @param path   the API path, starting with {@code /}
     * @param params query parameters; null values are dropped, may be {@code null}
     * @param body   the request body, serialised as JSON, may be {@code null}
     * @return the decoded body, or {@code null} for an empty response
     */
    public JsonElement delete(String path, Map<String, ?> params, Object body) {
        return json("DELETE", path, params, body);
    }

    /**
     * Send a {@code GET} and return the response body as plain text.
     *
     * <p>Used by the zone export endpoint, which serves a BIND zone file, and
     * by the API explorer endpoints, which serve HTML and JavaScript.</p>
     *
     * @param path   the API path, starting with {@code /}
     * @param params query parameters; null values are dropped, may be {@code null}
     * @return the response body as text
     */
    public String getRaw(String path, Map<String, ?> params) {
        return execute("GET", path, params, null);
    }

    /**
     * Send a request and return the decoded body, discarding an empty one.
     *
     * @param method the HTTP verb
     * @param path   the API path, starting with {@code /}
     * @param params query parameters; null values are dropped, may be {@code null}
     * @param body   the request body, serialised as JSON, may be {@code null}
     * @return the decoded body, or {@code null} when the response had none
     * @throws NothingDnsException           the server answered 4xx/5xx, or a
     *                                      2xx body was not valid JSON
     * @throws NothingDnsConnectionException the server could not be reached
     */
    public JsonElement json(String method, String path, Map<String, ?> params, Object body) {
        String text = execute(method, path, params, body);
        if (text == null || text.isBlank()) {
            return null;
        }
        try {
            JsonElement element = JsonParser.parseString(text);
            return element.isJsonNull() ? null : element;
        } catch (JsonSyntaxException e) {
            throw new NothingDnsException(
                    "NothingDNS returned a non-JSON body for " + method + " "
                            + baseUrl + path + ": " + truncate(text, 200),
                    e);
        }
    }

    // -- request pipeline --------------------------------------------------

    private String execute(String method, String path, Map<String, ?> params, Object body) {
        String url = baseUrl + path + buildQuery(params);
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(timeout);

        for (Map.Entry<String, String> header : defaultHeaders.entrySet()) {
            builder.header(header.getKey(), header.getValue());
        }
        String bearer = token;
        if (bearer != null) {
            builder.header("Authorization", "Bearer " + bearer);
        }
        if (body != null) {
            builder.header("Content-Type", "application/json");
            builder.method(method, HttpRequest.BodyPublishers.ofString(
                    gson.toJson(body), StandardCharsets.UTF_8));
        } else if (bodyAllowed(method)) {
            builder.method(method, HttpRequest.BodyPublishers.ofString("", StandardCharsets.UTF_8));
        } else {
            builder.method(method, HttpRequest.BodyPublishers.noBody());
        }
        if (!builder.build().headers().firstValue("Accept").isPresent()) {
            builder.header("Accept", "application/json");
        }

        HttpResponse<String> response;
        try {
            response = httpClient.send(builder.build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new NothingDnsConnectionException(
                    "Could not reach NothingDNS at " + url + ": " + e, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new NothingDnsConnectionException(
                    "Interrupted while calling NothingDNS at " + url, e);
        }

        int status = response.statusCode();
        if (status < 200 || status >= 300) {
            throw toException(status, response.body());
        }
        return response.body();
    }

    private static boolean bodyAllowed(String method) {
        // Only methods that may carry a payload get an (empty) body publisher.
        return false;
    }

    private static NothingDnsException toException(int status, String body) {
        String text = body == null ? "" : body;
        String message = "HTTP " + status;
        try {
            JsonElement parsed = JsonParser.parseString(text);
            if (parsed != null && parsed.isJsonObject()) {
                JsonObject object = parsed.getAsJsonObject();
                JsonElement reported = object.has("error")
                        ? object.get("error")
                        : object.get("message");
                if (reported != null && reported.isJsonPrimitive()) {
                    String value = reported.getAsString();
                    if (value != null && !value.isEmpty()) {
                        message = value;
                    }
                }
            }
        } catch (JsonSyntaxException ignored) {
            // Non-JSON body: fall through to the raw text below.
        }
        if (message.equals("HTTP " + status) && !text.isBlank()) {
            message = truncate(text, MAX_TEXT_IN_MESSAGE);
        }
        return new NothingDnsException(status, message, text);
    }

    private static String truncate(String value, int max) {
        String trimmed = value.trim();
        return trimmed.length() <= max ? trimmed : trimmed.substring(0, max) + "…";
    }

    /**
     * An unmodifiable view of the headers merged into every request.
     *
     * @return the default headers
     */
    public Map<String, String> getDefaultHeaders() {
        return Collections.unmodifiableMap(defaultHeaders);
    }

    /**
     * Release the transport's resources. The JDK {@link HttpClient} manages
     * its own pool, so there is nothing to shut down beyond dropping the
     * reference; this exists so the transport can be used with
     * try-with-resources alongside the client.
     */
    @Override
    public void close() {
        clearToken();
    }
}
