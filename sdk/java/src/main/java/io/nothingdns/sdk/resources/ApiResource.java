package io.nothingdns.sdk.resources;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import io.nothingdns.sdk.NothingDnsTransport;
import io.nothingdns.sdk.model.Json;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Shared plumbing for every resource namespace.
 *
 * <p>A namespace describes <em>what</em> to call; the transport decides
 * <em>how</em> the request is made. This base holds the two decoding helpers
 * every namespace needs — turn a body into one model, or into a list of models
 * — plus a small null-dropping body builder.</p>
 */
public abstract class ApiResource {

    /** The shared transport. */
    protected final NothingDnsTransport transport;

    /** The shared JSON codec. */
    protected final Gson gson;

    /**
     * Create a namespace bound to the shared transport.
     *
     * @param transport the shared transport
     */
    protected ApiResource(NothingDnsTransport transport) {
        this.transport = transport;
        this.gson = transport.gson();
    }

    /**
     * Decode a body into a single model.
     *
     * @param element the decoded body, may be {@code null}
     * @param type    the model class
     * @param <T>     the model type
     * @return the model, or {@code null} when the body is absent
     */
    protected <T> T model(JsonElement element, Class<T> type) {
        return Json.obj(element, type, gson);
    }

    /**
     * Decode a body into a list of models, from a bare array or one nested
     * under {@code key}.
     *
     * @param element the decoded body, may be {@code null}
     * @param key     the wrapper field, or {@code null} for a bare array
     * @param type    the model class
     * @param <T>     the model type
     * @return the models, never {@code null}
     */
    protected <T> List<T> list(JsonElement element, String key, Class<T> type) {
        return Json.list(element, key, type, gson);
    }

    /**
     * Extract the server's plain acknowledgement message.
     *
     * @param element the decoded body, may be {@code null}
     * @return the message, or {@code ""} when the body carries none
     */
    protected String message(JsonElement element) {
        return Json.message(element);
    }

    /**
     * Escape one path segment for safe interpolation.
     *
     * @param segment the raw segment, e.g. a zone name
     * @return the escaped segment
     */
    protected String escape(String segment) {
        return NothingDnsTransport.escape(segment);
    }

    /**
     * A new, empty request body.
     *
     * @return an insertion-ordered map
     */
    protected static Map<String, Object> body() {
        return new LinkedHashMap<>();
    }

    /**
     * Add a field to a request body, skipping {@code null}.
     *
     * <p>Skipping nulls is what makes the partial-update endpoints safe: an
     * omitted optional argument means "leave unchanged" rather than "send
     * null", which is how the server interprets every runtime-config
     * {@code PUT}.</p>
     *
     * @param target the request body
     * @param key    the wire field name
     * @param value  the value, or {@code null} to omit the field
     */
    protected static void put(Map<String, Object> target, String key, Object value) {
        if (value != null) {
            target.put(key, value);
        }
    }
}
