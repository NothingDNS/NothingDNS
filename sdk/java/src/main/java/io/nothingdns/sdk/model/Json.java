package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import java.util.ArrayList;
import java.util.List;

/**
 * Small, defensive helpers shared by every model class.
 *
 * <p>Everything here tolerates missing, null or wrongly-typed fields by
 * returning a sensible default, so a response from a newer server never breaks
 * an older client. Models also declare a private no-arg constructor so Gson
 * uses it (running field initialisers) instead of allocating without them.</p>
 *
 * <p>This class is an internal utility; it is public only so the resource
 * namespaces can share the same decoding rules.</p>
 */
public final class Json {

    private Json() {
    }

    /**
     * Coerce a value into a JSON object, returning an empty object when the
     * value is absent or not an object.
     *
     * @param element the value, may be {@code null}
     * @return the object, never {@code null}
     */
    public static JsonObject obj(JsonElement element) {
        return element != null && element.isJsonObject()
                ? element.getAsJsonObject()
                : new JsonObject();
    }

    /**
     * Coerce a value into a JSON array, returning an empty array when the value
     * is absent or not an array.
     *
     * @param element the value, may be {@code null}
     * @return the array, never {@code null}
     */
    public static JsonArray arr(JsonElement element) {
        return element != null && element.isJsonArray()
                ? element.getAsJsonArray()
                : new JsonArray();
    }

    /**
     * Read a string field.
     *
     * @param object the source object, may be {@code null}
     * @param key    the field name
     * @return the string value, or {@code ""} when absent
     */
    public static String str(JsonObject object, String key) {
        if (object == null) {
            return "";
        }
        JsonElement value = object.get(key);
        if (value == null || !value.isJsonPrimitive()) {
            return "";
        }
        try {
            return value.getAsString();
        } catch (RuntimeException e) {
            return "";
        }
    }

    /**
     * Read an integer field, tolerating a JSON number or numeric string.
     *
     * @param object the source object, may be {@code null}
     * @param key    the field name
     * @return the integer value, or {@code 0} when absent or not numeric
     */
    public static int integer(JsonObject object, String key) {
        if (object == null) {
            return 0;
        }
        JsonElement value = object.get(key);
        if (value == null || !value.isJsonPrimitive()) {
            return 0;
        }
        try {
            return value.getAsInt();
        } catch (RuntimeException e) {
            return 0;
        }
    }

    /**
     * Read a double field, tolerating a JSON number or numeric string.
     *
     * @param object the source object, may be {@code null}
     * @param key    the field name
     * @return the double value, or {@code 0} when absent or not numeric
     */
    public static double dbl(JsonObject object, String key) {
        if (object == null) {
            return 0.0;
        }
        JsonElement value = object.get(key);
        if (value == null || !value.isJsonPrimitive()) {
            return 0.0;
        }
        try {
            return value.getAsDouble();
        } catch (RuntimeException e) {
            return 0.0;
        }
    }

    /**
     * Read a boolean field, tolerating a JSON boolean or {@code "true"/"false"}.
     *
     * @param object the source object, may be {@code null}
     * @param key    the field name
     * @return the boolean value, or {@code false} when absent
     */
    public static boolean bool(JsonObject object, String key) {
        if (object == null) {
            return false;
        }
        JsonElement value = object.get(key);
        if (value == null || !value.isJsonPrimitive()) {
            return false;
        }
        JsonPrimitive primitive = value.getAsJsonPrimitive();
        if (primitive.isBoolean()) {
            return primitive.getAsBoolean();
        }
        if (primitive.isString()) {
            return "true".equalsIgnoreCase(primitive.getAsString());
        }
        return false;
    }

    /**
     * Read an array-of-strings field, skipping non-primitive entries.
     *
     * @param object the source object, may be {@code null}
     * @param key    the field name
     * @return the strings, never {@code null}
     */
    public static List<String> stringList(JsonObject object, String key) {
        List<String> out = new ArrayList<>();
        if (object == null) {
            return out;
        }
        for (JsonElement element : arr(object.get(key))) {
            if (element != null && element.isJsonPrimitive()) {
                out.add(element.getAsString());
            }
        }
        return out;
    }

    /**
     * Deserialize a single model.
     *
     * @param element the value, may be {@code null}
     * @param type    the model class
     * @param gson    the codec
     * @param <T>     the model type
     * @return the model, or {@code null} when {@code element} is absent
     */
    public static <T> T obj(JsonElement element, Class<T> type, Gson gson) {
        if (element == null || element.isJsonNull() || !element.isJsonObject()) {
            return null;
        }
        return gson.fromJson(element, type);
    }

    /**
     * Deserialize a list of models, from either a bare array or an array nested
     * under {@code key}.
     *
     * <p>When {@code key} is {@code null} the value must itself be an array;
     * otherwise the object field named {@code key} must hold the array. A
     * value of the wrong shape yields an empty list rather than an error, so a
     * server that reshapes a payload cannot crash a client.</p>
     *
     * @param element the value, may be {@code null}
     * @param key     the wrapper field, or {@code null} for a bare array
     * @param type    the model class
     * @param gson    the codec
     * @param <T>     the model type
     * @return the models, never {@code null}
     */
    public static <T> List<T> list(JsonElement element, String key, Class<T> type, Gson gson) {
        JsonArray array;
        if (key == null) {
            array = arr(element);
        } else {
            array = arr(obj(element).get(key));
        }
        List<T> out = new ArrayList<>(array.size());
        for (JsonElement item : array) {
            T model = obj(item, type, gson);
            if (model != null) {
                out.add(model);
            }
        }
        return out;
    }

    /**
     * Deserialize a list of models nested under {@code key}, defaulting to an
     * empty list when the field is absent.
     *
     * @param parent the wrapper object, may be {@code null}
     * @param key    the field name
     * @param type   the model class
     * @param gson   the codec
     * @param <T>    the model type
     * @return the models, never {@code null}
     */
    public static <T> List<T> listOf(JsonObject parent, String key, Class<T> type, Gson gson) {
        return list(parent == null ? null : parent.get(key), null, type, gson);
    }

    /**
     * Extract the server's plain acknowledgement {@code message} from a body.
     *
     * @param element the decoded body, may be {@code null}
     * @return the message, or {@code ""} when the body carries none
     */
    public static String message(JsonElement element) {
        return str(obj(element), "message");
    }
}
