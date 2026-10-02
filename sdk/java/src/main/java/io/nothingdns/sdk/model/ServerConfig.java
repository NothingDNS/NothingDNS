package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.annotations.SerializedName;

import java.util.List;

/**
 * Server configuration summary.
 *
 * <p>Returned by {@code GET /api/v1/server/config} (operator+). Shows the
 * listen port, log level and the DNS64 and DNS Cookie toggles.</p>
 */
public final class ServerConfig {

    private String version;
    @SerializedName("listen_port")
    private int listenPort;
    @SerializedName("log_level")
    private String logLevel;
    private Dns64Config dns64;
    private CookieConfig cookie;

    private ServerConfig() {
    }

    /**
     * Decode a server configuration summary.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the configuration, never {@code null}
     */
    public static ServerConfig from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        ServerConfig c = new ServerConfig();
        c.version = Json.str(o, "version");
        c.listenPort = Json.integer(o, "listen_port");
        c.logLevel = Json.str(o, "log_level");
        c.dns64 = Dns64Config.from(o.get("dns64"), gson);
        c.cookie = CookieConfig.from(o.get("cookie"), gson);
        return c;
    }

    /**
     * @return the running server version
     */
    public String getVersion() {
        return version;
    }

    /**
     * @return the UDP/TCP DNS listen port
     */
    public int getListenPort() {
        return listenPort;
    }

    /**
     * @return the current log level
     */
    public String getLogLevel() {
        return logLevel;
    }

    /**
     * @return the DNS64 settings, never {@code null}
     */
    public Dns64Config getDns64() {
        return dns64;
    }

    /**
     * @return the DNS Cookie settings, never {@code null}
     */
    public CookieConfig getCookie() {
        return cookie;
    }

    @Override
    public String toString() {
        return "ServerConfig{version='" + version + "', listenPort=" + listenPort
                + ", logLevel='" + logLevel + "'}";
    }

    /** DNS64/NAT64 synthesis settings (RFC 6147). */
    public static final class Dns64Config {
        private boolean enabled;
        private String prefix;
        @SerializedName("prefix_len")
        private int prefixLen;
        @SerializedName("exclude_nets")
        private List<String> excludeNets;

        private Dns64Config() {
        }

        /**
         * Decode DNS64 settings.
         *
         * @param element the decoded body, may be {@code null}
         * @param gson    the codec
         * @return the settings, never {@code null}
         */
        public static Dns64Config from(JsonElement element, Gson gson) {
            JsonObject o = Json.obj(element);
            Dns64Config d = new Dns64Config();
            d.enabled = Json.bool(o, "enabled");
            d.prefix = Json.str(o, "prefix");
            d.prefixLen = Json.integer(o, "prefix_len");
            d.excludeNets = Json.stringList(o, "exclude_nets");
            return d;
        }

        /**
         * @return whether DNS64 synthesis is on
         */
        public boolean isEnabled() {
            return enabled;
        }

        /**
         * @return the well-known NAT64 prefix, e.g. {@code 64:ff9b::/96}
         */
        public String getPrefix() {
            return prefix;
        }

        /**
         * @return the prefix length
         */
        public int getPrefixLen() {
            return prefixLen;
        }

        /**
         * @return networks excluded from synthesis, never {@code null}
         */
        public List<String> getExcludeNets() {
            return excludeNets;
        }

        @Override
        public String toString() {
            return "Dns64Config{enabled=" + enabled + ", prefix='" + prefix + "'}";
        }
    }

    /** DNS Cookies settings (RFC 7873). */
    public static final class CookieConfig {
        private boolean enabled;
        @SerializedName("secret_rotation")
        private String secretRotation;

        private CookieConfig() {
        }

        /**
         * Decode DNS Cookie settings.
         *
         * @param element the decoded body, may be {@code null}
         * @param gson    the codec
         * @return the settings, never {@code null}
         */
        public static CookieConfig from(JsonElement element, Gson gson) {
            JsonObject o = Json.obj(element);
            CookieConfig c = new CookieConfig();
            c.enabled = Json.bool(o, "enabled");
            c.secretRotation = Json.str(o, "secret_rotation");
            return c;
        }

        /**
         * @return whether DNS Cookies are enabled
         */
        public boolean isEnabled() {
            return enabled;
        }

        /**
         * @return the cookie secret rotation period
         */
        public String getSecretRotation() {
            return secretRotation;
        }

        @Override
        public String toString() {
            return "CookieConfig{enabled=" + enabled + "}";
        }
    }
}
