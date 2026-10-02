package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.List;

/**
 * The most-queried domains, and the list that contains them.
 *
 * <p>Returned by {@code GET /api/v1/topdomains} (operator+).</p>
 */
public final class TopDomains {

    private List<TopDomain> domains;
    private int limit;

    private TopDomains() {
        this.domains = new ArrayList<>();
    }

    /**
     * Decode the top-domains list.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the list, never {@code null}
     */
    public static TopDomains from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        TopDomains t = new TopDomains();
        t.domains = Json.list(o.get("domains"), null, TopDomain.class, gson);
        t.limit = Json.integer(o, "limit");
        return t;
    }

    /**
     * @return the most-queried domains, most frequent first, never {@code null}
     */
    public List<TopDomain> getDomains() {
        return domains;
    }

    /**
     * @return the limit the server applied
     */
    public int getLimit() {
        return limit;
    }

    @Override
    public String toString() {
        return "TopDomains{limit=" + limit + ", domains=" + domains.size() + "}";
    }

    /** One domain and its query count. */
    public static final class TopDomain {
        private String domain;
        private long count;

        private TopDomain() {
        }

        /**
         * Decode a top domain.
         *
         * @param element the decoded body, may be {@code null}
         * @param gson    the codec
         * @return the entry, never {@code null}
         */
        public static TopDomain from(JsonElement element, Gson gson) {
            JsonObject o = Json.obj(element);
            TopDomain d = new TopDomain();
            d.domain = Json.str(o, "domain");
            d.count = Json.integer(o, "count");
            return d;
        }

        /**
         * @return the domain name
         */
        public String getDomain() {
            return domain;
        }

        /**
         * @return how many times the domain was queried
         */
        public long getCount() {
            return count;
        }

        @Override
        public String toString() {
            return "TopDomain{domain='" + domain + "', count=" + count + "}";
        }
    }
}
