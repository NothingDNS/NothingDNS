package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.annotations.SerializedName;

import java.util.ArrayList;
import java.util.List;

/**
 * One row of the paginated query log, and the page that contains it.
 *
 * <p>Returned by {@code GET /api/v1/queries} (operator+). Unlike the dashboard
 * live stream, this group uses snake_case on the wire.</p>
 */
public final class QueryLogPage {

    private List<QueryLogEntry> queries;
    private int total;
    private int offset;
    private int limit;

    private QueryLogPage() {
        this.queries = new ArrayList<>();
    }

    /**
     * Decode a page of the query log.
     *
     * @param element the decoded body, may be {@code null}
     * @param gson    the codec
     * @return the page, never {@code null}
     */
    public static QueryLogPage from(JsonElement element, Gson gson) {
        JsonObject o = Json.obj(element);
        QueryLogPage p = new QueryLogPage();
        p.queries = Json.list(o.get("queries"), null, QueryLogEntry.class, gson);
        p.total = Json.integer(o, "total");
        p.offset = Json.integer(o, "offset");
        p.limit = Json.integer(o, "limit");
        return p;
    }

    /**
     * @return the log rows in this page, never {@code null}
     */
    public List<QueryLogEntry> getQueries() {
        return queries;
    }

    /**
     * @return the total number of rows matching the query
     */
    public int getTotal() {
        return total;
    }

    /**
     * @return the offset this page starts at
     */
    public int getOffset() {
        return offset;
    }

    /**
     * @return the page size the server applied
     */
    public int getLimit() {
        return limit;
    }

    @Override
    public String toString() {
        return "QueryLogPage{total=" + total + ", offset=" + offset
                + ", limit=" + limit + ", rows=" + queries.size() + "}";
    }

    /** One row of the query log. */
    public static final class QueryLogEntry {
        private String timestamp;
        @SerializedName("client_ip")
        private String clientIp;
        private String domain;
        @SerializedName("query_type")
        private String queryType;
        @SerializedName("response_code")
        private String responseCode;
        private List<String> answers;
        @SerializedName("duration_ms")
        private int durationMs;
        private boolean cached;
        private boolean blocked;
        private String protocol;

        private QueryLogEntry() {
            this.answers = new ArrayList<>();
        }

        /**
         * Decode a query log row.
         *
         * @param element the decoded body, may be {@code null}
         * @param gson    the codec
         * @return the row, never {@code null}
         */
        public static QueryLogEntry from(JsonElement element, Gson gson) {
            JsonObject o = Json.obj(element);
            QueryLogEntry e = new QueryLogEntry();
            e.timestamp = Json.str(o, "timestamp");
            e.clientIp = Json.str(o, "client_ip");
            e.domain = Json.str(o, "domain");
            e.queryType = Json.str(o, "query_type");
            e.responseCode = Json.str(o, "response_code");
            e.answers = Json.stringList(o, "answers");
            e.durationMs = Json.integer(o, "duration_ms");
            e.cached = Json.bool(o, "cached");
            e.blocked = Json.bool(o, "blocked");
            e.protocol = Json.str(o, "protocol");
            return e;
        }

        /**
         * @return when the query was answered, as an ISO-8601 timestamp
         */
        public String getTimestamp() {
            return timestamp;
        }

        /**
         * @return the client's IP address
         */
        public String getClientIp() {
            return clientIp;
        }

        /**
         * @return the queried domain
         */
        public String getDomain() {
            return domain;
        }

        /**
         * @return the queried record type
         */
        public String getQueryType() {
            return queryType;
        }

        /**
         * @return the DNS response code
         */
        public String getResponseCode() {
            return responseCode;
        }

        /**
         * @return the answer records, never {@code null}
         */
        public List<String> getAnswers() {
            return answers;
        }

        /**
         * @return the handling time, in milliseconds
         */
        public int getDurationMs() {
            return durationMs;
        }

        /**
         * @return whether the answer came from cache
         */
        public boolean isCached() {
            return cached;
        }

        /**
         * @return whether the query was blocked by filtering
         */
        public boolean isBlocked() {
            return blocked;
        }

        /**
         * @return the transport the query arrived on
         */
        public String getProtocol() {
            return protocol;
        }

        @Override
        public String toString() {
            return "QueryLogEntry{domain='" + domain + "', type='" + queryType
                    + "', rcode='" + responseCode + "'}";
        }
    }
}
