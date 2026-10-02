package io.nothingdns.sdk.model;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.List;

/**
 * The bulk reverse-DNS (PTR) generator's result models.
 *
 * <p>These back {@code POST /api/v1/zones/{zone}/ptr-bulk} (preview and applied
 * forms) and {@code GET /api/v1/zones/{zone}/ptr6-lookup}. The wire format for
 * all four is camelCase, so the Java field names match the wire directly.</p>
 */
public final class PtrModels {

    private PtrModels() {
    }

    /** One record the bulk PTR generator would create. */
    public static final class PtrChange {
        private String name;
        private String type;
        private int ttl;
        private String data;
        private String action;

        private PtrChange() {
        }

        /**
         * Decode one planned change.
         *
         * @param element the decoded body, may be {@code null}
         * @param gson    the codec
         * @return the change, never {@code null}
         */
        public static PtrChange from(JsonElement element, Gson gson) {
            JsonObject o = Json.obj(element);
            PtrChange c = new PtrChange();
            c.name = Json.str(o, "name");
            c.type = Json.str(o, "type");
            c.ttl = Json.integer(o, "ttl");
            c.data = Json.str(o, "data");
            c.action = Json.str(o, "action");
            return c;
        }

        /**
         * @return the owner name that would be created
         */
        public String getName() {
            return name;
        }

        /**
         * @return the record type, {@code PTR} or {@code A}
         */
        public String getType() {
            return type;
        }

        /**
         * @return the record TTL, in seconds
         */
        public int getTtl() {
            return ttl;
        }

        /**
         * @return the record data
         */
        public String getData() {
            return data;
        }

        /**
         * @return what the generator would do: {@code add}, {@code skip} or
         *         {@code override}
         */
        public String getAction() {
            return action;
        }

        @Override
        public String toString() {
            return "PtrChange{action='" + action + "', name='" + name
                    + "', type='" + type + "', data='" + data + "'}";
        }
    }

    /**
     * Result of {@code ptrBulk} with {@code preview=true}: nothing was written.
     */
    public static final class PtrBulkPreview {
        private boolean preview;
        private int total;
        private int willAdd;
        private int willAddA;
        private int willSkip;
        private int willOverride;
        private List<PtrChange> changes;

        private PtrBulkPreview() {
            this.changes = new ArrayList<>();
        }

        /**
         * Decode a preview result.
         *
         * @param element the decoded body, may be {@code null}
         * @param gson    the codec
         * @return the preview, never {@code null}
         */
        public static PtrBulkPreview from(JsonElement element, Gson gson) {
            JsonObject o = Json.obj(element);
            PtrBulkPreview p = new PtrBulkPreview();
            p.preview = Json.bool(o, "preview");
            p.total = Json.integer(o, "total");
            p.willAdd = Json.integer(o, "willAdd");
            p.willAddA = Json.integer(o, "willAddA");
            p.willSkip = Json.integer(o, "willSkip");
            p.willOverride = Json.integer(o, "willOverride");
            p.changes = Json.list(o.get("changes"), null, PtrChange.class, gson);
            return p;
        }

        /**
         * @return always true for a preview
         */
        public boolean isPreview() {
            return preview;
        }

        /**
         * @return the total number of addresses covered
         */
        public int getTotal() {
            return total;
        }

        /**
         * @return the number of PTR records that would be added
         */
        public int getWillAdd() {
            return willAdd;
        }

        /**
         * @return the number of A records that would be added
         */
        public int getWillAddA() {
            return willAddA;
        }

        /**
         * @return the number of addresses that would be skipped
         */
        public int getWillSkip() {
            return willSkip;
        }

        /**
         * @return the number of existing records that would be overridden
         */
        public int getWillOverride() {
            return willOverride;
        }

        /**
         * @return the planned changes, never {@code null}
         */
        public List<PtrChange> getChanges() {
            return changes;
        }

        @Override
        public String toString() {
            return "PtrBulkPreview{total=" + total + ", willAdd=" + willAdd
                    + ", willAddA=" + willAddA + ", willSkip=" + willSkip
                    + ", willOverride=" + willOverride + "}";
        }
    }

    /**
     * Result of {@code ptrBulk} when records were actually written.
     */
    public static final class PtrBulkResult {
        private int added;
        private int addedA;
        private int exists;
        private int existsA;
        private int skipped;

        private PtrBulkResult() {
        }

        /**
         * Decode an applied result.
         *
         * @param element the decoded body, may be {@code null}
         * @param gson    the codec
         * @return the result, never {@code null}
         */
        public static PtrBulkResult from(JsonElement element, Gson gson) {
            JsonObject o = Json.obj(element);
            PtrBulkResult r = new PtrBulkResult();
            r.added = Json.integer(o, "added");
            r.addedA = Json.integer(o, "addedA");
            r.exists = Json.integer(o, "exists");
            r.existsA = Json.integer(o, "existsA");
            r.skipped = Json.integer(o, "skipped");
            return r;
        }

        /**
         * @return the number of PTR records added
         */
        public int getAdded() {
            return added;
        }

        /**
         * @return the number of A records added
         */
        public int getAddedA() {
            return addedA;
        }

        /**
         * @return the number of PTR records that already existed
         */
        public int getExists() {
            return exists;
        }

        /**
         * @return the number of A records that already existed
         */
        public int getExistsA() {
            return existsA;
        }

        /**
         * @return the number of addresses skipped
         */
        public int getSkipped() {
            return skipped;
        }

        @Override
        public String toString() {
            return "PtrBulkResult{added=" + added + ", addedA=" + addedA
                    + ", exists=" + exists + ", existsA=" + existsA
                    + ", skipped=" + skipped + "}";
        }
    }

    /**
     * Result of {@code GET /api/v1/zones/{zone}/ptr6-lookup}: the PTR record
     * for one IPv6 address.
     */
    public static final class PtrLookup {
        private String ip;
        private String ptr;
        private String ptrFQDN;
        private String target;
        private int ttl;
        private boolean found;

        private PtrLookup() {
        }

        /**
         * Decode a PTR lookup.
         *
         * @param element the decoded body, may be {@code null}
         * @param gson    the codec
         * @return the lookup, never {@code null}
         */
        public static PtrLookup from(JsonElement element, Gson gson) {
            JsonObject o = Json.obj(element);
            PtrLookup p = new PtrLookup();
            p.ip = Json.str(o, "ip");
            p.ptr = Json.str(o, "ptr");
            p.ptrFQDN = Json.str(o, "ptrFQDN");
            p.target = Json.str(o, "target");
            p.ttl = Json.integer(o, "ttl");
            p.found = Json.bool(o, "found");
            return p;
        }

        /**
         * @return the IPv6 address that was looked up
         */
        public String getIp() {
            return ip;
        }

        /**
         * @return the PTR record's owner name
         */
        public String getPtr() {
            return ptr;
        }

        /**
         * @return the fully-qualified PTR name
         */
        public String getPtrFQDN() {
            return ptrFQDN;
        }

        /**
         * @return the target the PTR record points at
         */
        public String getTarget() {
            return target;
        }

        /**
         * @return the PTR record's TTL, in seconds
         */
        public int getTtl() {
            return ttl;
        }

        /**
         * @return whether a PTR record was found; check this before reading
         *         {@link #getPtr()} or {@link #getTarget()}
         */
        public boolean isFound() {
            return found;
        }

        @Override
        public String toString() {
            return "PtrLookup{ip='" + ip + "', found=" + found
                    + ", target='" + target + "'}";
        }
    }
}
