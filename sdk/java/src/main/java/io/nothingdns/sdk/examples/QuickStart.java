package io.nothingdns.sdk.examples;

import io.nothingdns.sdk.NothingDnsClient;
import io.nothingdns.sdk.NothingDnsException;
import io.nothingdns.sdk.model.CacheStats;
import io.nothingdns.sdk.model.Session;
import io.nothingdns.sdk.model.Zone;

import java.time.Duration;

/**
 * A runnable end-to-end tour of the NothingDNS SDK.
 *
 * <p>It logs in, lists the zones served by the node, adds one record, reads the
 * cache statistics, and prints a zone export. Run it against a server you
 * control; the record it adds is real, so point it at a scratch zone.</p>
 *
 * <p>Credentials come from the environment and are never hardcoded:</p>
 * <pre>
 * export NDNS_URL=http://localhost:8080
 * export NDNS_USER=admin
 * export NDNS_PASSWORD='…'
 *
 * java -cp target/classes:gson-2.11.0.jar \
 *      io.nothingdns.sdk.examples.QuickStart example.com 3600
 * </pre>
 *
 * <p>Arguments: {@code [zoneName] [ttl]}. Both are optional; the defaults are
 * {@code example.com} and {@code 3600}. The record it creates is
 * {@code www.<zone>} with the address {@code 192.0.2.1} (a TEST-NET address
 * from RFC 5737, so it is safe to publish).</p>
 */
public final class QuickStart {

    private QuickStart() {
    }

    /**
     * Run the tour.
     *
     * @param args optional zone name and TTL
     */
    public static void main(String[] args) {
        String zoneName = args.length > 0 ? args[0] : "example.com";
        int ttl = 3600;
        if (args.length > 1) {
            try {
                ttl = Integer.parseInt(args[1]);
            } catch (NumberFormatException e) {
                System.err.println("TTL '" + args[1] + "' is not a number; using " + ttl);
            }
        }

        String baseUrl = env("NDNS_URL", "http://localhost:8080");
        String username = requireEnv("NDNS_USER");
        String password = requireEnv("NDNS_PASSWORD");

        // try-with-resources releases the transport when the block exits.
        try (NothingDnsClient client =
                     new NothingDnsClient(baseUrl, null, Duration.ofSeconds(30), null, null)) {

            // 1. Health first — it needs no credentials, so it tells us whether
            //    the server is up before we try to authenticate.
            System.out.println("health      : " + client.health().getStatus());

            // 2. Log in. login() stores the token on the client, so every later
            //    call is authenticated automatically.
            Session session = client.auth().login(username, password);
            System.out.println("logged in as: " + session.getUsername()
                    + " (role=" + session.getRole() + ")");

            // 3. List the zones this node serves.
            var zoneList = client.zones().list();
            System.out.println("zones       : " + zoneList.getTotal()
                    + (zoneList.isTruncated() ? " (truncated)" : ""));
            for (Zone zone : zoneList.getZones()) {
                System.out.printf("  %-32s serial=%-10d records=%d%n",
                        zone.getName(), zone.getSerial(), zone.getRecords());
            }

            // 4. Add a record. Requires operator or admin.
            String owner = "www." + zoneName;
            String message = client.zones().addRecord(zoneName, owner, "A", "192.0.2.1", ttl);
            System.out.println("add record  : " + message);

            // 5. Read the cache statistics.
            CacheStats cache = client.cache().stats();
            System.out.printf("cache       : %d/%d entries, %d hits, %d misses, ratio %.3f%n",
                    cache.getSize(), cache.getCapacity(), cache.getHits(),
                    cache.getMisses(), cache.getHitRatio());

            // 6. Print a BIND zone file export.
            System.out.println("--- export of " + zoneName + " ---");
            System.out.println(client.zones().export(zoneName));

        } catch (NothingDnsException e) {
            // Every SDK failure arrives here: an HTTP error, or a connection
            // failure wrapped in NothingDnsConnectionException.
            System.err.println("NothingDNS call failed (HTTP " + e.getStatusCode() + "): "
                    + e.getMessage());
            if (e.getPayload() != null && !e.getPayload().isBlank()) {
                System.err.println("server said : " + e.getPayload());
            }

            // The static helpers turn a status code into a decision.
            if (NothingDnsException.isUnauthorized(e)) {
                System.err.println("hint        : the token is missing or expired — log in again");
            } else if (NothingDnsException.isForbidden(e)) {
                System.err.println("hint        : this account's role is too low "
                        + "(viewer < operator < admin)");
            } else if (NothingDnsException.isNotFound(e)) {
                System.err.println("hint        : the zone or record does not exist");
            } else if (NothingDnsException.isRateLimited(e)) {
                System.err.println("hint        : back off and retry after a short pause");
            }
            System.exit(1);
        }
    }

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return (value == null || value.isBlank()) ? fallback : value.trim();
    }

    private static String requireEnv(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            System.err.println("Set " + name + " before running this example.");
            System.exit(2);
        }
        return value;
    }
}
