package io.nothingdns.sdk;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Error translation, predicate helpers and acknowledgement parsing.
 *
 * <p>Exercises the 401/403/404/429 mappings, the static predicate helpers and
 * connection failures against the in-process mock API, mirroring
 * {@code sdk/python/tests/test_errors.py} and
 * {@code sdk/typescript/test/errors.test.mjs}.</p>
 */
class ErrorsTest {

    private MockApi mock;
    private NothingDnsClient client;

    @BeforeEach
    void startMockAndClient() throws IOException {
        mock = new MockApi();
        client = new NothingDnsClient(mock.baseUrl(), null, Duration.ofSeconds(5), null, null);
    }

    @AfterEach
    void stopMockAndClient() {
        client.close();
        mock.close();
    }

    // -- status predicates ----------------------------------------------------

    @Test
    void unauthorizedMapsToItsPredicateWithTheServerMessage() {
        NothingDnsException error = assertThrows(NothingDnsException.class,
                () -> client.auth().login("admin", "wrong"));

        assertEquals(401, error.getStatusCode());
        assertTrue(error.getMessage().contains("invalid credentials"), error.getMessage());
        assertEquals("{\"error\": \"invalid credentials\"}", error.getPayload());
        assertTrue(NothingDnsException.isUnauthorized(error));
        assertFalse(NothingDnsException.isForbidden(error));
    }

    @Test
    void forbiddenMapsToItsPredicate() {
        client.setToken(MockApi.TOKEN);

        NothingDnsException error = assertThrows(NothingDnsException.class,
                () -> client.dnssec().keys());

        assertEquals(403, error.getStatusCode());
        assertTrue(NothingDnsException.isForbidden(error));
    }

    @Test
    void rateLimitedMapsToItsPredicate() {
        NothingDnsException error = assertThrows(NothingDnsException.class,
                () -> client.cache().flush());

        assertEquals(429, error.getStatusCode());
        assertTrue(NothingDnsException.isRateLimited(error));
    }

    @Test
    void notFoundMapsToItsPredicateAndKeepsThePayload() {
        NothingDnsException error = assertThrows(NothingDnsException.class,
                () -> client.zones().get("missing.com"));

        assertTrue(NothingDnsException.isNotFound(error));
        assertTrue(error.getMessage().contains("missing.com"), error.getMessage());
        assertEquals("{\"error\": \"Zone missing.com not found\"}", error.getPayload());
    }

    @Test
    void predicatesRejectOtherStatusesAndConnectionFailures() {
        NothingDnsException conflict = new NothingDnsException(409, "zone already exists", null);
        assertFalse(NothingDnsException.isNotFound(conflict));
        assertFalse(NothingDnsException.isUnauthorized(conflict));
        assertFalse(NothingDnsException.isForbidden(conflict));
        assertFalse(NothingDnsException.isRateLimited(conflict));

        // A connection failure carries no HTTP status, so no predicate matches.
        NothingDnsException connection =
                new NothingDnsConnectionException("Could not reach NothingDNS at http://x");
        assertFalse(NothingDnsException.isNotFound(connection));
        assertFalse(NothingDnsException.isUnauthorized(connection));
        assertFalse(NothingDnsException.isForbidden(connection));
        assertFalse(NothingDnsException.isRateLimited(connection));

        // The helpers are null-safe (their static signature cannot accept an
        // arbitrary Throwable, so null is the "not an API error" case).
        assertFalse(NothingDnsException.isNotFound(null));
        assertFalse(NothingDnsException.isUnauthorized(null));
        assertFalse(NothingDnsException.isForbidden(null));
        assertFalse(NothingDnsException.isRateLimited(null));
    }

    // -- error shapes ---------------------------------------------------------

    @Test
    void errorStringIncludesStatusAndMessage() {
        NothingDnsException error = new NothingDnsException(409, "zone already exists", null);

        assertTrue(error.getMessage().contains("409"), error.getMessage());
        assertTrue(error.getMessage().contains("zone already exists"), error.getMessage());
    }

    // -- acknowledgement parsing ----------------------------------------------

    @Test
    void acknowledgementMessagesAreReturnedByMutations() {
        client.setToken(MockApi.TOKEN);

        List<String> acks = new ArrayList<>();
        acks.add(client.acl().set(List.of(
                io.nothingdns.sdk.model.AclRule.of("a", List.of("0.0.0.0/0"), "allow"))));
        acks.add(client.upstreams().add("1.1.1.1:53"));
        acks.add(client.auth().logout());

        // The "message" field of each mutation response is what the caller gets.
        assertEquals(List.of("acl updated", "upstream added", "logged out"), acks);
    }

    // -- connection failures --------------------------------------------------

    @Test
    void unreachableServerRaisesConnectionException() throws IOException {
        // Bind a port, note it, then release it so connections are refused.
        int deadPort;
        try (ServerSocket probe = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            deadPort = probe.getLocalPort();
        }

        try (NothingDnsClient dead =
                     new NothingDnsClient("http://127.0.0.1:" + deadPort, null,
                             Duration.ofSeconds(2), null, null)) {
            NothingDnsConnectionException error = assertThrows(
                    NothingDnsConnectionException.class, dead::health);

            assertTrue(error.getMessage().contains("Could not reach NothingDNS"),
                    error.getMessage());
            assertNull(error.getPayload());
        }
    }
}
