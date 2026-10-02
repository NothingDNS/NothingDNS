package io.nothingdns.sdk;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import io.nothingdns.sdk.model.AclRule;
import io.nothingdns.sdk.model.SlaveZone;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Behavioural tests for the {@link NothingDnsClient} against an in-process
 * mock API.
 *
 * <p>Mirrors the request-level contract — paths, methods, query strings, JSON
 * bodies, bearer-auth propagation and camelCase/snake_case model mapping —
 * following {@code sdk/python/tests/test_client.py} and
 * {@code sdk/typescript/test/client.test.mjs}. Each test gets a fresh mock so
 * recorded requests never leak between tests.</p>
 */
class ClientTest {

    private MockApi mock;
    private NothingDnsClient client;

    @BeforeEach
    void startMockAndClient() throws IOException {
        mock = new MockApi();
        client = new NothingDnsClient(mock.baseUrl(), null, java.time.Duration.ofSeconds(5),
                null, null);
    }

    @AfterEach
    void stopMockAndClient() {
        client.close();
        mock.close();
    }

    // -- health & authentication ---------------------------------------------

    @Test
    void healthReadyAndLiveNeedNoAuth() {
        assertEquals("healthy", client.health().getStatus());
        assertEquals("healthy", client.ready().getStatus());
        assertEquals("healthy", client.live().getStatus());
        // No probe carried an Authorization header.
        for (MockApi.Recorded request : mock.requests()) {
            assertNull(request.auth(), request.method() + " " + request.path());
        }
    }

    @Test
    void loginStoresTokenAndNextRequestCarriesIt() {
        var session = client.auth().login(MockApi.USERNAME, MockApi.PASSWORD);

        assertEquals("admin", session.getRole());
        assertEquals("2026-10-02T12:00:00Z", session.getExpires());
        assertEquals(MockApi.TOKEN, client.getToken());
        // The login request itself must not carry a token; the next one must.
        assertNull(mock.last().auth());
        client.status();
        assertEquals("Bearer " + MockApi.TOKEN, mock.last().auth());
    }

    @Test
    void loginCanSkipStoringTheToken() {
        var session = client.auth().login(MockApi.USERNAME, MockApi.PASSWORD, false);

        assertEquals(MockApi.TOKEN, session.getToken());
        assertNull(client.getToken());
    }

    @Test
    void setTokenIsUsedForRequests() {
        client.setToken(MockApi.SERVICE_TOKEN);

        client.status();
        assertEquals("Bearer " + MockApi.SERVICE_TOKEN, mock.last().auth());
    }

    @Test
    void logoutParsesTheAcknowledgementMessage() {
        client.setToken(MockApi.TOKEN);

        assertEquals("logged out", client.auth().logout());
    }

    @Test
    void baseUrlTrailingSlashIsNormalised() throws IOException {
        try (NothingDnsClient trailing =
                     new NothingDnsClient(mock.baseUrl() + "/", null,
                             java.time.Duration.ofSeconds(5), null, null)) {
            assertEquals(mock.baseUrl(), trailing.getBaseUrl());
            assertEquals("healthy", trailing.health().getStatus());
        }
    }

    // -- status models --------------------------------------------------------

    @Test
    void statusDecodesNestedSnakeCaseModels() {
        var status = client.status();

        assertEquals("1.2.17", status.getVersion());
        assertEquals(0.9, status.getCache().getHitRatio(), 1e-9);
        assertFalse(status.getCluster().isEnabled());
        assertEquals("n1", status.getCluster().getNodeId());
    }

    // -- zones & records ------------------------------------------------------

    @Test
    void zoneListDecodesZones() {
        var zones = client.zones().list();

        assertEquals(1, zones.getTotal());
        assertFalse(zones.isTruncated());
        assertEquals("example.com", zones.getZones().get(0).getName());
        assertEquals(7, zones.getZones().get(0).getSerial());
    }

    @Test
    void recordCrudSendsContractMethodsAndBodies() {
        var records = client.zones().listRecords("example.com");
        assertEquals("192.0.2.1", records.getRecords().get(0).getData());
        // The wire field is "class"; Java exposes it as getRecordClass().
        assertEquals("IN", records.getRecords().get(0).getRecordClass());

        client.zones().addRecord("example.com", "api", "A", "192.0.2.9", 60);
        MockApi.Recorded add = mock.last();
        assertEquals("POST", add.method());
        assertEquals("/api/v1/zones/example.com/records", add.path());
        assertEquals("api", add.body().get("name").getAsString());
        assertEquals("A", add.body().get("type").getAsString());
        assertEquals("192.0.2.9", add.body().get("data").getAsString());
        assertEquals(60, add.body().get("ttl").getAsInt());

        client.zones().replaceRecord("example.com", "api", "A", "192.0.2.9", "192.0.2.10", null);
        MockApi.Recorded replace = mock.last();
        assertEquals("PUT", replace.method());
        assertEquals("192.0.2.9", replace.body().get("old_data").getAsString());
        assertFalse(replace.body().has("ttl"), "a null ttl must be omitted, not sent as null");

        client.zones().deleteRecords("example.com", "api", "A");
        MockApi.Recorded delete = mock.last();
        assertEquals("DELETE", delete.method());
        assertEquals(Set.of("name", "type"), delete.body().keySet());
        assertEquals("api", delete.body().get("name").getAsString());
        assertEquals("A", delete.body().get("type").getAsString());
    }

    @Test
    void zoneExportReturnsRawZoneFile() {
        client.setToken(MockApi.TOKEN);

        String text = client.zones().export("example.com");

        assertTrue(text.startsWith("$ORIGIN example.com."),
                "export must return the raw zone file, not JSON");
    }

    @Test
    void ptrBulkPreviewKeepsWireCamelCaseKeys() {
        var preview = client.zones().ptrBulkPreview(
                "2.0.192.in-addr.arpa", "192.0.2.0/24", "host-{ip}.example.com", false, false);

        assertTrue(preview.isPreview());
        assertEquals(256, preview.getWillAdd());
        assertEquals("host-192-0-2-1.example.com",
                preview.getChanges().get(0).getData());
        // The request keeps the wire's camelCase keys.
        JsonObject body = mock.last().body();
        assertFalse(body.get("addA").getAsBoolean());
        assertTrue(body.get("preview").getAsBoolean());
        assertEquals("192.0.2.0/24", body.get("cidr").getAsString());
        assertEquals("host-{ip}.example.com", body.get("pattern").getAsString());
    }

    @Test
    void zoneTransfersDecodesSlaveZones() {
        List<SlaveZone> slaves = client.zones().transfers();

        assertEquals("sub.example.com", slaves.get(0).getZone());
        assertEquals("synced", slaves.get(0).getStatus());
        assertEquals(12, slaves.get(0).getRecords());
    }

    // -- ACL ------------------------------------------------------------------

    @Test
    void aclRoundTrip() {
        var acl = client.acl().get();
        assertEquals("allow", acl.getRules().get(0).getAction());
        assertEquals(List.of("10.0.0.0/8"), acl.getRules().get(0).getNetworks());
        assertFalse(acl.getAllowRecursion().isAllowAll());
        assertTrue(acl.isPersistent());

        List<AclRule> rules = new ArrayList<>();
        rules.add(AclRule.of("vpn", List.of("10.1.0.0/16"), "deny"));
        assertEquals("acl updated", client.acl().set(rules));
        JsonArray sent = mock.last().body().getAsJsonArray("rules");
        assertEquals(1, sent.size());
        JsonObject sentRule = sent.get(0).getAsJsonObject();
        assertEquals("vpn", sentRule.get("name").getAsString());
        assertEquals(List.of("10.1.0.0/16"), listOf(sentRule.getAsJsonArray("networks")));
        assertEquals("deny", sentRule.get("action").getAsString());
        assertFalse(sentRule.has("redirect"), "a null field must not reach the wire");

        var recursion = client.acl().setRecursion(List.of("10.0.0.0/8"));
        assertEquals(List.of("10.0.0.0/8"), recursion.getNetworks());
        assertFalse(recursion.isAllowAll());
    }

    // -- configuration --------------------------------------------------------

    @Test
    void configPartialUpdateDropsNullFieldsAndParsesMessage() {
        String message = client.config().setLogging("debug");

        assertEquals("log level updated", message);
        assertEquals("PUT", mock.last().method());
        assertEquals(Set.of("level"), mock.last().body().keySet());
        assertEquals("debug", mock.last().body().get("level").getAsString());

        client.config().setCache(null, 5000, null, null, null, null, null, null, true, null);
        assertEquals(Set.of("size", "serve_stale"), mock.last().body().keySet(),
                "null arguments must be omitted from the body, not sent as null");
        assertEquals(5000, mock.last().body().get("size").getAsInt());
        assertTrue(mock.last().body().get("serve_stale").getAsBoolean());
    }

    // -- dashboard & metrics --------------------------------------------------

    @Test
    void dashboardStatsDecodeCamelCaseKeys() {
        var stats = client.dashboard().stats();

        assertEquals(1234, stats.getQueriesTotal());
        assertEquals(0.91, stats.getCacheHitRate(), 1e-9);
        assertEquals(7, stats.getBlockedQueries());
        assertEquals(5, stats.getZoneCount());
    }

    @Test
    void dashboardQueriesKeepCamelCaseWireNames() {
        var events = client.dashboard().queries();

        assertEquals("10.0.0.5", events.get(0).getClientIp());
        assertEquals("NL", events.get(0).getCountryCode());
        assertTrue(events.get(0).isCached());
    }

    @Test
    void queryLogSendsParamsAndDecodesSnakeCasePayload() {
        var page = client.metrics().queryLog(null, 50, "example");

        assertEquals("/api/v1/queries?limit=50&q=example", mock.last().path());
        assertEquals("10.0.0.5", page.getQueries().get(0).getClientIp());
        assertEquals(1, page.getTotal());
    }

    // -- upstreams ------------------------------------------------------------

    @Test
    void upstreamListingAndAdd() {
        var pool = client.upstreams().list();
        assertEquals(12.5, pool.getServers().get(0).getLatencyMs(), 1e-9);

        assertEquals("upstream added", client.upstreams().add("1.1.1.1:53"));
        assertEquals("PUT", mock.last().method());
        assertEquals("add", mock.last().body().get("action").getAsString());
        assertEquals("1.1.1.1:53", mock.last().body().get("server").getAsString());
    }

    // -- local validation -----------------------------------------------------

    @Test
    void localValidationRejectsBeforeAnyRequest() {
        // Unknown role, unknown log level and unknown RPZ action are all
        // rejected client-side; no request may reach the wire.
        assertThrows(IllegalArgumentException.class,
                () -> client.auth().createUser("ops", "pw-op-1", "root"));
        assertThrows(IllegalArgumentException.class,
                () -> client.config().setLogging("loud"));
        assertThrows(IllegalArgumentException.class,
                () -> client.rpz().addRule("ads.example.com", "DENY", null));

        assertTrue(mock.requests().isEmpty(),
                "a rejected call must not have sent anything");
    }

    // -- request mechanics ----------------------------------------------------

    @Test
    void pathSegmentsAreEscaped() {
        assertThrows(NothingDnsException.class, () -> client.zones().get("weird zone/name"));

        assertTrue(mock.last().path().contains("%20"), mock.last().path());
        assertTrue(mock.last().path().contains("%2F"), mock.last().path());
    }

    /** Turn a Gson string array into a {@code List<String>}. */
    private static List<String> listOf(JsonArray array) {
        List<String> out = new ArrayList<>();
        array.forEach(element -> out.add(element.getAsString()));
        return out;
    }
}
