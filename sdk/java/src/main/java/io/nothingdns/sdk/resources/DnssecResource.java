package io.nothingdns.sdk.resources;

import io.nothingdns.sdk.NothingDnsTransport;
import io.nothingdns.sdk.model.DnssecKey;
import io.nothingdns.sdk.model.DnssecStatus;

/**
 * DNSSEC validation status and signing keys ({@code /api/v1/dnssec}).
 *
 * <p>Obtained from {@code client.dnssec()}. Reading the validation status
 * needs operator; reading signing-key metadata needs admin.</p>
 */
public final class DnssecResource extends ApiResource {

    /**
     * Create the DNSSEC namespace.
     *
     * @param transport the shared transport
     */
    public DnssecResource(NothingDnsTransport transport) {
        super(transport);
    }

    /**
     * Read the DNSSEC validation status (operator+).
     *
     * @return the status
     * @throws io.nothingdns.sdk.NothingDnsException 401 or 403 when the caller
     *                                                is below operator
     */
    public DnssecStatus status() {
        return model(transport.get("/api/v1/dnssec/status"), DnssecStatus.class);
    }

    /**
     * List the DNSSEC signing keys (admin).
     *
     * <p>Only public metadata is returned: key tags, algorithms and flags. No
     * private key material leaves the server.</p>
     *
     * @return the keys
     * @throws io.nothingdns.sdk.NothingDnsException 403 when the caller is not an
     *                                                admin
     */
    public DnssecKey.DnssecKeyList keys() {
        return model(transport.get("/api/v1/dnssec/keys"), DnssecKey.DnssecKeyList.class);
    }
}
