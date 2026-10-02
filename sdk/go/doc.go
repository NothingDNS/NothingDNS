// Package nothingdns is a typed, dependency-free Go client for the
// NothingDNS management API.
//
// # Getting started
//
// Create a [Client], log in, and use the resource namespaces:
//
//	client := nothingdns.NewClient("http://dns.example.com:8080", "", 0, nil, nil)
//	defer client.Close()
//
//	ctx := context.Background()
//	if _, err := client.Auth.Login(ctx, os.Getenv("NDNS_USER"), os.Getenv("NDNS_PASSWORD"), true); err != nil {
//	    log.Fatal(err)
//	}
//
//	zones, err := client.Zones.List(ctx)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for _, z := range zones.Zones {
//	    fmt.Println(z.Name, z.Records)
//	}
//
// The client mirrors the server's API groups as namespaces: [Client.Auth],
// [Client.Zones], [Client.Cache], [Client.Config], [Client.ACL],
// [Client.Blocklists], [Client.RPZ], [Client.DNSSEC], [Client.Upstreams],
// [Client.GeoIP], [Client.Cluster], [Client.Dashboard] and [Client.Metrics],
// plus top-level health, status, OpenAPI and API-docs helpers on the Client
// itself.
//
// # Authentication
//
// Authenticate in one of two ways:
//
//   - Interactive: call [AuthService.Login] with a username and password, or
//     [AuthService.Bootstrap] to create the first admin. The returned token is
//     stored on the client automatically, so later calls are authenticated.
//   - Static: construct the client with the server's configured
//     server.http.auth_token value as the token, or call [Client.SetToken].
//
// # Concurrency
//
// A [Client] and its underlying [Transport] are safe for concurrent use by
// multiple goroutines as long as the token is not changed while requests are
// in flight. Every method takes a [context.Context] as its first argument so
// calls can be cancelled and given deadlines.
//
// # Errors
//
// Every non-2xx response is returned as an *[ErrAPIError], which carries the
// status code, the server's message and the decoded payload. A server that
// cannot be reached yields an *[ErrConnectionError], and a body that cannot be
// decoded — or an argument that fails local validation — yields an
// *[ErrValidationError]. Use [IsNotFound], [IsUnauthorized], [IsForbidden] and
// [IsRateLimited] (or errors.Is with the package sentinels) to branch on the
// semantic failure:
//
//	if _, err := client.Zones.Get(ctx, "example.com"); IsNotFound(err) {
//	    // the zone does not exist
//	}
//
// # Roles
//
// The server enforces a viewer < operator < admin role hierarchy. Reads
// generally require operator, mutations require admin, and health probes and
// the current session require any authenticated user.
package nothingdns
