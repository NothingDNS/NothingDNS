using System.Text.Json;

namespace NothingDns.Sdk;

/// <summary>
/// The role names recognised by the NothingDNS server, ordered
/// <c>viewer &lt; operator &lt; admin</c>.
/// </summary>
public static class NothingDnsRoles
{
    /// <summary>Read-only access to zones, cache, status and statistics.</summary>
    public const string Viewer = "viewer";

    /// <summary>Everything a viewer can do, plus zone and record mutations and configuration reads.</summary>
    public const string Operator = "operator";

    /// <summary>Full control, including user management, cache flush and runtime configuration changes.</summary>
    public const string Admin = "admin";

    /// <summary>All valid role names, ordered from least to most privileged.</summary>
    public static readonly IReadOnlyList<string> All = new[] { Viewer, Operator, Admin };
}

/// <summary>
/// Authentication, user accounts and the server's role table
/// (<c>/api/v1/auth</c>).
/// </summary>
/// <remarks>
/// <para>
/// This namespace owns credential <em>acquisition</em>: it is the only place in
/// the SDK that builds a request body containing a password. Credential
/// <em>transmission</em> — the <c>Authorization: Bearer</c> header — belongs to
/// <see cref="NothingDnsTransport"/>, which every namespace shares. The two
/// concerns live in separate files so the code that sends a secret and the code
/// that attaches the resulting token are never mixed together.
/// </para>
/// <para>
/// A successful <see cref="LoginAsync"/> or <see cref="BootstrapAsync"/> stores the
/// returned token on the transport by default, so every later call on the client
/// is authenticated automatically.
/// </para>
/// </remarks>
public sealed class NothingDnsAuth
{
    private readonly NothingDnsTransport _transport;

    /// <summary>Initializes a new instance of the <see cref="NothingDnsAuth"/> class.</summary>
    /// <param name="transport">The shared transport used to reach the server.</param>
    /// <exception cref="ArgumentNullException"><paramref name="transport"/> is <see langword="null"/>.</exception>
    public NothingDnsAuth(NothingDnsTransport transport)
    {
        _transport = transport ?? throw new ArgumentNullException(nameof(transport));
    }

    /// <summary>Log in and receive a bearer token.</summary>
    /// <param name="username">Account name.</param>
    /// <param name="password">Account password.</param>
    /// <param name="storeToken">
    /// When <see langword="true"/> (the default), the returned token is kept on the
    /// client so later calls are authenticated automatically.
    /// </param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The session describing the token, the account and its role.</returns>
    /// <exception cref="ArgumentException"><paramref name="username"/> or <paramref name="password"/> is empty.</exception>
    /// <exception cref="NothingDnsApiException">
    /// 400 for a malformed request, 401 for bad credentials, or 429 when the login
    /// rate limit is hit.
    /// </exception>
    public async Task<Session> LoginAsync(
        string username,
        string password,
        bool storeToken = true,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(username);
        ArgumentException.ThrowIfNullOrEmpty(password);

        var body = NothingDnsTransport.Body(("username", username), ("password", password));
        var payload = await _transport
            .PostAsync("/api/v1/auth/login", body, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return Store(payload, storeToken);
    }

    /// <summary>Create the first admin account, or reset an existing account's password.</summary>
    /// <param name="username">New (or first) admin account name.</param>
    /// <param name="password">New password for the account.</param>
    /// <param name="oldPassword">
    /// Current password of the account being reset. Required when resetting an
    /// existing account rather than performing the initial bootstrap.
    /// </param>
    /// <param name="storeToken">
    /// When <see langword="true"/> (the default), the returned token is kept on the
    /// client.
    /// </param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The session for the account that was created or reset.</returns>
    /// <exception cref="ArgumentException"><paramref name="username"/> or <paramref name="password"/> is empty.</exception>
    /// <exception cref="NothingDnsApiException">
    /// 401 when <paramref name="oldPassword"/> is wrong, 403 when the change is not
    /// permitted for the caller, or 409 when the server already has an admin and no
    /// old password was supplied.
    /// </exception>
    public async Task<Session> BootstrapAsync(
        string username,
        string password,
        string? oldPassword = null,
        bool storeToken = true,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(username);
        ArgumentException.ThrowIfNullOrEmpty(password);

        var body = NothingDnsTransport.Body(
            ("username", username),
            ("password", password),
            ("old_password", oldPassword));

        var payload = await _transport
            .PostAsync("/api/v1/auth/bootstrap", body, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return Store(payload, storeToken);
    }

    /// <summary>Return the current session: token, username and role.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The active session as the server sees it.</returns>
    /// <exception cref="NothingDnsApiException">
    /// 401 when the token is missing or expired, or 405 when the endpoint is not
    /// available on this server build. The server rejects the legacy static
    /// <c>auth_token</c> for this call — a real login session is required.
    /// </exception>
    public async Task<Session> SessionAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .GetAsync("/api/v1/auth/session", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.Model<Session>(payload);
    }

    /// <summary>Invalidate the current session on the server and forget the local token.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The server's confirmation message.</returns>
    /// <exception cref="NothingDnsApiException">401 when the session is already invalid.</exception>
    public async Task<string> LogoutAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .PostAsync("/api/v1/auth/logout", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        _transport.ClearToken();
        return NothingDnsTransport.MessageOf(payload);
    }

    /// <summary>List the roles the server knows about.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The role table, in the server's own order.</returns>
    /// <exception cref="NothingDnsApiException">401 or 403 when the caller's role is insufficient (operator required).</exception>
    public async Task<IReadOnlyList<Role>> RolesAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .GetAsync("/api/v1/auth/roles", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.ListOf<Role>(payload, "roles");
    }

    /// <summary>List every user account.</summary>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>All accounts. Passwords are never returned by the API.</returns>
    /// <exception cref="NothingDnsApiException">401 or 403 when the caller's role is insufficient (operator required).</exception>
    public async Task<IReadOnlyList<User>> ListUsersAsync(CancellationToken cancellationToken = default)
    {
        var payload = await _transport
            .GetAsync("/api/v1/auth/users", cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.ListOf<User>(payload);
    }

    /// <summary>Create a user account.</summary>
    /// <param name="username">New account name; must be unique on this server.</param>
    /// <param name="password">Password for the new account.</param>
    /// <param name="role">
    /// The role to grant: <see cref="NothingDnsRoles.Viewer"/>,
    /// <see cref="NothingDnsRoles.Operator"/> or <see cref="NothingDnsRoles.Admin"/>.
    /// Defaults to <see cref="NothingDnsRoles.Viewer"/>.
    /// </param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The created account.</returns>
    /// <exception cref="ArgumentException"><paramref name="username"/> or <paramref name="password"/> is empty.</exception>
    /// <exception cref="NothingDnsValidationException"><paramref name="role"/> is not a known role.</exception>
    /// <exception cref="NothingDnsApiException">
    /// 403 when the caller is not an admin, or 409 when the username already exists.
    /// </exception>
    public async Task<User> CreateUserAsync(
        string username,
        string password,
        string role = NothingDnsRoles.Viewer,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(username);
        ArgumentException.ThrowIfNullOrEmpty(password);

        if (!NothingDnsRoles.All.Contains(role, StringComparer.Ordinal))
        {
            throw new NothingDnsValidationException(
                $"role must be one of {string.Join(", ", NothingDnsRoles.All)}, but was '{role}'.");
        }

        var body = NothingDnsTransport.Body(
            ("username", username),
            ("password", password),
            ("role", role));

        var payload = await _transport
            .PostAsync("/api/v1/auth/users", body, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.Model<User>(payload);
    }

    /// <summary>Delete a user account by name, using the path-parameter form of the endpoint.</summary>
    /// <param name="username">The account to remove.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The server's confirmation message.</returns>
    /// <exception cref="ArgumentException"><paramref name="username"/> is empty.</exception>
    /// <exception cref="NothingDnsApiException">
    /// 403 when the caller is not an admin, or 404 when the account does not exist.
    /// </exception>
    public async Task<string> DeleteUserAsync(string username, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(username);

        var payload = await _transport
            .DeleteAsync(
                $"/api/v1/auth/users/{NothingDnsTransport.Escape(username)}",
                cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.MessageOf(payload);
    }

    /// <summary>
    /// Delete a user account by name, using the query-parameter form of the
    /// endpoint (<c>DELETE /api/v1/auth/users?username=…</c>).
    /// </summary>
    /// <param name="username">The account to remove.</param>
    /// <param name="cancellationToken">Token to cancel the request.</param>
    /// <returns>The server's confirmation message.</returns>
    /// <exception cref="ArgumentException"><paramref name="username"/> is empty.</exception>
    /// <exception cref="NothingDnsApiException">
    /// 403 when the caller is not an admin, or 404 when the account does not exist.
    /// </exception>
    /// <remarks>
    /// The server exposes both forms of this route. <see cref="DeleteUserAsync"/>
    /// uses the path form and is the one you normally want; this overload exists
    /// for parity with the raw contract.
    /// </remarks>
    public async Task<string> DeleteUserByQueryAsync(
        string username,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(username);

        var query = new[] { new KeyValuePair<string, object?>("username", username) };
        var payload = await _transport
            .DeleteAsync("/api/v1/auth/users", query: query, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        return NothingDnsTransport.MessageOf(payload);
    }

    private Session Store(JsonElement payload, bool storeToken)
    {
        var session = NothingDnsTransport.Model<Session>(payload);
        if (storeToken && !string.IsNullOrEmpty(session.Token))
        {
            _transport.SetToken(session.Token);
        }

        return session;
    }
}
