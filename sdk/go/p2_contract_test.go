package nothingdns

// Contract tests for the API surface changed in phase 2 (F553): the
// config_defined flag on GET /api/v1/auth/users, single-record delete
// (DELETE /zones/{zone}/records with data, 404 when nothing matches) and the
// 400/409 answers the server now gives for refused input.

import (
	"context"
	"errors"
	"testing"
)

func TestListUsersDecodesConfigDefined(t *testing.T) {
	m := newMockAPI(t)
	c := newTestClient(t, m)
	c.SetToken(testToken)

	users, err := c.Auth.ListUsers(context.Background())
	wantNoError(t, err)
	if len(users) != 2 {
		t.Fatalf("users: got %d, want 2", len(users))
	}
	wantEqual(t, "root config_defined", users[0].ConfigDefined, true)
	wantEqual(t, "ops config_defined", users[1].ConfigDefined, false)
}

func TestDeleteRecordSendsDataAndMaps404(t *testing.T) {
	m := newMockAPI(t)
	c := newTestClient(t, m)
	c.SetToken(testToken)
	ctx := context.Background()

	message, err := c.Zones.DeleteRecord(ctx, "example.com", "api", "A", "192.0.2.9")
	wantNoError(t, err)
	wantEqual(t, "delete ack", message, "records deleted")
	rec := m.last()
	wantEqual(t, "delete method", rec.Method, "DELETE")
	wantEqual(t, "delete path", rec.Path, "/api/v1/zones/example.com/records")
	wantEqual(t, "delete body", bodyJSON(t, rec), `{"data":"192.0.2.9","name":"api","type":"A"}`)

	_, err = c.Zones.DeleteRecord(ctx, "example.com", "api", "A", "192.0.2.250")
	wantTrue(t, IsNotFound(err), "no matching record is a 404")

	before := m.count()
	_, err = c.Zones.DeleteRecord(ctx, "example.com", "api", "A", "  ")
	var verr *ErrValidationError
	wantTrue(t, errors.As(err, &verr), "blank data is refused locally (it would widen to the whole RRset)")
	wantEqual(t, "no request sent for blank data", m.count(), before)
}

func TestConflictAndBadRequestMapToSentinels(t *testing.T) {
	m := newMockAPI(t)
	c := newTestClient(t, m)
	c.SetToken(testToken)
	ctx := context.Background()

	_, err := c.Auth.DeleteUser(ctx, "root")
	var apiErr *ErrAPIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *ErrAPIError, got %T: %v", err, err)
	}
	wantEqual(t, "status", apiErr.StatusCode, 409)
	wantTrue(t, IsConflict(err), "409 is a conflict")
	wantTrue(t, errors.Is(err, ErrConflict), "errors.Is ErrConflict")
	wantTrue(t, !IsBadRequest(err), "409 is not a bad request")
	wantEqual(t, "message", apiErr.Message, "user is defined in the config file; change it there")

	_, err = c.Upstreams.Add(ctx, "9.9.9.9")
	wantTrue(t, IsBadRequest(err), "port-less upstream is a 400")
	wantTrue(t, errors.Is(err, ErrBadRequest), "errors.Is ErrBadRequest")
	wantTrue(t, !IsConflict(err), "400 is not a conflict")

	wantTrue(t, !IsConflict(errors.New("nope")), "plain error is not a 409")
	wantTrue(t, !IsBadRequest(nil), "nil error is not a 400")
}

// Issue #18: POST /api/v1/auth/password and PUT /api/v1/auth/users/{username};
// per-name cache flush (POST /api/v1/cache/flush?name=).

func TestChangePasswordStoresRotatedToken(t *testing.T) {
	m := newMockAPI(t)
	c := newTestClient(t, m)
	c.SetToken(testToken)
	ctx := context.Background()

	session, err := c.Auth.ChangePassword(ctx, testPassword, "new-password-1", true)
	wantNoError(t, err)
	wantEqual(t, "new token", session.Token, "rotated-token")
	wantEqual(t, "client switched token", c.Token(), "rotated-token")
	rec := m.last()
	wantEqual(t, "method", rec.Method, "POST")
	wantEqual(t, "path", rec.Path, "/api/v1/auth/password")
	wantEqual(t, "body", bodyJSON(t, rec), `{"new_password":"new-password-1","old_password":"`+testPassword+`"}`)

	_, err = c.Auth.ChangePassword(ctx, "wrong", "new-password-2", true)
	wantTrue(t, IsBadRequest(err), "wrong current password is a 400")
	wantEqual(t, "token kept after failure", c.Token(), "rotated-token")
}

func TestUpdateUserSendsOnlySetFields(t *testing.T) {
	m := newMockAPI(t)
	c := newTestClient(t, m)
	c.SetToken(testToken)
	ctx := context.Background()

	user, err := c.Auth.UpdateUser(ctx, "ops", "", "admin")
	wantNoError(t, err)
	wantEqual(t, "role", user.Role, "admin")
	rec := m.last()
	wantEqual(t, "method", rec.Method, "PUT")
	wantEqual(t, "path", rec.Path, "/api/v1/auth/users/ops")
	wantEqual(t, "body", bodyJSON(t, rec), `{"role":"admin"}`)

	_, err = c.Auth.UpdateUser(ctx, "root", "reset-pass-123", "")
	wantTrue(t, IsConflict(err), "config-defined user is a 409")

	before := m.count()
	var verr *ErrValidationError
	_, err = c.Auth.UpdateUser(ctx, "ops", "", "")
	wantTrue(t, errors.As(err, &verr), "empty update is refused locally")
	_, err = c.Auth.UpdateUser(ctx, "ops", "", "superuser")
	wantTrue(t, errors.As(err, &verr), "unknown role is refused locally")
	wantEqual(t, "no request sent", m.count(), before)
}

func TestFlushNameSendsQuery(t *testing.T) {
	m := newMockAPI(t)
	c := newTestClient(t, m)
	c.SetToken(testToken)
	ctx := context.Background()

	_, _ = c.Cache.FlushName(ctx, "www.example.com")
	rec := m.last()
	wantEqual(t, "method", rec.Method, "POST")
	wantEqual(t, "path", rec.Path, "/api/v1/cache/flush?name=www.example.com")

	before := m.count()
	var verr *ErrValidationError
	_, err := c.Cache.FlushName(ctx, "")
	wantTrue(t, errors.As(err, &verr), "empty name is refused locally")
	wantEqual(t, "no request sent", m.count(), before)
}

// Issue #19: GET/PUT /api/v1/zones/{zone}/soa and SOA timers on zone create.

func TestUpdateSOASendsOnlySetFields(t *testing.T) {
	m := newMockAPI(t)
	c := newTestClient(t, m)
	c.SetToken(testToken)
	ctx := context.Background()

	soa, err := c.Zones.GetSOA(ctx, "example.com")
	wantNoError(t, err)
	wantEqual(t, "get ttl", soa.TTL, 3600)
	wantEqual(t, "get path", m.last().Path, "/api/v1/zones/example.com/soa")

	rname, minimum := "dns@example.com", 60
	soa, err = c.Zones.UpdateSOA(ctx, "example.com", SOAUpdate{RName: &rname, Minimum: &minimum})
	wantNoError(t, err)
	wantEqual(t, "serial bumped", soa.Serial, int64(8))
	wantEqual(t, "rname", soa.RName, "dns.example.com.")
	wantEqual(t, "minimum", soa.Minimum, 60)
	rec := m.last()
	wantEqual(t, "method", rec.Method, "PUT")
	wantEqual(t, "path", rec.Path, "/api/v1/zones/example.com/soa")
	wantEqual(t, "body", bodyJSON(t, rec), `{"minimum":60,"rname":"dns@example.com"}`)

	retry := 3600
	_, err = c.Zones.UpdateSOA(ctx, "example.com", SOAUpdate{Retry: &retry})
	wantTrue(t, IsBadRequest(err), "retry >= refresh is a 400")

	before := m.count()
	var verr *ErrValidationError
	_, err = c.Zones.UpdateSOA(ctx, "example.com", SOAUpdate{})
	wantTrue(t, errors.As(err, &verr), "empty update is refused locally")
	wantEqual(t, "no request sent", m.count(), before)
}

func TestCreateZoneSendsSOATimers(t *testing.T) {
	m := newMockAPI(t)
	c := newTestClient(t, m)
	c.SetToken(testToken)

	refresh, minimum := 7200, 300
	_, _ = c.Zones.Create(context.Background(), "new.example", []string{"ns1.new.example"},
		&CreateZoneOptions{Refresh: &refresh, Minimum: &minimum})
	wantEqual(t, "body", bodyJSON(t, m.last()), `{"minimum":300,"name":"new.example","nameservers":["ns1.new.example"],"refresh":7200}`)
}
