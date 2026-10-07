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
