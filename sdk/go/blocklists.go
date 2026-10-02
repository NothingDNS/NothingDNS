package nothingdns

import (
	"context"
)

// BlocklistsService handles blocklist sources and global filtering (the
// /api/v1/blocklists endpoints).
type BlocklistsService struct {
	t *Transport
}

// AddBlocklistOptions describes the source to add. Exactly one of File or URL
// must be set.
type AddBlocklistOptions struct {
	// File is the path of a hosts-format file on the server to load.
	File *string
	// URL is the HTTP(S) URL of a hosts-format list for the server to fetch.
	URL *string
}

// addBlocklistRequest is the JSON body of POST /api/v1/blocklists.
type addBlocklistRequest struct {
	File *string `json:"file,omitempty"`
	URL  *string `json:"url,omitempty"`
}

// Stats returns blocklist statistics: the enabled flag and rule counts. It
// requires the operator role or higher.
func (s *BlocklistsService) Stats(ctx context.Context) (*BlocklistStats, error) {
	var out BlocklistStats
	if err := s.t.doJSON(ctx, "GET", "/api/v1/blocklists", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Add adds a blocklist source. It requires the admin role. Exactly one of
// opts.File or opts.URL must be given; opts may be nil only if you intend the
// server to reject the request.
//
// It fails with an *ErrValidationError when neither or both are supplied.
func (s *BlocklistsService) Add(ctx context.Context, opts *AddBlocklistOptions) (string, error) {
	var body addBlocklistRequest
	hasFile, hasURL := false, false
	if opts != nil {
		body.File = opts.File
		body.URL = opts.URL
		hasFile = opts.File != nil && *opts.File != ""
		hasURL = opts.URL != nil && *opts.URL != ""
	}
	if hasFile == hasURL {
		return "", &ErrValidationError{Message: "pass exactly one of File or URL"}
	}
	return s.t.doMessage(ctx, "POST", "/api/v1/blocklists", nil, body)
}

// Sources lists every configured blocklist source. It requires the operator
// role or higher.
//
// It returns one entry per source with its type, enabled flag and the number
// of domains it contributes.
func (s *BlocklistsService) Sources(ctx context.Context) ([]BlocklistSource, error) {
	var out []BlocklistSource
	if err := s.t.doJSON(ctx, "GET", "/api/v1/blocklists/sources", nil, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Toggle flips blocklist filtering on/off globally. It requires the admin
// role. The toggle is server-side, so call Stats to see the result. It returns
// the server's confirmation message.
func (s *BlocklistsService) Toggle(ctx context.Context) (string, error) {
	return s.t.doMessage(ctx, "POST", "/api/v1/blocklists/toggle", nil, nil)
}

// Remove removes one blocklist source by id. It requires the admin role.
// source is the source id as reported by Sources. It returns the server's
// confirmation message.
func (s *BlocklistsService) Remove(ctx context.Context, source string) (string, error) {
	return s.t.doMessage(ctx, "DELETE", "/api/v1/blocklists/"+s.t.escape(source), nil, nil)
}

// ToggleSource enables or disables a single blocklist source. It requires the
// admin role. It returns the server's confirmation message.
func (s *BlocklistsService) ToggleSource(ctx context.Context, source string) (string, error) {
	return s.t.doMessage(ctx, "POST", "/api/v1/blocklists/"+s.t.escape(source)+"/toggle", nil, nil)
}
