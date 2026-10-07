package dnssec

import (
	"bytes"
	"context"
	"crypto/sha1" // #nosec G505 -- required for DS digest algorithm 1 (RFC 4034 §5.1.2)
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nothingdns/nothingdns/internal/protocol"
)

// ValidationResult represents the outcome of DNSSEC validation.
type ValidationResult int

const (
	// ValidationSecure indicates the response passed DNSSEC validation.
	ValidationSecure ValidationResult = iota
	// ValidationInsecure indicates the zone is not signed or no DNSSEC info available.
	ValidationInsecure
	// ValidationBogus indicates DNSSEC validation failed (bad signature, expired, etc).
	ValidationBogus
	// ValidationIndeterminate indicates the validator couldn't determine the status.
	ValidationIndeterminate
)

func (r ValidationResult) String() string {
	switch r {
	case ValidationSecure:
		return "SECURE"
	case ValidationInsecure:
		return "INSECURE"
	case ValidationBogus:
		return "BOGUS"
	case ValidationIndeterminate:
		return "INDETERMINATE"
	default:
		return "UNKNOWN"
	}
}

// Resolver interface for fetching DNS records during validation.
type Resolver interface {
	// Query sends a DNS query and returns the response.
	Query(ctx context.Context, name string, qtype uint16) (*protocol.Message, error)
}

// ValidatorConfig holds validation settings.
type ValidatorConfig struct {
	// Enabled enables DNSSEC validation.
	Enabled bool

	// RequireDNSSEC fails validation if DNSSEC info unavailable.
	RequireDNSSEC bool

	// IgnoreTime ignores signature timestamps (for testing).
	IgnoreTime bool

	// MaxDelegationDepth limits chain validation depth.
	MaxDelegationDepth int

	// ClockSkew allows for time difference between systems.
	ClockSkew time.Duration

	// ValidationCacheTTL is the TTL for cached validation results.
	// If zero, caching is disabled.
	ValidationCacheTTL time.Duration
}

// DefaultValidatorConfig returns recommended validation settings.
func DefaultValidatorConfig() ValidatorConfig {
	return ValidatorConfig{
		Enabled:            true,
		RequireDNSSEC:      false,
		IgnoreTime:         false,
		MaxDelegationDepth: 20,
		ClockSkew:          5 * time.Minute,
		ValidationCacheTTL: 5 * time.Minute,
	}
}

// Validator performs DNSSEC validation.
type Validator struct {
	config          ValidatorConfig
	trustAnchors    *TrustAnchorStore
	resolver        Resolver
	validationCache *ValidationCache

	// work is the per-response verification budget (F408). It is nil on
	// the shared Validator; ValidateResponse runs on a per-call shallow copy
	// carrying a fresh budget, so concurrent responses never share one.
	work *responseBudget

	// zoneCuts caches authenticated zone-cut proofs across responses
	// (F477); shared by the per-call copies. nil disables caching.
	zoneCuts *zoneCutCache
	// now is the validator's clock; nil means time.Now (tests inject one).
	now func() time.Time
}

// NewValidator creates a new DNSSEC validator.
func NewValidator(config ValidatorConfig, anchors *TrustAnchorStore, resolver Resolver) *Validator {
	if anchors == nil {
		anchors = NewTrustAnchorStoreWithBuiltIn()
	}
	if config.MaxDelegationDepth == 0 {
		config.MaxDelegationDepth = 20
	}
	if config.ClockSkew == 0 {
		config.ClockSkew = 5 * time.Minute
	}

	return &Validator{
		config:          config,
		trustAnchors:    anchors,
		resolver:        resolver,
		validationCache: newValidationCacheIfNeeded(config),
		zoneCuts:        newZoneCutCache(maxZoneCutCacheEntries),
	}
}

func newValidationCacheIfNeeded(config ValidatorConfig) *ValidationCache {
	if config.ValidationCacheTTL <= 0 {
		return nil
	}
	return NewValidationCache(config.ValidationCacheTTL)
}

// DNSSECStatus returns the current DNSSEC validation status.
func (v *Validator) DNSSECStatus() DNSSECStatus {
	return DNSSECStatus{
		Enabled:       v.config.Enabled,
		RequireDNSSEC: v.config.RequireDNSSEC,
	}
}

// DNSSECStatus holds DNSSEC configuration status for the API.
type DNSSECStatus struct {
	Enabled       bool `json:"enabled"`
	RequireDNSSEC bool `json:"require_dnssec"`
}

// ValidateResponse validates a DNS response message.
//
// All cryptographic work for one response — chain building (including the
// chains of other zones reached through CNAME/DNAME owners) and the message
// itself — is charged against one per-response budget of signature
// verifications and NSEC3 hash computations (F408). Exceeding it fails
// closed: the response is Bogus.
func (v *Validator) ValidateResponse(ctx context.Context, msg *protocol.Message, queryName string) (ValidationResult, error) {
	return v.validateResponseBudget(ctx, msg, queryName, newResponseBudget())
}

// validateResponseBudget is ValidateResponse charging all work to b.
func (v *Validator) validateResponseBudget(ctx context.Context, msg *protocol.Message, queryName string, b *responseBudget) (ValidationResult, error) {
	if !v.config.Enabled {
		return ValidationInsecure, nil
	}
	session := *v
	session.work = b
	v = &session

	if msg == nil {
		return ValidationBogus, fmt.Errorf("nil message")
	}

	// Extract qtype for cache key
	var qtype uint16
	if len(msg.Questions) > 0 {
		qtype = msg.Questions[0].QType
	}

	// Cache short-circuit: deliberately DISABLED for ValidationSecure.
	//
	// The previous design cached the outcome (Secure/Insecure/Bogus)
	// keyed by (queryName, qtype) for ValidationCacheTTL (5m default)
	// and returned the cached value before checking the *current*
	// message's signatures. That's a validation bypass: an attacker
	// who can deliver a forged response for (queryName, qtype) within
	// the cache window — having an ID-and-port-matched response
	// already passed the transport layer — would inherit the
	// previously-cached "Secure" verdict without their forged RRSIG
	// being checked at all.
	//
	// Safe-to-cache outcomes are limited to "no trust anchor / chain
	// definitively broken" — properties of the zone hierarchy that
	// don't depend on the specific RRSet+RRSIG in `msg`. Keep that
	// caching; drop the post-validateMessage cache write below.
	if v.validationCache != nil && qtype != 0 {
		if result, ok := v.validationCache.Get(queryName, qtype); ok {
			// Only honor cached Insecure (no DNSSEC for this name) or
			// Bogus-from-chain-build entries. A cached Secure here
			// would be the bypass.
			if result == ValidationInsecure {
				return result, nil
			}
			// Bogus from chain build (no anchor / chain-walk failure)
			// is also stable per-zone for the cache window. Per-msg
			// Bogus from validateMessage we DON'T cache below.
		}
	}

	// Build the chain down to the zone that signed the answer (RRSIG signer
	// name), not necessarily the query name: names such as www.example.org
	// are not zone cuts, and walking every label with DS queries both wastes
	// round trips and trips over upstreams that mishandle DS queries for
	// non-delegation names. Only a signer that is an ancestor of the query
	// name is honoured, and its keys must still verify the signatures.
	chainTarget := signingZone(msg, queryName)

	// Find closest trust anchor
	anchor, remaining := v.trustAnchors.FindClosestAnchor(chainTarget)
	if anchor == nil {
		if v.config.RequireDNSSEC {
			return ValidationBogus, fmt.Errorf("no trust anchor found for %s", queryName)
		}
		result := ValidationInsecure
		if v.validationCache != nil && qtype != 0 {
			v.validationCache.Set(queryName, qtype, result)
		}
		return result, nil
	}

	// Build validation chain from anchor to query name
	chain, insecure, err := v.buildChain(ctx, anchor, remaining)
	if v.work.exceeded {
		return ValidationBogus, errWorkBudgetExceeded
	}
	if err != nil {
		// A chain FETCH failure (network/upstream, not crypto) proves
		// nothing about the zone: return Indeterminate, not Bogus. The
		// caller still fails closed (SERVFAIL) — treating it as Bogus
		// would only mislabel the EDE and pollute Bogus metrics/logs on
		// every transient upstream blip. Actual verification failures
		// (bad self-signature, unsigned DS, denial-proof gaps) stay Bogus.
		var fetchErr *chainFetchError
		if errors.As(err, &fetchErr) {
			return ValidationIndeterminate, fmt.Errorf("building validation chain: %w", err)
		}
		return ValidationBogus, fmt.Errorf("building validation chain: %w", err)
	}

	// The chain terminated at a proven-unsigned delegation: the query name is
	// in an Insecure subtree, so its records legitimately carry no signatures.
	// Return Insecure (not Secure — that would set AD on unsigned data, and not
	// Bogus — that would break every unsigned domain under a signed parent).
	if insecure {
		result := ValidationInsecure
		if v.validationCache != nil && qtype != 0 {
			v.validationCache.Set(queryName, qtype, result)
		}
		return result, nil
	}

	// Chain is fully signed down to the query name's zone. Validate the answer
	// against THIS message's signatures. Always. Do not cache the per-message
	// outcome — see comment above.
	result := v.validateMessage(ctx, msg, queryName, chain)
	if v.work.exceeded {
		return ValidationBogus, errWorkBudgetExceeded
	}
	return result, nil
}

// Per-response work budget (F408, KeyTrap CVE-2023-50387 / CVE-2023-50868).
// The per-RRset and per-section caps bound each step, but not their sum: a
// response with 32 Answer RRsets, each reached through its own chain whose
// every label needs a signed denial proof, multiplied them (about 1400
// signature verifications and 1300 NSEC3 hashes at 150 iterations for 31
// owners x 40 labels). A legitimate response — 10 RRsets behind a 3-link
// chain in the middle of a KSK + ZSK rollover — needs about 15 verifications.
const (
	maxSigVerificationsPerResponse = 128
	maxNSEC3HashesPerResponse      = 512
	// maxZoneCutLookupsPerResponse bounds the DS lookups made to prove there
	// is no zone cut between an RRSIG signer and an owner more than one label
	// below it (F472). A deep reverse-IPv6 PTR under a /32 zone needs 23.
	maxZoneCutLookupsPerResponse = 64
)

var errWorkBudgetExceeded = errors.New("DNSSEC per-response verification budget exceeded")

// responseBudget counts the expensive operations performed for one response.
// It is used by a single goroutine (one ValidateResponse call).
type responseBudget struct {
	sigLimit, hashLimit, lookupLimit int
	sigs, hashes, lookups            int // operations charged so far
	exceeded                         bool
}

func newResponseBudget() *responseBudget {
	return &responseBudget{sigLimit: maxSigVerificationsPerResponse, hashLimit: maxNSEC3HashesPerResponse,
		lookupLimit: maxZoneCutLookupsPerResponse}
}

// chargeSig reserves one signature verification. It reports false (and marks
// the budget exceeded) once the response's allowance is spent. Without a
// budget (internal callers outside ValidateResponse) it always succeeds.
func (v *Validator) chargeSig() bool {
	b := v.work
	if b == nil {
		return true
	}
	if b.sigs >= b.sigLimit {
		b.exceeded = true
		return false
	}
	b.sigs++
	return true
}

// chargeHash reserves one NSEC3 hash computation; see chargeSig.
func (v *Validator) chargeHash() bool {
	b := v.work
	if b == nil {
		return true
	}
	if b.hashes >= b.hashLimit {
		b.exceeded = true
		return false
	}
	b.hashes++
	return true
}

// chargeLookup reserves one zone-cut DS lookup (F472); see chargeSig.
func (v *Validator) chargeLookup() bool {
	b := v.work
	if b == nil {
		return true
	}
	if b.lookups >= b.lookupLimit {
		b.exceeded = true
		return false
	}
	b.lookups++
	return true
}

// nsec3Hash is NSEC3Hash charged against the response budget.
func (v *Validator) nsec3Hash(name string, algorithm uint8, iterations uint16, salt []byte) ([]byte, error) {
	if !v.chargeHash() {
		return nil, errWorkBudgetExceeded
	}
	return NSEC3Hash(name, algorithm, iterations, salt)
}

// signingZone returns the zone whose signatures authenticate msg for
// queryName: the RRSIG signer of the query name's own answer RRset or, for a
// negative answer, of the Authority records. It falls back to queryName when
// no usable signer is present (an unsigned answer must be proven insecure by
// walking the delegations down to the name).
func signingZone(msg *protocol.Message, queryName string) string {
	pick := func(rrs []*protocol.ResourceRecord, ownerMustMatch bool) string {
		for _, rr := range rrs {
			if rr == nil || rr.Name == nil || rr.Type != protocol.TypeRRSIG {
				continue
			}
			if ownerMustMatch && !sameDNSName(rr.Name.String(), queryName) {
				continue
			}
			sig, ok := rr.Data.(*protocol.RDataRRSIG)
			if !ok || sig.SignerName == nil {
				continue
			}
			signer := sig.SignerNameString()
			if inBailiwick(queryName, signer) {
				return canonicalZone(signer)
			}
		}
		return ""
	}
	if zone := pick(msg.Answers, true); zone != "" {
		return zone
	}
	// A query name below a DNAME owns only the unsigned synthesized CNAME:
	// the DNAME's signer authenticates it (F527). Walking the chain down to
	// the query name instead would ask for DS at names the DNAME occludes.
	if zone := dnameSigner(msg.Answers, queryName); zone != "" {
		return zone
	}
	if len(msg.Answers) == 0 {
		if zone := pick(msg.Authorities, false); zone != "" {
			return zone
		}
	}
	return queryName
}

// chainResult caches a chain built for a signer zone while validating one
// message.
type chainResult struct {
	chain    []*chainLink
	insecure bool
	err      error
}

// chainFor builds (once per message) the validation chain for name.
func (v *Validator) chainFor(ctx context.Context, name string, memo map[string]chainResult) chainResult {
	key := canonicalZone(name)
	if r, ok := memo[key]; ok {
		return r
	}
	var r chainResult
	anchor, remaining := v.trustAnchors.FindClosestAnchor(key)
	if anchor == nil {
		r.insecure = true
	} else {
		r.chain, r.insecure, r.err = v.buildChain(ctx, anchor, remaining)
	}
	memo[key] = r
	return r
}

// chainFetchError marks a chain-build failure caused by the FETCH of
// DNSKEY/DS material (network, upstream, resolver), as opposed to a
// cryptographic verification failure. ValidateResponse maps it to
// Indeterminate instead of Bogus.
type chainFetchError struct {
	err error
}

func (e *chainFetchError) Error() string { return e.err.Error() }
func (e *chainFetchError) Unwrap() error { return e.err }

// chainLink represents one link in the validation chain.
type chainLink struct {
	zone       string
	dnsKeys    []*protocol.ResourceRecord
	dsRecords  []*protocol.ResourceRecord
	validated  bool
	nsec3Param *protocol.RDataNSEC3PARAM // NSEC3 parameters for this zone (if using NSEC3)
}

// buildChain builds a validation chain from trust anchor to target.
//
// The returned `insecure` flag is true when the chain terminates at a
// PROVEN-unsigned delegation (empty DS with an authenticated denial of
// existence) before reaching the query name's zone — i.e. the query name lives
// in an Insecure subtree (RFC 4035 §4.3). Callers MUST treat that as
// ValidationInsecure and MUST NOT require per-RRset signatures below the cut;
// doing so would wrongly mark every legitimately-unsigned domain (the bulk of
// the DNS) as Bogus. When `insecure` is false and err is nil, every delegation
// down to the query name's zone was proven signed, so the answer's own RRset
// must carry a valid RRSIG.
func (v *Validator) buildChain(ctx context.Context, anchor *TrustAnchor, remaining []string) ([]*chainLink, bool, error) {
	chain := []*chainLink{}
	insecure := false

	// Start with trust anchor zone
	currentZone := anchor.Zone

	// Fetch DNSKEY (+ its RRSIGs) for the trust anchor zone and validate.
	dnsKeys, dnskeySigs, err := v.fetchDNSKEYAndSigs(ctx, currentZone)
	if err != nil {
		return nil, false, &chainFetchError{err: fmt.Errorf("fetching DNSKEY for %s: %w", currentZone, err)}
	}

	// The anchor authenticates the KSK; the KSK's self-signature over the whole
	// DNSKEY RRset authenticates the rest of the keys. Both are required —
	// otherwise an injected DNSKEY would be trusted (DNSSEC bypass).
	anchorKSKs := v.keysMatchingAnyAnchor(anchor, dnsKeys)
	if len(anchorKSKs) == 0 {
		return nil, false, fmt.Errorf("trust anchor validation failed for %s", currentZone)
	}
	if !v.verifyDNSKEYSelfSignature(dnsKeys, dnskeySigs, anchorKSKs) {
		return nil, false, fmt.Errorf("DNSKEY RRset for %s not self-signed by the anchored KSK", currentZone)
	}

	// Fetch NSEC3PARAM for trust anchor zone (if using NSEC3)
	nsec3Param, _ := v.fetchNSEC3PARAM(ctx, currentZone)

	chain = append(chain, &chainLink{
		zone:       currentZone,
		dnsKeys:    dnsKeys,
		dsRecords:  nil,
		validated:  true,
		nsec3Param: nsec3Param,
	})

	// Build chain through remaining labels, walking from the anchor DOWN
	// toward the query name. `remaining` is leaf-first ([example com] for
	// example.com. under the root anchor), so iterate it from the END: the
	// suffix slice remaining[i:] is the next child zone (com., then
	// example.com.). Walking leaf-first instead would append links out of
	// order, and validateMessage — which authenticates the answer with the
	// LAST link's keys — would check example.com.'s signatures against
	// com.'s DNSKEYs and mark every correctly-signed answer Bogus.
	//
	// `remaining` holds only the labels BELOW the anchor, so every child zone
	// name is remaining[i:] + the anchor's own labels. Joining remaining[i:]
	// alone is right only for the root anchor; under a non-root anchor such
	// as example.com. it asked for DS at "insecure." instead of
	// "insecure.example.com." and every delegation below it went Bogus (F407).
	anchorLabels := splitLabels(canonicalZone(anchor.Zone))
labels:
	for i := len(remaining) - 1; i >= 0; i-- {
		childLabels := make([]string, 0, len(remaining)-i+len(anchorLabels))
		childLabels = append(append(childLabels, remaining[i:]...), anchorLabels...)
		childZone := joinLabels(childLabels)
		parentLink := chain[len(chain)-1]

		// Check depth limit
		if len(chain) >= v.config.MaxDelegationDepth {
			return nil, false, fmt.Errorf("max delegation depth exceeded")
		}

		// Fetch DS records for child zone
		dsRecords, dsMsg, err := v.fetchDS(ctx, childZone)
		if err != nil {
			return nil, false, &chainFetchError{err: fmt.Errorf("fetching DS for %s: %w", childZone, err)}
		}
		// fetchDS returns a pooled *protocol.Message; release it once the
		// denial proof (or RRSIG verification) has been read from it.
		// Matches the defer msg.Release() pattern in fetchDNSKEYAndSigs,
		// fetchNSEC3PARAM, and fetchDNSKEY.
		defer dsMsg.Release()

		if len(dsRecords) == 0 {
			// An empty DS answer must be backed by an authenticated denial,
			// signed by the parent's keys (RFC 4035 §5.2, RFC 5155 §8.6);
			// otherwise an on-path attacker could strip the DS RRset to
			// downgrade validation. What the proof shows decides how the
			// chain continues:
			switch v.classifyDSDenial(dsMsg, childZone, chain) {
			case dsDenialInsecureDelegation:
				// Unsigned delegation - chain ends here. The query name is
				// in an Insecure subtree; signal it so the caller returns
				// Insecure rather than requiring non-existent signatures.
				insecure = true
				break labels
			case dsDenialNotZoneCut:
				// The label is not a delegation (a name, empty
				// non-terminal or CNAME inside the parent zone, e.g.
				// www.example.org): stay in the parent zone and keep
				// walking toward the query name.
				continue labels
			case dsDenialNameError:
				// The name does not exist in the parent zone, so neither
				// does anything below it. Stop here; the (negative) answer
				// is validated with the parent zone's keys.
				break labels
			default:
				return nil, false, fmt.Errorf("DS empty for %s but no authenticated denial proof (downgrade-attack guard)", childZone)
			}
		}

		// The DS RRset itself lives in (and is signed by) the PARENT zone.
		// Its RRSIG must validate under the parent's already-authenticated
		// DNSKEYs, or an on-path attacker could substitute a DS matching a
		// forged child KSK and mint a fully "Secure" fake chain — the digest
		// match in keysMatchingDS alone authenticates nothing.
		if !v.verifyDSRRSIG(dsMsg, dsRecords, parentLink.dnsKeys) {
			return nil, false, fmt.Errorf("DS RRset for %s not signed by parent zone %s", childZone, parentLink.zone)
		}

		// Only DS records this validator can use form an authentication
		// path. With none left the delegation is Insecure, exactly as if
		// the parent had proven no DS (RFC 4035 §5.2, RFC 6840 §5.2; F373).
		dsRecords = usableDSRecords(dsRecords)
		if len(dsRecords) == 0 {
			insecure = true
			break labels
		}

		// Fetch DNSKEY (+ its RRSIGs) for the child zone.
		childKeys, childSigs, err := v.fetchDNSKEYAndSigs(ctx, childZone)
		if err != nil {
			return nil, false, &chainFetchError{err: fmt.Errorf("fetching DNSKEY for %s: %w", childZone, err)}
		}

		// The DS authenticates the child's KSK; the KSK's self-signature over
		// the whole DNSKEY RRset authenticates the rest. Require both — without
		// the self-signature check an injected DNSKEY would be trusted and could
		// forge "Secure" answers (DNSSEC bypass).
		dsKSKs := v.keysMatchingDS(dsRecords, childKeys)
		if len(dsKSKs) == 0 {
			return nil, false, fmt.Errorf("delegation validation failed for %s", childZone)
		}
		if !v.verifyDNSKEYSelfSignature(childKeys, childSigs, dsKSKs) {
			return nil, false, fmt.Errorf("DNSKEY RRset for %s not self-signed by the DS-matched KSK", childZone)
		}

		// Fetch NSEC3PARAM for child zone (if using NSEC3)
		childNSEC3Param, _ := v.fetchNSEC3PARAM(ctx, childZone)

		chain = append(chain, &chainLink{
			zone:       childZone,
			dnsKeys:    childKeys,
			dsRecords:  detachRecords(dsRecords), // dsMsg is released on return
			validated:  true,
			nsec3Param: childNSEC3Param,
		})
		// currentZone tracked the parent for the next loop iteration; the
		// loop terminates after the last hop so the final assignment was
		// flagged ineffectual. We keep it removed; if the loop body grows,
		// re-add as needed.
		_ = childZone
	}

	return chain, insecure, nil
}

// usableDSRecords returns the DS records of an authenticated DS RRset that can
// authenticate a child key: a digest type calculateDSDigestFromDNSKEY
// implements and a DNSKEY algorithm ParseDNSKEYPublicKey implements (F373).
// SHA-1 DS records are dropped when a SHA-256 or SHA-384 DS is present
// (RFC 4509 §3, F374), so a non-matching stronger digest cannot be bypassed
// through its SHA-1 sibling.
func usableDSRecords(dsRecords []*protocol.ResourceRecord) []*protocol.ResourceRecord {
	var usable []*protocol.ResourceRecord
	strong := false
	for _, rr := range dsRecords {
		ds, ok := rr.Data.(*protocol.RDataDS)
		if !ok {
			continue
		}
		switch ds.Algorithm {
		case protocol.AlgorithmRSASHA256, protocol.AlgorithmRSASHA512,
			protocol.AlgorithmECDSAP256SHA256, protocol.AlgorithmECDSAP384SHA384,
			protocol.AlgorithmED25519:
		default:
			continue
		}
		switch ds.DigestType {
		case 2, 4:
			strong = true
		case 1:
		default:
			continue
		}
		usable = append(usable, rr)
	}
	if !strong {
		return usable
	}
	out := usable[:0]
	for _, rr := range usable {
		if rr.Data.(*protocol.RDataDS).DigestType != 1 {
			out = append(out, rr)
		}
	}
	return out
}

// keysMatchingDS returns the child DNSKEYs (KSKs) that a parent DS record
// authenticates. Bounded by maxDelegationOps (KeyTrap / VULN-040).
func (v *Validator) keysMatchingDS(dsRecords, childKeys []*protocol.ResourceRecord) []*protocol.ResourceRecord {
	var matched []*protocol.ResourceRecord
	ops := 0
	for _, dsRR := range dsRecords {
		ds, ok := dsRR.Data.(*protocol.RDataDS)
		if !ok {
			continue
		}
		for _, keyRR := range childKeys {
			dnskey, ok := keyRR.Data.(*protocol.RDataDNSKEY)
			if !ok {
				continue
			}
			if ops >= maxDelegationOps {
				return matched
			}
			ops++
			if ds.KeyTag != protocol.CalculateKeyTag(dnskey.Flags, dnskey.Algorithm, dnskey.PublicKey) {
				continue
			}
			if ds.Algorithm != dnskey.Algorithm {
				continue
			}
			digest := calculateDSDigestFromDNSKEY(keyRR.Name.String(), dnskey, ds.DigestType)
			if bytesEqual(digest, ds.Digest) {
				matched = append(matched, keyRR)
			}
		}
	}
	return matched
}

// keysMatchingAnchor returns the DNSKEYs that the configured trust anchor
// authenticates (by DS digest or by raw public key).
func (v *Validator) keysMatchingAnchor(anchor *TrustAnchor, dnsKeys []*protocol.ResourceRecord) []*protocol.ResourceRecord {
	var matched []*protocol.ResourceRecord
	for _, rr := range dnsKeys {
		dnskey, ok := rr.Data.(*protocol.RDataDNSKEY)
		if !ok {
			continue
		}
		keyTag := protocol.CalculateKeyTag(dnskey.Flags, dnskey.Algorithm, dnskey.PublicKey)
		if anchor.KeyTag != keyTag || anchor.Algorithm != dnskey.Algorithm {
			continue
		}
		if len(anchor.Digest) > 0 {
			digest := calculateDSDigestFromDNSKEY(rr.Name.String(), dnskey, anchor.DigestType)
			if bytesEqual(digest, anchor.Digest) {
				matched = append(matched, rr)
				continue
			}
		}
		if len(anchor.PublicKey) > 0 && bytesEqual(anchor.PublicKey, dnskey.PublicKey) {
			matched = append(matched, rr)
		}
	}
	return matched
}

// verifyDNSKEYSelfSignature authenticates an entire DNSKEY RRset. The DS (or
// trust anchor) only proves that ONE key in the set — the KSK — is genuine. The
// other keys (the ZSKs that actually sign answers) are trusted ONLY because the
// KSK signs the whole DNSKEY RRset with an RRSIG. Without verifying that
// self-signature, an on-path attacker could append their own DNSKEY to the
// fetched RRset and use it to forge "Secure" answers — the genuine KSK still
// matches the DS, so the delegation check passes. At least one RRSIG(DNSKEY)
// must validate under a DS/anchor-matched KSK over the full RRset; injecting a
// key changes the RRset and breaks that signature.
func (v *Validator) verifyDNSKEYSelfSignature(keys, sigs, trustedKSKs []*protocol.ResourceRecord) bool {
	if len(trustedKSKs) == 0 {
		return false
	}
	budget := maxSigVerificationsPerRRset
	for _, sigRR := range sigs {
		rrsig, ok := sigRR.Data.(*protocol.RDataRRSIG)
		if !ok || rrsig.TypeCovered != protocol.TypeDNSKEY {
			continue
		}
		if v.validateRRSIGBudget(keys, rrsig, trustedKSKs, &budget) {
			return true
		}
	}
	return false
}

// verifyDSRRSIG authenticates a non-empty DS RRset against the parent zone's
// already-validated DNSKEYs. The DS response carries the RRSIG(s) covering the
// DS RRset in its Answer section; at least one must validate.
func (v *Validator) verifyDSRRSIG(dsMsg *protocol.Message, dsRecords, parentKeys []*protocol.ResourceRecord) bool {
	if dsMsg == nil || len(dsRecords) == 0 || len(parentKeys) == 0 {
		return false
	}
	budget := maxSigVerificationsPerRRset
	for _, rr := range dsMsg.Answers {
		if rr == nil || rr.Type != protocol.TypeRRSIG {
			continue
		}
		rrsig, ok := rr.Data.(*protocol.RDataRRSIG)
		if !ok || rrsig.TypeCovered != protocol.TypeDS {
			continue
		}
		if v.validateRRSIGBudget(dsRecords, rrsig, parentKeys, &budget) {
			return true
		}
	}
	return false
}

// fetchDNSKEYAndSigs fetches a zone's DNSKEY RRset together with the RRSIG(s)
// covering it, in a single query, so the RRset's self-signature can be checked.
func (v *Validator) fetchDNSKEYAndSigs(ctx context.Context, zone string) (keys, sigs []*protocol.ResourceRecord, err error) {
	if v.resolver == nil {
		return nil, nil, fmt.Errorf("no resolver configured")
	}
	msg, err := v.resolver.Query(ctx, zone, protocol.TypeDNSKEY)
	if err != nil {
		return nil, nil, err
	}
	// Query hands back a pooled *protocol.Message. The extracted records
	// outlive this call (buildChain verifies signatures with them), but
	// msg.Release() zeroes and pools every record it holds — so return
	// detached copies. Sharing the RData pointers is safe: DNSSEC rdata
	// types have no case in releaseRData, so Release never pools or
	// mutates them. The Name is namePool-managed, hence the Copy.
	defer msg.Release()

	for _, rr := range msg.Answers {
		switch rr.Type {
		case protocol.TypeDNSKEY:
			keys = append(keys, detachRecord(rr))
		case protocol.TypeRRSIG:
			if sig, ok := rr.Data.(*protocol.RDataRRSIG); ok && sig.TypeCovered == protocol.TypeDNSKEY {
				sigs = append(sigs, detachRecord(rr))
			}
		}
	}
	return keys, sigs, nil
}

// detachRecords applies detachRecord to every record in rrs.
func detachRecords(rrs []*protocol.ResourceRecord) []*protocol.ResourceRecord {
	out := make([]*protocol.ResourceRecord, len(rrs))
	for i, rr := range rrs {
		out[i] = detachRecord(rr)
	}
	return out
}

// detachRecord returns a copy of rr that stays valid after the pooled
// message it came from is released. The record shell and Name are freshly
// allocated (Name is recycled by namePool on Release); the RData pointer
// is shared because protocol.releaseRData never pools or mutates the
// DNSSEC rdata types (DNSKEY, RRSIG, DS, NSEC, NSEC3, NSEC3PARAM).
func detachRecord(rr *protocol.ResourceRecord) *protocol.ResourceRecord {
	if rr == nil {
		return nil
	}
	return &protocol.ResourceRecord{
		Name:  rr.Name.Copy(),
		Type:  rr.Type,
		Class: rr.Class,
		TTL:   rr.TTL,
		Data:  rr.Data,
	}
}

// KeyTrap mitigation caps (VULN-040 / CVE-2023-50387).
// Bound per-message cryptographic work so a crafted response cannot pin CPU.
const (
	// maxRRsetsValidated bounds the number of Answer-section RRsets whose
	// signatures the validator will verify per response. Legitimate signed
	// zones almost never exceed a handful.
	maxRRsetsValidated = 32
	// maxNSECValidations bounds the number of NSEC/NSEC3 records the validator
	// will attempt to evaluate for one negative response. RFC 5155 needs at
	// most 3 NSEC3 records for a full denial proof.
	maxNSECValidations = 16
	// maxDelegationOps bounds the nested DS × DNSKEY comparison cost per
	// delegation. Legitimate zones ship 1–2 DS and 2–4 DNSKEYs.
	maxDelegationOps = 32
	// maxSigVerificationsPerRRset bounds the (RRSIG × same-tag DNSKEY)
	// signature verifications attempted for ONE RRset (F392). Without it, N
	// DNSKEYs sharing a key tag and M RRSIGs carrying that tag cost N×M
	// verifications (KeyTrap, CVE-2023-50387). A rollover RRset needs at
	// most 2 RRSIGs × 2 colliding keys; past the budget the RRset is Bogus.
	maxSigVerificationsPerRRset = 8
)

// validateMessage validates the DNS response message.
func (v *Validator) validateMessage(ctx context.Context, msg *protocol.Message, queryName string, chain []*chainLink) ValidationResult {
	if len(chain) == 0 {
		return ValidationBogus
	}

	// Get the zone that should have signed this response
	zoneLink := chain[len(chain)-1]

	// Group answers by name and type
	answerGroups := groupRecordsByRRSet(msg.Answers)

	// KeyTrap (VULN-040): refuse outright if the response packs more RRsets
	// than any legitimate zone would ever sign in one message. A ballooned
	// Answer section is a DoS-by-validation primitive.
	if len(answerGroups) > maxRRsetsValidated {
		return ValidationBogus
	}

	// Validate each answer RRSet. hasUnvalidated tracks whether any Answer RRset
	// was skipped without validation (a genuinely out-of-bailiwick owner served
	// by a different zone we don't have a chain for). If so we cannot claim the
	// WHOLE message is authenticated, so we downgrade Secure→Insecure at the end
	// (AD=0) rather than falsely stamping AD=1 (RFC 4035 §5.3.4).
	hasUnvalidated := false
	chains := map[string]chainResult{canonicalZone(zoneLink.zone): {chain: chain}}
	// Authenticated Authority denial records per signing zone, computed once
	// per response rather than once per wildcard-expanded RRset (F394).
	denials := map[*chainLink][]*protocol.ResourceRecord{}
	// Zone-cut checks between a signer and the names below it (F472).
	noCut := map[string]bool{}
	answerChain := walkAnswerChain(msg, queryName)
	for _, rrSet := range answerGroups {
		if len(rrSet) == 0 {
			continue
		}

		// An unsigned CNAME synthesized exactly (owner, target, TTL) from a
		// DNAME in this Answer section is authenticated by the DNAME's
		// signature, which this loop verifies like any other RRset (RFC
		// 6672 §5.3.1, RFC 4035 §5.3.3; F527).
		if answerChain.isSynthesizedCNAME(rrSet) {
			continue
		}

		// RRSIG RRsets cover OTHER types, not themselves — never demand a
		// signature "over" an RRSIG (it would have no covering RRSIG and would
		// trip the missing-signature check below).
		if rrSet[0].Type == protocol.TypeRRSIG {
			continue
		}

		owner := rrSet[0].Name.String()

		// Find matching RRSIGs (RFC 4035 §5.3.3: attempt every signature).
		rrsigs := v.findRRSIGs(msg.Answers, owner, rrSet[0].Type)

		// RRsets reached through a CNAME/DNAME chain may belong to other zones.
		// Validate each with the chain of its own zone: the RRSIG signer when
		// signed, otherwise a chain walked down to the owner, which proves
		// whether an unsigned RRset is legitimately insecure or stripped.
		if !sameDNSName(owner, queryName) {
			target := owner
			for _, rrsig := range rrsigs {
				if rrsig.SignerName == nil {
					continue
				}
				signer := rrsig.SignerNameString()
				if !inBailiwick(owner, signer) {
					return ValidationBogus
				}
				if target == owner {
					target = signer
				}
			}
			if !sameDNSName(target, zoneLink.zone) {
				other := v.chainFor(ctx, target, chains)
				var fetchErr *chainFetchError
				switch {
				case other.err != nil && len(rrsigs) == 0 && errors.As(other.err, &fetchErr) && !inBailiwick(owner, zoneLink.zone):
					// Could not fetch the delegation data of an out-of-bailiwick
					// owner: the unsigned RRset stays unauthenticated (no AD), as
					// before. In-bailiwick owners fall through to Bogus so a
					// transient failure cannot mask a stripped signature.
					hasUnvalidated = true
					continue
				case other.err != nil:
					return ValidationBogus
				case other.insecure:
					// Proven unsigned zone: the RRset cannot be authenticated,
					// so the message as a whole is not Secure.
					hasUnvalidated = true
					continue
				case len(rrsigs) == 0:
					// The owner's zone is signed, yet the RRset carries no
					// signature: stripped-RRSIG downgrade.
					return ValidationBogus
				}
				otherLink := other.chain[len(other.chain)-1]
				validated, ok := v.anyRRSIGValidates(rrSet, rrsigs, otherLink.dnsKeys)
				if !ok || apexTypeBelowSigner(rrSet[0].Type, owner, otherLink.zone) {
					return ValidationBogus
				}
				if !v.noZoneCutBelowSigner(ctx, other.chain, owner, validated.Labels, noCut) {
					return ValidationBogus
				}
				if int(validated.Labels) < rrsigOwnerLabels(rrSet[0].Name) {
					proven, optOut := v.wildcardExpansionProof(msg, owner, validated.Labels, rrSet[0].Type, other.chain, denials)
					if !proven {
						return ValidationBogus
					}
					if optOut {
						hasUnvalidated = true // RFC 5155 §9.2 (F523)
					}
				}
				continue
			}
		}

		if len(rrsigs) == 0 {
			// No signature for this RRset. We only reach validateMessage when
			// the chain proved the query name's zone is SIGNED (Insecure
			// subtrees are short-circuited in ValidateResponse). A missing
			// signature is a stripped-RRSIG downgrade — Bogus — for any RRset
			// that is (a) the queried name itself, or (b) IN-BAILIWICK of the
			// signing zone. Case (b) is the critical one: without it an on-path
			// attacker could strip the RRSIG on an in-zone record reached via a
			// CNAME chain (e.g. query www.example.com, CNAME to
			// foo.example.com, then a forged foo.example.com A with its
			// signature removed) and the message would still be declared Secure
			// with AD=1. Only genuinely out-of-bailiwick owners (a different
			// zone, validated by their own chain) stay lenient.
			if v.config.RequireDNSSEC || sameDNSName(owner, queryName) || inBailiwick(owner, zoneLink.zone) {
				return ValidationBogus
			}
			// Out-of-bailiwick, unsigned: we can't authenticate it with this
			// chain, so the message is not fully validated.
			hasUnvalidated = true
			continue
		}

		// Validate the signatures — any one validating authenticates the
		// RRset (RFC 4035 §5.3.3).
		validated, ok := v.anyRRSIGValidates(rrSet, rrsigs, zoneLink.dnsKeys)
		if !ok || apexTypeBelowSigner(rrSet[0].Type, owner, zoneLink.zone) {
			return ValidationBogus
		}
		if !v.noZoneCutBelowSigner(ctx, chain, owner, validated.Labels, noCut) {
			return ValidationBogus
		}

		// Wildcard-expanded answers (validated.Labels < the owner's label count)
		// require an authenticated proof that the owner has NO exact match in
		// the zone (RFC 4035 §5.3.4). Without it, a valid "*.zone" RRSIG could
		// be replayed onto an explicit name that has its own different record.
		// Labels is part of the signed RRSIG RDATA, so an attacker cannot
		// forge the wildcard path — tampering Labels breaks the signature above.
		if int(validated.Labels) < rrsigOwnerLabels(rrSet[0].Name) {
			proven, optOut := v.wildcardExpansionProof(msg, owner, validated.Labels, rrSet[0].Type, chain, denials)
			if !proven {
				return ValidationBogus
			}
			if optOut {
				// The next closer lies in an Opt-Out span: the proof cannot
				// exclude an unsigned delegation there, so the answer is not
				// Secure (RFC 5155 §9.2; F523, consistent with F377).
				hasUnvalidated = true
			}
		}
	}

	// A chain whose last name has no data of the query type is a negative
	// answer for that name (RFC 6604 §2.1): its zone must prove the
	// NXDOMAIN/NODATA, else the target RRset was stripped or the ending
	// forged (F528).
	if len(msg.Answers) > 0 && answerChain.open {
		switch v.validateChainTerminal(ctx, msg, answerChain.terminal, chains, noCut) {
		case ValidationBogus:
			return ValidationBogus
		case ValidationInsecure:
			hasUnvalidated = true
		}
	}

	// Validate negative response if applicable
	if len(msg.Answers) == 0 {
		result, encloser := v.validateNegativeProof(msg, queryName, chain)
		if result == ValidationBogus {
			return ValidationBogus
		}
		// The denial is the signer's only if no zone cut lies between the
		// signer and the deepest name the proof shows to exist (names below
		// it do not exist, and queryName itself, for an exact-match proof,
		// was checked against the delegation bitmap): otherwise a parent's
		// stale or replayed NSEC/NSEC3 would deny names inside a delegated
		// child (F508). Same cost model and cache as answers (F472, F477).
		if !v.noZoneCutBelowSigner(ctx, chain, queryName, uint8(min(len(splitLabels(encloser)), 255)), noCut) {
			return ValidationBogus
		}
		if result == ValidationInsecure {
			// Opt-Out denial: not fully authenticated, AD must stay clear
			// (RFC 5155 §9.2, F377).
			hasUnvalidated = true
		}
	}

	// If any in-bailiwick data was validated but some out-of-bailiwick RRset was
	// skipped, the message is not fully authenticated — return Insecure (AD=0)
	// rather than Secure. Never fail-open (AD=1 for unvalidated data).
	if hasUnvalidated {
		return ValidationInsecure
	}
	return ValidationSecure
}

// apexTypeBelowSigner reports whether a signed RRset of rrtype owned by owner
// can only be the data of a zone apex other than signer's: SOA, DNSKEY,
// NSEC3PARAM, CDS and CDNSKEY exist only at a zone apex, and NS is signed only
// at the apex (the parent's NS at a delegation is never signed, RFC 4035
// §2.2). Signed by an ancestor zone, such an RRset is the parent forging (or
// a stale signature over) child-apex data (F509). No lookup is needed.
func apexTypeBelowSigner(rrtype uint16, owner, signer string) bool {
	switch rrtype {
	case protocol.TypeSOA, protocol.TypeDNSKEY, protocol.TypeNSEC3PARAM, protocol.TypeCDS, protocol.TypeCDNSKEY, protocol.TypeNS:
		return !sameDNSName(owner, signer)
	}
	return false
}

// noZoneCutBelowSigner reports whether the zone of chain's last link (the
// zone whose keys just verified an RRset owned by owner) contains owner, i.e.
// no zone cut lies between them (RFC 4035 §5.3.1: the signer must be the zone
// containing the RRset). The chain is built only down to the RRSIG signer
// (715f339), so without this check a parent's signature over a name below one
// of its delegations — a stale pre-delegation signature, or a parent forging
// child data — validated Secure (F472).
//
// Only names strictly between the signer and the owner can be cuts the signer
// is not authoritative below, so an owner at or one label below the signer
// costs nothing. For a deeper owner each intermediate name, from the signer
// downward, must be proven NOT a delegation by the signer's own authenticated
// DS denial (an existing name or empty non-terminal without NS): one DS lookup
// per intermediate name, memoized per response in memo and charged to the
// response budget, and cached across responses for the proof's lifetime
// (zoneCutCache, F477). A DS RRset, an insecure-delegation proof, a name error, a
// missing proof or a failed fetch all fail closed. For a wildcard expansion
// (sigLabels < owner labels) the names checked end at the closest encloser:
// labels below it are synthesized and do not exist.
func (v *Validator) noZoneCutBelowSigner(ctx context.Context, chain []*chainLink, owner string, sigLabels uint8, memo map[string]bool) bool {
	if len(chain) == 0 {
		return false
	}
	signer := canonicalZone(chain[len(chain)-1].zone)
	if !inBailiwick(owner, signer) {
		return true // other-zone owners are bound to their own signer elsewhere
	}
	ownerLabels := dnsLabelsLower(owner)
	last := len(ownerLabels) - 1
	if int(sigLabels) < last {
		last = int(sigLabels)
	}
	for n := len(splitLabels(signer)) + 1; n <= last; n++ {
		name := strings.Join(ownerLabels[len(ownerLabels)-n:], ".") + "."
		key := signer + "|" + name
		ok, seen := memo[key]
		if !seen {
			if isCut, hit := v.zoneCuts.get(signer, name, v.clock()); hit {
				ok = !isCut
			} else {
				ok = v.provenNotZoneCut(ctx, signer, name, chain)
			}
			memo[key] = ok
		}
		if !ok {
			return false
		}
	}
	return true
}

// provenNotZoneCut reports whether chain's last zone (signer) proves, with an
// authenticated DS denial, that name is inside it and not a delegation. An
// authenticated result either way (no-cut proof, signed DS RRset, signed
// insecure-delegation proof) is cached for the proof's lifetime (F477);
// unauthenticated, failed or budget-exhausted outcomes are never cached.
func (v *Validator) provenNotZoneCut(ctx context.Context, signer, name string, chain []*chainLink) bool {
	if !v.chargeLookup() {
		return false
	}
	ds, dsMsg, err := v.fetchDS(ctx, name)
	if err != nil {
		return false
	}
	defer dsMsg.Release()
	proven, isCut := false, false
	if len(ds) > 0 {
		_, proven = v.anyRRSIGValidates(ds, v.findRRSIGs(dsMsg.Answers, name, protocol.TypeDS), chain[len(chain)-1].dnsKeys)
		isCut = true
	} else {
		switch v.classifyDSDenial(dsMsg, name, chain) {
		case dsDenialNotZoneCut:
			proven = true
		case dsDenialInsecureDelegation:
			proven, isCut = true, true
		}
	}
	if proven && (v.work == nil || !v.work.exceeded) {
		now := v.clock()
		v.zoneCuts.put(signer, name, isCut, now, proofLifetime(dsMsg, now))
	}
	return proven && !isCut
}

// wildcardExpansionProven reports whether msg carries an authenticated
// (zone-signed) NSEC/NSEC3 proof that legitimizes a wildcard-expanded positive
// answer for `owner` whose signature was made over "*.<closest encloser>",
// where the closest encloser is the rightmost sigLabels labels of owner
// (RFC 4035 §5.3.4 / RFC 5155 §8.8).
//
// The critical binding: the wildcard's DEPTH must match the PROVEN closest
// encloser. Verifying only "owner has no exact match" is NOT enough — a genuine
// shallow "*.example.com" RRSIG could otherwise be replayed onto a deep
// a.sub.example.com that must be NXDOMAIN (its real source of synthesis
// "*.sub.example.com" does not exist). We bind the depth by requiring proof
// that the NEXT CLOSER name — the rightmost (sigLabels+1) labels of owner — does
// NOT exist, so the wildcard's closest encloser really is the closest encloser.
// (When the wildcard is exactly one level above owner, the next closer equals
// owner and this reduces to proving owner's nonexistence.) Without such a proof
// the answer stays fail-closed (Bogus), never fail-open.
//
// denials memoizes authenticatedDenialRRs per chain link for the response
// (F394): its signature work must not repeat for every wildcard RRset.
//
// It is wildcardExpansionProof without the Opt-Out result.
func (v *Validator) wildcardExpansionProven(msg *protocol.Message, owner string, sigLabels uint8, qtype uint16, chain []*chainLink, denials map[*chainLink][]*protocol.ResourceRecord) bool {
	proven, _ := v.wildcardExpansionProof(msg, owner, sigLabels, qtype, chain, denials)
	return proven
}

// wildcardExpansionProof is wildcardExpansionProven that also reports optOut:
// the proof rests on an NSEC3 with the Opt-Out flag covering the next closer,
// so the answer must not be Secure (RFC 5155 §9.2, F523).
func (v *Validator) wildcardExpansionProof(msg *protocol.Message, owner string, sigLabels uint8, qtype uint16, chain []*chainLink, denials map[*chainLink][]*protocol.ResourceRecord) (proven, optOut bool) {
	ownerLabels := splitLabels(owner)
	if int(sigLabels) >= len(ownerLabels) {
		return false, false // not a wildcard expansion — caller should not have branched
	}
	// Next closer = one label deeper than the wildcard's closest encloser,
	// toward owner (rightmost sigLabels+1 labels of owner).
	nextCloser := strings.Join(ownerLabels[len(ownerLabels)-int(sigLabels)-1:], ".")

	if len(chain) == 0 {
		return false, false
	}
	link := chain[len(chain)-1]
	authenticated, done := denials[link]
	if !done {
		authenticated = v.authenticatedDenialRRs(msg, chain)
		denials[link] = authenticated
	}
	var nsec3RRs []*protocol.ResourceRecord
	checks := 0
	for _, rr := range authenticated {
		if checks >= maxNSECValidations {
			return false, false
		}
		checks++
		if rr == nil || rr.Name == nil {
			continue
		}
		switch rr.Type {
		case protocol.TypeNSEC:
			nsec, ok := rr.Data.(*protocol.RDataNSEC)
			if !ok {
				continue
			}
			nsecOwner := rr.Name.String()
			// Require a strict range-cover of the NEXT CLOSER (nonexistence),
			// which binds the wildcard depth. A NoData (owner==name) match is
			// rejected via the sameDNSName guard.
			if !sameDNSName(nsecOwner, nextCloser) && v.validateNSEC(nsecOwner, nextCloser, qtype, nsec) {
				return true, false
			}
		case protocol.TypeNSEC3:
			nsec3RRs = append(nsec3RRs, rr)
		}
	}
	if len(nsec3RRs) > 0 {
		// RFC 5155 §8.8: the closest encloser is fixed by the RRSIG Labels
		// field (the signed "*.<ce>" exists, so ce exists); the validator
		// MUST only find an NSEC3 covering the next closer name. No NSEC3
		// matching the closest encloser is required — RFC 5155 Appendix B.4,
		// BIND and Knot send the cover alone (F522). The strict cover binds
		// the wildcard depth: in the a.sub.example.com replay of a
		// "*.example.com" signature the next closer sub.example.com exists,
		// has its own NSEC3, and no NSEC3 strictly covers it. Only the next
		// closer is hashed — no ancestor search (F395, CVE-2023-50868 class).
		// An NSEC3 MATCHING the next closer proves it exists — the response
		// contradicts itself (e.g. a stale cover replayed beside the current
		// match) and the expansion is rejected.
		params, ok := nsec3SharedParams(nsec3RRs)
		if !ok {
			return false, false
		}
		h, err := v.nsec3Hash(nextCloser, params.algo, params.iter, params.salt)
		if err != nil {
			return false, false
		}
		target := strings.ToUpper(protocol.Base32Encode(h))
		for _, rr := range nsec3RRs {
			n := rr.Data.(*protocol.RDataNSEC3) // nsec3SharedParams checked the type
			ownerHash := strings.ToUpper(extractNSEC3Hash(rr.Name.String()))
			if ownerHash == target {
				return false, false
			}
			if nsec3HashInRange(target, ownerHash, strings.ToUpper(protocol.Base32Encode(n.NextHashed))) {
				proven = true
				if n.IsOptOut() {
					optOut = true
				}
			}
		}
		return proven, optOut
	}
	return false, false
}

// rrsigOwnerLabels returns the owner's label count as the RRSIG Labels field
// counts it (RFC 4034 §3.1.3): a leading "*" label is not counted. An RRSIG
// whose Labels equals this count covers the owner as written — including a
// literal "*.zone" owner queried directly — not a wildcard expansion (F348).
func rrsigOwnerLabels(owner *protocol.Name) int {
	labels := owner.LabelsSlice()
	if len(labels) > 0 && labels[0] == "*" {
		return len(labels) - 1
	}
	return len(labels)
}

// sameDNSName reports whether two DNS owner names are equal, ignoring ASCII
// case (RFC 1035 §2.3.3) and a single trailing root dot.
func sameDNSName(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(a, "."), strings.TrimSuffix(b, "."))
}

// inBailiwick reports whether owner is equal to, or a subdomain of, zone
// (case-insensitive, trailing-dot-insensitive). The root zone ("" or ".")
// contains every name. Used to decide which Answer RRsets MUST carry a valid
// signature from the signing zone's keys — an in-bailiwick RRset with no
// signature is a stripped-RRSIG downgrade attack, not lenient cross-zone data.
func inBailiwick(owner, zone string) bool {
	o := strings.ToLower(strings.TrimSuffix(owner, "."))
	z := strings.ToLower(strings.TrimSuffix(zone, "."))
	if z == "" {
		return true
	}
	return o == z || strings.HasSuffix(o, "."+z)
}

// findRRSIG finds an RRSIG record for the given name and type.
//
// DNS owner names are case-insensitive per RFC 1035 §2.3.3. The
// previous \`rr.Name.String() == name\` used Go string equality
// (case-sensitive), so an RRSIG whose owner was "Example.com." but
// whose covering RRset's owner came back as "example.com." would
// be silently skipped. The matching RRSIG existed in the response;
// the validator just couldn't find it — so the RRset reported
// "no signature" and the whole response went Bogus under
// RequireDNSSEC, or Insecure-equivalent without it.
//
// In practice authoritative servers return lowercase, so the bug
// findRRSIGs returns every RRSIG covering (name, rrtype) in message order.
//
// DNS owner names are case-insensitive per RFC 1035 §2.3.3. The
// previous rr.Name.String() == name comparison used Go string equality
// (case-sensitive), so an RRSIG whose owner was "Example.com." but
// whose covering RRset's owner came back as "example.com." would
// be silently skipped. The matching RRSIG existed in the response;
// the validator just couldn't find it — so the RRset reported
// "no signature" and the whole response went Bogus under
// RequireDNSSEC, or Insecure-equivalent without it.
//
// In practice authoritative servers return lowercase, so the bug
// stayed dormant — but DNSSEC validation MUST not depend on a
// server choosing to send canonical case. strings.EqualFold handles
// the ASCII case-folding RFC 1035 requires.
//
// RFC 4035 §5.3.3 requires the validator to attempt EVERY signature over
// an RRset and to accept the RRset when any one of them verifies under a
// supported key: key/algorithm rollovers legitimately publish overlapping
// RRSIGs (RFC 6781), and message order decides which signature appears
// first. Returning only the first match made a stale-key signature mask a
// live one (false SERVFAIL for a correctly-signed zone).
func (v *Validator) findRRSIGs(answers []*protocol.ResourceRecord, name string, rrtype uint16) []*protocol.RDataRRSIG {
	var out []*protocol.RDataRRSIG
	for _, rr := range answers {
		if rr == nil || rr.Name == nil {
			continue
		}
		if rr.Type != protocol.TypeRRSIG {
			continue
		}
		rrsig, ok := rr.Data.(*protocol.RDataRRSIG)
		if !ok {
			continue
		}
		if rrsig.TypeCovered == rrtype && strings.EqualFold(rr.Name.String(), name) {
			out = append(out, rrsig)
		}
	}
	return out
}

// anyRRSIGValidates reports whether at least one of rrsigs verifies rrSet
// under dnsKeys, returning the signature that validated (its Labels field
// drives the wildcard-expansion check). See findRRSIGs for why every
// signature is attempted.
func (v *Validator) anyRRSIGValidates(rrSet []*protocol.ResourceRecord, rrsigs []*protocol.RDataRRSIG, dnsKeys []*protocol.ResourceRecord) (*protocol.RDataRRSIG, bool) {
	budget := maxSigVerificationsPerRRset
	for _, rrsig := range rrsigs {
		if budget <= 0 {
			break
		}
		if v.validateRRSIGBudget(rrSet, rrsig, dnsKeys, &budget) {
			return rrsig, true
		}
	}
	return nil, false
}

// validateRRSIG validates an RRSIG over an RRSet.
func (v *Validator) validateRRSIG(rrSet []*protocol.ResourceRecord, rrsig *protocol.RDataRRSIG, dnsKeys []*protocol.ResourceRecord) bool {
	budget := maxSigVerificationsPerRRset
	return v.validateRRSIGBudget(rrSet, rrsig, dnsKeys, &budget)
}

// validateRRSIGBudget is validateRRSIG charging every signature verification
// against *budget, shared by all RRSIGs of one RRset (F392, KeyTrap). Once the
// budget is spent no further verification is attempted and the RRSIG fails.
func (v *Validator) validateRRSIGBudget(rrSet []*protocol.ResourceRecord, rrsig *protocol.RDataRRSIG, dnsKeys []*protocol.ResourceRecord, budget *int) bool {
	// Check signature timestamps with clock skew tolerance
	if !v.config.IgnoreTime {
		now := uint32(v.clock().Unix())
		// Convert clock skew to seconds for comparison with uint32 timestamps
		clockSkewSec := validatorClockSkewSeconds(v.config.ClockSkew)
		// Apply clock skew tolerance: allow signatures that expired recently
		// or are not yet valid by up to ClockSkew (handles time sync issues)
		if !rrsigTimeValid(rrsig.Inception, rrsig.Expiration, now, clockSkewSec) {
			return false
		}
	}

	// Create canonical signed data once (independent of which key signed it).
	signedData, err := v.canonicalizeRRSet(rrSet, rrsig)
	if err != nil {
		return false
	}

	// Try EVERY DNSKEY whose (KeyTag, Algorithm) matches the RRSIG. Key tags
	// are not unique (RFC 4034 §8): during key rollovers or deliberate
	// collisions two DNSKEYs can share a tag and algorithm, and the actual
	// signer may be the second one. Selecting only the first match and giving
	// up rejected otherwise-valid signatures (availability). Return true as soon
	// as any candidate verifies.
	for _, rr := range dnsKeys {
		if rr == nil {
			continue
		}
		dnskey, ok := rr.Data.(*protocol.RDataDNSKEY)
		if !ok {
			continue
		}
		if dnskey.Algorithm != rrsig.Algorithm {
			continue
		}
		if protocol.CalculateKeyTag(dnskey.Flags, dnskey.Algorithm, dnskey.PublicKey) != rrsig.KeyTag {
			continue
		}
		if *budget <= 0 || !v.chargeSig() {
			return false
		}
		*budget--
		pubKey, err := ParseDNSKEYPublicKey(dnskey.Algorithm, dnskey.PublicKey)
		if err != nil {
			continue
		}
		if VerifySignature(rrsig, signedData, pubKey) == nil {
			return true
		}
	}
	return false
}

func validatorClockSkewSeconds(clockSkew time.Duration) uint32 {
	if clockSkew <= 0 {
		return 0
	}

	const maxUint32 = ^uint32(0)
	maxDuration := time.Duration(int64(maxUint32) * int64(time.Second))
	if clockSkew >= maxDuration {
		return maxUint32
	}

	return uint32(clockSkew / time.Second)
}

func rrsigTimeValid(inception, expiration, now, skew uint32) bool {
	if skew >= 1<<31 {
		return true
	}
	if protocol.SerialAfter(now, expiration+skew) {
		return false
	}
	return !protocol.SerialAfter(inception, now+skew)
}

// canonicalizeRRSet builds the exact byte sequence that the signer hashed
// for an RRSIG, per RFC 4034 §3.1.8.1:
//
//	signature_input =
//	    RRSIG_RDATA(without the trailing Signature field)
//	  || RR(1) || RR(2) || ... || RR(n)   (RRs in canonical order)
//
// The earlier implementation emitted only the RR portion. Any HMAC/signature
// verification against signer-produced data therefore failed (or worse,
// "succeeded" against a different prefix-stripped input), turning DNSSEC
// validation into a placebo. The prefix construction here mirrors the
// signer's createSignedData in internal/dnssec/signer.go.
func (v *Validator) canonicalizeRRSet(rrSet []*protocol.ResourceRecord, rrsig *protocol.RDataRRSIG) ([]byte, error) {
	if rrsig == nil {
		return nil, fmt.Errorf("nil RRSIG")
	}
	if rrsig.SignerName == nil {
		return nil, fmt.Errorf("nil RRSIG signer name")
	}

	var result []byte

	// 1. RRSIG RDATA prefix: TypeCovered | Algorithm | Labels | OriginalTTL
	//    | SignatureExpiration | SignatureInception | KeyTag | SignerName
	//    (Signature field intentionally omitted.)
	result = append(result,
		byte(rrsig.TypeCovered>>8), byte(rrsig.TypeCovered),
		rrsig.Algorithm,
		rrsig.Labels,
		byte(rrsig.OriginalTTL>>24), byte(rrsig.OriginalTTL>>16),
		byte(rrsig.OriginalTTL>>8), byte(rrsig.OriginalTTL),
		byte(rrsig.Expiration>>24), byte(rrsig.Expiration>>16),
		byte(rrsig.Expiration>>8), byte(rrsig.Expiration),
		byte(rrsig.Inception>>24), byte(rrsig.Inception>>16),
		byte(rrsig.Inception>>8), byte(rrsig.Inception),
		byte(rrsig.KeyTag>>8), byte(rrsig.KeyTag),
	)
	result = append(result, rrsig.SignerName.CanonicalWire()...)

	// 2. Each RR in canonical wire form, in canonical RRset order.
	sorted := make([]*protocol.ResourceRecord, len(rrSet))
	copy(sorted, rrSet)
	canonicalSort(sorted)

	for _, rr := range sorted {
		rrWire, err := v.canonicalizeRR(rr, rrsig.OriginalTTL, rrsig.Labels)
		if err != nil {
			return nil, err
		}
		result = append(result, rrWire...)
	}

	return result, nil
}

// wildcardOwnerWire returns the canonical wire form of the owner name to hash
// for an RRSIG whose Labels field is `sigLabels`. Per RFC 4034 §3.1.8.1 /
// §5.3.2, when the RRSIG's Labels count is fewer than the number of labels in
// the received owner name, the RR is a wildcard expansion: the signer hashed
// the synthesized wildcard owner "*.<closest-encloser>", where the closest
// encloser is the rightmost `sigLabels` labels of the owner. Using the literal
// expanded owner instead makes every signed wildcard answer fail to verify.
// Returns (wire, wasWildcard).
func wildcardOwnerWire(owner *protocol.Name, sigLabels uint8) ([]byte, bool) {
	labels := owner.LabelsSlice()
	if int(sigLabels) >= len(labels) {
		return owner.CanonicalWire(), false
	}
	ce := labels[len(labels)-int(sigLabels):]
	wildcardLabels := make([]string, 0, len(ce)+1)
	wildcardLabels = append(wildcardLabels, "*")
	wildcardLabels = append(wildcardLabels, ce...)
	wn := protocol.NewName(wildcardLabels, true)
	wire := wn.CanonicalWire() // returns a fresh copy; safe to release wn
	wn.Release()
	return wire, true
}

// canonicalizeRR creates a canonical wire format representation of a record.
// Per RFC 4034 Section 6, canonical form includes:
// - Owner name in lowercase wire format (no compression)
// - Type (2 bytes, big-endian)
// - Class (2 bytes, big-endian)
// - TTL (4 bytes, big-endian) - from RRSIG's OriginalTTL
// - RDATA in canonical form
func (v *Validator) canonicalizeRR(rr *protocol.ResourceRecord, ttl uint32, sigLabels uint8) ([]byte, error) {
	if rr == nil {
		return nil, fmt.Errorf("nil RR")
	}
	if rr.Name == nil {
		return nil, fmt.Errorf("nil RR owner name")
	}
	if rr.Data == nil {
		return nil, fmt.Errorf("nil RDATA for %s type %d", rr.Name.String(), rr.Type)
	}

	// Estimate buffer size: max name (255) + type (2) + class (2) + ttl (4) + rdata
	buf := make([]byte, 0, 512)

	// 1. Canonical owner name (lowercase, wire format, no compression). For a
	// wildcard-expanded RR the signer hashed "*.<closest-encloser>", not the
	// received owner (RFC 4034 §3.1.8.1).
	ownerWire, _ := wildcardOwnerWire(rr.Name, sigLabels)
	buf = append(buf, ownerWire...)

	// 2. Type (2 bytes, big-endian)
	typeBytes := make([]byte, 2)
	protocol.PutUint16(typeBytes, rr.Type)
	buf = append(buf, typeBytes...)

	// 3. Class (2 bytes, big-endian)
	classBytes := make([]byte, 2)
	protocol.PutUint16(classBytes, rr.Class)
	buf = append(buf, classBytes...)

	// 4. TTL (4 bytes, big-endian) - use the TTL from RRSIG
	ttlBytes := make([]byte, 4)
	protocol.PutUint32(ttlBytes, ttl)
	buf = append(buf, ttlBytes...)

	// 5. RDATA length (2 bytes, big-endian)
	rdataLen := rr.Data.Len()
	if rdataLen > 0xffff {
		return nil, fmt.Errorf("RDATA for %s type %d too large: %d bytes (max 65535)", rr.Name.String(), rr.Type, rdataLen)
	}
	rdatalenBytes := make([]byte, 2)
	protocol.PutUint16(rdatalenBytes, uint16(rdataLen))
	buf = append(buf, rdatalenBytes...)

	// 6. RDATA (packed)
	if rdataLen > 0 {
		rdataBuf := make([]byte, rdataLen)
		n, err := rr.Data.Pack(rdataBuf, 0)
		if err != nil {
			return nil, fmt.Errorf("packing RDATA for %s type %d: %w", rr.Name.String(), rr.Type, err)
		}
		if n > 0 {
			if n > 0xffff {
				return nil, fmt.Errorf("RDATA for %s type %d too large: %d bytes (max 65535)", rr.Name.String(), rr.Type, n)
			}
			buf = append(buf, rdataBuf[:n]...)
		}
	}

	return buf, nil
}

// toLowerBytes converts a string to lowercase bytes.
func toLowerBytes(s string) []byte {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c = c + ('a' - 'A')
		}
		result[i] = c
	}
	return result
}

// canonicalSort sorts records in canonical order for signing.
func canonicalSort(rrs []*protocol.ResourceRecord) {
	// Simplified: sort by name then type then RDATA
	// Full implementation per RFC 4034 Section 6.3
	sort.Slice(rrs, func(i, j int) bool {
		// Compare names (canonical = lowercase)
		nameI := toLower(rrs[i].Name.String())
		nameJ := toLower(rrs[j].Name.String())
		if nameI != nameJ {
			return nameI < nameJ
		}

		// Compare types
		if rrs[i].Type != rrs[j].Type {
			return rrs[i].Type < rrs[j].Type
		}

		// Compare RDATA (packed)
		dataI := rrs[i].Data
		if dataI == nil {
			return false
		}
		bufI := make([]byte, dataI.Len())
		nI, errI := dataI.Pack(bufI, 0)
		if errI != nil {
			return false
		}
		rdataI := bufI[:nI]

		dataJ := rrs[j].Data
		if dataJ == nil {
			return true
		}
		bufJ := make([]byte, dataJ.Len())
		nJ, errJ := dataJ.Pack(bufJ, 0)
		if errJ != nil {
			return true
		}
		rdataJ := bufJ[:nJ]

		return string(rdataI) < string(rdataJ)
	})
}

// validateNegativeResponse validates NSEC/NSEC3 for negative answers.
//
// Two distinct response shapes need to be proven:
//
//	NXDOMAIN  — the name itself does not exist. RFC 4035 §5.4 / RFC 5155 §8
//	            require TWO proofs: (a) an NSEC/NSEC3 that covers queryName
//	            in the name space (proves the name does not exist) AND
//	            (b) an NSEC/NSEC3 that covers the wildcard "*.<closest
//	            encloser>" (proves no wildcard could have synthesised an
//	            answer). Accepting a single proof was a forgery primitive:
//	            an attacker could replay any one valid NSEC and have us
//	            silently mark arbitrary names as authenticated-NXDOMAIN.
//	NODATA    — the name exists but the requested type does not. A single
//	            NSEC/NSEC3 with owner == queryName and qtype absent from
//	            the type bitmap is sufficient (RFC 4035 §5.4).
//
// KeyTrap mitigation (VULN-040): caps NSEC/NSEC3 evaluations per message.
// NSEC3 hashing is the expensive operation and an attacker could otherwise
// stuff the Authority section with thousands of bogus NSEC3 records to pin
// CPU.
func (v *Validator) validateNegativeResponse(msg *protocol.Message, queryName string, chain []*chainLink) ValidationResult {
	result, _ := v.validateNegativeProof(msg, queryName, chain)
	return result
}

// validateNegativeProof is validateNegativeResponse that also returns the
// deepest name the proof shows to EXIST in the signing zone: queryName for an
// exact-match or empty-non-terminal NODATA, the closest encloser for an
// NXDOMAIN, wildcard NODATA or Opt-Out DS proof. validateMessage requires no
// zone cut between the signer and that name (F508).
func (v *Validator) validateNegativeProof(msg *protocol.Message, queryName string, chain []*chainLink) (ValidationResult, string) {
	if len(msg.Questions) == 0 {
		return ValidationBogus, ""
	}
	qtype := msg.Questions[0].QType
	isNXDomain := msg.Header.Flags.RCODE == protocol.RcodeNameError

	// NEW-H2: filter to only the NSEC/NSEC3 records whose RRset
	// carries a valid RRSIG signed by the current zone's keys.
	// Without this gate, an on-path attacker can spoof NSEC denial
	// without ever supplying a real signature — same downgrade-attack
	// class as H-2 on the chain-build DS path. RFC 4035 §5.4 / RFC
	// 5155 §8 require authenticated denial proofs.
	authenticated := ancestorDelegationFiltered(v.authenticatedDenialRRs(msg, chain), queryName, qtype)
	if len(authenticated) == 0 {
		return ValidationBogus, ""
	}
	// A DS RRset lives in the parent zone (RFC 4035 §3.1.4.1, §5.2): a denial
	// signed by the zone whose apex is queryName (the child's own apex
	// NSEC/NSEC3) never proves the DS absent (F379).
	if qtype == protocol.TypeDS && queryName != "." && sameDNSName(chain[len(chain)-1].zone, queryName) {
		return ValidationBogus, ""
	}

	// Walk the authenticated set once: collect NSEC records for the RFC 4035
	// proofs below and record NSEC3 records whose owner hash MATCHES
	// queryName with qtype absent (exact-match NODATA, RFC 5155 §8.5).
	nameProofs := make(map[string]bool) // distinct exact-match NSEC3 owners proving queryName NODATA
	var nsecRRs, nsec3NoData []*protocol.ResourceRecord

	checks := 0
	for _, rr := range authenticated {
		if checks >= maxNSECValidations {
			return ValidationBogus, ""
		}
		checks++

		key := strings.ToLower(rr.Name.String())

		if rr.Type == protocol.TypeNSEC {
			if nsec, ok := rr.Data.(*protocol.RDataNSEC); ok && nsec.NextDomain != nil {
				nsecRRs = append(nsecRRs, rr)
			}
		}
		if rr.Type == protocol.TypeNSEC3 {
			nsec3, ok := rr.Data.(*protocol.RDataNSEC3)
			if !ok {
				continue
			}
			nsec3NoData = append(nsec3NoData, rr)
			// validateNSEC3 also accepts a mere range COVER, which proves
			// only that queryName does not exist — never NODATA (F347).
			// A CNAME at queryName answers every qtype, so its bit must be
			// clear too (RFC 5155 §8.5, RFC 6840 §4.3, F378).
			// A delegation NSEC3 (NS set, SOA clear) is the parent's side of
			// the cut: it proves only the absence of DS (RFC 6840 §4.1,
			// F507).
			if v.chargeHash() && nsec3OwnerMatches(rr.Name.String(), queryName, nsec3) && !nsec3.HasType(protocol.TypeCNAME) &&
				(qtype == protocol.TypeDS || !isDelegationBitmap(nsec3.HasType)) &&
				v.validateNSEC3(rr.Name.String(), queryName, qtype, nsec3, chain) {
				nameProofs[key] = true
			}
		}
	}

	// For NXDOMAIN responses backed by NSEC3, compute the full RFC 5155 §8.4
	// closest-encloser proof: closest_encloser exact-match + next_closer
	// cover + wildcard cover. This supersedes the older "≥2 distinct
	// NSEC3 owners" heuristic.
	if isNXDomain {
		var nsec3RRs []*protocol.ResourceRecord
		for _, rr := range authenticated {
			if rr.Type == protocol.TypeNSEC3 {
				nsec3RRs = append(nsec3RRs, rr)
			}
		}
		if len(nsec3RRs) > 0 {
			if ce, ok := v.nsec3NameErrorProven(queryName, nsec3RRs); ok {
				if v.nsec3NextCloserOptOut(queryName, nsec3RRs) {
					return ValidationInsecure, ce // RFC 5155 §9.2 (F377)
				}
				return ValidationSecure, ce
			}
			// If NSEC3 records exist but closest-encloser proof fails, do
			// not fall back to the NSEC path — that would let an attacker
			// mix-and-match record types.
			if len(nsec3RRs) == checks {
				return ValidationBogus, ""
			}
		}
	}

	if isNXDomain {
		// NSEC NXDOMAIN (RFC 4035 §3.1.3.2 / §5.4): an NSEC that strictly
		// covers queryName AND an NSEC covering the wildcard at queryName's
		// closest encloser (one NSEC may prove both). An NSEC owned by
		// queryName proves the name EXISTS and is never a name-error proof
		// (F78).
		if ce, ok := nsecNameErrorEncloser(queryName, nsecRRs); ok {
			return ValidationSecure, ce
		}
		return ValidationBogus, ""
	}

	// NODATA (RFC 4035 §3.1.3.1, §3.1.3.4): an NSEC matching queryName with
	// qtype absent, an empty-non-terminal cover, or a wildcard NODATA proof.
	// A bare covering NSEC proves only that queryName does not exist, which
	// does not rule out a wildcard answer (F79).
	if len(nameProofs) >= 1 {
		return ValidationSecure, queryName
	}
	if encloser, ok := nsecNoDataEncloser(queryName, qtype, nsecRRs); ok {
		return ValidationSecure, encloser
	}
	if ce, ok := v.nsec3CoverNoDataEncloser(queryName, qtype, nsec3NoData); ok {
		// A closest-encloser proof whose next-closer cover is Opt-Out
		// leaves AD clear (RFC 5155 §9.2, F377).
		if v.nsec3NextCloserOptOut(queryName, nsec3NoData) {
			return ValidationInsecure, ce
		}
		return ValidationSecure, ce
	}
	return ValidationBogus, ""
}

// isDelegationBitmap reports whether an NSEC/NSEC3 type bitmap is that of a
// delegation point as seen from the parent: NS set, SOA clear.
func isDelegationBitmap(has func(uint16) bool) bool {
	return has(protocol.TypeNS) && !has(protocol.TypeSOA)
}

// ancestorDelegationFiltered drops the authenticated NSEC records a zone may
// not use to deny anything about queryName (RFC 6840 §4.1, RFC 4035 §5.4 /
// RFC 6672 §5.3.2): the parent's NSEC at a delegation (NS set, SOA clear)
// proves only that DS is absent at that very name, and says nothing about
// other types there (the child is authoritative, F507) or about any name below
// it; an NSEC whose owner has a DNAME cannot deny names below that owner, which
// the DNAME redirects (F510). NSEC3 is handled by the closest-encloser checks.
func ancestorDelegationFiltered(rrs []*protocol.ResourceRecord, queryName string, qtype uint16) []*protocol.ResourceRecord {
	out := rrs[:0:0]
	for _, rr := range rrs {
		if nsec, ok := rr.Data.(*protocol.RDataNSEC); ok && rr.Type == protocol.TypeNSEC {
			owner := rr.Name.String()
			if sameDNSName(owner, queryName) {
				if qtype != protocol.TypeDS && isDelegationBitmap(nsec.HasType) {
					continue
				}
			} else if inBailiwick(queryName, owner) && (isDelegationBitmap(nsec.HasType) || nsec.HasType(protocol.TypeDNAME)) {
				continue
			}
		}
		out = append(out, rr)
	}
	return out
}

// nsec3NextCloserOptOut reports whether rrs carry a closest-encloser proof for
// queryName in which an NSEC3 covering the next closer name has the Opt-Out
// flag (RFC 5155 §8.6, §9.2).
func (v *Validator) nsec3NextCloserOptOut(queryName string, rrs []*protocol.ResourceRecord) bool {
	ce, params, ok := v.nsec3ClosestEncloserAndNextCloser(queryName, rrs)
	if !ok {
		return false
	}
	labels := splitLabels(queryName)
	nextCloser := strings.Join(labels[len(labels)-len(splitLabels(ce))-1:], ".")
	h, err := v.nsec3Hash(nextCloser, params.algo, params.iter, params.salt)
	if err != nil {
		return false
	}
	target := strings.ToUpper(protocol.Base32Encode(h))
	for _, rr := range rrs {
		n := rr.Data.(*protocol.RDataNSEC3) // nsec3SharedParams checked the type
		if n.IsOptOut() && nsec3HashInRange(target, strings.ToUpper(extractNSEC3Hash(rr.Name.String())),
			strings.ToUpper(protocol.Base32Encode(n.NextHashed))) {
			return true
		}
	}
	return false
}

// nsec3OwnerMatches reports whether the NSEC3 owner hash equals the NSEC3
// hash of name under the record's own parameters.
func nsec3OwnerMatches(owner, name string, nsec3 *protocol.RDataNSEC3) bool {
	h, err := NSEC3Hash(name, nsec3.HashAlgorithm, nsec3.Iterations, nsec3.Salt)
	if err != nil {
		return false
	}
	return strings.EqualFold(protocol.Base32Encode(h), extractNSEC3Hash(owner))
}

// nsec3CoverNoDataEncloser implements the NSEC3 NODATA proofs that do not use
// an NSEC3 matching queryName (RFC 5155 §8.6/§8.7): a closest-encloser proof
// for queryName plus either an NSEC3 matching "*.<closest encloser>" with
// qtype absent (wildcard NODATA), or — for DS only — an Opt-Out NSEC3
// covering the next closer name (unsigned delegation in an Opt-Out span).
// It returns the proven closest encloser.
func (v *Validator) nsec3CoverNoDataEncloser(queryName string, qtype uint16, rrs []*protocol.ResourceRecord) (string, bool) {
	ce, _, ok := v.nsec3ClosestEncloserAndNextCloser(queryName, rrs)
	if !ok {
		return "", false
	}
	if qtype == protocol.TypeDS && v.nsec3NextCloserOptOut(queryName, rrs) {
		return ce, true
	}
	wildcard := wildcardAt(ce)
	for _, rr := range rrs {
		n := rr.Data.(*protocol.RDataNSEC3)
		if v.chargeHash() && nsec3OwnerMatches(rr.Name.String(), wildcard, n) && !n.HasType(qtype) && !n.HasType(protocol.TypeCNAME) {
			return ce, true
		}
	}
	return "", false
}

// dnsLabelsLower returns name's labels, lowercased, leftmost first.
func dnsLabelsLower(name string) []string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return nil
	}
	return strings.Split(name, ".")
}

// commonAncestorLabels returns the number of trailing labels a and b share.
func commonAncestorLabels(a, b []string) int {
	n := 0
	for n < len(a) && n < len(b) && a[len(a)-1-n] == b[len(b)-1-n] {
		n++
	}
	return n
}

// nsecCoverClosestEncloser reports whether nsec (owned by owner) strictly
// covers queryName as a NONEXISTENT name, returning the closest encloser
// derived from that cover (RFC 4592 §3.3.1 / RFC 4035 §5.4: the longest common
// ancestor of queryName with the NSEC owner or next name). A cover whose next
// name is a descendant of queryName proves queryName is an empty
// non-terminal, i.e. that it exists; ok is false and ent is true then.
func nsecCoverClosestEncloser(owner string, nsec *protocol.RDataNSEC, queryName string) (ce string, ent, ok bool) {
	next := nsec.NextDomain.String()
	if sameDNSName(owner, queryName) || !nameInRange(queryName, owner, next) {
		return "", false, false
	}
	if !sameDNSName(next, queryName) && inBailiwick(next, queryName) {
		return "", true, false
	}
	q := dnsLabelsLower(queryName)
	n := commonAncestorLabels(q, dnsLabelsLower(owner))
	if m := commonAncestorLabels(q, dnsLabelsLower(next)); m > n {
		n = m
	}
	if n >= len(q) {
		return "", false, false
	}
	return joinLabels(q[len(q)-n:]), false, true
}

// wildcardAt returns "*.<ce>" for a closest encloser ce.
func wildcardAt(ce string) string {
	if ce == "." {
		return "*."
	}
	return "*." + ce
}

// nsecNameErrorEncloser reports whether the authenticated NSEC records prove
// that queryName does not exist and that no wildcard at its closest encloser
// could have synthesized an answer.
// It returns the closest encloser of the proof.
func nsecNameErrorEncloser(queryName string, nsecs []*protocol.ResourceRecord) (string, bool) {
	for _, c := range nsecs {
		ce, _, ok := nsecCoverClosestEncloser(c.Name.String(), c.Data.(*protocol.RDataNSEC), queryName)
		if !ok {
			continue
		}
		wildcard := wildcardAt(ce)
		for _, w := range nsecs {
			wn := w.Data.(*protocol.RDataNSEC)
			if nameInRange(wildcard, w.Name.String(), wn.NextDomain.String()) {
				return ce, true
			}
		}
	}
	return "", false
}

// nsecNoDataEncloser reports whether the authenticated NSEC records prove that
// queryName has no RRset of qtype: an exact-match NSEC without qtype, an
// empty-non-terminal cover, or a wildcard NODATA proof (cover of queryName
// plus an NSEC owned by the closest encloser's wildcard without qtype).
// It returns the deepest name the proof shows to exist: queryName (exact
// match, empty non-terminal) or the closest encloser (wildcard NODATA).
func nsecNoDataEncloser(queryName string, qtype uint16, nsecs []*protocol.ResourceRecord) (string, bool) {
	for _, rr := range nsecs {
		nsec := rr.Data.(*protocol.RDataNSEC)
		if sameDNSName(rr.Name.String(), queryName) {
			// A CNAME bit means the CNAME answers qtype (RFC 6840 §4.3, F378).
			if !nsec.HasType(qtype) && !nsec.HasType(protocol.TypeCNAME) {
				return queryName, true
			}
			continue
		}
		ce, ent, ok := nsecCoverClosestEncloser(rr.Name.String(), nsec, queryName)
		if ent {
			return queryName, true
		}
		if !ok {
			continue
		}
		wildcard := wildcardAt(ce)
		for _, w := range nsecs {
			if wn := w.Data.(*protocol.RDataNSEC); sameDNSName(w.Name.String(), wildcard) && !wn.HasType(qtype) && !wn.HasType(protocol.TypeCNAME) {
				return ce, true
			}
		}
	}
	return "", false
}

// validateNSEC3ClosestEncloser implements the three-part NXDOMAIN proof
// from RFC 5155 §8.4:
//
//  1. Closest encloser proof: there exists an ancestor of queryName (the
//     "closest encloser") whose NSEC3 hash exactly matches one of the
//     owner-name hashes in the response. Walks ancestors from
//     queryName upward; the FIRST ancestor whose hash matches a present
//     NSEC3 is the closest encloser.
//  2. Next closer cover: the "next closer name" — one label deeper than
//     the closest encloser, toward queryName — must have its hash fall
//     inside the [owner_hash, next_hash) range of some NSEC3.
//  3. Wildcard cover: the synthesised wildcard "*.<closest_encloser>"
//     must also have its hash fall inside an NSEC3 range, proving no
//     wildcard could have answered the query either.
//
// All three proofs must use NSEC3 records carrying the same hash params
// (algorithm, iterations, salt). The function returns true only when all
// three sub-proofs succeed; any single failure means NXDOMAIN is unproven
// and the caller must mark the response Bogus.
func (v *Validator) validateNSEC3ClosestEncloser(queryName string, rrs []*protocol.ResourceRecord) bool {
	_, ok := v.nsec3NameErrorProven(queryName, rrs)
	return ok
}

// nsec3NameErrorProven is validateNSEC3ClosestEncloser returning the proven
// closest encloser.
func (v *Validator) nsec3NameErrorProven(queryName string, rrs []*protocol.ResourceRecord) (string, bool) {
	closestEncloser, params, ok := v.nsec3ClosestEncloserAndNextCloser(queryName, rrs)
	if !ok {
		return "", false
	}

	// 3. Wildcard "*.<closest_encloser>" cover — required for NXDOMAIN to prove
	// no wildcard could have answered either. (For a wildcard-POSITIVE answer
	// this step is intentionally omitted: the wildcard DOES exist and answered.)
	wildcard := "*." + strings.TrimSuffix(closestEncloser, ".")
	if closestEncloser == "." {
		wildcard = "*."
	}
	if !v.nsec3NameCovered(wildcard, params, rrs) {
		return "", false
	}
	return closestEncloser, true
}

// nsec3Params holds the shared NSEC3 hash parameters of one proof.
type nsec3Params struct {
	algo uint8
	iter uint16
	salt []byte
}

// nsec3SharedParams validates that every NSEC3 RR carries identical hash params
// (RFC 5155 §8.1) and returns them.
func nsec3SharedParams(rrs []*protocol.ResourceRecord) (nsec3Params, bool) {
	var first *protocol.RDataNSEC3
	for _, rr := range rrs {
		if rr == nil || rr.Name == nil {
			return nsec3Params{}, false
		}
		n, ok := rr.Data.(*protocol.RDataNSEC3)
		if !ok || n == nil {
			return nsec3Params{}, false
		}
		if first == nil {
			first = n
			continue
		}
		if n.HashAlgorithm != first.HashAlgorithm || n.Iterations != first.Iterations || !bytes.Equal(n.Salt, first.Salt) {
			return nsec3Params{}, false
		}
	}
	if first == nil {
		return nsec3Params{}, false
	}
	return nsec3Params{first.HashAlgorithm, first.Iterations, first.Salt}, true
}

// nsec3NameCovered reports whether the NSEC3 hash of name falls inside the
// [owner, next) range of any NSEC3 in rrs (proof that name does not exist).
func (v *Validator) nsec3NameCovered(name string, p nsec3Params, rrs []*protocol.ResourceRecord) bool {
	h, err := v.nsec3Hash(name, p.algo, p.iter, p.salt)
	if err != nil {
		return false
	}
	target := strings.ToUpper(protocol.Base32Encode(h))
	for _, rr := range rrs {
		n, ok := rr.Data.(*protocol.RDataNSEC3)
		if !ok || n == nil {
			continue
		}
		owner := strings.ToUpper(extractNSEC3Hash(rr.Name.String()))
		next := strings.ToUpper(protocol.Base32Encode(n.NextHashed))
		if nsec3HashInRange(target, owner, next) {
			return true
		}
	}
	return false
}

// nsec3ClosestEncloserAndNextCloser performs RFC 5155 §8.4 steps 1–2: it finds
// the closest encloser of queryName (an ancestor whose NSEC3 hash matches a
// present owner-hash) and verifies the next-closer name is covered — i.e.
// queryName has NO exact match. It deliberately does NOT check the wildcard
// cover (step 3), so it serves both NXDOMAIN (which adds the wildcard cover)
// and wildcard-POSITIVE answers (which need only steps 1–2 per RFC 5155 §8.8).
func (v *Validator) nsec3ClosestEncloserAndNextCloser(queryName string, rrs []*protocol.ResourceRecord) (string, nsec3Params, bool) {
	if len(rrs) == 0 {
		return "", nsec3Params{}, false
	}
	params, ok := nsec3SharedParams(rrs)
	if !ok {
		return "", nsec3Params{}, false
	}

	hashName := func(name string) (string, bool) {
		h, err := v.nsec3Hash(name, params.algo, params.iter, params.salt)
		if err != nil {
			return "", false
		}
		return strings.ToUpper(protocol.Base32Encode(h)), true
	}
	ownerHashOf := func(rr *protocol.ResourceRecord) string {
		return strings.ToUpper(extractNSEC3Hash(rr.Name.String()))
	}

	// 1. Closest encloser: walk queryName's ancestors (longest first, excluding
	// queryName itself), find the FIRST whose hash equals some NSEC3 owner-hash.
	labels := splitLabels(queryName)
	var closestEncloser string
	var ceNSEC3 *protocol.RDataNSEC3
	for i := 1; i <= len(labels); i++ {
		ancestor := strings.Join(labels[i:], ".")
		if ancestor == "" {
			ancestor = "."
		}
		hUpper, ok := hashName(ancestor)
		if !ok {
			continue
		}
		for _, rr := range rrs {
			if ownerHashOf(rr) == hUpper {
				closestEncloser = ancestor
				ceNSEC3 = rr.Data.(*protocol.RDataNSEC3) // nsec3SharedParams checked the type
				break
			}
		}
		if closestEncloser != "" {
			break
		}
	}
	if closestEncloser == "" {
		return "", nsec3Params{}, false
	}
	// RFC 5155 §8.3 / RFC 6840 §4.1: a closest encloser whose NSEC3 shows a
	// delegation (NS set, SOA clear) or a DNAME is the boundary of what this
	// zone may deny — names below it belong to the child zone or are
	// redirected by the DNAME (F507, F510).
	if isDelegationBitmap(ceNSEC3.HasType) || ceNSEC3.HasType(protocol.TypeDNAME) {
		return "", nsec3Params{}, false
	}

	// 2. Next closer: one label deeper than closest encloser, toward queryName;
	// its hash must be covered by some NSEC3 range.
	ceLabels := splitLabels(closestEncloser)
	if len(labels) <= len(ceLabels) {
		return "", nsec3Params{}, false
	}
	nextCloserIdx := len(labels) - len(ceLabels) - 1
	nextCloser := strings.Join(labels[nextCloserIdx:], ".")
	if nextCloser == "" {
		return "", nsec3Params{}, false
	}
	if !v.nsec3NameCovered(nextCloser, params, rrs) {
		return "", nsec3Params{}, false
	}

	return closestEncloser, params, true
}

// nsec3HashInRange reports whether hash falls inside the half-open range
// [ownerHash, nextHash) on the canonical NSEC3 hash ring. Because the ring
// wraps, when ownerHash >= nextHash the range is "owner..max OR 0..next".
func nsec3HashInRange(hash, ownerHash, nextHash string) bool {
	if ownerHash == nextHash {
		// Degenerate: a single-NSEC3 zone covers everything except its own
		// hash. Match if hash != ownerHash.
		return hash != ownerHash
	}
	if ownerHash < nextHash {
		return hash > ownerHash && hash < nextHash
	}
	// Wrap-around
	return hash > ownerHash || hash < nextHash
}

// validateNSEC validates an NSEC record for authenticated denial.
//
// DNS owner names are case-insensitive (RFC 1035 §2.3.3) and DNSSEC
// canonical RR ordering (RFC 4034 §6.1) requires lowercase comparison.
// The previous code compared owner, queryName, and nsec.NextDomain
// with byte-equality and lexical `<` / `>` (inside nameInRange) —
// any name returned by an authoritative server in mixed case would
// fail to "exact-match" against owner (so the type-bitmap check
// was skipped) and could fall in or out of the NSEC gap depending
// on whether uppercase ASCII (0x41-0x5A) sorts before or after the
// other endpoint's lowercase letters. Result: valid denial proofs
// rejected or invalid proofs accepted, both Bad.
//
// Normalise both queryName and owner to lowercase here so the
// downstream comparisons (== and nameInRange) operate on the same
// case-folded form.
func (v *Validator) validateNSEC(owner, queryName string, qtype uint16, nsec *protocol.RDataNSEC) bool {
	// NSEC proves that the queried name doesn't exist or the type doesn't exist
	// Owner < queryName < NextDomain
	owner = strings.ToLower(owner)
	queryName = strings.ToLower(queryName)
	next := strings.ToLower(nsec.NextDomain.String())

	// Exact match: the name EXISTS, so this NSEC can only prove the TYPE is
	// absent (NoData, RFC 4035 §3.1.3.1). This must be checked before the
	// range test — nameInRange is strict (owner < name), so an owner==query
	// NSEC never falls "in the gap" and NoData proofs (including the
	// owner-matching NSECs Cloudflare-style compact denial returns for DS
	// queries) would all be rejected, turning legitimately-unsigned
	// delegations Bogus.
	if owner == queryName {
		return !nsec.HasType(qtype)
	}

	// Otherwise the name must fall in the NSEC gap (proof of nonexistence).
	return nameInRange(queryName, owner, next)
}

// validateNSEC3 validates an NSEC3 record for authenticated denial.
func (v *Validator) validateNSEC3(owner, queryName string, qtype uint16, nsec3 *protocol.RDataNSEC3, chain []*chainLink) bool {
	// Chain is required to determine the zone context and NSEC3 parameters
	if len(chain) == 0 {
		return false
	}

	// Verify NSEC3 record parameters against zone's NSEC3PARAM (if available).
	// Per RFC 5155, NSEC3PARAM must match the parameters used in NSEC3 records.
	zoneLink := chain[len(chain)-1]
	if zoneLink.nsec3Param != nil {
		if zoneLink.nsec3Param.HashAlgorithm != nsec3.HashAlgorithm ||
			zoneLink.nsec3Param.Iterations != nsec3.Iterations {
			return false
		}
		// Salt check: NSEC3PARAM salt should match NSEC3 salt for the zone
		// (NSEC3 records from different salt periods have different salts)
		// Per RFC 5155 §10.3, the salt in NSEC3 must match the zone's NSEC3PARAM
		if !bytes.Equal(zoneLink.nsec3Param.Salt, nsec3.Salt) {
			return false
		}
	}

	// Hash the query name using the NSEC3 record's parameters
	hashedName, err := v.nsec3Hash(queryName, nsec3.HashAlgorithm, nsec3.Iterations, nsec3.Salt)
	if err != nil {
		return false
	}

	// NSEC3 owner hashes are base32 (RFC 5155 §1.3) — base32 alphabet is
	// case-insensitive but ASCII lexical comparisons are not. Base32Encode
	// emits uppercase; servers can legally serve the NSEC3 owner in any
	// case. Normalize both to uppercase before comparing so a mixed-case
	// owner name doesn't trip nameInRange's < / > boundary check or the
	// equality check below — either would silently reject a valid NSEC3
	// proof and turn the response Bogus.
	hashedNameStr := strings.ToUpper(protocol.Base32Encode(hashedName))
	ownerHash := strings.ToUpper(extractNSEC3Hash(owner))
	nextHashStr := strings.ToUpper(protocol.Base32Encode(nsec3.NextHashed))

	// When the hashed query name exactly matches the owner hash, the name
	// EXISTS and this NSEC3 can only prove the TYPE is absent (NoData,
	// RFC 5155 §8.5). Check before the range test — nameInRange is strict
	// (owner < name), so an exact-match NSEC3 never falls "in the gap" and
	// valid NoData proofs would all be rejected.
	if hashedNameStr == ownerHash {
		return !nsec3.HasType(qtype)
	}

	// Otherwise the hashed name must fall in the NSEC3 gap (nonexistence).
	return nameInRange(hashedNameStr, ownerHash, nextHashStr)
}

// extractNSEC3Hash extracts the hash portion from an NSEC3 owner name.
func extractNSEC3Hash(owner string) string {
	// NSEC3 owner format: <hash>.<zone>
	// Extract just the hash part
	labels := splitLabels(owner)
	if len(labels) == 0 {
		return ""
	}
	return labels[0]
}

// canonicalNameCompare orders two domain names per RFC 4034 §6.1 canonical
// ordering: compare label sequences right-to-left (most significant label
// first), each label as a case-insensitive byte string; when one name is a
// proper suffix of the other, the shorter (parent) sorts first. Plain string
// comparison is NOT a substitute — it sorts "sub.a.example." after
// "b.example." even though canonical order puts everything under "a.example."
// before "b.example.", which would misjudge NSEC gap membership.
func canonicalNameCompare(a, b string) int {
	// RFC 4034 §6.1: sort by the most significant (rightmost) label first;
	// each label is a case-folded, left-justified octet string where the
	// absence of an octet sorts first (so "aa" < "b" and a parent sorts
	// before its children). Comparing whole wire-format names left-to-right
	// is NOT canonical order: the length byte would decide ("b" < "aa") and
	// the leftmost label would outrank the zone labels, so a genuine NSEC from
	// a correctly ordered zone could "cover" an existing name (F77).
	la := wireLabels(protocol.CanonicalWireName(a))
	lb := wireLabels(protocol.CanonicalWireName(b))
	for i, j := len(la)-1, len(lb)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if c := bytes.Compare(la[i], lb[j]); c != 0 {
			return c
		}
	}
	return len(la) - len(lb)
}

// wireLabels splits an uncompressed wire-format name into its labels
// (leftmost first), excluding the root label.
func wireLabels(wire []byte) [][]byte {
	var labels [][]byte
	for i := 0; i < len(wire); {
		n := int(wire[i])
		if n == 0 || i+1+n > len(wire) {
			break
		}
		labels = append(labels, wire[i+1:i+1+n])
		i += 1 + n
	}
	return labels
}

// nameInRange checks if a name falls between owner and next (in canonical order).
// It handles both the normal case and NSEC wrap-around where the last record
// in the zone has a next domain name that is canonically before the owner,
// meaning the range covers names from owner to the end of the zone AND from the
// beginning of the zone up to next.
func nameInRange(name, owner, next string) bool {
	ownerNext := canonicalNameCompare(owner, next)
	nameOwner := canonicalNameCompare(name, owner)
	nameNext := canonicalNameCompare(name, next)
	if ownerNext < 0 {
		// Normal case: name must be strictly between owner and next
		return nameOwner > 0 && nameNext < 0
	}
	if ownerNext > 0 {
		// Wrap-around case: name is in range if it is after owner OR before next
		return nameOwner > 0 || nameNext < 0
	}
	// owner == next: single NSEC covering entire zone; any name except owner is in range
	return nameOwner != 0
}

// groupRecordsByRRSet groups records by name and type.
func groupRecordsByRRSet(records []*protocol.ResourceRecord) map[string][]*protocol.ResourceRecord {
	groups := make(map[string][]*protocol.ResourceRecord)
	for _, rr := range records {
		if rr.Type == protocol.TypeRRSIG {
			continue // Don't include RRSIGs in RRSet
		}
		key := rr.Name.String() + "|" + strconv.Itoa(int(rr.Type))
		groups[key] = append(groups[key], rr)
	}
	return groups
}

// fetchDNSKEY fetches DNSKEY records for a zone.
func (v *Validator) fetchDNSKEY(ctx context.Context, zone string) ([]*protocol.ResourceRecord, error) {
	if v.resolver == nil {
		return nil, fmt.Errorf("no resolver configured")
	}

	msg, err := v.resolver.Query(ctx, zone, protocol.TypeDNSKEY)
	if err != nil {
		return nil, err
	}
	// Query hands back a pooled *protocol.Message; release it once the
	// keys are extracted. Release also zeroes and pools the extracted
	// records themselves — fetchDNSKEY currently has no callers, and any
	// future caller must copy the result before reuse (see
	// fetchdnskey_pool_leak_test.go, which mandates this fix shape).
	defer msg.Release()

	var keys []*protocol.ResourceRecord
	for _, rr := range msg.Answers {
		if rr.Type == protocol.TypeDNSKEY {
			keys = append(keys, rr)
		}
	}

	return keys, nil
}

// fetchDS fetches DS records for a delegation and returns the raw
// message alongside, so a caller observing an empty DS RRset can
// verify that the parent zone authoritatively proved DS non-existence
// (RFC 4035 §5.2 / RFC 5155 §8) rather than silently downgrading the
// subtree to Insecure on a stripped response.
func (v *Validator) fetchDS(ctx context.Context, zone string) ([]*protocol.ResourceRecord, *protocol.Message, error) {
	if v.resolver == nil {
		return nil, nil, fmt.Errorf("no resolver configured")
	}

	msg, err := v.resolver.Query(ctx, zone, protocol.TypeDS)
	if err != nil {
		return nil, nil, err
	}
	if msg != nil && msg.Header.Flags.RCODE == protocol.RcodeServerFailure {
		msg.Release()
		return nil, nil, fmt.Errorf("DS query for %s failed upstream (SERVFAIL)", zone)
	}

	// Only DS records owned by zone count: an upstream that follows a CNAME
	// at zone returns the target's DS RRset, which says nothing about zone.
	var dsRecords []*protocol.ResourceRecord
	for _, rr := range msg.Answers {
		if rr.Type == protocol.TypeDS && rr.Name != nil && sameDNSName(rr.Name.String(), zone) {
			dsRecords = append(dsRecords, rr)
		}
	}

	return dsRecords, msg, nil
}

// verifyDSDenial checks that msg (the response to a "<zone> IN DS"
// query) constitutes an authenticated proof that no DS exists at
// zone. This is the load-bearing check between "the parent zone
// honestly says this child is unsigned" and "an attacker stripped
// the DS RRset to downgrade DNSSEC validation to Insecure."
//
// Returns true only when at least one NSEC or NSEC3 record in
// msg.Authorities both (a) proves NoData(DS) at zone, and (b)
// carries a valid RRSIG signed by one of the parent zone's keys
// already established in chain[len(chain)-1].dnsKeys. The chain
// argument also supplies the parent's NSEC3PARAM for the NSEC3
// path.
//
// References:
//   - RFC 4035 §5.2 "Authenticating Denial of Existence"
//   - RFC 5155 §8.6 "Validating Insecure Delegation State"
//
// nsecProvesNoDS reports whether an NSEC authenticates an insecure delegation
// (NoData for the DS type) at `zone`, with the RFC 4035 §5.4 / RFC 6840 §4.4
// type-bitmap constraints: the NSEC must exactly match the delegation name and
// have the NS bit SET, the DS bit CLEAR, and the SOA bit CLEAR. The SOA-clear
// requirement is the security-relevant one — it stops an attacker replaying the
// zone-apex NSEC (which carries SOA) to fake an insecure delegation for a name
// that actually has a DS.
func nsecProvesNoDS(nsecOwner, zone string, nsec *protocol.RDataNSEC) bool {
	if !sameDNSName(nsecOwner, zone) {
		return false
	}
	return nsec.HasType(protocol.TypeNS) &&
		!nsec.HasType(protocol.TypeDS) &&
		!nsec.HasType(protocol.TypeSOA)
}

// nsec3ProvesNoDS is the NSEC3 analogue of nsecProvesNoDS. A matching NSEC3
// (owner hash == H(zone)) must have NS set and DS/SOA clear; a covering NSEC3
// (zone hash in the gap) authenticates an insecure delegation only when the
// Opt-Out flag is set (RFC 5155 §6). Range-cover without opt-out is rejected.
func nsec3ProvesNoDS(nsec3Owner, zone string, nsec3 *protocol.RDataNSEC3) bool {
	hashed, err := NSEC3Hash(zone, nsec3.HashAlgorithm, nsec3.Iterations, nsec3.Salt)
	if err != nil {
		return false
	}
	target := strings.ToUpper(protocol.Base32Encode(hashed))
	owner := strings.ToUpper(extractNSEC3Hash(nsec3Owner))
	next := strings.ToUpper(protocol.Base32Encode(nsec3.NextHashed))
	if target == owner {
		return nsec3.HasType(protocol.TypeNS) &&
			!nsec3.HasType(protocol.TypeDS) &&
			!nsec3.HasType(protocol.TypeSOA)
	}
	if nameInRange(target, owner, next) {
		return nsec3.Flags&protocol.NSEC3FlagOptOut != 0
	}
	return false
}

// dsDenial classifies an authenticated negative answer to "<zone> IN DS".
type dsDenial int

const (
	// dsDenialNone: no authenticated proof; the empty DS answer is untrusted.
	dsDenialNone dsDenial = iota
	// dsDenialInsecureDelegation: zone is a delegation without DS (NS set,
	// DS clear), or lies in an NSEC3 opt-out span.
	dsDenialInsecureDelegation
	// dsDenialNotZoneCut: the name exists in the parent zone (or is an empty
	// non-terminal, or a CNAME) but is not a delegation.
	dsDenialNotZoneCut
	// dsDenialNameError: the name does not exist in the parent zone.
	dsDenialNameError
)

// classifyDSDenial inspects the parent-signed NSEC/NSEC3 records (and a
// parent-signed CNAME) in a DS response and reports what they prove about
// zone. Only records whose signatures validate under the current chain's keys
// are considered, so a forged proof cannot shorten the chain.
func (v *Validator) classifyDSDenial(msg *protocol.Message, zone string, chain []*chainLink) dsDenial {
	if msg == nil || len(chain) == 0 || len(chain[len(chain)-1].dnsKeys) == 0 {
		return dsDenialNone
	}
	keys := chain[len(chain)-1].dnsKeys

	// A validating upstream may answer the DS query for a CNAME owner with
	// the CNAME itself. A CNAME cannot coexist with NS, so the name is not a
	// zone cut.
	var cnames []*protocol.ResourceRecord
	for _, rr := range msg.Answers {
		if rr != nil && rr.Name != nil && rr.Type == protocol.TypeCNAME && sameDNSName(rr.Name.String(), zone) {
			cnames = append(cnames, rr)
		}
	}
	if len(cnames) > 0 {
		if _, ok := v.anyRRSIGValidates(cnames, v.findRRSIGs(msg.Answers, cnames[0].Name.String(), protocol.TypeCNAME), keys); ok {
			return dsDenialNotZoneCut
		}
	}

	denial := v.authenticatedDenialRRs(msg, chain)
	var nsec3s []*protocol.ResourceRecord
	result := dsDenialNone
	for _, rr := range denial {
		switch data := rr.Data.(type) {
		case *protocol.RDataNSEC:
			if kind := nsecDSDenial(rr.Name.String(), zone, data); kind > result {
				result = kind
			}
		case *protocol.RDataNSEC3:
			nsec3s = append(nsec3s, rr)
		}
	}
	if result == dsDenialInsecureDelegation || result == dsDenialNotZoneCut {
		return result
	}
	if len(nsec3s) > 0 {
		if kind := v.nsec3DSDenial(zone, nsec3s); kind != dsDenialNone {
			return kind
		}
	}
	return result
}

// nsecDSDenial classifies what a single authenticated NSEC proves about zone.
func nsecDSDenial(owner, zone string, nsec *protocol.RDataNSEC) dsDenial {
	if sameDNSName(owner, zone) {
		switch {
		case nsec.HasType(protocol.TypeSOA):
			// The child apex answered for itself; not a proof from the parent.
			return dsDenialNone
		case nsec.HasType(protocol.TypeNS) && !nsec.HasType(protocol.TypeDS):
			return dsDenialInsecureDelegation
		case !nsec.HasType(protocol.TypeNS):
			return dsDenialNotZoneCut
		}
		return dsDenialNone
	}
	if nsec.NextDomain == nil || !nameInRange(zone, owner, nsec.NextDomain.String()) {
		return dsDenialNone
	}
	// zone sorts between owner and next. If next is below zone, zone is an
	// empty non-terminal; otherwise it does not exist.
	if next := nsec.NextDomain.String(); !sameDNSName(next, zone) && inBailiwick(next, zone) {
		return dsDenialNotZoneCut
	}
	return dsDenialNameError
}

// nsec3DSDenial classifies what an authenticated NSEC3 set proves about zone.
func (v *Validator) nsec3DSDenial(zone string, rrs []*protocol.ResourceRecord) dsDenial {
	params, ok := nsec3SharedParams(rrs)
	if !ok {
		return dsDenialNone
	}
	h, err := v.nsec3Hash(zone, params.algo, params.iter, params.salt)
	if err != nil {
		return dsDenialNone
	}
	target := strings.ToUpper(protocol.Base32Encode(h))

	// Exact match: the name exists in the parent zone.
	for _, rr := range rrs {
		n := rr.Data.(*protocol.RDataNSEC3)
		if strings.ToUpper(extractNSEC3Hash(rr.Name.String())) != target {
			continue
		}
		switch {
		case n.HasType(protocol.TypeSOA):
			return dsDenialNone
		case n.HasType(protocol.TypeNS) && !n.HasType(protocol.TypeDS):
			return dsDenialInsecureDelegation
		case !n.HasType(protocol.TypeNS):
			// Includes empty non-terminals (empty bitmap).
			return dsDenialNotZoneCut
		}
		return dsDenialNone
	}

	// No match: closest encloser proof (RFC 5155 §8.4 steps 1-2). An Opt-Out
	// NSEC3 covering the next closer name may hide an unsigned delegation
	// (§8.6); otherwise the name does not exist.
	closestEncloser, params, ok := v.nsec3ClosestEncloserAndNextCloser(zone, rrs)
	if !ok {
		return dsDenialNone
	}
	labels := splitLabels(zone)
	ceLabels := splitLabels(closestEncloser)
	if closestEncloser == "." {
		ceLabels = nil
	}
	nextCloser := strings.Join(labels[len(labels)-len(ceLabels)-1:], ".")
	nh, err := v.nsec3Hash(nextCloser, params.algo, params.iter, params.salt)
	if err != nil {
		return dsDenialNone
	}
	nextTarget := strings.ToUpper(protocol.Base32Encode(nh))
	for _, rr := range rrs {
		n := rr.Data.(*protocol.RDataNSEC3)
		owner := strings.ToUpper(extractNSEC3Hash(rr.Name.String()))
		next := strings.ToUpper(protocol.Base32Encode(n.NextHashed))
		if nsec3HashInRange(nextTarget, owner, next) && n.Flags&protocol.NSEC3FlagOptOut != 0 {
			return dsDenialInsecureDelegation
		}
	}
	return dsDenialNameError
}

// verifyDSDenial reports whether msg authenticates an insecure delegation at
// zone. See classifyDSDenial for the full classification.
func (v *Validator) verifyDSDenial(msg *protocol.Message, zone string, chain []*chainLink) bool {
	return v.classifyDSDenial(msg, zone, chain) == dsDenialInsecureDelegation
}

// authenticatedDenialRRs returns the subset of msg.Authorities that
// are NSEC/NSEC3 records belonging to an RRset whose matching RRSIG
// validates under chain's current zone keys. NEW-H2:
// validateNegativeResponse previously walked msg.Authorities directly
// and trusted whatever wire bytes the response contained — an
// on-path adversary could forge an NSEC/NSEC3 NXDOMAIN/NODATA proof
// with no DNSSEC signature and have the validator return Secure.
// Same downgrade class as H-2's fetchDS path; same fix shape as
// verifyDSDenial.
func (v *Validator) authenticatedDenialRRs(msg *protocol.Message, chain []*chainLink) []*protocol.ResourceRecord {
	if msg == nil || len(chain) == 0 {
		return nil
	}
	keys := chain[len(chain)-1].dnsKeys
	if len(keys) == 0 {
		return nil
	}

	// Group Authority NSEC/NSEC3 records into RRsets by (name, type).
	type rrsetKey struct {
		name   string
		rrtype uint16
	}
	sets := make(map[rrsetKey][]*protocol.ResourceRecord)
	for _, rr := range msg.Authorities {
		if rr == nil || rr.Name == nil {
			continue
		}
		if rr.Type != protocol.TypeNSEC && rr.Type != protocol.TypeNSEC3 {
			continue
		}
		k := rrsetKey{strings.ToLower(rr.Name.String()), rr.Type}
		sets[k] = append(sets[k], rr)
	}
	// KeyTrap (F393): a complete denial needs at most 3 NSEC3 RRsets (RFC
	// 5155) and the negative/wildcard proofs already reject more than
	// maxNSECValidations records, so refuse an oversized Authority section
	// BEFORE verifying its signatures, not after.
	if len(sets) > maxNSECValidations {
		return nil
	}

	var out []*protocol.ResourceRecord
	for k, rrSet := range sets {
		// NSEC/NSEC3 records are never wildcard-synthesized (RFC 4035
		// §5.3.4, RFC 4592 §4.4): only a signature whose Labels covers the
		// owner as written authenticates them. Otherwise the RRSIG of a
		// literal "*.zone" NSEC verifies for ANY renamed owner below zone,
		// moving its gap anywhere (forged NXDOMAIN / insecure delegation,
		// F372).
		var sigs []*protocol.RDataRRSIG
		for _, sig := range v.findRRSIGs(msg.Authorities, k.name, k.rrtype) {
			if int(sig.Labels) == rrsigOwnerLabels(rrSet[0].Name) {
				sigs = append(sigs, sig)
			}
		}
		if _, ok := v.anyRRSIGValidates(rrSet, sigs, keys); !ok {
			continue
		}
		out = append(out, rrSet...)
	}
	return out
}

// fetchNSEC3PARAM fetches NSEC3PARAM records for a zone.
// Returns nil if the zone doesn't use NSEC3.
func (v *Validator) fetchNSEC3PARAM(ctx context.Context, zone string) (*protocol.RDataNSEC3PARAM, error) {
	if v.resolver == nil {
		return nil, fmt.Errorf("no resolver configured")
	}

	msg, err := v.resolver.Query(ctx, zone, protocol.TypeNSEC3PARAM)
	if err != nil {
		return nil, err
	}
	// Query hands back a pooled *protocol.Message; release it once the
	// parameter is extracted. Returning the bare RData pointer is safe:
	// RDataNSEC3PARAM has no case in protocol.releaseRData, so Release
	// never pools or mutates it.
	defer msg.Release()

	for _, rr := range msg.Answers {
		if rr.Type == protocol.TypeNSEC3PARAM {
			if nsec3param, ok := rr.Data.(*protocol.RDataNSEC3PARAM); ok {
				return nsec3param, nil
			}
		}
	}
	return nil, nil // No NSEC3PARAM means zone doesn't use NSEC3
}

// calculateDSDigestFromDNSKEY computes the DS digest for a DNSKEY.
// Per RFC 4034 Section 5:
//
//	digest = hash(canonical_owner_name | DNSKEY_RDATA)
//
// Where DNSKEY_RDATA = flags | protocol | algorithm | public_key
func calculateDSDigestFromDNSKEY(zone string, dnskey *protocol.RDataDNSKEY, digestType uint8) []byte {
	// Create the data to be hashed: canonical owner name + DNSKEY RDATA
	var data []byte

	// 1. Canonical owner name (lowercase, wire format)
	name := zone
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	name = strings.TrimSuffix(name, ".")
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if label == "" {
			continue
		}
		data = append(data, byte(len(label)))
		data = append(data, toLowerBytes(label)...)
	}
	data = append(data, 0) // Root label terminator

	// 2. DNSKEY RDATA: flags (2) | protocol (1) | algorithm (1) | public_key
	flagsBytes := make([]byte, 2)
	protocol.PutUint16(flagsBytes, dnskey.Flags)
	data = append(data, flagsBytes...)
	data = append(data, dnskey.Protocol)
	data = append(data, dnskey.Algorithm)
	data = append(data, dnskey.PublicKey...)

	// Hash the data based on digest type
	switch digestType {
	case 1: // SHA-1 (NOT RECOMMENDED but supported for compatibility)
		h := sha1.New() // #nosec G401,G505 -- DS digest type 1, mandated by RFC 4034
		h.Write(data)
		return h.Sum(nil)
	case 2: // SHA-256 (MUST implement per RFC 8624)
		h := sha256.New()
		h.Write(data)
		return h.Sum(nil)
	case 4: // SHA-384 (MAY implement per RFC 8624)
		h := sha512.New384()
		h.Write(data)
		return h.Sum(nil)
	default:
		return nil
	}
}

// HasSignature checks if a message contains DNSSEC signatures.
func HasSignature(msg *protocol.Message) bool {
	for _, rr := range msg.Answers {
		if rr.Type == protocol.TypeRRSIG {
			return true
		}
	}
	for _, rr := range msg.Authorities {
		if rr.Type == protocol.TypeRRSIG || rr.Type == protocol.TypeNSEC || rr.Type == protocol.TypeNSEC3 {
			return true
		}
	}
	return false
}

// ExtractRRSIGs extracts RRSIG records for a specific type.
func ExtractRRSIGs(msg *protocol.Message, rrtype uint16) []*protocol.RDataRRSIG {
	var rrsigs []*protocol.RDataRRSIG
	for _, rr := range msg.Answers {
		if rr.Type == protocol.TypeRRSIG {
			if rrsig, ok := rr.Data.(*protocol.RDataRRSIG); ok && rrsig.TypeCovered == rrtype {
				rrsigs = append(rrsigs, rrsig)
			}
		}
	}
	return rrsigs
}
