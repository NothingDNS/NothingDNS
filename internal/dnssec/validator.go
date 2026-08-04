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
func (v *Validator) ValidateResponse(ctx context.Context, msg *protocol.Message, queryName string) (ValidationResult, error) {
	if !v.config.Enabled {
		return ValidationInsecure, nil
	}

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

	// Find closest trust anchor
	anchor, remaining := v.trustAnchors.FindClosestAnchor(queryName)
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
	return result, nil
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
	anchorKSKs := v.keysMatchingAnchor(anchor, dnsKeys)
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
	for i := len(remaining) - 1; i >= 0; i-- {
		childZone := joinLabels(remaining[i:])
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

		if len(dsRecords) == 0 {
			// An empty DS answer might mean (a) the parent zone
			// authoritatively says the child is unsigned — chain
			// genuinely ends in an Insecure delegation — or (b) an
			// on-path attacker stripped the DS RRset to downgrade
			// validation. The two are indistinguishable without an
			// authenticated denial proof. RFC 4035 §5.2 / RFC 5155
			// §8.6 require NSEC/NSEC3 proof of DS non-existence,
			// signed by the parent's ZSK, before treating the
			// subtree as Insecure.
			if !v.verifyDSDenial(dsMsg, childZone, chain) {
				return nil, false, fmt.Errorf("DS empty for %s but no authenticated denial proof (downgrade-attack guard)", childZone)
			}
			// Unsigned delegation - chain ends here. The query name is in an
			// Insecure subtree; signal it so the caller returns Insecure rather
			// than requiring (non-existent) signatures.
			insecure = true
			break
		}

		// The DS RRset itself lives in (and is signed by) the PARENT zone.
		// Its RRSIG must validate under the parent's already-authenticated
		// DNSKEYs, or an on-path attacker could substitute a DS matching a
		// forged child KSK and mint a fully "Secure" fake chain — the digest
		// match in keysMatchingDS alone authenticates nothing.
		if !v.verifyDSRRSIG(dsMsg, dsRecords, parentLink.dnsKeys) {
			return nil, false, fmt.Errorf("DS RRset for %s not signed by parent zone %s", childZone, parentLink.zone)
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
			dsRecords:  dsRecords,
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
	for _, sigRR := range sigs {
		rrsig, ok := sigRR.Data.(*protocol.RDataRRSIG)
		if !ok || rrsig.TypeCovered != protocol.TypeDNSKEY {
			continue
		}
		if v.validateRRSIG(keys, rrsig, trustedKSKs) {
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
	for _, rr := range dsMsg.Answers {
		if rr == nil || rr.Type != protocol.TypeRRSIG {
			continue
		}
		rrsig, ok := rr.Data.(*protocol.RDataRRSIG)
		if !ok || rrsig.TypeCovered != protocol.TypeDS {
			continue
		}
		if v.validateRRSIG(dsRecords, rrsig, parentKeys) {
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
	for _, rr := range msg.Answers {
		switch rr.Type {
		case protocol.TypeDNSKEY:
			keys = append(keys, rr)
		case protocol.TypeRRSIG:
			if sig, ok := rr.Data.(*protocol.RDataRRSIG); ok && sig.TypeCovered == protocol.TypeDNSKEY {
				sigs = append(sigs, rr)
			}
		}
	}
	return keys, sigs, nil
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
	for _, rrSet := range answerGroups {
		if len(rrSet) == 0 {
			continue
		}

		// RRSIG RRsets cover OTHER types, not themselves — never demand a
		// signature "over" an RRSIG (it would have no covering RRSIG and would
		// trip the missing-signature check below).
		if rrSet[0].Type == protocol.TypeRRSIG {
			continue
		}

		owner := rrSet[0].Name.String()

		// Find matching RRSIG
		rrsig := v.findRRSIG(msg.Answers, owner, rrSet[0].Type)
		if rrsig == nil {
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

		// Validate the signature
		if !v.validateRRSIG(rrSet, rrsig, zoneLink.dnsKeys) {
			return ValidationBogus
		}

		// Wildcard-expanded answers (RRSIG.Labels < the owner's label count)
		// require an authenticated proof that the owner has NO exact match in
		// the zone (RFC 4035 §5.3.4). Without it, a valid "*.zone" RRSIG could
		// be replayed onto an explicit name that has its own different record.
		// rrsig.Labels is part of the signed RRSIG RDATA, so an attacker cannot
		// forge the wildcard path — tampering Labels breaks the signature above.
		if int(rrsig.Labels) < len(rrSet[0].Name.LabelsSlice()) {
			if !v.wildcardExpansionProven(msg, owner, rrsig.Labels, rrSet[0].Type, chain) {
				return ValidationBogus
			}
		}
	}

	// Validate negative response if applicable
	if len(msg.Answers) == 0 {
		result := v.validateNegativeResponse(msg, queryName, chain)
		if result == ValidationBogus {
			return ValidationBogus
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
func (v *Validator) wildcardExpansionProven(msg *protocol.Message, owner string, sigLabels uint8, qtype uint16, chain []*chainLink) bool {
	ownerLabels := splitLabels(owner)
	if int(sigLabels) >= len(ownerLabels) {
		return false // not a wildcard expansion — caller should not have branched
	}
	// Next closer = one label deeper than the wildcard's closest encloser,
	// toward owner (rightmost sigLabels+1 labels of owner).
	nextCloser := strings.Join(ownerLabels[len(ownerLabels)-int(sigLabels)-1:], ".")

	authenticated := v.authenticatedDenialRRs(msg, chain)
	var nsec3RRs []*protocol.ResourceRecord
	checks := 0
	for _, rr := range authenticated {
		if checks >= maxNSECValidations {
			return false
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
				return true
			}
		case protocol.TypeNSEC3:
			nsec3RRs = append(nsec3RRs, rr)
		}
	}
	if len(nsec3RRs) > 0 {
		// The proven closest encloser must have EXACTLY sigLabels labels, i.e.
		// equal the wildcard's closest encloser — otherwise a deeper real
		// closest encloser (as in the a.sub.example.com attack) is rejected.
		if ce, _, ok := v.nsec3ClosestEncloserAndNextCloser(owner, nsec3RRs); ok && len(splitLabels(ce)) == int(sigLabels) {
			return true
		}
	}
	return false
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
// stayed dormant — but DNSSEC validation MUST not depend on a
// server choosing to send canonical case. strings.EqualFold handles
// the ASCII case-folding RFC 1035 requires.
func (v *Validator) findRRSIG(answers []*protocol.ResourceRecord, name string, rrtype uint16) *protocol.RDataRRSIG {
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
			return rrsig
		}
	}
	return nil
}

// validateRRSIG validates an RRSIG over an RRSet.
func (v *Validator) validateRRSIG(rrSet []*protocol.ResourceRecord, rrsig *protocol.RDataRRSIG, dnsKeys []*protocol.ResourceRecord) bool {
	// Check signature timestamps with clock skew tolerance
	if !v.config.IgnoreTime {
		now := uint32(time.Now().Unix())
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
	if len(msg.Questions) == 0 {
		return ValidationBogus
	}
	qtype := msg.Questions[0].QType
	isNXDomain := msg.Header.Flags.RCODE == protocol.RcodeNameError

	// NEW-H2: filter to only the NSEC/NSEC3 records whose RRset
	// carries a valid RRSIG signed by the current zone's keys.
	// Without this gate, an on-path attacker can spoof NSEC denial
	// without ever supplying a real signature — same downgrade-attack
	// class as H-2 on the chain-build DS path. RFC 4035 §5.4 / RFC
	// 5155 §8 require authenticated denial proofs.
	authenticated := v.authenticatedDenialRRs(msg, chain)
	if len(authenticated) == 0 {
		return ValidationBogus
	}

	// Walk authenticated set once, counting distinct proof contributions.
	// A name-cover proof: NSEC/NSEC3 whose range covers queryName.
	// A wildcard-cover proof: NSEC range covers "*.<ancestor>" of queryName,
	// or (for NSEC3) any second distinct NSEC3 that passes range checks.
	nameProofs := make(map[string]bool)     // distinct owner names whose range proves queryName
	wildcardProofs := make(map[string]bool) // distinct owner names whose range covers a wildcard

	checks := 0
	for _, rr := range authenticated {
		if checks >= maxNSECValidations {
			return ValidationBogus
		}
		checks++

		key := strings.ToLower(rr.Name.String())

		if rr.Type == protocol.TypeNSEC {
			nsec, ok := rr.Data.(*protocol.RDataNSEC)
			if !ok {
				continue
			}
			if v.validateNSEC(rr.Name.String(), queryName, qtype, nsec) {
				nameProofs[key] = true
			}
			if nsecCoversWildcardOfAncestor(rr.Name.String(), nsec, queryName) {
				wildcardProofs[key] = true
			}
		}
		if rr.Type == protocol.TypeNSEC3 {
			nsec3, ok := rr.Data.(*protocol.RDataNSEC3)
			if !ok {
				continue
			}
			if v.validateNSEC3(rr.Name.String(), queryName, qtype, nsec3, chain) {
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
			if v.validateNSEC3ClosestEncloser(queryName, nsec3RRs) {
				return ValidationSecure
			}
			// If NSEC3 records exist but closest-encloser proof fails, do
			// not fall back to the NSEC path — that would let an attacker
			// mix-and-match record types.
			if len(nsec3RRs) == checks {
				return ValidationBogus
			}
		}
	}

	if isNXDomain {
		// Require at least one name-cover AND a distinct wildcard-cover.
		// For NSEC3 the second proof can come from any distinct NSEC3 (see
		// above) — this is a strict superset of "single-proof accepted" but
		// not the full RFC 5155 §8 three-proof closest-encloser algorithm.
		if len(nameProofs) >= 1 && len(wildcardProofs) >= 1 {
			// And the two proofs must come from distinct owner names; an
			// attacker recycling the same NSEC for both slots is rejected.
			for k := range nameProofs {
				if !wildcardProofs[k] {
					return ValidationSecure
				}
				if len(wildcardProofs) >= 2 {
					return ValidationSecure
				}
			}
		}
		return ValidationBogus
	}

	// NODATA: a single matching proof is sufficient.
	if len(nameProofs) >= 1 {
		return ValidationSecure
	}
	return ValidationBogus
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
	closestEncloser, params, ok := v.nsec3ClosestEncloserAndNextCloser(queryName, rrs)
	if !ok {
		return false
	}

	// 3. Wildcard "*.<closest_encloser>" cover — required for NXDOMAIN to prove
	// no wildcard could have answered either. (For a wildcard-POSITIVE answer
	// this step is intentionally omitted: the wildcard DOES exist and answered.)
	wildcard := "*." + strings.TrimSuffix(closestEncloser, ".")
	if closestEncloser == "." {
		wildcard = "*."
	}
	return v.nsec3NameCovered(wildcard, params, rrs)
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
	h, err := NSEC3Hash(name, p.algo, p.iter, p.salt)
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
		h, err := NSEC3Hash(name, params.algo, params.iter, params.salt)
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

// nsecCoversWildcardOfAncestor reports whether the NSEC's [owner, NextDomain)
// range covers a wildcard owner "*.<X>" for some ancestor X of queryName
// (including queryName itself). RFC 4035 §5.4 wildcard non-existence proof.
func nsecCoversWildcardOfAncestor(owner string, nsec *protocol.RDataNSEC, queryName string) bool {
	if nsec == nil || nsec.NextDomain == nil {
		return false
	}
	next := nsec.NextDomain.String()
	// Walk ancestors of queryName: the name itself, then its parent, ... up
	// to (but not including) the root. The wildcard "*.<root>" == "*." is
	// included as the broadest fallback.
	name := strings.TrimSuffix(queryName, ".")
	for {
		wildcard := "*." + name
		if name == "" {
			wildcard = "*."
		}
		if nameInRange(wildcard, owner, next) {
			return true
		}
		idx := strings.Index(name, ".")
		if idx < 0 {
			// Last iteration: try wildcard at root.
			if name != "" {
				name = ""
				continue
			}
			break
		}
		name = name[idx+1:]
	}
	return false
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
	hashedName, err := NSEC3Hash(queryName, nsec3.HashAlgorithm, nsec3.Iterations, nsec3.Salt)
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
	la := splitLabels(strings.ToLower(a))
	lb := splitLabels(strings.ToLower(b))
	for i := 1; i <= len(la) && i <= len(lb); i++ {
		if c := strings.Compare(la[len(la)-i], lb[len(lb)-i]); c != 0 {
			return c
		}
	}
	switch {
	case len(la) < len(lb):
		return -1
	case len(la) > len(lb):
		return 1
	default:
		return 0
	}
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

	var dsRecords []*protocol.ResourceRecord
	for _, rr := range msg.Answers {
		if rr.Type == protocol.TypeDS {
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

func (v *Validator) verifyDSDenial(msg *protocol.Message, zone string, chain []*chainLink) bool {
	if msg == nil || len(chain) == 0 {
		return false
	}
	parentKeys := chain[len(chain)-1].dnsKeys
	if len(parentKeys) == 0 {
		return false
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

	for k, rrSet := range sets {
		rrsig := v.findRRSIG(msg.Authorities, k.name, k.rrtype)
		if rrsig == nil {
			continue
		}
		if !v.validateRRSIG(rrSet, rrsig, parentKeys) {
			continue
		}
		// Signature good. Does this RRset prove NoData(DS) at zone?
		for _, rr := range rrSet {
			switch rr.Type {
			case protocol.TypeNSEC:
				nsec, ok := rr.Data.(*protocol.RDataNSEC)
				if !ok {
					continue
				}
				if nsecProvesNoDS(rr.Name.String(), zone, nsec) {
					return true
				}
			case protocol.TypeNSEC3:
				nsec3, ok := rr.Data.(*protocol.RDataNSEC3)
				if !ok {
					continue
				}
				if nsec3ProvesNoDS(rr.Name.String(), zone, nsec3) {
					return true
				}
			}
		}
	}
	return false
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

	var out []*protocol.ResourceRecord
	for k, rrSet := range sets {
		rrsig := v.findRRSIG(msg.Authorities, k.name, k.rrtype)
		if rrsig == nil {
			continue
		}
		if !v.validateRRSIG(rrSet, rrsig, keys) {
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
