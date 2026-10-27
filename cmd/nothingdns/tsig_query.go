// NothingDNS - TSIG on ordinary queries (RFC 8945)
//
// A server that receives a TSIG-signed request verifies it: a key it does not
// know or a MAC that does not match is answered NOTAUTH (§5.2), and the
// answer to a verified request is signed with the same key, bound to the
// request's MAC (§5.3). Zone transfers, NOTIFY and UPDATE verify and sign in
// their own handlers; an ordinary query that carried a TSIG was answered
// without either, so a forged MAC was accepted and BIND's `dig -y` reported
// "Couldn't verify signature: expected a TSIG" (F759). The keys are the
// configured transfer.tsig_keys.

package main

import (
	"context"
	"net"

	"github.com/nothingdns/nothingdns/internal/protocol"
	"github.com/nothingdns/nothingdns/internal/server"
	"github.com/nothingdns/nothingdns/internal/transfer"
)

// tsigQueryStage verifies the TSIG of an ordinary query and arranges for the
// answer to be signed.
func tsigQueryStage(h *integratedHandler) Stage {
	return func(ctx context.Context, q *query, w server.ResponseWriter) (bool, error) {
		msg := q.msg
		if msg.Header.Flags.Opcode != protocol.OpcodeQuery || q.qtype == protocol.TypeAXFR || q.qtype == protocol.TypeIXFR {
			return false, nil // handled by the transfer stage
		}
		var keyName string
		for _, rr := range msg.Additionals {
			if rr != nil && rr.Type == protocol.TypeTSIG && rr.Name != nil {
				keyName = rr.Name.String()
				break
			}
		}
		if keyName == "" {
			return false, nil
		}

		key := h.verifiedQueryKey(msg, keyName, w.ClientInfo().IP())
		if key == nil {
			sendError(q.currentWriter, msg, protocol.RcodeNotAuth)
			return true, nil
		}
		mac, err := transfer.TSIGRequestMAC(msg)
		if err != nil {
			sendError(q.currentWriter, msg, protocol.RcodeNotAuth)
			return true, nil
		}
		q.currentWriter = &tsigResponseWriter{inner: q.currentWriter, key: key, requestMAC: mac}
		return false, nil
	}
}

// verifiedQueryKey returns the configured key keyName if msg verifies with it
// and the client may use it, else nil.
func (h *integratedHandler) verifiedQueryKey(msg *protocol.Message, keyName string, clientIP net.IP) *transfer.TSIGKey {
	h.xferKeysMu.RLock()
	defer h.xferKeysMu.RUnlock()
	if h.transfer.AXFRKeys == nil || h.transfer.AXFRKeys.store == nil {
		return nil
	}
	store := h.transfer.AXFRKeys.store
	key, ok := store.GetKey(keyName)
	if !ok || store.ValidateKeySource(keyName, clientIP) != nil {
		return nil
	}
	if transfer.VerifyMessage(msg, key, nil) != nil {
		return nil
	}
	return key
}

// tsigResponseWriter signs the answer to a TSIG-verified query.
type tsigResponseWriter struct {
	inner      server.ResponseWriter
	key        *transfer.TSIGKey
	requestMAC []byte
}

// Write signs msg and sends it. The signature covers the message as the
// writers wrapping inner finally send it (their rewrites are applied first,
// as for UPDATE responses), and msg is cut down so that message and TSIG
// together fit the client's limit.
func (tw *tsigResponseWriter) Write(msg *protocol.Message) (int, error) {
	applyResponseWriterRewrites(tw.inner, msg)
	sign := func() (*protocol.ResourceRecord, error) {
		return transfer.NewTSIGStreamSigner(tw.key, tw.requestMAC, 300).Sign(msg)
	}
	rr, err := sign()
	if err != nil {
		return 0, err
	}
	if limit := tw.inner.MaxSize(); limit > 0 && msg.WireLength()+rr.WireLength() > limit {
		msg.Truncate(limit - rr.WireLength())
		if rr, err = sign(); err != nil {
			return 0, err
		}
	}
	msg.Additionals = append(msg.Additionals, rr)
	return tw.inner.Write(msg)
}

// Unwrap returns the wrapped writer.
func (tw *tsigResponseWriter) Unwrap() server.ResponseWriter { return tw.inner }

// ClientInfo delegates to the inner writer.
func (tw *tsigResponseWriter) ClientInfo() *server.ClientInfo { return tw.inner.ClientInfo() }

// MaxSize delegates to the inner writer.
func (tw *tsigResponseWriter) MaxSize() int { return tw.inner.MaxSize() }
