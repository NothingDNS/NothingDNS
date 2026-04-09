package quic

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Transport parameter IDs (RFC 9000 Section 18.2).
const (
	ParamOriginalDestConnID     = 0x0000
	ParamMaxIdleTimeout         = 0x0001
	ParamStatelessResetToken    = 0x0002
	ParamMaxUDPPayloadSize      = 0x0003
	ParamInitialMaxData         = 0x0004
	ParamInitialMaxStreamDataBidiLocal  = 0x0005
	ParamInitialMaxStreamDataBidiRemote = 0x0006
	ParamInitialMaxStreamDataUni        = 0x0007
	ParamInitialMaxStreamsBidi   = 0x0008
	ParamInitialMaxStreamsUni    = 0x0009
	ParamAckDelayExponent       = 0x000a
	ParamMaxAckDelay            = 0x000b
	ParamDisableActiveMigration = 0x000c
	ParamActiveConnIDLimit      = 0x000e
	ParamInitialSourceConnID    = 0x000f
	// DoQ-specific (RFC 9250)
	ParamDoQMaxIDLETimeout      = 0x0047 // Draft-identified but not in RFC 9000
)

// Default transport parameter values.
const (
	DefaultMaxUDPPayloadSize    = 65527
	DefaultInitialMaxData       = 1048576 // 1 MB
	DefaultInitialMaxStreamData = 262144  // 256 KB
	DefaultInitialMaxStreamsBidi = 100
	DefaultInitialMaxStreamsUni  = 100
	DefaultAckDelayExponent     = 3
	DefaultMaxAckDelay          = 25 // ms
	DefaultActiveConnIDLimit    = 2
	DefaultMaxIdleTimeoutMs     = 30000 // 30 seconds
)

var (
	ErrInvalidTransportParams = errors.New("quic: invalid transport parameters")
)

// TransportParams holds QUIC transport parameters.
type TransportParams struct {
	MaxUDPPayloadSize           uint64
	InitialMaxData              uint64
	InitialMaxStreamDataBidiLocal  uint64
	InitialMaxStreamDataBidiRemote uint64
	InitialMaxStreamDataUni        uint64
	InitialMaxStreamsBidi       uint64
	InitialMaxStreamsUni        uint64
	MaxIdleTimeout              uint64 // milliseconds
	AckDelayExponent            uint64
	MaxAckDelay                 uint64 // milliseconds
	ActiveConnIDLimit           uint64
	DisableActiveMigration      bool
	OriginalDestConnID          ConnectionID
	InitialSourceConnID         ConnectionID
	RetrySourceConnID           ConnectionID
	StatelessResetToken         [16]byte
	HasStatelessResetToken      bool
}

// DefaultTransportParams returns server transport parameters with sensible defaults.
func DefaultTransportParams() *TransportParams {
	return &TransportParams{
		MaxUDPPayloadSize:              DefaultMaxUDPPayloadSize,
		InitialMaxData:                 DefaultInitialMaxData,
		InitialMaxStreamDataBidiLocal:  DefaultInitialMaxStreamData,
		InitialMaxStreamDataBidiRemote: DefaultInitialMaxStreamData,
		InitialMaxStreamDataUni:        DefaultInitialMaxStreamData,
		InitialMaxStreamsBidi:          DefaultInitialMaxStreamsBidi,
		InitialMaxStreamsUni:           DefaultInitialMaxStreamsUni,
		MaxIdleTimeout:                 DefaultMaxIdleTimeoutMs,
		AckDelayExponent:               DefaultAckDelayExponent,
		MaxAckDelay:                    DefaultMaxAckDelay,
		ActiveConnIDLimit:              DefaultActiveConnIDLimit,
	}
}

// Encode serializes transport parameters into wire format (RFC 9000 Section 18.2).
func (tp *TransportParams) Encode() []byte {
	buf := make([]byte, 0, 256)

	// MaxUDPPayloadSize
	buf = tp.encodeParam(buf, ParamMaxUDPPayloadSize, func(b []byte) []byte {
		return AppendVarint(b, tp.MaxUDPPayloadSize)
	})

	// InitialMaxData
	buf = tp.encodeParam(buf, ParamInitialMaxData, func(b []byte) []byte {
		return AppendVarint(b, tp.InitialMaxData)
	})

	// InitialMaxStreamDataBidiLocal
	buf = tp.encodeParam(buf, ParamInitialMaxStreamDataBidiLocal, func(b []byte) []byte {
		return AppendVarint(b, tp.InitialMaxStreamDataBidiLocal)
	})

	// InitialMaxStreamDataBidiRemote
	buf = tp.encodeParam(buf, ParamInitialMaxStreamDataBidiRemote, func(b []byte) []byte {
		return AppendVarint(b, tp.InitialMaxStreamDataBidiRemote)
	})

	// InitialMaxStreamDataUni
	buf = tp.encodeParam(buf, ParamInitialMaxStreamDataUni, func(b []byte) []byte {
		return AppendVarint(b, tp.InitialMaxStreamDataUni)
	})

	// InitialMaxStreamsBidi
	buf = tp.encodeParam(buf, ParamInitialMaxStreamsBidi, func(b []byte) []byte {
		return AppendVarint(b, tp.InitialMaxStreamsBidi)
	})

	// InitialMaxStreamsUni
	buf = tp.encodeParam(buf, ParamInitialMaxStreamsUni, func(b []byte) []byte {
		return AppendVarint(b, tp.InitialMaxStreamsUni)
	})

	// MaxIdleTimeout
	if tp.MaxIdleTimeout > 0 {
		buf = tp.encodeParam(buf, ParamMaxIdleTimeout, func(b []byte) []byte {
			return AppendVarint(b, tp.MaxIdleTimeout)
		})
	}

	// AckDelayExponent
	if tp.AckDelayExponent != DefaultAckDelayExponent {
		buf = tp.encodeParam(buf, ParamAckDelayExponent, func(b []byte) []byte {
			return AppendVarint(b, tp.AckDelayExponent)
		})
	}

	// MaxAckDelay
	if tp.MaxAckDelay != DefaultMaxAckDelay {
		buf = tp.encodeParam(buf, ParamMaxAckDelay, func(b []byte) []byte {
			return AppendVarint(b, tp.MaxAckDelay)
		})
	}

	// ActiveConnIDLimit
	if tp.ActiveConnIDLimit != DefaultActiveConnIDLimit {
		buf = tp.encodeParam(buf, ParamActiveConnIDLimit, func(b []byte) []byte {
			return AppendVarint(b, tp.ActiveConnIDLimit)
		})
	}

	// InitialSourceConnID
	if len(tp.InitialSourceConnID) > 0 {
		buf = tp.encodeParam(buf, ParamInitialSourceConnID, func(b []byte) []byte {
			b = append(b, byte(len(tp.InitialSourceConnID)))
			b = append(b, tp.InitialSourceConnID...)
			return b
		})
	}

	// StatelessResetToken
	if tp.HasStatelessResetToken {
		buf = tp.encodeParam(buf, ParamStatelessResetToken, func(b []byte) []byte {
			return append(b, tp.StatelessResetToken[:]...)
		})
	}

	return buf
}

func (tp *TransportParams) encodeParam(buf []byte, id uint64, valueFn func([]byte) []byte) []byte {
	buf = AppendVarint(buf, id)
	value := valueFn(nil)
	buf = AppendVarint(buf, uint64(len(value)))
	buf = append(buf, value...)
	return buf
}

// DecodeTransportParams decodes transport parameters from wire format.
func DecodeTransportParams(data []byte) (*TransportParams, error) {
	tp := DefaultTransportParams()

	offset := 0
	for offset < len(data) {
		paramID, n := DecodeVarint(data[offset:])
		if n == 0 {
			return nil, ErrInvalidTransportParams
		}
		offset += n

		paramLen, n := DecodeVarint(data[offset:])
		if n == 0 {
			return nil, ErrInvalidTransportParams
		}
		offset += n

		if offset+int(paramLen) > len(data) {
			return nil, ErrInvalidTransportParams
		}

		paramData := data[offset : offset+int(paramLen)]
		offset += int(paramLen)

		switch paramID {
		case ParamMaxUDPPayloadSize:
			v, _ := DecodeVarint(paramData)
			tp.MaxUDPPayloadSize = v
		case ParamInitialMaxData:
			v, _ := DecodeVarint(paramData)
			tp.InitialMaxData = v
		case ParamInitialMaxStreamDataBidiLocal:
			v, _ := DecodeVarint(paramData)
			tp.InitialMaxStreamDataBidiLocal = v
		case ParamInitialMaxStreamDataBidiRemote:
			v, _ := DecodeVarint(paramData)
			tp.InitialMaxStreamDataBidiRemote = v
		case ParamInitialMaxStreamDataUni:
			v, _ := DecodeVarint(paramData)
			tp.InitialMaxStreamDataUni = v
		case ParamInitialMaxStreamsBidi:
			v, _ := DecodeVarint(paramData)
			tp.InitialMaxStreamsBidi = v
		case ParamInitialMaxStreamsUni:
			v, _ := DecodeVarint(paramData)
			tp.InitialMaxStreamsUni = v
		case ParamMaxIdleTimeout:
			v, _ := DecodeVarint(paramData)
			tp.MaxIdleTimeout = v
		case ParamAckDelayExponent:
			v, _ := DecodeVarint(paramData)
			tp.AckDelayExponent = v
		case ParamMaxAckDelay:
			v, _ := DecodeVarint(paramData)
			tp.MaxAckDelay = v
		case ParamActiveConnIDLimit:
			v, _ := DecodeVarint(paramData)
			tp.ActiveConnIDLimit = v
		case ParamDisableActiveMigration:
			tp.DisableActiveMigration = true
		case ParamStatelessResetToken:
			if len(paramData) == 16 {
				copy(tp.StatelessResetToken[:], paramData)
				tp.HasStatelessResetToken = true
			}
		case ParamInitialSourceConnID:
			if len(paramData) > 0 {
				cidLen := int(paramData[0])
				if cidLen <= len(paramData)-1 {
					tp.InitialSourceConnID = ConnectionID(paramData[1 : 1+cidLen])
				}
			}
		case ParamOriginalDestConnID:
			tp.OriginalDestConnID = ConnectionID(paramData)
		}
	}

	return tp, nil
}

// Validate checks that transport parameters have sensible values.
func (tp *TransportParams) Validate() error {
	if tp.MaxUDPPayloadSize < 1200 {
		return fmt.Errorf("%w: max_udp_payload_size too small (%d)", ErrInvalidTransportParams, tp.MaxUDPPayloadSize)
	}
	if tp.InitialMaxStreamsBidi > 65535 {
		return fmt.Errorf("%w: initial_max_streams_bidi too large", ErrInvalidTransportParams)
	}
	if tp.AckDelayExponent > 20 {
		return fmt.Errorf("%w: ack_delay_exponent too large", ErrInvalidTransportParams)
	}
	if tp.MaxAckDelay >= 1<<14 {
		return fmt.Errorf("%w: max_ack_delay too large", ErrInvalidTransportParams)
	}
	return nil
}

// GenerateStatelessResetToken generates a stateless reset token from
// a connection ID and a secret key per RFC 9002.
func GenerateStatelessResetToken(secret []byte, connID ConnectionID) [16]byte {
	// RFC 9002: HMAC-SHA256 of the connection ID with the secret key
	mac := hmac.New(sha256.New, secret)
	mac.Write(connID)
	var token [16]byte
	copy(token[:], mac.Sum(nil)[:16])
	return token
}

// EncodeTransportParamsForTLS encodes transport parameters in the format
// expected by crypto/tls for the EncodedParameters field:
//
//	2 bytes: length of parameters
//	N bytes: parameters
func EncodeTransportParamsForTLS(tp *TransportParams) []byte {
	params := tp.Encode()
	buf := make([]byte, 2+len(params))
	binary.BigEndian.PutUint16(buf[0:], uint16(len(params)))
	copy(buf[2:], params)
	return buf
}

// DecodeTransportParamsFromTLS decodes transport parameters from the format
// used by crypto/tls (2-byte length prefix + parameters).
func DecodeTransportParamsFromTLS(data []byte) (*TransportParams, error) {
	if len(data) < 2 {
		return nil, ErrInvalidTransportParams
	}
	paramLen := int(binary.BigEndian.Uint16(data[0:]))
	if len(data) < 2+paramLen {
		return nil, ErrInvalidTransportParams
	}
	return DecodeTransportParams(data[2 : 2+paramLen])
}
