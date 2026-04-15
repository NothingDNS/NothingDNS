# NothingDNS Authentication KDF Design Document

## Overview

NothingDNS uses a **custom PBKDF2-HMAC-SHA512** implementation for password hashing. This document explains why a custom implementation is used, the exact algorithm parameters, and the test vectors used for validation.

## Why a Custom Implementation?

The project maintains a **zero external dependency** policy for core cryptographic code. While `golang.org/x/crypto/pbkdf2` exists, it is an external module. To keep the dependency graph minimal and ensure full auditability of the authentication path, the KDF is implemented using only the Go standard library (`crypto/hmac`, `crypto/sha512`).

## Algorithm Specification

### Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| PRF | HMAC-SHA512 | Standard, widely-reviewed pseudorandom function |
| Salt length | 32 bytes (256 bits) | Sufficient to prevent rainbow table attacks |
| Derived key length | 64 bytes (512 bits) | Matches SHA512 output size |
| Iterations | 310,000 | OWASP 2023 recommendation for PBKDF2-HMAC-SHA512 |

### Algorithm Steps

The implementation follows RFC 2898 §5.2 exactly:

1. **Salt generation**: If no salt is provided, 32 random bytes are generated via `crypto/rand`.
2. **Key derivation**:
   - Let `blockCount = ceil(keyLen / hmacSize)` where `hmacSize = 64` bytes.
   - For each block `i` from 1 to `blockCount`:
     - Compute `U_1 = HMAC-SHA512(password, salt || INT_32_BE(i))`
     - For `j` from 2 to `iterations`:
       - Compute `U_j = HMAC-SHA512(password, U_{j-1})`
     - Compute `T_i = U_1 XOR U_2 XOR ... XOR U_iterations`
   - Concatenate `T_1 || T_2 || ... || T_blockCount` and truncate to `keyLen` bytes.
3. **Storage format**: The final stored hash is `salt || derivedKey` (96 bytes total for the modern format).

### Legacy Format

An earlier version of the code used 16-byte salts and 32-byte derived keys (48 bytes total). `VerifyPassword` detects the legacy format by hash length and verifies it correctly, enabling seamless password upgrades on user login.

## Security Considerations

- **Memory hardness**: PBKDF2 is not memory-hard like Argon2 or scrypt. The high iteration count (310,000) is the primary defense against brute force.
- **Timing safety**: `VerifyPassword` uses `crypto/subtle.ConstantTimeCompare` to prevent timing attacks.
- **Salt uniqueness**: Salts are generated with `crypto/rand`, ensuring uniqueness across users and deployments.

## Known-Answer Test Vectors

These vectors are hardcoded in `internal/auth/auth_test.go` to detect accidental algorithm changes during refactoring.

### Vector 1

| Field | Value |
|-------|-------|
| Password | `test-password` |
| Salt (32 bytes) | `fixed-salt-32-bytes-for-testing!` |
| Iterations | 310,000 |
| Key length | 64 |
| Expected hash (hex) | `66697865642d73616c742d33322d62797465732d666f722d74657374696e6721c9bed9c9868a54078f34c0f8bafb2c226bfe8023aa75fda3fad1f4cc24339064e3bcc15b7d777c2985e01430ccdba99f4bf1bed1c1a2abfe610e25d059d5a1ad` |

## Change Control

Any modification to `HashPassword` or `VerifyPassword` **must**:

1. Preserve backward compatibility for existing stored hashes (legacy 48-byte format).
2. Update this document if parameters change.
3. Ensure the known-answer test in `auth_test.go` continues to pass.
4. Be reviewed for cryptographic correctness.

## References

- OWASP. *Password Storage Cheat Sheet*, 2023. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- RSA Laboratories. *PKCS #5 v2.1: Password-Based Cryptography Standard*, 2012.
- IETF. *RFC 2898 — PKCS #5: Password-Based Cryptography Specification Version 2.0*.
