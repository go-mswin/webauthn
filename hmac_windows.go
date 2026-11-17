// Copyright (c) the go-mswin authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows && (amd64 || arm64)

package webauthn

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The hmac-secret and credProtect plumbing, from Microsoft's webauthn.h
// (github.com/microsoft/webauthn, API version 9):
//
//   - MakeCredential takes extensions in WEBAUTHN_EXTENSIONS: "hmac-secret" as a
//     BOOL TRUE, "credProtect" as WEBAUTHN_CRED_PROTECT_EXTENSION_IN, and
//     reports them back in WEBAUTHN_CREDENTIAL_ATTESTATION.Extensions (v2).
//   - GetAssertion lists hmac-secret as "Input Type: Not Supported" among the
//     extensions. The salts travel instead in
//     GET_ASSERTION_OPTIONS.pHmacSecretSaltValues (options version 6), with
//     WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG in dwFlags to make Windows
//     pass them RAW rather than through the WebAuthn PRF derivation, and the
//     output comes back in WEBAUTHN_ASSERTION.pHmacSecret (assertion version 3).

const (
	// getAssertionOptVersionHMAC is the options version that carries
	// pHmacSecretSaltValues.
	getAssertionOptVersionHMAC = 6
	// assertionVersionHMAC is the first WEBAUTHN_ASSERTION version with pHmacSecret.
	assertionVersionHMAC = 3
	// attestationVersionExtensions is the first attestation version with the
	// output Extensions.
	attestationVersionExtensions = 2

	hmacSecretValuesFlag = 0x00100000

	extHMACSecret  = "hmac-secret"
	extCredProtect = "credProtect"
)

// webauthnExtension is WEBAUTHN_EXTENSION.
type webauthnExtension struct {
	pwszExtensionIdentifier *uint16
	cbExtension             uint32
	pvExtension             unsafe.Pointer
}

// webauthnCredProtectIn is WEBAUTHN_CRED_PROTECT_EXTENSION_IN.
type webauthnCredProtectIn struct {
	dwCredProtect       uint32
	bRequireCredProtect int32
}

// webauthnHMACSecretSalt is WEBAUTHN_HMAC_SECRET_SALT.
type webauthnHMACSecretSalt struct {
	cbFirst  uint32
	pbFirst  *byte
	cbSecond uint32
	pbSecond *byte
}

// webauthnHMACSecretSaltValues is WEBAUTHN_HMAC_SECRET_SALT_VALUES.
type webauthnHMACSecretSaltValues struct {
	pGlobalHmacSalt            *webauthnHMACSecretSalt
	cCredWithHmacSecretSalt    uint32
	pCredWithHmacSecretSaltLst unsafe.Pointer
}

// registerExtensions is what a registration's extensions point at; the value
// keeps every referenced allocation alive until the call has returned.
type registerExtensions struct {
	list     []webauthnExtension
	ids      []*uint16
	hmac     int32
	credProt webauthnCredProtectIn
}

func newRegisterExtensions(req RegisterRequest) (*registerExtensions, error) {
	e := &registerExtensions{}
	if req.HMACSecret {
		id, err := windows.UTF16PtrFromString(extHMACSecret)
		if err != nil {
			return nil, err
		}
		e.hmac = 1
		e.ids = append(e.ids, id)
		e.list = append(e.list, webauthnExtension{
			pwszExtensionIdentifier: id,
			cbExtension:             uint32(unsafe.Sizeof(e.hmac)),
			pvExtension:             unsafe.Pointer(&e.hmac),
		})
	}
	if req.CredProtect != 0 {
		id, err := windows.UTF16PtrFromString(extCredProtect)
		if err != nil {
			return nil, err
		}
		e.credProt = webauthnCredProtectIn{dwCredProtect: req.CredProtect, bRequireCredProtect: 1}
		e.ids = append(e.ids, id)
		e.list = append(e.list, webauthnExtension{
			pwszExtensionIdentifier: id,
			cbExtension:             uint32(unsafe.Sizeof(e.credProt)),
			pvExtension:             unsafe.Pointer(&e.credProt),
		})
	}
	return e, nil
}

// apply points the options' extension list at e's entries.
func (e *registerExtensions) apply(o *webauthnExtensions) {
	if len(e.list) == 0 {
		return
	}
	*o = webauthnExtensions{cExtensions: uint32(len(e.list)), pExtensions: unsafe.Pointer(&e.list[0])}
}

// hmacSalts is what an assertion's pHmacSecretSaltValues points at.
type hmacSalts struct {
	first, second [32]byte
	salt          webauthnHMACSecretSalt
	values        webauthnHMACSecretSaltValues
}

func newHMACSalts(salts [][32]byte) (*hmacSalts, error) {
	if len(salts) == 0 || len(salts) > MaxHMACSalts {
		return nil, fmt.Errorf("webauthn: %d hmac-secret salts, want 1 or %d", len(salts), MaxHMACSalts)
	}
	h := &hmacSalts{first: salts[0]}
	h.salt = webauthnHMACSecretSalt{cbFirst: 32, pbFirst: &h.first[0]}
	if len(salts) == 2 {
		h.second = salts[1]
		h.salt.cbSecond, h.salt.pbSecond = 32, &h.second[0]
	}
	h.values = webauthnHMACSecretSaltValues{pGlobalHmacSalt: &h.salt}
	return h, nil
}

// readHMACSecret copies the outputs, before the assertion is freed. Each
// output is 32 bytes; anything else is refused as "no secret" rather than
// handed on as a key of the wrong size.
func readHMACSecret(a *webauthnAssertion) [][]byte {
	if a.dwVersion < assertionVersionHMAC || a.pHmacSecret == nil {
		return nil
	}
	s := (*webauthnHMACSecretSalt)(a.pHmacSecret)
	if s.cbFirst != 32 || s.pbFirst == nil {
		return nil
	}
	out := [][]byte{copyBytes(s.pbFirst, s.cbFirst)}
	if s.cbSecond != 0 {
		if s.cbSecond != 32 || s.pbSecond == nil {
			return nil
		}
		out = append(out, copyBytes(s.pbSecond, s.cbSecond))
	}
	return out
}

// readExtensions reports what Windows says a new credential has.
func readExtensions(a *webauthnCredentialAttestation, out *Registration) {
	if a.dwVersion < attestationVersionExtensions || a.extensions.cExtensions == 0 || a.extensions.pExtensions == nil {
		return
	}
	for _, e := range unsafe.Slice((*webauthnExtension)(a.extensions.pExtensions), a.extensions.cExtensions) {
		if e.pwszExtensionIdentifier == nil || e.pvExtension == nil {
			continue
		}
		switch windows.UTF16PtrToString(e.pwszExtensionIdentifier) {
		case extHMACSecret:
			if e.cbExtension == 4 {
				out.HMACSecret = *(*int32)(e.pvExtension) != 0
			}
		case extCredProtect:
			if e.cbExtension == 4 {
				out.CredProtect = *(*uint32)(e.pvExtension)
			}
		}
	}
}
