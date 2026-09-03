// Copyright (c) the go-windows authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// Package webauthn asks Windows to authenticate somebody, in pure Go with
// CGO_ENABLED=0.
//
// It calls the Win32 WebAuthn API in webauthn.dll — the same one browsers use.
// Windows finds the authenticator, shows its own dialog, collects a PIN or a
// fingerprint, and hands back a signed assertion.
//
// # Why not CTAP, as on Linux and macOS
//
// Because Windows will not let a normal program talk to a security key at all.
// Since Windows 10 version 1903, opening a FIDO HID device requires elevation:
// Microsoft closed that door and pointed everyone at this API. A CTAP
// transport here would work only for administrators, which is not a program
// anybody should ship. (The one project that does it anyway installs an
// elevated Windows service and relays CTAPHID over a named pipe — the size of
// that workaround is the measure of the wall.)
//
// So this package is shaped differently from its siblings, and deliberately.
// github.com/go-authn/fido is not underneath it: the protocol is Windows's
// business here, and what comes back is an assertion, not a CTAP reply.
//
// # What was proved, and what only somebody could tell you
//
// An assertion says a credential answered and, through its flags, whether the
// authenticator verified who was holding it. It does NOT say what convinced
// it. Windows Hello accepts a face, a fingerprint, or a **PIN** — and a PIN is
// something known, not something anyone is. A caller that read "user verified"
// as "biometrics" would be reporting the wrong kind of proof.
//
// Two things narrow it, and this package offers both:
//
//   - [Request.Attachment] constrains what may answer at all. [CrossPlatform]
//     asks for a security key — something carried. [Platform] asks for the one
//     built into this machine.
//   - [Assertion.Transport] reports what actually answered, when Windows says.
//     Asking is a request; this is an observation, and they can differ.
package webauthn

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Attachment says which authenticators may answer.
type Attachment uint32

// The attachments, numbered as webauthn.h numbers them.
const (
	// AnyAttachment lets Windows offer whatever it has. The answer does not
	// say which kind was used unless [Assertion.Transport] does.
	AnyAttachment Attachment = 0
	// Platform is the authenticator built into this machine: Windows Hello.
	Platform Attachment = 1
	// CrossPlatform is something carried and plugged in: a security key.
	CrossPlatform Attachment = 2
)

func (a Attachment) String() string {
	switch a {
	case AnyAttachment:
		return "any authenticator"
	case Platform:
		return "this machine's authenticator"
	case CrossPlatform:
		return "a security key"
	}
	return fmt.Sprintf("attachment(%d)", uint32(a))
}

// UserVerification says how hard Windows should insist on knowing who is
// there.
type UserVerification uint32

// The requirements, numbered as webauthn.h numbers them.
const (
	VerificationAny         UserVerification = 0
	VerificationRequired    UserVerification = 1
	VerificationPreferred   UserVerification = 2
	VerificationDiscouraged UserVerification = 3
)

func (v UserVerification) String() string {
	switch v {
	case VerificationAny:
		return "any"
	case VerificationRequired:
		return "required"
	case VerificationPreferred:
		return "preferred"
	case VerificationDiscouraged:
		return "discouraged"
	}
	return fmt.Sprintf("verification(%d)", uint32(v))
}

// Transport is how an authenticator was reached. Windows reports it in the
// assertion, from version 4 of that structure onwards.
type Transport uint32

// The transports, as the WEBAUTHN_CTAP_TRANSPORT_* bits.
const (
	TransportUnknown   Transport = 0
	TransportUSB       Transport = 0x01
	TransportNFC       Transport = 0x02
	TransportBLE       Transport = 0x04
	TransportTest      Transport = 0x08
	TransportInternal  Transport = 0x10
	TransportHybrid    Transport = 0x20
	TransportSmartCard Transport = 0x40
)

// String uses the names the specification gives these, which are the ones the
// header spells out as WEBAUTHN_CTAP_TRANSPORT_*_STRING.
func (t Transport) String() string {
	switch t {
	case TransportUSB:
		return "usb"
	case TransportNFC:
		return "nfc"
	case TransportBLE:
		return "ble"
	case TransportTest:
		return "test"
	case TransportInternal:
		return "internal"
	case TransportHybrid:
		return "hybrid"
	case TransportSmartCard:
		return "smart-card"
	case TransportUnknown:
		return "unreported"
	}
	return fmt.Sprintf("transport(%#x)", uint32(t))
}

// Carried reports whether the authenticator was a separate object rather than
// part of this machine.
//
// It is the honest half of the question a policy wants to ask. "internal" is
// this computer; usb, nfc, ble, smart-card and hybrid are all something
// brought to it. An UNREPORTED transport answers neither way, and this says
// so through ok rather than guessing -- older Windows fills in no transport at
// all, and treating silence as "not carried" would quietly downgrade every
// security key on those machines.
func (t Transport) Carried() (carried, ok bool) {
	switch t {
	case TransportUSB, TransportNFC, TransportBLE, TransportHybrid, TransportSmartCard:
		return true, true
	case TransportInternal:
		return false, true
	}
	return false, false
}

// Credential names one registered credential.
type Credential struct {
	// ID is what a registration returned.
	ID []byte
}

// Request is one authentication.
type Request struct {
	// RPID is the relying party: the domain the credential belongs to.
	RPID string
	// Origin is what goes in the client data, and Windows checks that it
	// matches RPID. For a program that is not a web page, use
	// "https://" + RPID.
	Origin string
	// Challenge is the bytes to be signed over. It must be fresh: a repeated
	// challenge makes a recorded assertion replayable for ever.
	Challenge []byte
	// Allow lists the credentials that may answer. Empty asks the
	// authenticator for a discoverable one, which it has only if a
	// registration asked for that.
	Allow []Credential
	// Attachment constrains what may answer. See the package documentation for
	// why this is how a caller keeps a claim about KINDS honest.
	Attachment Attachment
	// Verification says whether the authenticator must establish who is
	// holding it, rather than only that somebody is.
	Verification UserVerification
	// TimeoutMilliseconds is guidance to Windows, which may override it. Zero
	// leaves the choice to Windows.
	TimeoutMilliseconds uint32
}

// Assertion is what Windows returns.
type Assertion struct {
	// AuthenticatorData is the signed statement: relying-party hash, flags,
	// signature counter, and any extension output.
	AuthenticatorData []byte
	// Signature covers AuthenticatorData followed by the SHA-256 of
	// ClientDataJSON.
	Signature []byte
	// ClientDataJSON is what was hashed into the signature. It is returned
	// because a verifier needs the exact bytes, not a reconstruction: rebuild
	// it and one different space makes every signature look forged.
	ClientDataJSON []byte
	// CredentialID says which credential answered, which matters when the
	// request allowed several.
	CredentialID []byte
	// UserID is the user handle, present for a discoverable credential.
	UserID []byte
	// Transport is what actually answered, or [TransportUnknown] when this
	// Windows did not say.
	Transport Transport
}

// Error is a failure reported by Windows, carrying the name Windows gives it.
type Error struct {
	// Op is the call that failed.
	Op string
	// HResult is the code Windows returned.
	HResult uint32
	// Name is what WebAuthNGetErrorName calls it, when it could be asked.
	Name string
}

func (e *Error) Error() string {
	if e.Name != "" {
		return fmt.Sprintf("webauthn: %s: %s (%#08x)", e.Op, e.Name, e.HResult)
	}
	return fmt.Sprintf("webauthn: %s: %#08x", e.Op, e.HResult)
}

var (
	// ErrUnsupported is returned off Windows, and on a Windows too old to have
	// the API -- it arrived in version 1903.
	ErrUnsupported = errors.New("webauthn: the Windows WebAuthn API is not available here")

	// ErrCancelled is returned when the person dismissed the dialog, or the
	// context ended and the operation was cancelled.
	ErrCancelled = errors.New("webauthn: the operation was cancelled")
)

// clientData builds the JSON Windows will hash.
//
// The field order is not free: what is signed is these exact bytes, and a
// verifier is handed them back rather than told to rebuild them. Constructing
// it with a struct rather than a format string is what keeps the escaping
// right for an origin that contains anything unusual.
func clientData(kind, origin string, challenge []byte) ([]byte, error) {
	if origin == "" {
		return nil, fmt.Errorf("webauthn: an assertion needs an origin")
	}
	if len(challenge) == 0 {
		return nil, fmt.Errorf("webauthn: an assertion needs a challenge, and a fresh one")
	}
	return json.Marshal(struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}{
		Type:        kind,
		Challenge:   base64.RawURLEncoding.EncodeToString(challenge),
		Origin:      origin,
		CrossOrigin: false,
	})
}

// check refuses a request that cannot be honoured, before Windows is asked.
//
// Failing here rather than there means the error names the programming
// mistake instead of quoting a Windows error code about it.
func (r Request) check() error {
	if r.RPID == "" {
		return fmt.Errorf("webauthn: a request needs a relying party id")
	}
	if r.Origin == "" {
		return fmt.Errorf("webauthn: a request needs an origin; for a program that is not a web page, %q", "https://"+r.RPID)
	}
	if !strings.Contains(r.Origin, r.RPID) {
		// Windows enforces this itself and answers NTE_INVALID_PARAMETER,
		// which says nothing about which parameter.
		return fmt.Errorf("webauthn: origin %q does not belong to relying party %q", r.Origin, r.RPID)
	}
	if len(r.Challenge) == 0 {
		return fmt.Errorf("webauthn: a request needs a challenge, and a fresh one")
	}
	for i, c := range r.Allow {
		if len(c.ID) == 0 {
			return fmt.Errorf("webauthn: allowed credential %d has no id", i)
		}
	}
	return nil
}
