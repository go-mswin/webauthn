// Copyright (c) the go-mswin authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package webauthn

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// TestTheClientDataIsWhatAVerifierWillHash. What gets signed is these exact
// bytes; a verifier is handed them back rather than told to rebuild them,
// because one different space makes every signature look forged.
func TestTheClientDataIsWhatAVerifierWillHash(t *testing.T) {
	challenge := []byte{0x01, 0x02, 0xFF, 0xFE}
	b, err := clientData("webauthn.get", "https://example.test", challenge)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("the client data is not JSON: %v", err)
	}
	if got.Type != "webauthn.get" || got.Origin != "https://example.test" || got.CrossOrigin {
		t.Errorf("client data = %+v", got)
	}
	// base64url WITHOUT padding is what WebAuthn specifies. Padding here is a
	// classic way to make a signature verify nowhere.
	if strings.Contains(got.Challenge, "=") {
		t.Errorf("the challenge is padded: %q", got.Challenge)
	}
	back, err := base64.RawURLEncoding.DecodeString(got.Challenge)
	if err != nil || string(back) != string(challenge) {
		t.Errorf("the challenge did not survive the round trip: %q (%v)", got.Challenge, err)
	}
}

// TestAnOriginWithSomethingUnusualIsEscaped. Building this with a format
// string, which is the obvious way, produces invalid JSON for an origin that
// contains a quote -- and Windows then rejects the whole call with a
// parameter error that names no parameter.
func TestAnOriginWithSomethingUnusualIsEscaped(t *testing.T) {
	b, err := clientData("webauthn.get", `https://ex"ample.test`, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("an origin with a quote produced invalid JSON: %v", err)
	}
	if got["origin"] != `https://ex"ample.test` {
		t.Errorf("origin came back as %q", got["origin"])
	}
}

func TestClientDataRefusesWhatItCannotSign(t *testing.T) {
	if _, err := clientData("webauthn.get", "", []byte("x")); err == nil {
		t.Error("accepted an empty origin")
	}
	if _, err := clientData("webauthn.get", "https://example.test", nil); err == nil {
		t.Error("accepted an empty challenge")
	}
}

func TestARequestIsCheckedBeforeWindowsIsAsked(t *testing.T) {
	ok := Request{RPID: "example.test", Origin: "https://example.test", Challenge: []byte("c")}
	if err := ok.check(); err != nil {
		t.Fatalf("a complete request was refused: %v", err)
	}
	for _, c := range []struct {
		name string
		req  Request
		want string
	}{
		{"no relying party", Request{Origin: "https://x", Challenge: []byte("c")}, "relying party id"},
		{"no origin", Request{RPID: "example.test", Challenge: []byte("c")}, "needs an origin"},
		{
			"an origin belonging to somebody else",
			Request{RPID: "example.test", Origin: "https://evil.test", Challenge: []byte("c")},
			"does not belong",
		},
		{"no challenge", Request{RPID: "example.test", Origin: "https://example.test"}, "challenge"},
		{
			"an allowed credential with no id",
			Request{RPID: "e.test", Origin: "https://e.test", Challenge: []byte("c"), Allow: []Credential{{}}},
			"has no id",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := c.req.check()
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error is %q, which does not mention %q", err, c.want)
			}
		})
	}
}

// TestSilenceIsNotAnAnswerAboutTheTransport is the point of Carried returning
// two values. An older Windows fills in no transport at all, and reading that
// as "not carried" would quietly downgrade every security key on those
// machines to something built in.
func TestSilenceIsNotAnAnswerAboutTheTransport(t *testing.T) {
	for _, c := range []struct {
		tr             Transport
		carried, known bool
	}{
		{TransportUSB, true, true},
		{TransportNFC, true, true},
		{TransportBLE, true, true},
		{TransportHybrid, true, true},
		{TransportSmartCard, true, true},
		{TransportInternal, false, true},
		{TransportUnknown, false, false},
		{TransportTest, false, false},
		{Transport(0x1000), false, false},
	} {
		carried, known := c.tr.Carried()
		if carried != c.carried || known != c.known {
			t.Errorf("%v.Carried() = %v,%v want %v,%v", c.tr, carried, known, c.carried, c.known)
		}
	}
}

func TestEverythingSaysWhatItIs(t *testing.T) {
	for _, c := range []struct {
		got  string
		want string
	}{
		{AnyAttachment.String(), "any"},
		{Platform.String(), "machine"},
		{CrossPlatform.String(), "security key"},
		{Attachment(99).String(), "attachment(99)"},
		{VerificationAny.String(), "any"},
		{VerificationRequired.String(), "required"},
		{VerificationPreferred.String(), "preferred"},
		{VerificationDiscouraged.String(), "discouraged"},
		{UserVerification(99).String(), "verification(99)"},
		{TransportUSB.String(), "usb"},
		{TransportNFC.String(), "nfc"},
		{TransportBLE.String(), "ble"},
		{TransportTest.String(), "test"},
		{TransportInternal.String(), "internal"},
		{TransportHybrid.String(), "hybrid"},
		{TransportSmartCard.String(), "smart-card"},
		{TransportUnknown.String(), "unreported"},
		{Transport(0x1000).String(), "transport(0x1000)"},
	} {
		if !strings.Contains(c.got, c.want) {
			t.Errorf("%q does not mention %q", c.got, c.want)
		}
	}
}

// TestCancelledIsNotARefusal. Somebody who dismissed the dialog was not
// refused; they changed their mind, and saying otherwise accuses them.
func TestCancelledIsNotARefusal(t *testing.T) {
	for _, hr := range []uint32{nteUserCancelled, hresultCancelled} {
		e := &Error{Op: "GetAssertion", HResult: hr, Name: describe(hr)}
		if !e.Cancelled() {
			t.Errorf("%#08x is not read as a cancellation", hr)
		}
		if e.Unavailable() {
			t.Errorf("%#08x is read as nothing being there", hr)
		}
	}
	for _, hr := range []uint32{nteDeviceNotFound, nteNotFound, nteNotSupported} {
		e := &Error{HResult: hr}
		if !e.Unavailable() {
			t.Errorf("%#08x is not read as nothing being there", hr)
		}
		if e.Cancelled() {
			t.Errorf("%#08x is read as a cancellation", hr)
		}
	}
	// A refusal is neither.
	e := &Error{HResult: nteInvalidParameter}
	if e.Cancelled() || e.Unavailable() {
		t.Error("an ordinary failure was excused")
	}
}

func TestAnUnknownCodeIsNotGivenAName(t *testing.T) {
	if got := describe(0xDEADBEEF); got != "" {
		t.Errorf("an unknown code was named %q", got)
	}
	// ...but the number still reaches the person, because it is searchable.
	e := &Error{Op: "GetAssertion", HResult: 0xDEADBEEF}
	if !strings.Contains(e.Error(), "0xdeadbeef") {
		t.Errorf("Error() = %q, which loses the code", e.Error())
	}
	named := &Error{Op: "GetAssertion", HResult: nteUserCancelled, Name: describe(nteUserCancelled)}
	if !strings.Contains(named.Error(), "NTE_USER_CANCELLED") {
		t.Errorf("Error() = %q", named.Error())
	}
}

func TestEveryNamedCodeHasAName(t *testing.T) {
	for _, hr := range []uint32{
		nteInvalidParameter, nteNotSupported, nteNotFound,
		nteTokenKeysetStorageFull, nteDeviceNotFound, nteUserCancelled, hresultCancelled,
	} {
		if describe(hr) == "" {
			t.Errorf("%#08x has no name", hr)
		}
	}
}
