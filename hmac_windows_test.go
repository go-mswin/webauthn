// Copyright (c) the go-mswin authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows && (amd64 || arm64)

package webauthn

import (
	"bytes"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestSaltsAreLaidOutForWindows(t *testing.T) {
	var a, b [32]byte
	a[0], b[0] = 1, 2
	h, err := newHMACSalts([][32]byte{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if h.values.pGlobalHmacSalt != &h.salt || h.salt.cbFirst != 32 || h.salt.cbSecond != 32 {
		t.Fatalf("salt structure = %+v", h.salt)
	}
	if *h.salt.pbFirst != 1 || *h.salt.pbSecond != 2 {
		t.Error("the salts were not copied in order")
	}
	one, err := newHMACSalts([][32]byte{a})
	if err != nil {
		t.Fatal(err)
	}
	if one.salt.cbSecond != 0 || one.salt.pbSecond != nil {
		t.Error("a single salt left a second one behind")
	}
	for _, n := range []int{0, 3} {
		if _, err := newHMACSalts(make([][32]byte, n)); err == nil {
			t.Errorf("%d salts were accepted", n)
		}
	}
}

func TestHMACSecretOutputIsReadOnlyWhenWellFormed(t *testing.T) {
	first, second := bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{9}, 32)
	good := webauthnHMACSecretSalt{cbFirst: 32, pbFirst: &first[0], cbSecond: 32, pbSecond: &second[0]}
	got := readHMACSecret(&webauthnAssertion{dwVersion: 4, pHmacSecret: unsafe.Pointer(&good)})
	if len(got) != 2 || !bytes.Equal(got[0], first) || !bytes.Equal(got[1], second) {
		t.Fatalf("outputs = %x", got)
	}
	short := webauthnHMACSecretSalt{cbFirst: 16, pbFirst: &first[0]}
	badSecond := webauthnHMACSecretSalt{cbFirst: 32, pbFirst: &first[0], cbSecond: 5, pbSecond: &second[0]}
	for name, a := range map[string]*webauthnAssertion{
		"old version":   {dwVersion: 2, pHmacSecret: unsafe.Pointer(&good)},
		"no secret":     {dwVersion: 4},
		"short output":  {dwVersion: 4, pHmacSecret: unsafe.Pointer(&short)},
		"short second":  {dwVersion: 4, pHmacSecret: unsafe.Pointer(&badSecond)},
		"nil first ptr": {dwVersion: 4, pHmacSecret: unsafe.Pointer(&webauthnHMACSecretSalt{cbFirst: 32})},
	} {
		if r := readHMACSecret(a); r != nil {
			t.Errorf("%s: read %x", name, r)
		}
	}
}

func TestRegistrationExtensionsAreWhatWindowsReports(t *testing.T) {
	req := RegisterRequest{HMACSecret: true, CredProtect: 3}
	e, err := newRegisterExtensions(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.list) != 2 || e.hmac != 1 || e.credProt.dwCredProtect != 3 || e.credProt.bRequireCredProtect != 1 {
		t.Fatalf("extensions = %+v", e)
	}
	var o webauthnExtensions
	e.apply(&o)
	if o.cExtensions != 2 {
		t.Errorf("cExtensions = %d", o.cExtensions)
	}
	var none webauthnExtensions
	empty, _ := newRegisterExtensions(RegisterRequest{})
	empty.apply(&none)
	if none.cExtensions != 0 || none.pExtensions != nil {
		t.Error("an empty request produced extensions")
	}

	// The OUTPUT entries differ from the input ones: hmac-secret is a BOOL
	// either way, but credProtect comes back as a bare DWORD (webauthn.h).
	t.Logf("WebAuthn API version on this machine: %d", APIVersion())
	hmacOut, cpOut := int32(1), uint32(3)
	hid, _ := windows.UTF16PtrFromString(extHMACSecret)
	cid, _ := windows.UTF16PtrFromString(extCredProtect)
	outList := []webauthnExtension{
		{pwszExtensionIdentifier: hid, cbExtension: 4, pvExtension: unsafe.Pointer(&hmacOut)},
		{pwszExtensionIdentifier: cid, cbExtension: 4, pvExtension: unsafe.Pointer(&cpOut)},
		{pwszExtensionIdentifier: nil},
	}
	a := &webauthnCredentialAttestation{dwVersion: 4}
	a.extensions = webauthnExtensions{cExtensions: 3, pExtensions: unsafe.Pointer(&outList[0])}
	var out Registration
	readExtensions(a, &out)
	if !out.HMACSecret || out.CredProtect != 3 {
		t.Errorf("read back %+v", out)
	}
	old := &webauthnCredentialAttestation{dwVersion: 1, extensions: a.extensions}
	var none2 Registration
	readExtensions(old, &none2)
	if none2.HMACSecret || none2.CredProtect != 0 {
		t.Error("read extensions from a version that has none")
	}
}
