// Copyright (c) the go-mswin authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows && (amd64 || arm64)

package webauthn

import (
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestTheStructsAreLaidOutLikeTheHeader.
//
// dwVersion tells the DLL how many fields were laid out; it does NOT tell it
// where they are. A field in the wrong place is read as whatever sits at that
// offset -- a length taken from a pointer, a pointer taken from a length --
// and nothing reports it. Compiling proves nothing at all here.
//
// The numbers come from webauthn.h and the C alignment rules: DWORD is four
// bytes, a pointer is eight on 64-bit, and a pointer is aligned to its size,
// so a DWORD before one is followed by four bytes of padding.
//
// This does not prove Windows agrees. It proves that a later edit which
// reorders or inserts a field has to notice.
func TestTheStructsAreLaidOutLikeTheHeader(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("the offsets below are the 64-bit ones")
	}
	for _, c := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"WEBAUTHN_CLIENT_DATA size", unsafe.Sizeof(webauthnClientData{}), 24},
		{"WEBAUTHN_CREDENTIAL size", unsafe.Sizeof(webauthnCredential{}), 24},
		{"WEBAUTHN_CREDENTIALS size", unsafe.Sizeof(webauthnCredentials{}), 16},
		{"WEBAUTHN_EXTENSIONS size", unsafe.Sizeof(webauthnExtensions{}), 16},

		{"GET_ASSERTION_OPTIONS size (through v3)", unsafe.Sizeof(webauthnGetAssertionOptions{}), 80},
		{"  .CredentialList", unsafe.Offsetof(webauthnGetAssertionOptions{}.credentialList), 8},
		{"  .Extensions", unsafe.Offsetof(webauthnGetAssertionOptions{}.extensions), 24},
		{"  .dwAuthenticatorAttachment", unsafe.Offsetof(webauthnGetAssertionOptions{}.dwAuthenticatorAttachment), 40},
		{"  .dwUserVerificationRequirement", unsafe.Offsetof(webauthnGetAssertionOptions{}.dwUserVerificationRequirement), 44},
		{"  .pCancellationId", unsafe.Offsetof(webauthnGetAssertionOptions{}.pCancellationID), 72},

		{"ASSERTION size (through v4)", unsafe.Sizeof(webauthnAssertion{}), 128},
		{"  .pbAuthenticatorData", unsafe.Offsetof(webauthnAssertion{}.pbAuthenticatorData), 8},
		{"  .pbSignature", unsafe.Offsetof(webauthnAssertion{}.pbSignature), 24},
		{"  .Credential", unsafe.Offsetof(webauthnAssertion{}.credential), 32},
		{"  .pbUserId", unsafe.Offsetof(webauthnAssertion{}.pbUserID), 64},
		{"  .dwUsedTransport", unsafe.Offsetof(webauthnAssertion{}.dwUsedTransport), 120},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, the header says %d", c.name, c.got, c.want)
		}
	}
}

// TestTheErrorNumbersAreTheKernels checks the table in errors.go against
// golang.org/x/sys/windows, which generates its constants from the SDK
// headers.
//
// ⛔ This test exists because a status table written from memory shipped in a
// sibling package with FIVE wrong entries, and a real device caught it rather
// than a test. A number that looks right is the most dangerous kind.
func TestTheErrorNumbersAreTheKernels(t *testing.T) {
	for _, c := range []struct {
		name string
		got  uint32
		want uint32
	}{
		{"NTE_INVALID_PARAMETER", nteInvalidParameter, uint32(windows.NTE_INVALID_PARAMETER)},
		{"NTE_NOT_SUPPORTED", nteNotSupported, uint32(windows.NTE_NOT_SUPPORTED)},
		{"NTE_NOT_FOUND", nteNotFound, uint32(windows.NTE_NOT_FOUND)},
		{"NTE_TOKEN_KEYSET_STORAGE_FULL", nteTokenKeysetStorageFull, uint32(windows.NTE_TOKEN_KEYSET_STORAGE_FULL)},
		{"NTE_DEVICE_NOT_FOUND", nteDeviceNotFound, uint32(windows.NTE_DEVICE_NOT_FOUND)},
		{"NTE_USER_CANCELLED", nteUserCancelled, uint32(windows.NTE_USER_CANCELLED)},
		{"HRESULT_FROM_WIN32(ERROR_CANCELLED)", hresultCancelled, 0x80070000 | uint32(windows.ERROR_CANCELLED)},
	} {
		if c.got != c.want {
			t.Errorf("%s = %#08x, x/sys says %#08x", c.name, c.got, c.want)
		}
	}
}

// TestTheRegistrationStructsAreLaidOutLikeTheHeader.
//
// Same reasoning as the assertion side, and the same arithmetic: DWORD is four
// bytes, a pointer is eight on 64-bit, and a pointer is aligned to its size, so
// a DWORD before one is followed by four bytes of padding.
func TestTheRegistrationStructsAreLaidOutLikeTheHeader(t *testing.T) {
	if unsafe.Sizeof(uintptr(0)) != 8 {
		t.Skip("the offsets below are the 64-bit ones")
	}
	for _, c := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{"WEBAUTHN_RP_ENTITY_INFORMATION size", unsafe.Sizeof(webauthnRPEntity{}), 32},
		{"WEBAUTHN_USER_ENTITY_INFORMATION size", unsafe.Sizeof(webauthnUserEntity{}), 40},
		{"  .pbId", unsafe.Offsetof(webauthnUserEntity{}.pbID), 8},
		{"  .pwszDisplayName", unsafe.Offsetof(webauthnUserEntity{}.pwszDisplayName), 32},
		{"WEBAUTHN_COSE_CREDENTIAL_PARAMETER size", unsafe.Sizeof(webauthnCoseParam{}), 24},
		{"  .lAlg", unsafe.Offsetof(webauthnCoseParam{}.lAlg), 16},
		{"WEBAUTHN_COSE_CREDENTIAL_PARAMETERS size", unsafe.Sizeof(webauthnCoseParams{}), 16},

		{"MAKE_CREDENTIAL_OPTIONS size (through v2)", unsafe.Sizeof(webauthnMakeCredentialOptions{}), 72},
		{"  .CredentialList", unsafe.Offsetof(webauthnMakeCredentialOptions{}.credentialList), 8},
		{"  .Extensions", unsafe.Offsetof(webauthnMakeCredentialOptions{}.extensions), 24},
		{"  .dwAuthenticatorAttachment", unsafe.Offsetof(webauthnMakeCredentialOptions{}.dwAuthenticatorAttachment), 40},
		{"  .bRequireResidentKey", unsafe.Offsetof(webauthnMakeCredentialOptions{}.bRequireResidentKey), 44},
		{"  .dwUserVerificationRequirement", unsafe.Offsetof(webauthnMakeCredentialOptions{}.dwUserVerificationRequirement), 48},
		{"  .dwAttestationConveyancePreference", unsafe.Offsetof(webauthnMakeCredentialOptions{}.dwAttestationConveyancePreference), 52},
		{"  .pCancellationId", unsafe.Offsetof(webauthnMakeCredentialOptions{}.pCancellationID), 64},

		{"CREDENTIAL_ATTESTATION size (through v4)", unsafe.Sizeof(webauthnCredentialAttestation{}), 136},
		{"  .pwszFormatType", unsafe.Offsetof(webauthnCredentialAttestation{}.pwszFormatType), 8},
		{"  .pbAuthenticatorData", unsafe.Offsetof(webauthnCredentialAttestation{}.pbAuthenticatorData), 24},
		{"  .pbAttestation", unsafe.Offsetof(webauthnCredentialAttestation{}.pbAttestation), 40},
		{"  .pbAttestationObject", unsafe.Offsetof(webauthnCredentialAttestation{}.pbAttestationObject), 72},
		{"  .pbCredentialId", unsafe.Offsetof(webauthnCredentialAttestation{}.pbCredentialID), 88},
		{"  .Extensions", unsafe.Offsetof(webauthnCredentialAttestation{}.extensions), 96},
		{"  .dwUsedTransport", unsafe.Offsetof(webauthnCredentialAttestation{}.dwUsedTransport), 112},
		{"  .bResidentKey", unsafe.Offsetof(webauthnCredentialAttestation{}.bResidentKey), 124},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, the header says %d", c.name, c.got, c.want)
		}
	}
}
