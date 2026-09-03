// Copyright (c) the go-windows authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

package webauthn

// The HRESULTs Windows returns from these calls.
//
// ⛔ These numbers are NOT written from memory. Each one is checked against
// golang.org/x/sys/windows's own constant by a test on the Windows lane -- a
// status table is exactly the kind of thing that looks right and is not, and
// this project has already shipped one with five wrong entries.
//
// The set is the one libfido2's winhello.c translates, which is the set these
// two calls actually produce.
const (
	nteInvalidParameter       = 0x80090027 // NTE_INVALID_PARAMETER
	nteNotSupported           = 0x80090029 // NTE_NOT_SUPPORTED
	nteNotFound               = 0x80090011 // NTE_NOT_FOUND
	nteTokenKeysetStorageFull = 0x80090023 // NTE_TOKEN_KEYSET_STORAGE_FULL
	nteDeviceNotFound         = 0x80090035 // NTE_DEVICE_NOT_FOUND
	nteUserCancelled          = 0x80090036 // NTE_USER_CANCELLED

	// hresultCancelled is HRESULT_FROM_WIN32(ERROR_CANCELLED): the facility
	// bits 0x80070000 over ERROR_CANCELLED, which is 1223.
	hresultCancelled = 0x80070000 | 1223
)

// describe names an HRESULT. An unknown code gets no name rather than a
// guessed one, and [Error] then prints the number, which is something a person
// can search for.
func describe(hr uint32) string {
	switch hr {
	case nteInvalidParameter:
		return "NTE_INVALID_PARAMETER"
	case nteNotSupported:
		return "NTE_NOT_SUPPORTED"
	case nteNotFound:
		return "NTE_NOT_FOUND"
	case nteTokenKeysetStorageFull:
		return "NTE_TOKEN_KEYSET_STORAGE_FULL"
	case nteDeviceNotFound:
		return "NTE_DEVICE_NOT_FOUND"
	case nteUserCancelled:
		return "NTE_USER_CANCELLED"
	case hresultCancelled:
		return "ERROR_CANCELLED"
	}
	return ""
}

// Cancelled reports whether Windows says the person dismissed the dialog.
//
// It is not a failure of authentication: nobody was refused, somebody changed
// their mind. A caller that reported it as a refusal would be accusing them.
func (e *Error) Cancelled() bool {
	return e.HResult == nteUserCancelled || e.HResult == hresultCancelled
}

// Unavailable reports whether there was nothing here to ask.
//
// NTE_DEVICE_NOT_FOUND and NTE_NOT_FOUND mean no authenticator could serve the
// request -- no key plugged in, or none holding the credential that was asked
// for. NTE_NOT_SUPPORTED means this Windows cannot do what was asked. None of
// those is somebody failing to authenticate, and a policy counts them
// separately.
func (e *Error) Unavailable() bool {
	switch e.HResult {
	case nteDeviceNotFound, nteNotFound, nteNotSupported:
		return true
	}
	return false
}
