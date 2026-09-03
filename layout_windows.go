// Copyright (c) the go-mswin authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

// The 64-bit Windows targets only, which is where go-mswin/win32 -- this org's
// foundation -- draws the line too. The structure layouts below are 64-bit
// truths: on 386 a pointer is four bytes and every size differs, so building
// this there would produce a package that compiles and reads the wrong fields.
// windows/386 gets the stub, which says so out loud.
//go:build windows && (amd64 || arm64)

package webauthn

import "unsafe"

// The struct sizes, asserted at COMPILE time.
//
// dwVersion tells the DLL how many fields were laid out; it does not tell it
// where they are, and a field in the wrong place is read as whatever sits at
// that offset. The test beside this one checks the same numbers with readable
// failures, but it runs only on Windows -- these run wherever the package is
// cross-compiled, which is everywhere, so a layout edited on a Mac fails on the
// Mac rather than twenty minutes later.
//
// A wrong size makes the subtraction negative, and an unsigned constant cannot
// be negative: the compiler names the line.
const (
	_ = uint(unsafe.Sizeof(webauthnClientData{}) - 24)
	_ = uint(24 - unsafe.Sizeof(webauthnClientData{}))
	_ = uint(unsafe.Sizeof(webauthnCredential{}) - 24)
	_ = uint(24 - unsafe.Sizeof(webauthnCredential{}))
	_ = uint(unsafe.Sizeof(webauthnGetAssertionOptions{}) - 80)
	_ = uint(80 - unsafe.Sizeof(webauthnGetAssertionOptions{}))
	_ = uint(unsafe.Sizeof(webauthnAssertion{}) - 128)
	_ = uint(128 - unsafe.Sizeof(webauthnAssertion{}))

	_ = uint(unsafe.Sizeof(webauthnRPEntity{}) - 32)
	_ = uint(32 - unsafe.Sizeof(webauthnRPEntity{}))
	_ = uint(unsafe.Sizeof(webauthnUserEntity{}) - 40)
	_ = uint(40 - unsafe.Sizeof(webauthnUserEntity{}))
	_ = uint(unsafe.Sizeof(webauthnCoseParam{}) - 24)
	_ = uint(24 - unsafe.Sizeof(webauthnCoseParam{}))
	_ = uint(unsafe.Sizeof(webauthnMakeCredentialOptions{}) - 72)
	_ = uint(72 - unsafe.Sizeof(webauthnMakeCredentialOptions{}))
	_ = uint(unsafe.Sizeof(webauthnCredentialAttestation{}) - 136)
	_ = uint(136 - unsafe.Sizeof(webauthnCredentialAttestation{}))
)
