// Copyright (c) the go-mswin authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows

package webauthn

import "context"

// APIVersion is zero off Windows.
func APIVersion() uint32 { return 0 }

// Available is false off Windows.
func Available() bool { return false }

// Assert is unavailable off Windows.
//
// It reports [ErrUnsupported] rather than a failure: a Mac has not refused
// anybody, it has no Windows WebAuthn API. The macOS and Linux siblings are
// go-macos/fido and go-gnulinux/fido, over github.com/go-authn/fido.
func Assert(context.Context, Request) (*Assertion, error) { return nil, ErrUnsupported }
