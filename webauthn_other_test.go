// Copyright (c) the go-mswin authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build !windows || (windows && !amd64 && !arm64)

package webauthn

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// TestOffWindowsThisIsUnsupportedRatherThanFailed. A Mac has not refused
// anybody; it has no Windows WebAuthn API. Reporting a failure would send a
// person to try harder at something that does not exist here.
func TestOffWindowsThisIsUnsupported(t *testing.T) {
	if v := APIVersion(); v != 0 {
		t.Errorf("APIVersion = %d off Windows", v)
	}
	if Available() {
		t.Error("Available is true off Windows")
	}
	_, err := Assert(context.Background(), Request{
		RPID: "example.test", Origin: "https://example.test", Challenge: []byte("c"),
	})
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("Assert = %v, want unsupported", err)
	}
	if _, err := Register(context.Background(), RegisterRequest{
		RPID: "example.test", RPName: "Example", Origin: "https://example.test",
		Challenge: []byte("c"), User: User{ID: []byte("uid")},
	}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Register = %v, want unsupported", err)
	}
	if errors.Is(ErrUnsupported, ErrCancelled) {
		t.Error("the wrong operating system reads as a cancellation")
	}
	// windows/386 lands here too, and the message must say why rather than
	// leaving somebody to wonder whether their Windows is too old.
	if !strings.Contains(ErrUnsupported.Error(), "64-bit") {
		t.Errorf("ErrUnsupported = %q, which does not say the architecture is the reason", ErrUnsupported)
	}
}
