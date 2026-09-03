// Copyright (c) the go-mswin authors. All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause

//go:build windows

package webauthn

import (
	"context"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The DLL, loaded lazily so that a Windows without it fails at the call rather
// than at package initialisation. Every supported Windows since 1903 has it;
// an older one must be told what is wrong, not crash on import.
var (
	dll = windows.NewLazySystemDLL("webauthn.dll")

	procGetAPIVersionNumber = dll.NewProc("WebAuthNGetApiVersionNumber")
	procIsPlatformAvailable = dll.NewProc("WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable")
	procGetAssertion        = dll.NewProc("WebAuthNAuthenticatorGetAssertion")
	procFreeAssertion       = dll.NewProc("WebAuthNFreeAssertion")
	procGetCancellationID   = dll.NewProc("WebAuthNGetCancellationId")
	procCancelCurrent       = dll.NewProc("WebAuthNCancelCurrentOperation")

	user32               = windows.NewLazySystemDLL("user32.dll")
	procGetForegroundWnd = user32.NewProc("GetForegroundWindow")
	procGetTopWindow     = user32.NewProc("GetTopWindow")
	procGetDesktopWindow = user32.NewProc("GetDesktopWindow")
)

// The structure versions this package declares.
//
// dwVersion is how the API stays compatible: it says how many fields the
// caller laid out, and the DLL reads no further. Declaring a LOW version is
// therefore safe on new Windows, and declaring a high one on old Windows is
// what Microsoft's header says is also fine -- but every declared field must
// be present and correctly placed, and each one is a chance to get the layout
// wrong in a way nothing catches.
//
// Version 3 is the smallest that carries pCancellationId, which is the only
// way a context can interrupt the Windows dialog. Without it, cancelling would
// be a lie: the dialog would stay on the person's screen.
const (
	clientDataVersion      = 1
	credentialVersion      = 1
	getAssertionOptVersion = 3
)

// The C types, laid out to match webauthn.h field for field. Go's natural
// alignment matches the C compiler's here: every field is a DWORD or a
// pointer, so the padding the compiler inserts is the same on both sides.

type webauthnClientData struct {
	dwVersion        uint32
	cbClientDataJSON uint32
	pbClientDataJSON *byte
	pwszHashAlgID    *uint16
}

type webauthnCredential struct {
	dwVersion          uint32
	cbID               uint32
	pbID               *byte
	pwszCredentialType *uint16
}

type webauthnCredentials struct {
	cCredentials uint32
	pCredentials *webauthnCredential
}

type webauthnExtensions struct {
	cExtensions uint32
	pExtensions unsafe.Pointer
}

// webauthnGetAssertionOptions is WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS
// declared through version 3.
type webauthnGetAssertionOptions struct {
	dwVersion                     uint32
	dwTimeoutMilliseconds         uint32
	credentialList                webauthnCredentials
	extensions                    webauthnExtensions
	dwAuthenticatorAttachment     uint32
	dwUserVerificationRequirement uint32
	dwFlags                       uint32

	// Added in version 2.
	pwszU2fAppID *uint16
	pbU2fAppID   *int32

	// Added in version 3.
	pCancellationID *windows.GUID
}

// webauthnAssertion is WEBAUTHN_ASSERTION, laid out through version 4 --
// version 4 is where dwUsedTransport appears, which is the field that lets a
// caller say what actually answered instead of only what was asked for.
//
// Windows allocates this and fills dwVersion with how much of it is valid.
// Reading past that is reading uninitialised memory, so [readAssertion] checks
// the version before touching the later fields.
type webauthnAssertion struct {
	dwVersion            uint32
	cbAuthenticatorData  uint32
	pbAuthenticatorData  *byte
	cbSignature          uint32
	pbSignature          *byte
	credential           webauthnCredential
	cbUserID             uint32
	pbUserID             *byte
	extensions           webauthnExtensions
	cbCredLargeBlob      uint32
	pbCredLargeBlob      *byte
	dwCredLargeBlobState uint32
	pHmacSecret          unsafe.Pointer
	dwUsedTransport      uint32
}

// assertionVersionWithTransport is the first WEBAUTHN_ASSERTION version whose
// dwUsedTransport field exists.
const assertionVersionWithTransport = 4

// APIVersion is the version of the Windows WebAuthn API on this machine, or
// zero if there is none.
func APIVersion() uint32 {
	if err := procGetAPIVersionNumber.Find(); err != nil {
		return 0
	}
	r, _, _ := procGetAPIVersionNumber.Call()
	return uint32(r)
}

// Available reports whether Windows has an authenticator built into this
// machine that can verify who is using it -- Windows Hello, in practice.
//
// It says nothing about a security key: one may be plugged in with this false,
// and this may be true with no key anywhere. The two are separate questions
// and this answers only one of them.
func Available() bool {
	if err := procIsPlatformAvailable.Find(); err != nil {
		return false
	}
	var ok int32
	r, _, _ := procIsPlatformAvailable.Call(uintptr(unsafe.Pointer(&ok)))
	return uint32(r) == 0 && ok != 0
}

// foregroundWindow borrows a handle for the dialog to belong to.
//
// Windows REQUIRES one: the dialog is modal to a window, and without it the
// call fails. A program with no window of its own has to borrow, and borrowing
// the foreground is what Teleport does in production; libfido2 falls back the
// same way when the foreground window cannot be had.
//
// A program that HAS a window should pass [Request.Window] instead, because
// borrowing parents a modal dialog to somebody else's window -- it can end up
// behind theirs, or move when they move. go-mswin/win32 is where windows come
// from.
func foregroundWindow() uintptr {
	if h, _, _ := procGetForegroundWnd.Call(); h != 0 {
		return h
	}
	if h, _, _ := procGetTopWindow.Call(0); h != 0 {
		return h
	}
	h, _, _ := procGetDesktopWindow.Call()
	return h
}

// Assert asks Windows to authenticate somebody.
//
// It blocks while Windows shows its dialog. Cancelling ctx cancels the
// operation THROUGH WINDOWS -- the dialog comes down -- rather than merely
// abandoning the wait, which would leave it on the person's screen with
// nothing behind it.
func Assert(ctx context.Context, req Request) (*Assertion, error) {
	if err := procGetAssertion.Find(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnsupported, err)
	}
	if err := req.check(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	cd, err := clientData("webauthn.get", req.Origin, req.Challenge)
	if err != nil {
		return nil, err
	}
	rpID, err := windows.UTF16PtrFromString(req.RPID)
	if err != nil {
		return nil, fmt.Errorf("webauthn: relying party id: %w", err)
	}
	sha256, err := windows.UTF16PtrFromString("SHA-256")
	if err != nil {
		return nil, err
	}
	credType, err := windows.UTF16PtrFromString("public-key")
	if err != nil {
		return nil, err
	}

	data := webauthnClientData{
		dwVersion:        clientDataVersion,
		cbClientDataJSON: uint32(len(cd)),
		pbClientDataJSON: &cd[0],
		pwszHashAlgID:    sha256,
	}

	// The allow list. The backing arrays must outlive the call, which they do
	// because they are named here and the call is below; a slice built inline
	// in the struct literal would be a pointer into something Go may move.
	creds := make([]webauthnCredential, len(req.Allow))
	ids := make([][]byte, len(req.Allow))
	for i, c := range req.Allow {
		ids[i] = append([]byte(nil), c.ID...)
		creds[i] = webauthnCredential{
			dwVersion:          credentialVersion,
			cbID:               uint32(len(ids[i])),
			pbID:               &ids[i][0],
			pwszCredentialType: credType,
		}
	}

	opts := webauthnGetAssertionOptions{
		dwVersion:                     getAssertionOptVersion,
		dwTimeoutMilliseconds:         req.TimeoutMilliseconds,
		dwAuthenticatorAttachment:     uint32(req.Attachment),
		dwUserVerificationRequirement: uint32(req.Verification),
	}
	if len(creds) > 0 {
		opts.credentialList = webauthnCredentials{
			cCredentials: uint32(len(creds)),
			pCredentials: &creds[0],
		}
	}

	// Cancellation. Windows hands out an id, the call carries it, and another
	// goroutine can use it to bring the dialog down.
	var cancelID windows.GUID
	if procGetCancellationID.Find() == nil {
		if r, _, _ := procGetCancellationID.Call(uintptr(unsafe.Pointer(&cancelID))); uint32(r) == 0 {
			opts.pCancellationID = &cancelID
		}
	}
	if opts.pCancellationID != nil {
		stop := make(chan struct{})
		defer close(stop)
		go func() {
			select {
			case <-ctx.Done():
				if procCancelCurrent.Find() == nil {
					procCancelCurrent.Call(uintptr(unsafe.Pointer(&cancelID)))
				}
			case <-stop:
			}
		}()
	}

	var out *webauthnAssertion
	hwnd := req.Window
	if hwnd == 0 {
		hwnd = foregroundWindow()
	}
	hr, _, _ := procGetAssertion.Call(
		hwnd,
		uintptr(unsafe.Pointer(rpID)),
		uintptr(unsafe.Pointer(&data)),
		uintptr(unsafe.Pointer(&opts)),
		uintptr(unsafe.Pointer(&out)),
	)
	// Keep everything the call pointed at alive until it has returned. Without
	// this the collector is within its rights to free the client data or the
	// credential ids while Windows is still reading them.
	runtime.KeepAlive(cd)
	runtime.KeepAlive(ids)
	runtime.KeepAlive(creds)
	runtime.KeepAlive(rpID)
	runtime.KeepAlive(sha256)
	runtime.KeepAlive(credType)
	runtime.KeepAlive(&data)
	runtime.KeepAlive(&opts)
	runtime.KeepAlive(&cancelID)

	if uint32(hr) != 0 {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCancelled, err)
		}
		return nil, &Error{Op: "WebAuthNAuthenticatorGetAssertion", HResult: uint32(hr), Name: describe(uint32(hr))}
	}
	if out == nil {
		return nil, fmt.Errorf("webauthn: Windows reported success and returned nothing")
	}
	defer procFreeAssertion.Call(uintptr(unsafe.Pointer(out)))

	a := readAssertion(out)
	a.ClientDataJSON = cd
	return a, nil
}

// readAssertion copies what Windows filled in.
//
// Everything is COPIED before WebAuthNFreeAssertion runs. Returning slices
// that pointed into the freed structure would be a use-after-free that works
// perfectly in a test and fails under load.
func readAssertion(a *webauthnAssertion) *Assertion {
	out := &Assertion{
		AuthenticatorData: copyBytes(a.pbAuthenticatorData, a.cbAuthenticatorData),
		Signature:         copyBytes(a.pbSignature, a.cbSignature),
		CredentialID:      copyBytes(a.credential.pbID, a.credential.cbID),
		UserID:            copyBytes(a.pbUserID, a.cbUserID),
	}
	// dwUsedTransport exists only from version 4. Reading it on an older
	// Windows would be reading whatever happens to sit past the end of what
	// was allocated.
	if a.dwVersion >= assertionVersionWithTransport {
		out.Transport = Transport(a.dwUsedTransport)
	}
	return out
}

func copyBytes(p *byte, n uint32) []byte {
	if p == nil || n == 0 {
		return nil
	}
	return append([]byte(nil), unsafe.Slice(p, n)...)
}
