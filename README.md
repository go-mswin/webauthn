# webauthn

[![Go Reference](https://pkg.go.dev/badge/github.com/go-mswin/webauthn.svg)](https://pkg.go.dev/github.com/go-mswin/webauthn)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-0A6E96?style=flat-square)](LICENSE)
[![CI](https://github.com/go-mswin/webauthn/actions/workflows/ci.yml/badge.svg)](https://github.com/go-mswin/webauthn/actions/workflows/ci.yml)

Asks Windows to authenticate somebody, through `webauthn.dll` — the same API
browsers use. Pure Go, `CGO_ENABLED=0`, no cgo and no SDK.

```go
a, err := webauthn.Assert(ctx, webauthn.Request{
    RPID:         "example.test",
    Origin:       "https://example.test",
    Challenge:    challenge,               // fresh, always
    Allow:        []webauthn.Credential{{ID: credentialID}},
    Attachment:   webauthn.CrossPlatform,  // a security key, not Hello
    Verification: webauthn.VerificationRequired,
})
fmt.Println(a.Transport)   // "usb" — what actually answered
```

## Where it sits in go-mswin

[go-mswin/winrt](https://github.com/go-mswin/winrt) already answers the OTHER
half: `RequireUserConsent` asks Windows Hello, through `UserConsentVerifier`.
That is the authenticator built into the machine. This package is for the one
somebody carries — and for the case where you need a signed assertion rather
than a yes.

[go-mswin/win32](https://github.com/go-mswin/win32) is where windows come from,
which matters here: the dialog is modal to an `HWND`. Pass your own through
`Request.Window`; leaving it zero borrows the foreground, which is what a
console program has to do and what Teleport does in production.

## Why this is not a CTAP transport

Its siblings, [go-macos/fido](https://github.com/go-macos/fido) and
[go-gnulinux/fido](https://github.com/go-gnulinux/fido), move 64-byte reports
and let [go-authn/fido](https://github.com/go-authn/fido) speak the protocol.
This one cannot, and the reason is not a preference.

**Since Windows 10 version 1903, opening a FIDO HID device requires
elevation.** Microsoft closed that door and pointed everyone at this API. A
CTAP transport here would work only for administrators, which is not a program
anybody should ship. The measure of that wall is what it takes to get around
it: the one project that does installs an elevated Windows *service* and relays
CTAPHID over a named pipe.

So Windows speaks the protocol, shows its own dialog, collects the PIN or the
fingerprint itself, and hands back an assertion. `go-authn/fido` is not
underneath this package. That the three platforms end up with different shapes
is fine —
[go-authn/mfa](https://github.com/go-authn/mfa) asks for a `Factor`, not for a
transport.

And it cuts the other way too: on Windows the platform half is `winrt`, not
this, so a future `go-mswin/factors` will draw its two kinds from two different
packages. That is what the layering was for.

## What was proved, and what only somebody could tell you

An assertion says a credential answered, and its flags say whether the
authenticator verified who was holding it. It does **not** say what convinced
it. Windows Hello accepts a face, a fingerprint, or a **PIN** — and a PIN is
something *known*, not something anyone *is*. Reporting "user verified" as
biometrics would be reporting the wrong kind of proof, which is the one thing a
multi-factor policy exists to prevent.

Two things narrow it, and both are here:

- **`Attachment` constrains what may answer.** `CrossPlatform` asks for a
  security key — something carried. `Platform` asks for the one built into this
  machine.
- **`Assertion.Transport` reports what actually answered.** Asking is a
  request; this is an observation, and they can differ.

`Transport.Carried()` returns **two** values, deliberately. Windows fills the
transport in only from version 4 of its assertion structure, and an older one
says nothing at all. Reading silence as "not carried" would quietly downgrade
every security key on those machines to something built in, so silence is
reported as silence.

## Registration reports what the authenticator DID

`Register` makes a credential. Two of the things it returns are observations
rather than echoes of the request, and they are where a caller gets caught:

- **`Registration.Discoverable`** says whether a discoverable credential was
  actually made. Asking for one is a request, and an authenticator with no room
  left declines it while still making a perfectly good credential — which then
  cannot be used without naming its id. A caller who assumed otherwise has
  locked somebody out of an account they can no longer select. `DiscoverableKnown`
  is separate again, because older Windows does not report it at all.
- **`Registration.Transport`** says what answered, exactly as on the assertion
  side.

The user handle is bounded at 64 bytes here, which is WebAuthn's rule rather
than Windows's, and it should be an opaque identifier rather than an email
address — also the specification's rule, and a privacy one.

## What it refuses to confuse

- **Dismissing the dialog is not failing.** `Error.Cancelled()` is separate:
  nobody was refused, somebody changed their mind, and saying otherwise accuses
  them.
- **Nothing there to ask is not a refusal.** `Error.Unavailable()` covers
  `NTE_DEVICE_NOT_FOUND`, `NTE_NOT_FOUND` and `NTE_NOT_SUPPORTED`.
- **Cancelling the context cancels the operation *through Windows*.** The
  package asks for a cancellation id and uses
  `WebAuthNCancelCurrentOperation`, so the dialog comes down. Abandoning the
  wait instead would leave it on the person's screen with nothing behind it.
- **The client data is returned, not describable.** What is signed is those
  exact bytes; a verifier that rebuilds them and gets one space different sees
  every signature as forged. It is also built with a JSON encoder rather than a
  format string, so an origin containing a quote does not produce a call
  Windows rejects with a parameter error that names no parameter.

## 64-bit Windows only

`amd64` and `arm64`, which is where
[go-mswin/win32](https://github.com/go-mswin/win32) draws the line too. On
`386` a pointer is four bytes and every structure size differs, so building the
real implementation there would produce a package that compiles and reads the
wrong fields. `windows/386` gets the stub, and its error says the architecture
is the reason rather than leaving somebody to wonder whether their Windows is
too old.

## The two things a compiler cannot catch

**`dwVersion` tells the DLL how many fields were laid out. It does not tell it
where they are.** A field in the wrong place is read as whatever sits at that
offset — a length taken from a pointer, a pointer taken from a length — and
nothing reports it. A test pins every size and offset against `webauthn.h` and
the C alignment rules, and the sizes are asserted a second time **at compile
time**, so a layout edited on a Mac fails on that Mac rather than twenty minutes
later on a Windows runner.

**A status table is exactly the kind of thing that looks right and is not.** A
sibling package shipped one written from memory with five wrong entries, and a
real device caught it rather than a test. So the HRESULTs here are checked, on
the Windows lane, against `golang.org/x/sys/windows`'s own constants — which
are generated from the SDK headers. The set is the one libfido2's `winhello.c`
translates.

## What is not here

**A run against a real authenticator.** Everything that needs no dialog is
covered to 100%, on Linux, and the layout and error tables are checked on the
Windows lane. But a CI runner has no security key and nobody to touch it: the
call itself has never been made. That is the honest state, and it wants one run
on a Windows machine with a key in it.
