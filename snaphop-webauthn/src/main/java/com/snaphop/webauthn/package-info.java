/// Checks passkey (WebAuthn Level 3) registrations and sign-ins on a server,
/// with the JDK's cryptography and no other dependency.
///
/// The types, in the order a caller meets them:
///
/// 1. [WebauthnRelyingParty] is the website: its RP ID, the origins it is
///    served from, and how strict to be. Its builder sets them.
/// 2. [WebauthnRegistration] is what the browser returns from
///    `navigator.credentials.create()`;
///    [WebauthnRelyingParty#register(WebauthnRegistration, byte[], byte[])]
///    checks it and returns a [WebauthnCredential] to store.
/// 3. [WebauthnAssertion] is what the browser returns from
///    `navigator.credentials.get()`;
///    [WebauthnRelyingParty#signIn(WebauthnAssertion, byte[], WebauthnCredential)]
///    checks it against the stored credential and returns a [WebauthnSignIn].
/// 4. [WebauthnException] says why a response was refused, as a
///    [WebauthnException.Reason] and a message.
///
/// What it does not do: make challenges (use 32 bytes from
/// `SecureRandom`, once each), store anything, read the browser's JSON, or
/// check attestation statements (see [WebauthnRelyingParty.Attestation]).
@org.jspecify.annotations.NullMarked
package com.snaphop.webauthn;
