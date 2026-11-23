/// Checks passkey (WebAuthn) registrations and sign-ins on a server.
///
/// Start with [com.snaphop.webauthn.WebauthnRelyingParty#builder()].
///
/// The module's only runtime dependency is `com.snaphop.cbor`, which has
/// none. JSpecify nullness annotations are part of the API but only needed
/// at compile time, so the module requires them as `static transitive`.
/// Cryptography is the JDK's own.
///
/// Thread safety: builders are the only mutable types. A relying party and
/// everything it returns are immutable and thread-safe.
module com.snaphop.webauthn {
  exports com.snaphop.webauthn;

  requires com.snaphop.cbor;
  requires static transitive org.jspecify;
}
