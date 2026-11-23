# snaphop-webauthn

Small Java libraries for checking passkeys (WebAuthn) on a server. Together they are about 76 KB,
and their only runtime dependency is the JDK.

| Library | Module | What it is |
|---------|--------|------------|
| `snaphop-webauthn` | `com.snaphop.webauthn` | Checks passkey registrations and sign-ins (WebAuthn Level 3, sections 7.1 and 7.2) with the JDK's cryptography. A lighter replacement for [webauthn4j](https://github.com/webauthn4j/webauthn4j) and Yubico's [java-webauthn-server](https://github.com/Yubico/java-webauthn-server) when attestation is not needed. 49 KB |
| `snaphop-cbor` | `com.snaphop.cbor` | Reads CBOR (RFC 8949) strictly, with limits for input nobody vouches for. What `snaphop-webauthn` reads authenticator data with. 27 KB |

## Status

Experimental, not yet released. Written for
[agentic-todo](https://github.com/agentgt/agentic-todo) (Sage Mage), whose server needs
passkeys without the Jackson, Guava and reflection the existing libraries bring. To be reviewed by
Codex before anything depends on it. Expect the API to change before 1.0.

## Why another one

| | webauthn4j 0.32 | java-webauthn-server 2.10 | snaphop-webauthn |
|---|---|---|---|
| Runtime dependencies | Jackson 3 (databind, CBOR), SLF4J: 3.4 MB | Jackson 2, Guava, PeterO CBOR, Apache HttpClient 5: 9 MB | none (snaphop-cbor): 76 KB |
| Reflection | Jackson databind | Jackson databind | none |
| Attestation | every format, with trust anchors | every format, with trust anchors and the FIDO Metadata Service | none: `none` only, or other formats recorded unverified |

Passkeys from Apple, Google and Microsoft come without attestation, so a site that only wants
passkeys doesn't need the larger part of those libraries.

## Usage

```java
WebauthnRelyingParty rp = WebauthnRelyingParty.builder()
    .id("example.org")
    .origin("https://example.org")
    .build();

// Registering. The challenge and user handle are those in the options given to
// navigator.credentials.create(); the bytes are the response's, base64url-decoded.
WebauthnCredential credential = rp.register(
    WebauthnRegistration.of(clientDataJson, attestationObject), challenge, userHandle);
store(credential.credentialId(), credential.publicKeyCose(), credential.userHandle(),
    credential.signCount(), credential.backupEligible(), credential.backedUp());

// Signing in. Look the stored credential up by the response's credential ID.
WebauthnAssertion assertion = WebauthnAssertion.builder()
    .credentialId(rawId)
    .clientDataJson(clientDataJson)
    .authenticatorData(authenticatorData)
    .signature(signature)
    .userHandle(userHandle) // null when the browser sent none
    .build();
WebauthnCredential stored = WebauthnCredential.builder(credentialId, publicKeyCose, userHandle)
    .signCount(signCount).backupEligible(backupEligible).backedUp(backedUp)
    .build();
WebauthnSignIn signIn = rp.signIn(assertion, challenge, stored);
update(signIn.credential()); // its counter and backup state
```

Anything refused is a `WebauthnException`, with a `reason()` for code and a message for people,
such as `The origin "https://evil.example" is not one of this relying party's: https://example.org`.

The caller makes challenges (32 random bytes from `SecureRandom`, used once, forgotten after a
few minutes), stores credentials, and reads the browser's JSON.

## What it checks

Everything WebAuthn Level 3 asks of a relying party that doesn't verify attestation, and these,
more strictly than either library above:

- **The client data** must be UTF-8 JSON with nothing after it and no member twice (two `origin`
  members could be read differently by two parsers). The challenge is compared as the exact
  base64url text, origins exactly, `crossOrigin` and `topOrigin` against what the relying party
  allows.
- **The authenticator data's** flags must agree with what follows: attested credential data
  exactly when AT is set (never in a sign-in), extensions exactly when ED is set, nothing after the
  last part. A credential can't be backed up without being backup eligible, and its eligibility
  can't change.
- **Credential public keys** (COSE): the algorithm must go with the key type and curve,
  coordinates must be the curve's size, below its prime and on the curve, RSA moduli at least
  2048 bits. Checked at registration, so a key that can never verify isn't stored.
- **Signatures**: ECDSA signatures must be strict DER with r and s from 1 to n - 1 (what
  CVE-2022-21449 let through), before the JDK checks them. EdDSA signatures must be their exact
  length.
- **The signature counter** must go up, unless it stays at 0 (passkeys that sync don't count).
- **CBOR** must be well-formed and valid: text is UTF-8, no map has a key twice (including keys
  written two ways), nesting and lengths are limited before anything is allocated.

Algorithms: ES256, ES384, ES512, EdDSA (Ed25519 and Ed448), Ed25519, Ed448, RS256 and PS256.

## How it is tested

- **The WebAuthn Level 3 test vectors**: all fifteen registration and sign-in ceremonies of
  section 16 (every algorithm, every attestation format, cross-origin, a 1023-byte credential ID).
- **A software authenticator** in the tests makes real ceremonies for every key type, then about a
  hundred changes to them, each refused for its reason with its exact message.
- **Oracles**: every ceremony and change is also checked by webauthn4j and java-webauthn-server.
  What this library accepts, both of them accept; where they differ (18 cases), each is listed with
  why. In every one of them this library refuses and an oracle accepts. Some examples:
  - both oracles register a key whose point is not on its curve;
  - both oracles register a key whose algorithm doesn't go with its curve;
  - java-webauthn-server ignores `crossOrigin`, `topOrigin`, text after the client data, and bytes
    after a sign-in's authenticator data;
  - webauthn4j keeps the last of a COSE key's members written twice.
- **Damage**: thousands of real ceremonies with random damage (a bit flipped, a byte changed,
  added, taken out, cut short). This library only ever refuses with a `WebauthnException`, and
  never accepts what an oracle refuses.
- **CBOR**: RFC 8949's examples (Appendix A read as its diagnostic notation, Appendix F's 94
  not-well-formed items refused), random values written every legal way, and damaged encodings,
  all read the same by PeterO's CBOR (java-webauthn-server's).
- **Mutation testing** with PIT on both libraries (see [development.md](development.md)).

## Building

```
./mvnw verify
```

See [development.md](development.md).

## License

[Zero-Clause BSD](LICENSE).
