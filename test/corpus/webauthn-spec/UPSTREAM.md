# WebAuthn test vectors

From section 16, "Test Vectors", of the W3C editor's draft of
[Web Authentication: An API for accessing Public Key Credentials, Level 3](https://w3c.github.io/webauthn/),
revision `d12a3f32e8dfc53c3ef9b4973b0797b4b1b538b8` (dated 2026-08-25), source repository
https://github.com/w3c/webauthn.

`test-vectors.txt` holds every byte string literal (`h'...'`) of sections 16.1 to 16.17, as
hex, under a `[16.N title]` line for its section. Values in a section's registration
example are prefixed `registration.`, those in its authentication example
`authentication.`. Comments, CDDL notation and base64url forms were dropped; nothing else
was changed. Extracted by a script from the rendered draft on 2026-11-22.

All examples use the RP ID `example.org`, the origin `https://example.org` and, where
applicable, the top origin `https://example.com`.

The specification is published under the W3C Software and Document License
(https://www.w3.org/copyright/software-license-2023/), which allows copying with this
notice: Copyright © 2026 World Wide Web Consortium.
