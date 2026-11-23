# Development Guide

**There are no hard rules; these are guidelines.** The one rule that must be followed: the `main`
branch is linear, and we rebase instead of merging.

This guide is adapted from [snaphop-ical's](https://github.com/snaphop/snaphop-ical/blob/main/development.md), itself adapted from [Rainbow Gum's](https://github.com/jstachio/rainbowgum/blob/main/development.md).

## Git Workflow

Keep git commit titles under 72 chars.

PR branches done by humans should be squashed before being merged if the history is not worth
preserving or is confusing. Agents should not squash until told to.

An agent coauthors commits that make novel additions to the code base (a `Co-Authored-By`
trailer). Novel means complicated logic. It does not mean unit tests, refactoring, trivial
documentation adjustments, dependency updates and other mechanical changes. If in doubt, the
agent asks.

## Build

Always build with `./mvnw`, not a system installed `mvn`. The wrapper pins the Maven version
(`.mvn/wrapper/maven-wrapper.properties`).

```
./mvnw verify
```

`verify` is the whole check, and every warning fails it:

- javac lint (`-Xlint:all`) with warnings as errors.
- doclint on every doc comment that exists, private ones included.
- [Error Prone](https://errorprone.info) default checks.
- [NullAway](https://github.com/uber/NullAway) in JSpecify mode, for `@NullMarked` packages.
- `javadoc` on the library modules: every public type and member needs a doc comment,
  with `@param` and `@return`.

The libraries target Java 25 (`maven.compiler.release`): the oldest LTS that has Markdown doc
comments. The build needs JDK 25 or newer. `.sdkmanrc` names the JDK we build with.

### Modules

| Module | What it is |
|--------|------------|
| `snaphop-cbor` | The CBOR reader: module and package `com.snaphop.cbor` |
| `snaphop-webauthn` | Passkey (WebAuthn) checks: module and package `com.snaphop.webauthn`. Requires `com.snaphop.cbor` |
| `test/snaphop-cbor-test` | End to end tests of `snaphop-cbor`, with PeterO's CBOR and Jackson's as oracles |
| `test/snaphop-webauthn-test` | End to end tests of `snaphop-webauthn`, with webauthn4j and Yubico's java-webauthn-server as oracles |
| `test/corpus` | Test data from other projects, each with its license and `UPSTREAM.md`; not a Maven module |

## Publishing

The libraries and their parent pom are published to SnapHop's Maven repository, as
[flylite](https://github.com/snaphop/flylite) is; Maven Central may come later. Test modules are
never installed or published.

| Repository | Deployed to | Read from |
|------------|-------------|-----------|
| Releases | `https://maven.snaphop.com/deploy/repository/public-release/` | `https://maven.snaphop.com/release` |
| Snapshots | `https://maven.snaphop.com/deploy/repository/public-snapshot/` | |

The deploy targets and their user names are in `.snaphop/settings.xml`. The password comes from
the `NEXUS_SNAPHOP_COM_PASSWORD` environment variable, a secret of the GitHub repository (the
name is older than the server, which is not Nexus).

- **A release:** `bin/release.sh` on `main`, clean and in sync with `origin/main`. It sets the
  version to `X.Y.Z`, runs `verify` with the `release` profile, commits `Release X.Y.Z`, tags
  `vX.Y.Z`, commits `Prepare X.Y.(Z+1)-SNAPSHOT`, and pushes `main` and the tag. The tag runs the
  `Deploy to SnapHop` workflow, which builds, tests and deploys that version. `NO_PUSH=true`
  stops before pushing. The `release` profile refuses a `SNAPSHOT` version or dependency, and a
  build without `-s .snaphop/settings.xml`.
- **A snapshot:** run the `Deploy to SnapHop` workflow by hand on a branch.
- **From this machine**, as a fallback: `bin/deploy.sh`, with the password in the environment.

An agent does not release, push a tag or deploy unless asked to.

## Testing

Prefer end to end tests over unit tests: real ceremonies and real CBOR in, verdicts and values out.

Prefer parameterized enum data driven tests over methods, for more permutations. A change to a
ceremony is one enum constant (`CeremonyTest.RegistrationCase`).

Tests belong in a test module in the `test` directory, not in the module they test, unless they
are very fast. Slow tests always go in a test module. So does any test that needs another
library. The library modules' own tests are fast and self-contained so that mutation testing can
run them.

### Oracles

Other implementations may be used in test modules as oracles: give the same bytes to both and
compare. They never become dependencies of a library module.

- `snaphop-webauthn-test`: [webauthn4j](https://github.com/webauthn4j/webauthn4j) and
  [java-webauthn-server](https://github.com/Yubico/java-webauthn-server). The rule: what this
  library accepts, both of them accept. Where the three differ, the case lists the three verdicts
  (`RAA`: refused by us, accepted by webauthn4j and by Yubico) and why, and checks they still
  differ, so that a change on any side is noticed.
- `snaphop-cbor-test`: [PeterO's CBOR](https://github.com/peteroupc/CBOR-Java), which
  java-webauthn-server uses, for verdicts and values; Jackson's CBOR, whose verdicts are counted
  but not asserted (it keeps the last of a duplicate key).

The WebAuthn test module also feeds the software authenticator's browser-shaped responses to
[SimpleWebAuthn](https://github.com/MasterKale/SimpleWebAuthn) on Node 22 or newer. The npm lockfile
pins its dependencies. This compares the resulting credential, flags, counters, and assertion
verdicts. To run it locally from the repository root:

```sh
npm ci --ignore-scripts --prefix test/snaphop-webauthn-test/simplewebauthn
./mvnw -Dsimplewebauthn.required=true verify
```

CI requires the JavaScript comparison. A JDK-only local build skips it when the npm package is
absent.

Data copied from other projects goes in `test/corpus/<project>`, with its license and an
`UPSTREAM.md` naming where it came from and any changes. Tests read it from there, by path:

- `test/corpus/rfc8949`: RFC 8949's Appendix A and F examples.
- `test/corpus/webauthn-spec`: the WebAuthn Level 3 test vectors.

### A software authenticator

`TestAuthenticator` (in `snaphop-webauthn`'s tests, copied into `snaphop-webauthn-test`) makes
real keys and signs real ceremonies, every part of which a test can change before or after
signing. Use it rather than recorded bytes when a test needs a ceremony that differs from a
whole one in one way.

### Random input

`FuzzTest` (CBOR) and `DamageTest` (ceremonies) write values every legal way and damage them at
random. What they assert: a value reads back as itself, and damage is refused with the library's
own exception and nothing else. `-Dfuzz.iterations=N` and `-Ddamage.iterations=N` set how many;
`-Ddamage.show=true` prints each disagreement with the oracles.

### Mutation testing

With PIT (`STRONGER` mutators), on both libraries and their own tests:

```
./mvnw -pl snaphop-cbor,snaphop-webauthn -Pmutation -Dfuzz.iterations=300 test-compile org.pitest:pitest-maven:mutationCoverage
```

It writes each module's `target/pit-reports/index.html`. A surviving mutant needs a test, or is
equivalent (it can't change what the code does) and is left alone; code that only survivors cover
is often dead and goes.

### Messages

Golden strings of error messages are desirable in these libraries. For error messages, always
assert the complete message with `assertEquals`. Do not use `contains` or other partial-message
assertions. RFC 8949's not-well-formed examples have theirs in
`snaphop-cbor/src/test/resources/appendix-f.expected`, reviewed by hand.

Do not write unit tests that are not end to end just to improve code coverage.

## Error Handling

Error messages are part of the UI and should be very clear with lots of context: what was
wrong, and where (a byte offset, a character position, a member's name). They never contain
keys or anything secret. Errors are exceptions, never log messages:

- `CborParseException` for CBOR that is refused, with `offset()` and `problem()`.
- `WebauthnException` for a ceremony that is refused, with a `reason()` for code.

### No logging

The libraries do not log. A verifier has no business writing to a log, and a logging dependency
would be the first runtime dependency. If something ever must be logged, use the
JDK's `System.Logger`, never SLF4J or any other logging library.

## Dependencies

The library modules have no runtime dependencies outside this repository (`snaphop-webauthn`
requires `snaphop-cbor`). Cryptography is the JDK's. JSpecify (`org.jspecify`) is the one allowed
dependency, and only at compile time: `requires static transitive org.jspecify` in
`module-info.java`, `optional` in the pom.

No `sun.misc.Unsafe`, `jdk.internal` or other unsupported JDK API: the modules don't require
`jdk.unsupported`, and each library's `ModuleTest` checks what they require. Native code, if it is
ever needed, goes through the FFM API (Panama), never JNI.

Integration with any other library never goes into a library module. It goes into a module
of its own.

## API Design and Code Style

Minimize API surface and allow future flexibility. Limit packages to very few, as it is hard to
encapsulate across packages. The main package has the same name as the module:
`com.snaphop.webauthn`, `com.snaphop.cbor`.

Public types are prefixed with `Webauthn` or `Cbor`, so they aren't confused with the JDK's or
other libraries' (`Credential`, `Integer`).

Prefer interfaces over abstract classes. If an abstract adapter is worthwhile, prefix it with
`Abstract`. The prefix marks it as a skeleton for implementing a type, not a type with its own
identity, so nothing should check `instanceof` against it or take it as a parameter.

Protected methods of an abstract adapter class that a subclass implements or overrides are
prefixed with `do`. Interfaces do not need this.

Inner classes in public interfaces are public. Use top level package-private classes instead,
unless the nested type is meant to be public (a builder, a mode enum).

Most classes should be sealed or final; in other words, not extendable. Public interfaces are
sealed unless callers are meant to implement them.

Prefer putting a package-private implementation class in the same file as the public
interface it implements, rather than in its own file. Java allows multiple top level types per
file as long as only one is public. `WebauthnRelyingParty.java` is the example:
`DefaultWebauthnRelyingParty` lives alongside it. A separate file is fine once the implementation gets large enough that
co-locating it would hurt readability, but that should be the exception.

Prefer builders over getters and setters; builders are the only classes that get to be
mutable. A builder does not need a one to one mapping with what it builds; it can hand back
different implementations of a shared interface depending on what got configured. Builders are
preferred over static factory methods that take a pile of arguments.

Other than builders, the code is thread-safe. Results are immutable: records, sealed
interfaces, and lists from `List.copyOf`.

We use both `package-info.java` and `module-info.java`. Annotate the package with JSpecify's
`@NullMarked`, not the module, as that is not well supported.

Methods that may return null are suffixed with `OrNull`. Accessors follow modern record style
and are not prefixed with `get`.

Prefer a setting whose values name distinct modes over a boolean. `CborReader.Mode` with
`WELL_FORMED` and `CANONICAL` is the example, rather than a `canonical(boolean)`.

Keep the existing two-space indentation and follow surrounding formatting.

### Javadoc

Doc comments are Markdown (`///`, JEP 467), not HTML `/** */`. Link with `[Type]` and
`[Type#method()]`; write code in backticks.

Public javadoc should never go into implementation details that are likely to change or are
hidden. Public javadoc should not reference package-private or private classes.

Package-private code needs no comments. When it has them, doclint checks them.

## Human specific

This is for humans: try not to write documentation targeted specifically at agents. We do not
make AGENTS.md files.

Colorful comments in code can add levity, and they make it clear an agent probably did not
write that code, but do not put them in javadoc.

We do not add license headers to source code; they add zero protection.

## Writing documentation

Never use a hyphen or dash as a parenthetical or some form of clause injection. A general rule:
if there is a space on both sides of the hyphen, an agent probably wrote it. Use multiple
sentences, colons, semicolons, parentheses, or best of all structured documentation.

Prefer structured documentation over giant paragraphs: ordered and unordered lists, and
sections.
