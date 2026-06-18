# Mini Console

**mini-console** is a *reserved* slot for an optional, unified **admin UI** over the whole `mini-`
family — one place to inspect mini-directory identities, rotate mini-token signing keys, review
audit logs, and manage mini-kms key groups, instead of curling each service's admin API by hand.

> **Roadmap placeholder — there is no logic here yet.** This module deliberately contains no UI and
> no server code. It exists so the umbrella build and `docs/DIRECTION.md` can refer to mini-console
> as a real, compiling module *before* any of it is written. If you came here to learn how a service
> in this family works, read one of the shipping services instead — **[mini-kms](../mini-kms)** and
> **[mini-idp](../mini-idp)** are the most heavily commented, and **[mini-directory](../mini-directory)**,
> **[mini-oidc](../mini-oidc)**, **[mini-gateway](../mini-gateway)**, and **[mini-ca](../mini-ca)**
> round out the set.

## Table of contents

- [Why it's a placeholder](#why-its-a-placeholder)
- [What's actually in the module today](#whats-actually-in-the-module-today)
- [Intended scope (when it gets built)](#intended-scope-when-it-gets-built)
- [Where it would fit in the family](#where-it-would-fit-in-the-family)
- [Building & testing](#building--testing)

## Why it's a placeholder

The family ethos (see the root `CLAUDE.md`) is that **scaffolds say so** — a placeholder must not
masquerade as a half-built service that *looks* finished. mini-console is the purest form of that
rule: it claims the name and the base package `com.codeheadsystems.miniconsole`, compiles, and
passes one trivial guard test, and that is **all** it does. Reserving the module now means:

- the single aggregator build (`./gradlew build`) already knows about it, so wiring it up later is
  additive rather than structural;
- `docs/DIRECTION.md` and the layout table in `CLAUDE.md` can list it as a real Gradle project; and
- nobody mistakes an empty directory for "lost" code — the placeholder is explicit and self-documenting.

It is a **plain library** (`miniauth.library-conventions`, *not* `application-conventions`) precisely
because there is nothing to run. The day it grows a transport, it graduates to the application plugin
like the other front doors.

## What's actually in the module today

Two files, both honest about the module's status:

```
services/mini-console/
├── build.gradle.kts                                   # library-conventions; no deps beyond JUnit
└── src/
    ├── main/java/com/codeheadsystems/miniconsole/MiniConsole.java       # IMPLEMENTED = false
    └── test/java/com/codeheadsystems/miniconsole/MiniConsoleTest.java   # asserts NOT implemented
```

`MiniConsole` is a final, non-instantiable class exposing a single flag:

```java
public static final boolean IMPLEMENTED = false;
```

and `MiniConsoleTest` is the guard that keeps everyone honest:

```java
@Test
void isStillARoadmapPlaceholder() {
  // This guard flips to a real assertion when mini-console starts being implemented.
  assertFalse(MiniConsole.IMPLEMENTED);
}
```

When real work begins, flipping `IMPLEMENTED` to `true` makes this test fail — a deliberate
trip-wire that forces whoever starts the implementation to replace the placeholder guard with real
tests, so the module can never quietly drift from "placeholder" to "half-built."

## Intended scope (when it gets built)

A single, optional, **admin-only** console that composes the existing services' admin APIs — it would
*invent no new authority of its own*, only present what the services already expose:

- **Identities** — browse and edit mini-directory's humans, service accounts, groups, and roles, and
  preview a principal's resolved grants (the `/admin/principals/{id}/resolution` view).
- **Keys** — trigger and review mini-token signing-key rotation across the issuers, and manage
  mini-kms key groups (create / rotate / disable / destroy).
- **Audit** — read the issuance / rotation / revocation audit logs the services keep.
- **Certificates** — review mini-ca's issuance log and revocation list.

Like the rest of the family it would bind to **loopback by default**, gate everything behind a
bootstrap admin token resolved from env/file (never argv, never logged), and keep **no secrets in
logs**. It is explicitly **not scheduled** — see the *Future tracks* note in `docs/DIRECTION.md`.

## Where it would fit in the family

mini-console sits *above* the services as a pure consumer of their admin surfaces — it is a client,
not a new source of truth:

```
                        ┌─────────────────────────────────────────────┐
                        │              mini-console (UI)               │   ← roadmap; reads/calls
                        └───┬──────────┬──────────┬──────────┬─────────┘     existing admin APIs only
                            │          │          │          │
                    mini-directory  mini-idp   mini-oidc   mini-kms / mini-ca
                    (identities)   (m2m tokens)(human SSO) (keys / certs)
```

Because it would only call APIs that already exist, mini-console adds **no** new trust boundary —
which is exactly why it can wait until the services beneath it have settled.

## Building & testing

It participates in the one aggregator build like every other module:

```bash
./gradlew build                          # compiles mini-console + runs its single guard test
./gradlew :services:mini-console:test    # just this module's test
```

There is nothing to install or run (no `application` plugin, no `installDist`). This README will be
replaced with a real teaching document — endpoints, screens, the security model — if and when
mini-console is actually implemented.
