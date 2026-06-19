# Teaching mini-auth — the syllabus

> **What this is.** The front door to a course-style documentation set that teaches **how
> authentication and authorization actually work**, using the `mini-*` services as the worked
> example. It does not replace the orientation docs — it sits on top of them. One screen, then it
> routes you. **This is the live syllabus; start here.**

## How this set relates to the other docs

You are standing in front of four kinds of document. Keep them straight and the repo opens up:

| Doc | Kind | Use it to… |
| --- | --- | --- |
| [`DIRECTION.md`](DIRECTION.md) | **Map** | understand the *why* and the architecture of the whole family. Every concept here hands off to it for rationale rather than restating it. |
| [`GLOSSARY.md`](GLOSSARY.md) | **Dictionary** | look up a term. The docs here link a term to the glossary on first use and never redefine it. |
| [`LEARNING.md`](LEARNING.md) | **Reading order** | walk the *source files* in dependency order. Complementary to this set: **concepts first here, then code there.** |
| **`TEACHING.md` (this set)** | **Course** | learn the *ideas* in teaching order, then prove them with hands-on labs. |

The course is deliberately split into four physically-separate kinds, and they don't bleed into
each other:

- **`concepts/`** — *explanation.* Build the idea from zero, then point at the real code.
- **`tutorials/`** — *hands-on, guaranteed to succeed.* Lean; they link out for exact syntax.
- **`howto/`** — *task-oriented*, for someone who already gets it.
- **`security/`** — *attack & defense*, framing the threat-model findings the services already ship.
- **`diagrams/`** — shared sequence diagrams the other docs embed.

---

## Pick your path

Find yourself in this table and start where it points.

| You are… | You already know | Start here |
| --- | --- | --- |
| **A backend dev learning auth** *(the primary audience)* | HTTP/JSON, can read Java, have *used* an IdP as a black box. "JWT" is a string you copy around. | [`concepts/authn-vs-authz.md`](concepts/authn-vs-authz.md) → the stage ladder below, in order. |
| **A homelab operator** | Docker, reverse proxies, the CLI. You don't want crypto theory first. | [`howto/run-the-whole-family.md`](howto/run-the-whole-family.md), then tutorials [`04`](tutorials/04-human-sso-end-to-end.md) and [`05`](tutorials/05-gate-a-no-auth-app.md). |
| **A security student / threat-modeler** | OWASP-level vocabulary. You read the `security/` findings for fun. | [`concepts/secure-design-invariants.md`](concepts/secure-design-invariants.md) + the [`security/`](security/) track. |
| **An architect** | System design. | You're already served by [`DIRECTION.md`](DIRECTION.md). |

**Before any deep dive, read [`concepts/honest-seams.md`](concepts/honest-seams.md).** It lists the
handful of paths that are *designed but not yet wired* — so a lab never sends you to trace something
through running code that the running code doesn't actually do.

---

## The stage ladder

The course is dependency-ordered: each stage leads with the *why/what*, then drops into a lab that
proves it. Do them in order and each one earns the next. (This is a different order from
`LEARNING.md`, which walks the code DAG — read concepts here, then code there.)

| Stage | You'll be able to… | Concept | Lab |
| --- | --- | --- | --- |
| **0** | Name which problem each `mini-` service solves | [`authn-vs-authz`](concepts/authn-vs-authz.md) | — |
| **1** | See a decision as a pure function; explain deny-by-default | [`authorization-model`](concepts/authorization-model.md) | [`01-resolve-a-principal`](tutorials/01-resolve-a-principal.md) |
| **2** | Say what a signed token *is* and verify one offline, by hand | [`what-a-token-is`](concepts/what-a-token-is.md) | [`02-build-and-verify-a-token-by-hand`](tutorials/02-build-and-verify-a-token-by-hand.md) ← **keystone** |
| **3** | Trace a machine identity end to end | [`oauth-and-oidc-flows`](concepts/oauth-and-oidc-flows.md) | [`03-machine-identity-end-to-end`](tutorials/03-machine-identity-end-to-end.md) |
| **4** | Run a human SSO login: PKCE, passkeys, sessions, refresh | [`sessions-vs-tokens`](concepts/sessions-vs-tokens.md) | [`04-human-sso-end-to-end`](tutorials/04-human-sso-end-to-end.md) |
| **5** | Gate a no-auth app via forward-auth | *(reuse stage 4)* | [`05-gate-a-no-auth-app`](tutorials/05-gate-a-no-auth-app.md) |
| **6** | Explain how the family protects its own keys | [`envelope-encryption-and-kms`](concepts/envelope-encryption-and-kms.md) | [`06-protect-the-signing-keys`](tutorials/06-protect-the-signing-keys.md) |
| **∥** | Carry the family's security reflexes anywhere | [`secure-design-invariants`](concepts/secure-design-invariants.md) | the [`security/`](security/) threat labs |

**The keystone is stage 2.** Building and verifying a token signature by hand — then tampering one
byte and watching it fail — is the single device that converts "JWT = opaque string" into a real
mental model. Don't skip it.

---

## The labs share one scenario

Tutorials 3–6 thread a single story: **"protect `grafana` in my homelab."** A machine gets a token
(stage 3), a human logs in and reaches the gated app (stages 4–5), and the family wraps its own
signing keys so nothing plaintext touches disk (stage 6). Each service slots into that one story
instead of standing alone.

Every lab uses **predict-then-run**: you write down the expected allow/deny (or pass/fail) *before*
you run the command. Being wrong on purpose is where the learning is.

---

## Two reading conventions

- **"Now read it" boxes.** Every concept closes with exact `file:symbol` pointers into the shipping
  code. The point of this set is to send you *into* the code with a model already in hand.
- **`> Wired vs. designed` callouts.** Where a doc touches a designed-but-not-wired seam, it says so
  in a standard callout and links [`concepts/honest-seams.md`](concepts/honest-seams.md). The repo
  is honest about its scaffolds; so is the course.
