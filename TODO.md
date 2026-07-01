# TODO — learning-project improvements

Tasks identified by the multi-agent learning-review of mini-auth (docs, crypto/token code,
integration story, and learner experience). Ordered by priority. Each task has a checkbox
(`[ ]` = not done, `[x]` = done), a short rationale, and a **Claude prompt** you can paste to
have Claude do the work.

After finishing a task: flip its `[ ]` to `[x]`, run `./gradlew build` from the repo root
(it must stay green — that IS the CI gate), and note any follow-ups under the task.

---

## P1 — biggest gains

### 1. [x] Add a `FullChainFlow` end-to-end harness exercise
**Why:** No single runnable thing demonstrates the headline learning goal — `identity → token →
gateway verifies → resource`. Today each mini-console harness flow exercises only one hop, with a
manual copy-paste in the seam. This is the missing executable answer to "how do the systems work
together to protect a resource."

**Claude prompt:**
> Add a new `FullChainFlow` to `services/mini-console/.../harness/` that chains the whole request
> path: resolve a service-account identity in mini-directory, mint a client-credentials token from
> mini-idp, then present that same token to mini-gateway's `/verify` and assert it passes. Reuse the
> existing client libraries (mini-directory-client, mini-idp-client, mini-gateway-client). Register
> it in `ExerciseRegistry`, follow the existing flow conventions (offline verification, PASS/SKIP/FAIL,
> secret-free results, honest SKIP when a credential isn't supplied), and add a corresponding row to
> `HarnessPages`. Update `services/mini-console/README.md`. Run `./gradlew build` and make it green.

### 2. [x] Fix (or document) the gateway token-dialect mismatch
**Why:** `BearerAuthenticator.toUser` (`services/mini-gateway/.../auth/BearerAuthenticator.java:58-68`)
reads scopes/admin only from top-level `scope`/`admin` claims (mini-oidc's token shape). But mini-idp
machine tokens carry authority in a `grants` claim and have no top-level `scope`, so a valid machine
token authenticates yet can **never** satisfy a SCOPE route — its authority is silently dropped.
This is a real correctness bug, not just a teaching gap.

**Claude prompt:**
> In `services/mini-gateway/.../auth/BearerAuthenticator.java`, fix the token-dialect mismatch:
> a mini-idp machine token (authority in the `grants` claim, no top-level `scope`) currently
> authenticates but carries zero scopes/admin at the gateway. Prefer teaching `toUser` to also read
> the `grants` claim and map it via mini-token's `GrantsClaim.toAuthorization()` (this would give that
> method its first production caller). If a code change is out of scope, instead add a clear comment
> documenting that the gateway intentionally consumes only mini-oidc-shaped tokens and that mini-idp
> tokens satisfy AUTHENTICATED but not SCOPE. Add a test covering a mini-idp token against a SCOPE
> route either way. Run `./gradlew build`.

### 3. [x] Add a passkeys/WebAuthn concept doc + make lab 04 completable
**Why:** Passkeys/WebAuthn is the thinnest-scaffolded major topic and the one learners arrive least
familiar with — no concept doc, no glossary entries. Lab 04 (`docs/tutorials/04-human-sso-end-to-end.md`),
the human-SSO "payoff," degrades into prose with placeholders because the ceremony can't be done with
curl. A motivation cliff at the most exciting service.

**Claude prompt:**
> Create `docs/concepts/what-a-passkey-is.md` parallel in style to `docs/concepts/what-a-token-is.md`:
> public-key credential, registration vs authentication ceremony, challenge–response, why it resists
> phishing, attestation vs assertion, and where pk-auth fits — ending with a "Now read it" box pointing
> into mini-oidc's `auth/` package. Add glossary entries to `docs/GLOSSARY.md` for WebAuthn, passkey,
> assertion, challenge, RP-ID, and origin. Then make `docs/tutorials/04-human-sso-end-to-end.md`
> copy-paste completable: ship a tiny static enrol+login helper page (or a Chrome DevTools
> virtual-authenticator script) under `docs/examples/` and reference it from the lab. Wire the new
> concept doc into the stage ladder in `docs/TEACHING.md`.

---

## P2

### 4. [x] Move "designed, not wired" honesty into the code
**Why:** The honest seams are documented in `docs/concepts/honest-seams.md` and CLAUDE.md but are
invisible at the code site a learner actually reads. `GrantsClaim.toAuthorization()` has no production
caller, yet its Javadoc reads as a live verifier path; `M2mTokenFlow` prints `grants=…` as if proving
the authorization story.

**Claude prompt:**
> Add concise in-code markers at the designed-but-not-wired seams so a learner sees them where they
> read the code. On `libs/mini-token/.../token/GrantsClaim.java` `toAuthorization()`, add a one-line
> note like `// NOTE: no production caller yet — see docs/concepts/honest-seams.md` and soften the
> present-tense "the verifier performs" wording. Add a matching note at the grants-printing step in
> `M2mTokenFlow`. Verify against `docs/concepts/honest-seams.md` so the lists stay consistent. No
> behavior change; run `./gradlew build`.

### 5. [x] Add a "Before you start / Troubleshooting" section
**Why:** Labs are billed "guaranteed to succeed," but step 1 pulls the internet and binds fixed ports
(8455/8466/8477…). There's no rescue for port-in-use, wrong JDK, offline build, or stray background
servers — so a failure at step 1 is a dead end.

**Claude prompt:**
> Add a "Before you start / Troubleshooting" section (either near the top of `docs/TEACHING.md` or as
> a new `docs/SETUP.md` linked from it): JDK 21 check, note that the first build needs network, how to
> fix port-in-use on the standard service ports, and how to find/kill stray background servers from the
> labs. Keep it short and task-oriented in the `howto/` voice.

### 6. [ ] Localize the DEK / envelope-encryption narrative
**Why:** The central KMS concept is split across three files. `LocalKeyring.java:32-36` draws the full
`passphrase→root→KEK→DEK→data` hierarchy, but that file never mints a DEK — `wrap()` is a comment-free
one-liner delegating to `encrypt()`, and the DEK is actually born in `KmsService.generateDataKey`. A
student reading the keyring can't see the layer the diagram promises.

**Claude prompt:**
> Tighten the envelope-encryption teaching in mini-kms core. In `services/mini-kms/core/.../keyring/
> LocalKeyring.java`, add two lines to `wrap()` explaining that wrap == encrypt and that we're
> encrypting key material (the DEK is minted in `KmsService.generateDataKey`), or move the hierarchy
> diagram next to `generateDataKey` and cross-reference. Add a short "when to use which" note in
> `KmsService` contrasting `encrypt()` (data straight under the KEK) vs `generateDataKey()` (the
> envelope pattern). Comments only; run `./gradlew build`.

---

## P3

### 7. [ ] Reduce doc entry-point overload
**Why:** A newcomer landing in `docs/` faces ~8 index-like files; `TEACHING-OUTLINE.md` (a
design-history doc) sits next to the live syllabus with a near-identical name and will be opened by
mistake.

**Claude prompt:**
> Reduce the docs entry surface. Make the root `README.md` + `docs/TEACHING.md` the two doors a learner
> is told to open, with a one-line "Which doc do I want?" decision list at the top of the root README.
> Move `docs/TEACHING-OUTLINE.md` into `docs/meta/` (or `docs/contributing/`) so it can't be mistaken
> for the syllabus, and fix any links that referenced it. Tighten the framing so `LEARNING.md` reads as
> "once you've done the course, re-walk the source," not a competing start point.

### 8. [ ] Add a "Learning?" banner to each service README + render diagrams for editor readers
**Why:** Per-service READMEs are reference docs with no pointer back into the curriculum, and the one
visual layer (mermaid) degrades to raw source for the code-first reader working in an editor.

**Claude prompt:**
> Add a 3-line "Learning?" banner to the top of each `services/*/README.md` and `libs/*/README.md`
> pointing to the matching concept doc + lab (e.g. mini-oidc → `docs/concepts/oauth-and-oidc-flows.md`
> + lab 04). Separately, make the `docs/diagrams/` mermaid viewable outside GitHub: either commit
> pre-rendered SVG/PNG alongside each `.md`, or add one line per diagram telling editor readers how to
> view it (e.g. paste into mermaid.live).

### 9. [ ] Add an mTLS / workload-identity concept-stage doc
**Why:** mini-ca ships and the glossary defines CSR/PoP/SAN/EKU, but there's no concept doc on *why*
mTLS / how chain-to-root validation works, and mini-ca is absent from the stage ladder (only a
code-tour capstone).

**Claude prompt:**
> Create `docs/concepts/certificates-and-mtls.md`: what mTLS is and why workloads use it, the CSR →
> issue → verify flow, proof-of-possession, chain-to-root validation, and why short leaf TTLs. End
> with a "Now read it" box into mini-ca's `ca/` package. Add it to the stage ladder in
> `docs/TEACHING.md` so the mini-ca capstone has a concept stage behind it.

### 10. [ ] Reframe or upgrade the mini-console "exercise harness"
**Why:** All reviewers flagged that the harness flows are integration smoke-tests a learner *watches*,
not exercises they *do* (make a choice, get feedback). The framing oversells "exercise."

**Claude prompt:**
> Either (a) relabel the mini-console harness honestly as a "watch-it-work" integration demo in
> `services/mini-console/README.md` and `docs/design/mini-console.md`, or (b) make at least one flow
> genuinely interactive in the predict-then-observe style of the tutorials — e.g. let the learner
> supply a grant/scope and have the harness show the resulting allow vs deny decision. If you change
> behavior, keep results secret-free and run `./gradlew build`.

### 11. [ ] (Optional) Add a "Stage 0.5: the tools you'll use" primer
**Why:** Every lab assumes curl, env vars, background jobs, and jq/python. Lowers the on-ramp for the
bottom edge of the stated audience.

**Claude prompt:**
> Add an optional short "Stage 0.5 — the tools you'll use" primer (curl basics, exporting env vars,
> running/killing background jobs, jq/python for decoding tokens) and link it from `docs/TEACHING.md`
> as optional pre-reading for learners new to the command line.
