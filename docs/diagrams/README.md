# Sequence diagrams

> **The visual layer the repo lacked.** [`DIRECTION.md`](../DIRECTION.md) has the *topology* (who
> depends on whom). These are the **sequence** diagrams — *what happens, in what order*, for the
> flows the course teaches. The concept and tutorial docs embed them.

Each diagram is mermaid (GitHub renders it inline). They show the **wired** runtime paths; where a
step is a designed-but-not-wired seam, the diagram says so and links
[`concepts/honest-seams.md`](../concepts/honest-seams.md).

| Diagram | Flow | Used by |
| --- | --- | --- |
| [`client-credentials.md`](client-credentials.md) | machine gets a token (mini-idp) | stage 3 |
| [`auth-code-pkce.md`](auth-code-pkce.md) | human SSO login (mini-oidc) | stage 4 |
| [`forward-auth.md`](forward-auth.md) | proxy subrequest gating a no-auth app (mini-gateway) | stage 5 |
| [`kms-wrap-on-save.md`](kms-wrap-on-save.md) | signing key wrapped at rest (the recursive integration) | stage 6 |
