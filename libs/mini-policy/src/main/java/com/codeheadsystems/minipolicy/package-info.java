/**
 * mini-policy: the family's shared authorization decision — may THIS principal perform THIS action
 * on THIS resource?
 *
 * <p>The model is tiny and value-typed: {@link com.codeheadsystems.minipolicy.Principal},
 * {@link com.codeheadsystems.minipolicy.Action}, {@link com.codeheadsystems.minipolicy.Resource},
 * {@link com.codeheadsystems.minipolicy.Grant} ({@code permits(action, resource)} with wildcard
 * support), and {@link com.codeheadsystems.minipolicy.Decision}. The seam is
 * {@link com.codeheadsystems.minipolicy.PolicyEngine}, implemented by
 * {@link com.codeheadsystems.minipolicy.GrantBasedPolicyEngine} (admin bypass, then grant match,
 * else <b>deny-by-default</b>) plus the {@code AllowAll}/{@code DenyAll} engines used as documented
 * seams. Sourcing the grants family-wide (mini-directory resolution; the token → mini-kms path) is
 * integration work in the consuming services, not in this library.
 */
package com.codeheadsystems.minipolicy;
