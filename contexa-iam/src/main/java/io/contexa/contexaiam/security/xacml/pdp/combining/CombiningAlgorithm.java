package io.contexa.contexaiam.security.xacml.pdp.combining;

/**
 * XACML 3.0 standard combining algorithms for policy evaluation.
 * Determines how multiple matching policies are combined into a single decision.
 */
public enum CombiningAlgorithm {

    /**
     * If any matching policy returns DENY, the result is DENY.
     * Most secure option - recommended as default.
     */
    DENY_OVERRIDES,

    /**
     * If any matching policy returns ALLOW, the result is ALLOW.
     */
    PERMIT_OVERRIDES,

    /**
     * The first matching policy determines the result.
     * Original behavior before combining algorithm support.
     */
    FIRST_APPLICABLE,

    /**
     * Unless an explicit ALLOW is found, the result is DENY.
     */
    DENY_UNLESS_PERMIT
}
