package io.contexa.contexaiam.admin.promptquality.governance;

/**
 * W6-10 (P6-CHANGE-7): whether the policy set a bundle runs with is there. The OSS has no policy sets; a host that
 * keeps them implements this, and without an implementation the rollback records that the condition does not apply.
 */
public interface PromptPolicySetLookup {

    boolean policySetExists(String registryScope, String promptKey, String bundleVersion);
}
