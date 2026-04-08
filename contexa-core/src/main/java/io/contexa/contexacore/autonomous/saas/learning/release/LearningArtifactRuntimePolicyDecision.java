package io.contexa.contexacore.autonomous.saas.learning.release;

import io.contexa.contexacore.autonomous.saas.learning.LearningArtifactReleaseState;

import java.util.List;

/**
 * Runtime policy decision for a single learning artifact.
 */
public record LearningArtifactRuntimePolicyDecision(
        LearningArtifactReleaseState releaseState,
        boolean tenantOptIn,
        boolean killSwitchActive,
        boolean runtimeAllowed,
        boolean reviewOnly,
        boolean withdrawn,
        String policyState,
        String deploymentAction,
        List<String> policyFacts) {

    public LearningArtifactRuntimePolicyDecision {
        policyState = policyState == null ? "COLLECTING" : policyState;
        deploymentAction = deploymentAction == null ? "WITHHOLD" : deploymentAction;
        policyFacts = policyFacts == null ? List.of() : List.copyOf(policyFacts);
    }
}
