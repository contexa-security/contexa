package io.contexa.contexacore.autonomous.context;

public interface PromptConfidenceGuardrail {

    PromptDecisionAdjustment evaluate(CanonicalSecurityContext context, ProposedPromptDecision decision);
}
