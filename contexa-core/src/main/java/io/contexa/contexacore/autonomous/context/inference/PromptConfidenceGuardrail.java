package io.contexa.contexacore.autonomous.context.inference;
import io.contexa.contexacore.autonomous.context.model.PromptDecisionAdjustment;
import io.contexa.contexacore.autonomous.context.model.ProposedPromptDecision;
import io.contexa.contexacore.autonomous.context.CanonicalSecurityContext;

public interface PromptConfidenceGuardrail {

    PromptDecisionAdjustment evaluate(CanonicalSecurityContext context, ProposedPromptDecision decision);
}
