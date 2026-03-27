package io.contexa.contexacore.autonomous.context;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexacore.autonomous.tiered.SecurityDecision;

public record ProposedPromptDecision(
        ZeroTrustAction action,
        Double riskScore,
        Double confidence,
        String reasoning,
        int processingLayer) {

    public static ProposedPromptDecision from(SecurityDecision decision) {
        if (decision == null) {
            return new ProposedPromptDecision(ZeroTrustAction.ESCALATE, null, null, null, 0);
        }
        return new ProposedPromptDecision(
                decision.getAction(),
                decision.resolveAuditRiskScore(),
                decision.resolveAuditConfidence(),
                decision.getReasoning(),
                decision.getProcessingLayer());
    }
}
