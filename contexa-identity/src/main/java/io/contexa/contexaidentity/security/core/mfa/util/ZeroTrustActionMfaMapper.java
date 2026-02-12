package io.contexa.contexaidentity.security.core.mfa.util;

import io.contexa.contexacommon.enums.ZeroTrustAction;
import io.contexa.contexaidentity.security.core.mfa.model.MfaDecision;

public final class ZeroTrustActionMfaMapper {

    private ZeroTrustActionMfaMapper() {}

    public static MfaDecision.DecisionType toDecisionType(ZeroTrustAction action) {
        if (action == null) {
            return MfaDecision.DecisionType.CHALLENGED;
        }
        return switch (action) {
            case ALLOW -> MfaDecision.DecisionType.NO_MFA_REQUIRED;
            case CHALLENGE, PENDING_ANALYSIS -> MfaDecision.DecisionType.CHALLENGED;
            case BLOCK -> MfaDecision.DecisionType.BLOCKED;
            case ESCALATE -> MfaDecision.DecisionType.ESCALATED;
        };
    }
}
