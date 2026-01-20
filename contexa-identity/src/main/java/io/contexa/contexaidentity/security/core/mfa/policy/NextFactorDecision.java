package io.contexa.contexaidentity.security.core.mfa.policy;

import io.contexa.contexacommon.enums.AuthType;
import lombok.Builder;
import lombok.Getter;


@Getter
@Builder
public class NextFactorDecision {
    private final boolean hasNextFactor;
    private final AuthType nextFactorType;
    private final String nextStepId;
    private final boolean allFactorsCompleted;
    private final String errorMessage;

    
    public static NextFactorDecision noMoreFactors() {
        return NextFactorDecision.builder()
            .hasNextFactor(false)
            .allFactorsCompleted(true)
            .build();
    }

    
    public static NextFactorDecision nextFactor(AuthType type, String stepId) {
        return NextFactorDecision.builder()
            .hasNextFactor(true)
            .nextFactorType(type)
            .nextStepId(stepId)
            .allFactorsCompleted(false)
            .build();
    }

    
    public static NextFactorDecision error(String message) {
        return NextFactorDecision.builder()
            .hasNextFactor(false)
            .allFactorsCompleted(false)
            .errorMessage(message)
            .build();
    }
}
