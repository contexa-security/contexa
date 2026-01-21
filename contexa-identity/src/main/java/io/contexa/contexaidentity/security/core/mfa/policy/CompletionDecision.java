package io.contexa.contexaidentity.security.core.mfa.policy;

import lombok.Builder;
import lombok.Getter;
import java.util.List;

@Getter
@Builder
public class CompletionDecision {
    private final boolean completed;
    private final boolean needsFactorSelection;
    private final int attemptCount;
    private final String errorMessage;
    private final List<String> missingRequiredStepIds;

    public static CompletionDecision completed() {
        return CompletionDecision.builder()
            .completed(true)
            .needsFactorSelection(false)
            .build();
    }

    public static CompletionDecision needsFactorSelection(int attemptCount) {
        return CompletionDecision.builder()
            .completed(false)
            .needsFactorSelection(true)
            .attemptCount(attemptCount)
            .build();
    }

    public static CompletionDecision incomplete(List<String> missingSteps) {
        return CompletionDecision.builder()
            .completed(false)
            .needsFactorSelection(true)
            .missingRequiredStepIds(missingSteps)
            .build();
    }

    public static CompletionDecision error(String message) {
        return CompletionDecision.builder()
            .completed(false)
            .needsFactorSelection(false)
            .errorMessage(message)
            .build();
    }
}
