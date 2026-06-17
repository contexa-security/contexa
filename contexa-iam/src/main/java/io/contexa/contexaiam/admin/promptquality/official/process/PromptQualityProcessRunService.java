package io.contexa.contexaiam.admin.promptquality.official.process;

import java.util.List;
import java.util.Map;

public interface PromptQualityProcessRunService {

    void startStep(
            PromptQualityProcessScope scope,
            String stepCode,
            String domainStateDimension,
            String domainStateCode,
            String evidenceRef,
            String route,
            String actor,
            String reason);

    void completeStep(
            PromptQualityProcessScope scope,
            String stepCode,
            String domainStateDimension,
            String domainStateCode,
            String evidenceRef,
            String route,
            String summary,
            String nextAction,
            Map<String, Object> result,
            String actor,
            String reason);

    void failStep(
            PromptQualityProcessScope scope,
            String stepCode,
            String domainStateDimension,
            String domainStateCode,
            String evidenceRef,
            String route,
            String errorMessage,
            String actor,
            String reason);

    void completeMain(
            PromptQualityProcessScope scope,
            String domainStateDimension,
            String domainStateCode,
            String evidenceRef,
            String actor,
            String reason);

    void recordEvent(
            PromptQualityProcessScope scope,
            String stepCode,
            String type,
            Map<String, Object> payload,
            String actor,
            String reason);

    List<PromptQualityProcessStepSnapshot> steps(PromptQualityProcessScope scope);

    default List<PromptQualityProcessHistorySnapshot> history(PromptQualityProcessScope scope) {
        return List.of();
    }

    default List<PromptQualityProcessEventSnapshot> events(PromptQualityProcessScope scope) {
        return List.of();
    }
}
