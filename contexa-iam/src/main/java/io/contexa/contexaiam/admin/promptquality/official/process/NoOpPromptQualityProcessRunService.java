package io.contexa.contexaiam.admin.promptquality.official.process;

import java.util.List;
import java.util.Map;

/**
 * OSS boundary for the Enterprise prompt-quality resolution process.
 * Official verification persistence remains active while resolution process state is absent.
 */
public final class NoOpPromptQualityProcessRunService implements PromptQualityProcessRunService {

    @Override
    public void startStep(
            PromptQualityProcessScope scope, String stepCode, String domainStateDimension,
            String domainStateCode, String evidenceRef, String route, String actor, String reason) {
    }

    @Override
    public void completeStep(
            PromptQualityProcessScope scope, String stepCode, String domainStateDimension,
            String domainStateCode, String evidenceRef, String route, String summary, String nextAction,
            Map<String, Object> result, String actor, String reason) {
    }

    @Override
    public void failStep(
            PromptQualityProcessScope scope, String stepCode, String domainStateDimension,
            String domainStateCode, String evidenceRef, String route, String errorMessage,
            String actor, String reason) {
    }

    @Override
    public void completeMain(
            PromptQualityProcessScope scope, String domainStateDimension, String domainStateCode,
            String evidenceRef, String actor, String reason) {
    }

    @Override
    public void recordEvent(
            PromptQualityProcessScope scope, String stepCode, String type,
            Map<String, Object> payload, String actor, String reason) {
    }

    @Override
    public List<PromptQualityProcessStepSnapshot> steps(PromptQualityProcessScope scope) {
        return List.of();
    }
}
