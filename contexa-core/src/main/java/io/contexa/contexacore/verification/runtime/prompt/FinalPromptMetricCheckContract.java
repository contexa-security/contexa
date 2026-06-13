package io.contexa.contexacore.verification.runtime.prompt;

import java.util.List;
import java.util.Map;

public record FinalPromptMetricCheckContract(
        String metricCode,
        String checkName,
        String source,
        String issueKey,
        String remediationOwner,
        String severity,
        String failureType,
        boolean customerVisible,
        String readinessScope,
        FinalPromptMetricRule rule,
        FinalPromptMetricRule inputReadinessRule,
        FinalPromptMetricRule applicabilityRule,
        String purposeSignal,
        String meaning,
        String securityRelevance,
        String interpretationLink,
        String qualityQuestion,
        String problemTitle,
        String shortProblem,
        String expectedMessage,
        String passMessage,
        String failureMessage,
        String notApplicableMessage,
        String whyItMatters,
        String nextAction,
        String reverifyCriterion,
        String passEvidenceTemplate,
        String failureEvidenceTemplate,
        List<Map<String, String>> evidenceBindings,
        Map<String, String> valueMappings
) {
}
