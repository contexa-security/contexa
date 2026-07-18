package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityCustomerSentencePolicy;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialActualPromptProblem;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

final class OfficialActualPromptProblemNarrative {

    private final OfficialPromptEvidenceFormatter evidenceFormatter;

    OfficialActualPromptProblemNarrative(OfficialPromptEvidenceFormatter evidenceFormatter) {
        this.evidenceFormatter = evidenceFormatter;
    }

    String problemId(String packageId, String fieldKey, String state) {
        String seed = safe(packageId) + "|" + safe(fieldKey) + "|" + safe(state);
        return "app-" + UUID.nameUUIDFromBytes(seed.getBytes(StandardCharsets.UTF_8));
    }

    List<String> normalizeMetricCodes(List<String> metricCodes) {
        List<String> result = new ArrayList<>();
        for (String metricCode : metricCodes == null ? List.<String>of() : metricCodes) {
            String normalized = normalize(metricCode);
            if (StringUtils.hasText(normalized) && !result.contains(normalized)) {
                result.add(normalized);
            }
        }
        return List.copyOf(result);
    }

    String title(OfficialActualPromptProblem problem) {
        return requiredText(problem, "prompt_label", problem == null ? null : problem.promptLabel());
    }

    String summary(OfficialActualPromptProblem problem) {
        return customerText(problem, "prompt_value", problem == null ? null : problem.promptValue());
    }

    String firstReason(List<OfficialActualPromptProblem> problems) {
        return problems == null || problems.isEmpty() ? "" : summary(problems.get(0));
    }

    String statement(OfficialActualPromptProblem problem) {
        return summary(problem);
    }

    String rootCause(OfficialActualPromptProblem problem) {
        return requiredText(problem, "why_it_matters", problem == null ? null : problem.whyItMatters());
    }

    String evidence(OfficialActualPromptProblem problem) {
        return customerText(problem, "actual_state", problem == null ? null : problem.actualState());
    }

    String expectedResult(OfficialActualPromptProblem problem) {
        return customerText(problem, "expected_state", problem == null ? null : problem.expectedState());
    }

    String actualResult(OfficialActualPromptProblem problem) {
        return summary(problem);
    }

    String action(OfficialActualPromptProblem problem) {
        return requiredText(problem, "fix_action", problem == null ? null : problem.fixAction());
    }

    String reverify(OfficialActualPromptProblem problem) {
        return requiredText(problem, "reverify_criterion_detail",
                problem == null ? null : problem.reverifyCriterionDetail());
    }

    String displayValue(String value) {
        return evidenceFormatter.displayValue(value);
    }

    String severityLabel(String severity) {
        return "BLOCKING".equals(normalize(severity))
                ? message("enterprise.pqa.runtimeVerification.problem.severity.blocking")
                : message("enterprise.pqa.runtimeVerification.problem.severity.review");
    }

    String processStep(OfficialActualPromptProblem problem) {
        String owner = normalize(problem == null ? null : problem.remediationOwner());
        if (owner.contains("PROMPT")) {
            return "PROMPT_GOVERNANCE";
        }
        if (owner.contains("BASELINE") || owner.contains("LEARNING")) {
            return "ISSUE_REMEDIATION";
        }
        return "OFFICIAL_VERIFICATION";
    }

    private String requiredText(OfficialActualPromptProblem problem, String fieldName, String value) {
        if (problem == null || !StringUtils.hasText(value)) {
            throw new IllegalStateException("ENGINE_CONTRACT_ERROR: Actual final userPrompt problem is missing contract text. "
                    + "field=" + fieldName
                    + ", problemId=" + safe(problem == null ? null : problem.problemId())
                    + ", fieldKey=" + safe(problem == null ? null : problem.fieldKey()));
        }
        return value.trim();
    }

    private String customerText(OfficialActualPromptProblem problem, String fieldName, String value) {
        String raw = requiredText(problem, fieldName, value);
        if (PromptQualityCustomerSentencePolicy.isCustomerSentence(raw)) {
            return raw;
        }
        String converted = customerEvidenceSentence(problem, raw);
        if (PromptQualityCustomerSentencePolicy.isCustomerSentence(converted)) {
            return converted;
        }
        String subject = firstNonBlank(
                problem.promptLabel(),
                problem.fieldKey(),
                message("enterprise.pqa.runtimeVerification.problem.promptItem"));
        return message(
                "enterprise.pqa.runtimeVerification.problem.customerSentenceRequired",
                subject);
    }

    private String customerEvidenceSentence(OfficialActualPromptProblem problem, String rawEvidence) {
        List<String> fragments = evidenceFormatter.evidenceFragments(rawEvidence);
        String subject = firstNonBlank(
                problem.promptLabel(),
                problem.fieldKey(),
                message("enterprise.pqa.runtimeVerification.problem.promptItem"));
        return fragments.isEmpty()
                ? message(
                        "enterprise.pqa.runtimeVerification.problem.customerSentenceRequired",
                        subject)
                : message(
                        "enterprise.pqa.runtimeVerification.problem.evidenceSentence",
                        subject,
                        evidenceFormatter.joinFragments(fragments));
    }

    String message(String key, Object... args) {
        return evidenceFormatter.message(key, args);
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (StringUtils.hasText(value)) {
                return value.trim();
            }
        }
        return "";
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private String safe(String value) {
        return value == null ? "" : value.trim();
    }
}
