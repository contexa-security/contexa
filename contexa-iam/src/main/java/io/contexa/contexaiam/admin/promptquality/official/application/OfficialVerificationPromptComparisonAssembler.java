package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexacore.verification.evidence.SealedEvidencePackage;
import io.contexa.contexacore.verification.runtime.OfficialVerificationCheckResultView;
import io.contexa.contexacore.verification.runtime.OfficialVerificationRunView;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationPromptComparison;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

public final class OfficialVerificationPromptComparisonAssembler {

    private final SealedPromptEvidenceComparisonAssembler sealedEvidenceAssembler;
    private final PromptComparisonValueInterpreter values;
    private final PromptQualityMessageResolver messageResolver;

    public OfficialVerificationPromptComparisonAssembler(
            SealedPromptEvidenceComparisonAssembler sealedEvidenceAssembler,
            PromptComparisonValueInterpreter values,
            PromptQualityMessageResolver messageResolver) {
        this.sealedEvidenceAssembler = Objects.requireNonNull(sealedEvidenceAssembler, "sealedEvidenceAssembler");
        this.values = Objects.requireNonNull(values, "values");
        this.messageResolver = Objects.requireNonNull(messageResolver, "messageResolver");
    }

    public List<OfficialVerificationPromptComparison> assemble(
            SealedEvidencePackage evidencePackage,
            List<? extends OfficialVerificationRunView> runs) {
        List<OfficialVerificationPromptComparison> metricComparisons = metricComparisons(runs);
        List<OfficialVerificationPromptComparison> manifestComparisons =
                sealedEvidenceAssembler.assemble(evidencePackage);
        if (metricComparisons.isEmpty() && manifestComparisons.isEmpty()) {
            return List.of();
        }
        Map<String, OfficialVerificationPromptComparison> comparisons = new LinkedHashMap<>();
        for (OfficialVerificationPromptComparison comparison : manifestComparisons) {
            if (comparison != null && StringUtils.hasText(comparison.fieldKey())) {
                comparisons.put(values.dedupeKey(comparison.fieldKey(), comparison.state()), comparison);
            }
        }
        for (OfficialVerificationPromptComparison comparison : metricComparisons) {
            if (comparison != null && StringUtils.hasText(comparison.fieldKey())) {
                comparisons.merge(
                        values.dedupeKey(comparison.fieldKey(), comparison.state()),
                        comparison,
                        this::merge);
            }
        }
        return List.copyOf(comparisons.values());
    }

    private List<OfficialVerificationPromptComparison> metricComparisons(
            List<? extends OfficialVerificationRunView> runs) {
        if (runs == null || runs.isEmpty()) {
            return List.of();
        }
        Map<String, OfficialVerificationPromptComparison> comparisons = new LinkedHashMap<>();
        for (OfficialVerificationRunView run : runs) {
            if (run == null) {
                continue;
            }
            String metricCode = normalized(run.endpointKey());
            if (OfficialVerificationMetricClassifier.internalGateMetric(metricCode)) {
                continue;
            }
            for (OfficialVerificationCheckResultView check : run.checks() == null
                    ? List.<OfficialVerificationCheckResultView>of()
                    : run.checks()) {
                if (!eligibleFailedCheck(check)) {
                    continue;
                }
                OfficialVerificationPromptComparison comparison = comparison(metricCode, check);
                comparisons.merge(
                        values.dedupeKey(comparison.fieldKey(), comparison.state()),
                        comparison,
                        this::merge);
            }
        }
        return List.copyOf(comparisons.values());
    }

    private boolean eligibleFailedCheck(OfficialVerificationCheckResultView check) {
        return check != null
                && !check.pass()
                && !OfficialVerificationMetricClassifier.finalPromptInputNotReady(check)
                && OfficialVerificationMetricClassifier.customerPromptQualityCheck(check);
    }

    private OfficialVerificationPromptComparison comparison(
            String metricCode,
            OfficialVerificationCheckResultView check) {
        String fieldKey = fieldKey(metricCode, check);
        String state = state(check);
        return new OfficialVerificationPromptComparison(
                fieldKey,
                firstNonBlank(check.label(), fieldKey),
                firstNonBlank(check.expectedValue(), ""),
                firstNonBlank(check.actualValue(), ""),
                firstNonBlank(check.expectedValue(), ""),
                state,
                values.stateLabel(state),
                firstNonBlank(check.operatorReason(), check.actualValue(), check.label()),
                StringUtils.hasText(metricCode) ? List.of(metricCode) : List.of(),
                List.of(firstNonBlank(check.checkCode(), fieldKey)),
                List.of(), List.of(), List.of(),
                firstNonBlank(check.source(), "finalUserPrompt"),
                "sealedEvidence.userPromptText",
                firstNonBlank(check.remediationOwner(), remediationOwner(metricCode)),
                "FINAL_USER_PROMPT_METRIC_CHECK");
    }

    private OfficialVerificationPromptComparison merge(
            OfficialVerificationPromptComparison existing,
            OfficialVerificationPromptComparison incoming) {
        if (existing == null) {
            return incoming;
        }
        if (incoming == null) {
            return existing;
        }
        return new OfficialVerificationPromptComparison(
                firstNonBlank(existing.fieldKey(), incoming.fieldKey()),
                firstNonBlank(existing.fieldLabel(), incoming.fieldLabel()),
                firstNonBlank(existing.sealedEvidenceValue(), incoming.sealedEvidenceValue()),
                firstNonBlank(existing.promptValue(), incoming.promptValue()),
                firstNonBlank(existing.officialFactValue(), incoming.officialFactValue()),
                firstNonBlank(existing.state(), incoming.state()),
                firstNonBlank(existing.stateLabel(), incoming.stateLabel()),
                firstNonBlank(existing.meaning(), incoming.meaning()),
                union(existing.metricCodes(), incoming.metricCodes()),
                union(existing.checkCodes(), incoming.checkCodes()),
                union(existing.findingIds(), incoming.findingIds()),
                union(existing.issueIds(), incoming.issueIds()),
                union(existing.remediationGroupIds(), incoming.remediationGroupIds()),
                firstNonBlank(existing.promptLocation(), incoming.promptLocation()),
                firstNonBlank(existing.evidenceSource(), incoming.evidenceSource()),
                firstNonBlank(existing.recommendedOwner(), incoming.recommendedOwner()),
                firstNonBlank(existing.canonicalSource(), incoming.canonicalSource()));
    }

    private String fieldKey(String metricCode, OfficialVerificationCheckResultView check) {
        String source = safe(check == null ? null : check.source());
        if (source.startsWith("finalUserPrompt") || source.startsWith("finalSystemPrompt")) {
            return source;
        }
        throw new IllegalStateException(message("enterprise.pqa.diagnostic.finalPromptFailed")
                + "metricCode=" + safe(metricCode)
                + ", checkCode=" + safe(check == null ? null : check.checkCode())
                + ", source=" + source);
    }

    private String state(OfficialVerificationCheckResultView check) {
        if (OfficialVerificationMetricClassifier.finalPromptInputNotReady(check)) {
            return "INPUT_NOT_READY";
        }
        String failureType = firstNonBlank(check == null ? null : check.failureType(), "");
        if ("INPUT_NOT_READY".equalsIgnoreCase(failureType)) {
            return "PROMPT_PURPOSE_NOT_SATISFIED";
        }
        String purpose = firstNonBlank(check == null ? null : check.purposeResult(), "");
        if ("NOT_EVALUATED_INPUT_NOT_READY".equalsIgnoreCase(purpose)
                || "INPUT_NOT_READY".equalsIgnoreCase(purpose)) {
            return "INPUT_NOT_READY";
        }
        return firstNonBlank(failureType, purpose, "CONTRACT_MISMATCH");
    }

    private String remediationOwner(String metricCode) {
        return switch (normalized(metricCode)) {
            case "BMA", "USNS" -> message("enterprise.pqa.diagnostic.learningBaselineProducer");
            case "BSR" -> message("enterprise.pqa.diagnostic.behavioralContextProducer");
            case "COR", "RAP" -> message("enterprise.pqa.diagnostic.ragPermissionFilter");
            case "PFR", "MTR" -> message("enterprise.pqa.diagnostic.promptCapturer");
            case "PRE" -> message("enterprise.pqa.diagnostic.protectedResourceRegistrar");
            case "RPI" -> message("enterprise.pqa.diagnostic.reverificationProcess");
            case "EIR", "CCR", "CCSR" -> message("enterprise.pqa.diagnostic.contextAssembler");
            default -> message("enterprise.pqa.diagnostic.officialVerification");
        };
    }

    private List<String> union(List<String> left, List<String> right) {
        List<String> result = new ArrayList<>();
        for (String value : left == null ? List.<String>of() : left) {
            if (StringUtils.hasText(value) && !result.contains(value.trim())) {
                result.add(value.trim());
            }
        }
        for (String value : right == null ? List.<String>of() : right) {
            if (StringUtils.hasText(value) && !result.contains(value.trim())) {
                result.add(value.trim());
            }
        }
        return List.copyOf(result);
    }

    private String message(String key, Object... args) {
        String resolved = messageResolver.resolve(key, args);
        if (!StringUtils.hasText(resolved) || key.equals(resolved)) {
            throw new IllegalStateException("Missing prompt-quality message key: " + key);
        }
        return resolved;
    }

    private String firstNonBlank(String... values) {
        if (values != null) {
            for (String value : values) {
                if (StringUtils.hasText(value)) {
                    return value.trim();
                }
            }
        }
        return "";
    }

    private String normalized(String value) {
        return safe(value).toUpperCase(Locale.ROOT);
    }

    private String safe(String value) {
        return StringUtils.hasText(value) ? value.trim() : "";
    }
}