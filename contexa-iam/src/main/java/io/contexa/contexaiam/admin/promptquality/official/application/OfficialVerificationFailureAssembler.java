package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunFailureCause;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceCheckResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidenceMetricResult;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePromptConsistencyResult;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public final class OfficialVerificationFailureAssembler {

    private final PromptQualityMessageResolver messageResolver;

    public OfficialVerificationFailureAssembler(PromptQualityMessageResolver messageResolver) {
        this.messageResolver = Objects.requireNonNull(messageResolver, "messageResolver");
    }

    public List<OfficialRunFailureCause> failureCauses(List<RuntimeEvidenceMetricResult> metrics) {
        if (metrics == null || metrics.isEmpty()) {
            return List.of();
        }
        List<OfficialRunFailureCause> result = new ArrayList<>();
        for (RuntimeEvidenceMetricResult metric : metrics) {
            if (metric == null || metric.checks() == null) {
                continue;
            }
            for (RuntimeEvidenceCheckResult check : metric.checks()) {
                if (check == null
                        || check.pass()
                        || OfficialVerificationMetricClassifier.runtimeInputNotReady(check)
                        || !OfficialVerificationMetricClassifier.customerPromptQualityCheck(check)) {
                    continue;
                }
                result.add(toFailureCause(metric, check));
            }
        }
        return List.copyOf(result);
    }

    public List<RuntimeEvidenceMetricResult> issueMetrics(
            List<RuntimeEvidenceMetricResult> officialMetrics,
            RuntimeEvidencePromptConsistencyResult promptConsistency) {
        if (promptConsistency == null || promptConsistency.passed()) {
            return officialMetrics;
        }
        List<RuntimeEvidenceMetricResult> result = new ArrayList<>(
                officialMetrics == null ? List.of() : officialMetrics);
        result.add(new RuntimeEvidenceMetricResult(
                DefaultRuntimeEvidencePromptConsistencyGate.ISSUE_METRIC_CODE,
                null,
                message("enterprise.pqa.promptConsistency.metricName"),
                message("enterprise.pqa.promptConsistency.metricGroup"),
                0.0d,
                promptConsistency.state(),
                promptConsistency.stateLabel(),
                (int) promptConsistency.checks().stream().filter(RuntimeEvidenceCheckResult::pass).count(),
                promptConsistency.checks().size(),
                promptConsistency.checks()));
        return List.copyOf(result);
    }

    private OfficialRunFailureCause toFailureCause(
            RuntimeEvidenceMetricResult metric,
            RuntimeEvidenceCheckResult check) {
        return new OfficialRunFailureCause(
                metric.metricCode(),
                metric.metricName(),
                metric.officialRunId(),
                check.checkCode(),
                check.label(),
                check.expectedValue(),
                check.actualValue(),
                check.source(),
                check.remediationOwner(),
                StringUtils.hasText(check.operatorReason())
                        ? check.operatorReason()
                        : message(
                                "enterprise.pqa.runtimeVerification.failure.rootCauseTpl",
                                check.label(),
                                check.expectedValue(),
                                check.actualValue()),
                StringUtils.hasText(check.nextAction())
                        ? check.nextAction()
                        : message("enterprise.pqa.runtimeVerification.failure.remediation"),
                StringUtils.hasText(check.reverifyCriterion())
                        ? check.reverifyCriterion()
                        : check.label());
    }

    private String message(String key, Object... args) {
        String resolved = messageResolver.resolve(key, args);
        if (!StringUtils.hasText(resolved) || key.equals(resolved)) {
            throw new IllegalStateException("Missing prompt-quality message key: " + key);
        }
        return resolved;
    }
}