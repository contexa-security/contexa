package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorMetricSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorRunBatch;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.common.PromptQualityMessageResolver;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunAttemptSummary;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunFailureCause;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunMetricSummary;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunPackageListItem;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunPackageSummary;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunRemediationGroup;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

final class OfficialRunOperatorSnapshotMapper {

    private final OfficialRunDetailPresentation presentation;
    private final PromptQualityMessageResolver messageResolver;

    OfficialRunOperatorSnapshotMapper(
            OfficialRunDetailPresentation presentation,
            PromptQualityMessageResolver messageResolver) {
        this.presentation = Objects.requireNonNull(presentation, "presentation");
        this.messageResolver = Objects.requireNonNull(messageResolver, "messageResolver");
    }

    String stateLabel(String state) {
        return presentation.stateLabel(state);
    }

    OfficialRunPackageListItem listItem(OperatorRunBatch batch) {
        return new OfficialRunPackageListItem(
                batch.packageId(), batch.aggregateRunId(), batch.finalDecision(), batch.blocked(),
                batch.blockReasonSummary(), batch.expectedMetricCount(), batch.actualMetricCount(),
                batch.passedMetricCount(), batch.failedMetricCount(), batch.certificateId(), batch.caseId(),
                batch.promptHash(), batch.contextHash(), batch.contextHashState(), batch.templateResourceId(),
                batch.actualResourceId(), batch.resourceUrlTemplate(), batch.actualRequestPath(),
                batch.httpMethod(), batch.createdAt());
    }

    OfficialRunPackageSummary summary(OperatorSnapshot snapshot) {
        OperatorRunBatch batch = snapshot.batch();
        List<OfficialRunFailureCause> failures = failureCauses(snapshot);
        List<OfficialRunRemediationGroup> groups = remediationGroups(snapshot);
        List<String> actions = merge(groupNextActions(groups), nextActions(failures));
        return new OfficialRunPackageSummary(
                batch.packageId(), batch.aggregateRunId(), batch.finalDecision(), batch.blocked(),
                batch.blockReasonSummary(), batch.expectedMetricCount(), batch.actualMetricCount(),
                batch.passedMetricCount(), batch.failedMetricCount(), batch.certificateId(), batch.caseId(),
                batch.finalDecision(), presentation.stateLabel(batch.finalDecision()),
                StringUtils.hasText(batch.certificateId()) && !batch.blocked(), batch.blockReasonSummary(),
                batch.promptHash(), batch.contextHash(), batch.contextHashState(), batch.templateResourceId(),
                batch.actualResourceId(), batch.resourceUrlTemplate(), batch.actualRequestPath(), batch.httpMethod(),
                batch.createdAt(),
                snapshot.metrics().stream().filter(Objects::nonNull).map(this::metricSummary).toList(),
                failures, actions, null, groups,
                List.of(new OfficialRunAttemptSummary(
                        batch.aggregateRunId(), batch.packageId(), 1,
                        batch.createdAt() == null ? "" : batch.createdAt().toString(),
                        batch.createdAt() == null ? "" : batch.createdAt().toString(),
                        batch.actualMetricCount(), batch.passedMetricCount(), batch.failedMetricCount(),
                        batch.finalDecision(), presentation.stateLabel(batch.finalDecision()), true)));
    }

    List<OfficialRunFailureCause> failureCauses(OperatorSnapshot snapshot) {
        if (snapshot == null || !snapshot.available()) {
            return List.of();
        }
        Map<String, OperatorMetricSnapshot> metricsByCode = snapshot.metrics().stream()
                .filter(Objects::nonNull)
                .collect(Collectors.toMap(
                        metric -> normalize(metric.metricCode()), metric -> metric, (left, right) -> left,
                        LinkedHashMap::new));
        List<OfficialRunFailureCause> findingFailures = snapshot.findings().stream()
                .filter(Objects::nonNull)
                .map(finding -> {
                    OperatorMetricSnapshot metric = metricsByCode.get(normalize(finding.metricCode()));
                    return new OfficialRunFailureCause(
                            normalize(finding.metricCode()),
                            metric == null ? finding.metricCode() : metric.metricName(),
                            finding.officialRunId(), finding.checkCode(),
                            firstNonBlank(finding.operatorTitle(), finding.checkCode()),
                            firstNonBlank(finding.expectedResult(), finding.expectedValue()),
                            firstNonBlank(finding.actualResult(), finding.actualValue()),
                            firstNonBlank(finding.evidencePath(), "official_verification_operator_finding"),
                            firstNonBlank(finding.remediationOwner(), finding.affectedTarget()),
                            firstNonBlank(finding.problemStatement(), finding.operatorReason(), finding.operatorTitle()),
                            firstNonBlank(finding.rootCause(), finding.operatorReason(), finding.evidenceSummary()),
                            firstNonBlank(finding.affectedTarget(), finding.remediationOwner()),
                            firstNonBlank(finding.impact(), finding.operatorSummary(), finding.evidenceSummary()),
                            finding.nextAction(), finding.reverifyCriterion(), finding.issueId(), finding.findingId(), null);
                })
                .toList();
        Set<String> findingMetricCodes = findingFailures.stream()
                .map(cause -> normalize(cause.metricCode()))
                .filter(StringUtils::hasText)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        List<OfficialRunFailureCause> snapshotFailures = snapshot.metrics().stream()
                .filter(Objects::nonNull)
                .filter(metric -> failedState(metric.state()))
                .filter(metric -> !findingMetricCodes.contains(normalize(metric.metricCode())))
                .map(this::metricFailureCause)
                .toList();
        if (findingFailures.isEmpty()) {
            return snapshotFailures;
        }
        if (snapshotFailures.isEmpty()) {
            return findingFailures;
        }
        List<OfficialRunFailureCause> merged = new ArrayList<>(findingFailures.size() + snapshotFailures.size());
        merged.addAll(findingFailures);
        merged.addAll(snapshotFailures);
        return List.copyOf(merged);
    }

    List<OfficialRunRemediationGroup> remediationGroups(OperatorSnapshot snapshot) {
        if (snapshot == null || !snapshot.available() || snapshot.remediationGroups().isEmpty()) {
            return List.of();
        }
        return snapshot.remediationGroups().stream()
                .filter(Objects::nonNull)
                .map(group -> new OfficialRunRemediationGroup(
                        group.groupId(), group.rootCauseKey(), group.remediationOwner(), group.operatorTitle(),
                        group.operatorReason(), group.nextAction(), group.reverifyCriterion(),
                        group.affectedMetricCodes(), group.affectedCheckCodes(), group.findingCount(),
                        group.relatedProcessStep()))
                .toList();
    }

    List<String> groupNextActions(List<OfficialRunRemediationGroup> groups) {
        if (groups == null || groups.isEmpty()) {
            return List.of();
        }
        return groups.stream()
                .filter(Objects::nonNull)
                .map(OfficialRunRemediationGroup::nextAction)
                .filter(StringUtils::hasText)
                .distinct()
                .limit(5)
                .toList();
    }

    List<String> nextActions(List<OfficialRunFailureCause> failures) {
        if (failures == null || failures.isEmpty()) {
            return List.of();
        }
        return failures.stream()
                .map(OfficialRunFailureCause::remediationHint)
                .filter(StringUtils::hasText)
                .distinct()
                .limit(5)
                .toList();
    }

    List<String> merge(List<String> left, List<String> right) {
        List<String> result = new ArrayList<>();
        appendDistinct(result, left);
        appendDistinct(result, right);
        return List.copyOf(result);
    }

    private OfficialRunMetricSummary metricSummary(OperatorMetricSnapshot metric) {
        return new OfficialRunMetricSummary(
                metric.metricCode(), metric.metricName(), metric.metricGroup(), metric.score(), metric.state(),
                metric.severity(), metric.passedChecks(), metric.totalChecks(), metric.failedCheckCount(),
                metric.operatorTitle(), metric.operatorSummary(), metric.primaryFailureReason(),
                metric.remediationOwner(), metric.nextAction(), metric.reverifyCriterion(),
                metric.officialRunId(), metric.createdAt());
    }

    private OfficialRunFailureCause metricFailureCause(OperatorMetricSnapshot metric) {
        String state = normalize(metric.state());
        String stateLabel = presentation.stateLabel(metric.state());
        String reason = firstNonBlank(
                metric.primaryFailureReason(), metric.operatorSummary(),
                message("enterprise.pqa.officialRun.metricFallback.notPassed"));
        String action = firstNonBlank(
                metric.nextAction(), message("enterprise.pqa.officialRun.metricFallback.nextAction"));
        String reverify = firstNonBlank(
                metric.reverifyCriterion(), message("enterprise.pqa.officialRun.metricFallback.reverify"));
        return new OfficialRunFailureCause(
                normalize(metric.metricCode()), firstNonBlank(metric.metricName(), metric.metricCode()),
                metric.officialRunId(), normalize(metric.metricCode()) + "-" + state.toLowerCase(Locale.ROOT),
                firstNonBlank(metric.operatorTitle(), metric.metricName(), metric.metricCode()),
                message("enterprise.pqa.officialRun.metricFallback.expectedPassed"),
                stateLabel + " (" + state + ")", "official_verification_metric_snapshot.state",
                firstNonBlank(metric.remediationOwner(), "PQA_RUNTIME"),
                firstNonBlank(metric.operatorSummary(), metric.operatorTitle(), metric.metricName(),
                        message("enterprise.pqa.officialRun.metricFallback.problemReview")),
                reason, firstNonBlank(metric.remediationOwner(), metric.metricGroup(), "PQA_RUNTIME"),
                reason, action, reverify);
    }

    private void appendDistinct(List<String> target, List<String> source) {
        if (source == null) {
            return;
        }
        for (String item : source) {
            if (StringUtils.hasText(item) && !target.contains(item.trim())) {
                target.add(item.trim());
            }
        }
    }

    private boolean failedState(String state) {
        String normalized = normalize(state);
        return StringUtils.hasText(normalized)
                && !Set.of("SUCCESS", "PASS", "PASSED", "NOT_APPLICABLE", "NOT_APPLICABLE_METRIC").contains(normalized);
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

    private String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private String message(String key, Object... args) {
        String resolved = messageResolver.resolve(key, args);
        if (!StringUtils.hasText(resolved) || key.equals(resolved)) {
            throw new IllegalStateException("Missing prompt-quality message key: " + key);
        }
        return resolved;
    }
}