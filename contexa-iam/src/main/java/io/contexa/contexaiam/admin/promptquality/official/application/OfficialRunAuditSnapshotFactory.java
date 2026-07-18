package io.contexa.contexaiam.admin.promptquality.official.application;

import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorAuditSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.application.OfficialVerificationOperatorSnapshotService.OperatorSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.domain.PromptQualityAssuranceCase;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunAuditSnapshot;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialRunFailureCause;
import io.contexa.contexaiam.admin.promptquality.official.model.OfficialVerificationMetricTrace;
import io.contexa.contexaiam.admin.promptquality.official.model.RuntimeEvidencePackageDetail;
import io.contexa.contexaiam.admin.promptquality.official.process.PromptQualityProcessEventSnapshot;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

final class OfficialRunAuditSnapshotFactory {

    private final OfficialRunDetailPresentation presentation;

    OfficialRunAuditSnapshotFactory(OfficialRunDetailPresentation presentation) {
        this.presentation = Objects.requireNonNull(presentation, "presentation");
    }

    List<OfficialRunAuditSnapshot> snapshots(
            String packageId,
            String aggregateRunId,
            List<OfficialVerificationMetricTrace> runs,
            RuntimeEvidencePackageDetail sealedEvidence,
            PromptQualityAssuranceCase assuranceCase,
            List<OfficialRunFailureCause> failureCauses,
            List<String> nextActions,
            List<PromptQualityProcessEventSnapshot> processEvents,
            OperatorSnapshot operatorSnapshot) {
        if (!StringUtils.hasText(packageId)) {
            return List.of();
        }
        if (operatorSnapshot != null && operatorSnapshot.available()
                && operatorSnapshot.auditSnapshots() != null
                && !operatorSnapshot.auditSnapshots().isEmpty()) {
            return operatorSnapshot.auditSnapshots().stream().map(this::storedSnapshot).toList();
        }
        boolean persisted = processEvents != null && processEvents.stream()
                .filter(event -> event != null && "OFFICIAL_VERIFICATION_AUDIT_SNAPSHOT".equalsIgnoreCase(clean(event.type())))
                .anyMatch(event -> !StringUtils.hasText(aggregateRunId) || clean(event.payloadJson()).contains(aggregateRunId));
        boolean snapshotAvailable = operatorSnapshot != null && operatorSnapshot.available();
        String state = snapshotAvailable && StringUtils.hasText(operatorSnapshot.batch().finalDecision())
                ? operatorSnapshot.batch().finalDecision()
                : ((failureCauses == null || failureCauses.isEmpty()) ? "SUCCESS" : "BLOCKED");
        String promptHash = sealedEvidence == null || sealedEvidence.summary() == null ? "" : sealedEvidence.summary().promptHash();
        String contextHash = sealedEvidence == null ? "" : fact(sealedEvidence.promptMetadata(), "contextHash");
        int failed = snapshotAvailable ? operatorSnapshot.batch().failedMetricCount() : (failureCauses == null ? 0 : failureCauses.size());
        int total = snapshotAvailable ? operatorSnapshot.batch().actualMetricCount() : (runs == null ? 0 : runs.size());
        Map<String, Object> payload = payload(
                packageId, aggregateRunId, assuranceCase, state, total, failed,
                promptHash, contextHash, snapshotAvailable, operatorSnapshot);
        return List.of(new OfficialRunAuditSnapshot(
                "pqa-audit-" + packageId + "-" + valueOrEmpty(aggregateRunId),
                packageId,
                aggregateRunId,
                Instant.now().toString(),
                state,
                presentation.stateLabel(state),
                total,
                failed,
                snapshotAvailable && StringUtils.hasText(operatorSnapshot.batch().certificateId()) && !operatorSnapshot.batch().blocked(),
                firstNonBlank(snapshotAvailable ? operatorSnapshot.batch().certificateId() : null, ""),
                firstNonBlank(assuranceCase == null ? null : assuranceCase.caseId(), snapshotAvailable ? operatorSnapshot.batch().caseId() : null),
                promptHash,
                contextHash,
                List.of(),
                List.of(),
                persisted,
                jsonPayload(payload)));
    }

    OfficialRunAuditSnapshot storedSnapshot(OperatorAuditSnapshot snapshot) {
        return new OfficialRunAuditSnapshot(
                valueOrEmpty(snapshot.snapshotId()),
                valueOrEmpty(snapshot.packageId()),
                valueOrEmpty(snapshot.aggregateRunId()),
                snapshot.createdAt() == null ? "" : snapshot.createdAt().toString(),
                valueOrEmpty(snapshot.state()),
                firstNonBlank(snapshot.stateLabel(), presentation.stateLabel(snapshot.state())),
                snapshot.totalMetricCount(),
                snapshot.failedMetricCount(),
                snapshot.certificateIssued(),
                valueOrEmpty(snapshot.certificateId()),
                valueOrEmpty(snapshot.caseId()),
                valueOrEmpty(snapshot.promptHash()),
                valueOrEmpty(snapshot.contextHash()),
                snapshot.blockingFindings(),
                snapshot.nextActions(),
                true,
                firstNonBlank(snapshot.payloadJson(), "{}"));
    }

    private Map<String, Object> payload(
            String packageId,
            String aggregateRunId,
            PromptQualityAssuranceCase assuranceCase,
            String state,
            int total,
            int failed,
            String promptHash,
            String contextHash,
            boolean snapshotAvailable,
            OperatorSnapshot operatorSnapshot) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("packageId", valueOrEmpty(packageId));
        payload.put("aggregateRunId", valueOrEmpty(aggregateRunId));
        payload.put("certificateId", firstNonBlank(snapshotAvailable ? operatorSnapshot.batch().certificateId() : null, ""));
        payload.put("caseId", firstNonBlank(
                assuranceCase == null ? null : assuranceCase.caseId(),
                snapshotAvailable ? operatorSnapshot.batch().caseId() : null,
                ""));
        payload.put("state", valueOrEmpty(state));
        payload.put("totalMetricCount", total);
        payload.put("failedMetricCount", failed);
        payload.put("promptHash", valueOrEmpty(promptHash));
        payload.put("contextHash", valueOrEmpty(contextHash));
        payload.put("operatorSnapshotAvailable", snapshotAvailable);
        if (snapshotAvailable) {
            payload.put("expectedMetricCount", operatorSnapshot.batch().expectedMetricCount());
            payload.put("finalDecision", operatorSnapshot.batch().finalDecision());
            payload.put("blockReasonSummary", valueOrEmpty(operatorSnapshot.batch().blockReasonSummary()));
            payload.put("findings", operatorSnapshot.findings().stream()
                    .map(finding -> Map.of(
                            "findingId", valueOrEmpty(finding.findingId()),
                            "metricCode", valueOrEmpty(finding.metricCode()),
                            "checkCode", valueOrEmpty(finding.checkCode()),
                            "issueId", valueOrEmpty(finding.issueId()),
                            "reason", valueOrEmpty(firstNonBlank(finding.operatorReason(), finding.evidenceSummary()))))
                    .toList());
            payload.put("remediationGroups", operatorSnapshot.remediationGroups().stream()
                    .map(group -> Map.of(
                            "groupId", valueOrEmpty(group.groupId()),
                            "owner", valueOrEmpty(group.remediationOwner()),
                            "rootCause", valueOrEmpty(group.rootCauseKey()),
                            "metrics", valueOrEmpty(String.join(",", group.affectedMetricCodes())),
                            "checks", valueOrEmpty(String.join(",", group.affectedCheckCodes()))))
                    .toList());
        }
        return payload;
    }

    private String jsonPayload(Map<String, Object> payload) {
        if (payload == null || payload.isEmpty()) {
            return "{}";
        }
        return payload.entrySet().stream()
                .map(entry -> "\"" + jsonEscape(entry.getKey()) + "\":\"" + jsonEscape(String.valueOf(entry.getValue())) + "\"")
                .collect(Collectors.joining(",", "{", "}"));
    }

    private String jsonEscape(String value) {
        return valueOrEmpty(value).replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private String fact(Map<?, ?> raw, String key) {
        return raw == null || raw.get(key) == null ? "" : String.valueOf(raw.get(key));
    }

    private String valueOrEmpty(String value) {
        return StringUtils.hasText(value) ? value.trim() : "";
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

    private String clean(String value) {
        return value == null ? "" : value.trim();
    }
}