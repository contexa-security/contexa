package io.contexa.contexacore.domain.entity;

import org.junit.jupiter.api.Test;

import java.time.LocalDate;
import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;

class OutboxRecordLifecycleTest {

    @Test
    void prePersistPopulatesMissingAuditFieldsAcrossOutboxRecords() {
        SecurityDecisionForwardingOutboxRecord securityDecision = SecurityDecisionForwardingOutboxRecord.builder()
                .correlationId("corr-001")
                .tenantExternalRef("tenant-acme")
                .payloadJson("{}")
                .build();
        securityDecision.prePersist();
        assertInitialized(securityDecision.getStatus(), securityDecision.getAttemptCount(), securityDecision.getCreatedAt(), securityDecision.getUpdatedAt());

        PromptContextAuditForwardingOutboxRecord promptAudit = PromptContextAuditForwardingOutboxRecord.builder()
                .auditId("audit-001")
                .correlationId("corr-001")
                .tenantExternalRef("tenant-acme")
                .payloadJson("{}")
                .build();
        promptAudit.prePersist();
        assertInitialized(promptAudit.getStatus(), promptAudit.getAttemptCount(), promptAudit.getCreatedAt(), promptAudit.getUpdatedAt());

        ThreatOutcomeForwardingOutboxRecord threatOutcome = ThreatOutcomeForwardingOutboxRecord.builder()
                .outcomeId("outcome-001")
                .correlationId("corr-001")
                .tenantExternalRef("tenant-acme")
                .payloadJson("{}")
                .build();
        threatOutcome.prePersist();
        assertInitialized(threatOutcome.getStatus(), threatOutcome.getAttemptCount(), threatOutcome.getCreatedAt(), threatOutcome.getUpdatedAt());

        DecisionFeedbackForwardingOutboxRecord decisionFeedback = DecisionFeedbackForwardingOutboxRecord.builder()
                .feedbackId("feedback-001")
                .correlationId("corr-001")
                .tenantExternalRef("tenant-acme")
                .payloadJson("{}")
                .build();
        decisionFeedback.prePersist();
        assertInitialized(decisionFeedback.getStatus(), decisionFeedback.getAttemptCount(), decisionFeedback.getCreatedAt(), decisionFeedback.getUpdatedAt());

        BaselineSignalOutboxRecord baselineSignal = BaselineSignalOutboxRecord.initialize(LocalDate.of(2026, 3, 30));
        baselineSignal.setCreatedAt(null);
        baselineSignal.setUpdatedAt(null);
        baselineSignal.prePersist();
        assertInitialized(baselineSignal.getStatus(), baselineSignal.getAttemptCount(), baselineSignal.getCreatedAt(), baselineSignal.getUpdatedAt());

        ModelPerformanceTelemetryOutboxRecord telemetry = ModelPerformanceTelemetryOutboxRecord.initialize(LocalDate.of(2026, 3, 30));
        telemetry.setCreatedAt(null);
        telemetry.setUpdatedAt(null);
        telemetry.prePersist();
        assertInitialized(telemetry.getStatus(), telemetry.getAttemptCount(), telemetry.getCreatedAt(), telemetry.getUpdatedAt());
    }

    @Test
    void preUpdateRefreshesUpdatedAtAndStabilizesDefaults() {
        SecurityDecisionForwardingOutboxRecord record = SecurityDecisionForwardingOutboxRecord.builder()
                .correlationId("corr-001")
                .tenantExternalRef("tenant-acme")
                .payloadJson("{}")
                .status(null)
                .attemptCount(null)
                .createdAt(LocalDateTime.now().minusMinutes(5))
                .updatedAt(LocalDateTime.now().minusMinutes(5))
                .build();

        LocalDateTime previousUpdatedAt = record.getUpdatedAt();
        record.preUpdate();

        assertThat(record.getStatus()).isEqualTo(SecurityDecisionForwardingOutboxRecord.STATUS_PENDING);
        assertThat(record.getAttemptCount()).isZero();
        assertThat(record.getUpdatedAt()).isAfter(previousUpdatedAt);
    }

    private void assertInitialized(String status, Integer attemptCount, LocalDateTime createdAt, LocalDateTime updatedAt) {
        assertThat(status).isEqualTo(SecurityDecisionForwardingOutboxRecord.STATUS_PENDING);
        assertThat(attemptCount).isZero();
        assertThat(createdAt).isNotNull();
        assertThat(updatedAt).isNotNull();
    }
}
