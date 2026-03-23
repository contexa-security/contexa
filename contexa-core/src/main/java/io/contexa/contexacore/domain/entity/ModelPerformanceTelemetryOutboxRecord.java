package io.contexa.contexacore.domain.entity;

import io.contexa.contexacore.autonomous.saas.dto.ModelPerformanceTelemetryPayload;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Entity
@Table(name = "model_performance_telemetry_outbox", indexes = {
        @Index(name = "uk_model_performance_telemetry_outbox_period", columnList = "period", unique = true),
        @Index(name = "idx_model_performance_telemetry_outbox_dispatch", columnList = "status,next_attempt_at,period")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EntityListeners(AuditingEntityListener.class)
public class ModelPerformanceTelemetryOutboxRecord {

    public static final String STATUS_PENDING = "PENDING";
    public static final String STATUS_DISPATCHING = "DISPATCHING";
    public static final String STATUS_DELIVERED = "DELIVERED";
    public static final String STATUS_FAILED = "FAILED";
    public static final String STATUS_DEAD_LETTER = "DEAD_LETTER";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "telemetry_id", nullable = false, length = 64)
    private String telemetryId;

    @Column(name = "period", nullable = false)
    private LocalDate period;

    @Column(name = "layer1_sample_count", nullable = false)
    @Builder.Default
    private long layer1SampleCount = 0L;

    @Column(name = "layer1_escalation_count", nullable = false)
    @Builder.Default
    private long layer1EscalationCount = 0L;

    @Column(name = "layer1_processing_total_ms", nullable = false)
    @Builder.Default
    private long layer1ProcessingTotalMs = 0L;

    @Column(name = "layer2_sample_count", nullable = false)
    @Builder.Default
    private long layer2SampleCount = 0L;

    @Column(name = "layer2_processing_total_ms", nullable = false)
    @Builder.Default
    private long layer2ProcessingTotalMs = 0L;

    @Column(name = "block_count", nullable = false)
    @Builder.Default
    private long blockCount = 0L;

    @Column(name = "challenge_count", nullable = false)
    @Builder.Default
    private long challengeCount = 0L;

    @Column(name = "total_event_count", nullable = false)
    @Builder.Default
    private long totalEventCount = 0L;

    @Column(name = "escalate_protection_triggered", nullable = false)
    @Builder.Default
    private int escalateProtectionTriggered = 0;

    @Column(name = "status", nullable = false, length = 32)
    @Builder.Default
    private String status = STATUS_PENDING;

    @Column(name = "attempt_count", nullable = false)
    @Builder.Default
    private Integer attemptCount = 0;

    @Column(name = "next_attempt_at")
    private LocalDateTime nextAttemptAt;

    @Column(name = "last_error", length = 2000)
    private String lastError;

    @Column(name = "delivered_at")
    private LocalDateTime deliveredAt;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    public static ModelPerformanceTelemetryOutboxRecord initialize(LocalDate period) {
        return ModelPerformanceTelemetryOutboxRecord.builder()
                .telemetryId(period != null ? period.toString() : null)
                .period(period)
                .status(STATUS_PENDING)
                .attemptCount(0)
                .build();
    }

    public void recordLayer1(boolean escalated, Long elapsedMs) {
        this.layer1SampleCount++;
        if (escalated) {
            this.layer1EscalationCount++;
        }
        if (elapsedMs != null && elapsedMs > 0L) {
            this.layer1ProcessingTotalMs += elapsedMs;
        }
        resetDispatchState();
    }

    public void recordLayer2(Long elapsedMs) {
        this.layer2SampleCount++;
        if (elapsedMs != null && elapsedMs > 0L) {
            this.layer2ProcessingTotalMs += elapsedMs;
        }
        resetDispatchState();
    }

    public void recordDecision(String action) {
        this.totalEventCount++;
        if (action != null) {
            if ("BLOCK".equalsIgnoreCase(action)) {
                this.blockCount++;
            }
            if ("CHALLENGE".equalsIgnoreCase(action)) {
                this.challengeCount++;
            }
        }
        resetDispatchState();
    }

    public void recordEscalateProtectionTriggered() {
        this.escalateProtectionTriggered++;
        resetDispatchState();
    }

    public ModelPerformanceTelemetryPayload toPayload() {
        return ModelPerformanceTelemetryPayload.builder()
                .telemetryId(telemetryId)
                .period(period)
                .layer1SampleCount(layer1SampleCount)
                .layer1EscalationCount(layer1EscalationCount)
                .layer1EscalationRate(ratio(layer1EscalationCount, layer1SampleCount))
                .layer1AvgProcessingMs(average(layer1ProcessingTotalMs, layer1SampleCount))
                .layer2SampleCount(layer2SampleCount)
                .layer2AvgProcessingMs(average(layer2ProcessingTotalMs, layer2SampleCount))
                .blockCount(blockCount)
                .challengeCount(challengeCount)
                .blockRate(ratio(blockCount, totalEventCount))
                .challengeRate(ratio(challengeCount, totalEventCount))
                .totalEventCount(totalEventCount)
                .escalateProtectionTriggered(escalateProtectionTriggered)
                .generatedAt(LocalDateTime.now())
                .build();
    }

    public void markDispatching() {
        this.status = STATUS_DISPATCHING;
        this.attemptCount = this.attemptCount == null ? 1 : this.attemptCount + 1;
        this.lastError = null;
    }

    public void markDelivered(LocalDateTime deliveredAt) {
        this.status = STATUS_DELIVERED;
        this.deliveredAt = deliveredAt;
        this.nextAttemptAt = null;
        this.lastError = null;
    }

    public void markRetry(String errorMessage, LocalDateTime nextAttemptAt) {
        this.status = STATUS_FAILED;
        this.lastError = truncate(errorMessage);
        this.nextAttemptAt = nextAttemptAt;
    }

    public void markDeadLetter(String errorMessage) {
        this.status = STATUS_DEAD_LETTER;
        this.lastError = truncate(errorMessage);
        this.nextAttemptAt = null;
    }

    private void resetDispatchState() {
        if (STATUS_DELIVERED.equals(this.status) || STATUS_DEAD_LETTER.equals(this.status)) {
            this.status = STATUS_PENDING;
            this.nextAttemptAt = null;
            this.lastError = null;
            this.deliveredAt = null;
            this.attemptCount = 0;
        }
    }

    private long average(long total, long count) {
        if (count <= 0L) {
            return 0L;
        }
        return Math.round((double) total / (double) count);
    }

    private double ratio(long numerator, long denominator) {
        if (denominator <= 0L) {
            return 0.0d;
        }
        return (double) numerator / (double) denominator;
    }

    private String truncate(String message) {
        if (message == null) {
            return null;
        }
        return message.length() > 2000 ? message.substring(0, 2000) : message;
    }
}
