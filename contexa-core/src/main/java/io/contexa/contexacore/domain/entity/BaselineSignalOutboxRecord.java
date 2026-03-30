package io.contexa.contexacore.domain.entity;

import io.contexa.contexacore.autonomous.saas.dto.BaselineSignalPayload;
import io.contexa.contexacore.utils.JpaMapConverter;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

@Entity
@Table(name = "baseline_signal_outbox", indexes = {
        @Index(name = "uk_baseline_signal_outbox_period", columnList = "period_start", unique = true),
        @Index(name = "idx_baseline_signal_outbox_dispatch", columnList = "status,next_attempt_at,period_start")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EntityListeners(AuditingEntityListener.class)
public class BaselineSignalOutboxRecord {

    public static final String STATUS_PENDING = "PENDING";
    public static final String STATUS_DISPATCHING = "DISPATCHING";
    public static final String STATUS_DELIVERED = "DELIVERED";
    public static final String STATUS_FAILED = "FAILED";
    public static final String STATUS_DEAD_LETTER = "DEAD_LETTER";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "signal_id", nullable = false, length = 64)
    private String signalId;

    @Column(name = "period_start", nullable = false)
    private LocalDate periodStart;

    @Column(name = "industry_category", length = 80)
    private String industryCategory;

    @Column(name = "organization_baseline_count", nullable = false)
    @Builder.Default
    private long organizationBaselineCount = 0L;

    @Column(name = "user_baseline_count", nullable = false)
    @Builder.Default
    private long userBaselineCount = 0L;

    @Convert(converter = JpaMapConverter.class)
    @Lob
    @Column(name = "access_hours_distribution_json", columnDefinition = "TEXT")
    @Builder.Default
    private Map<String, Object> accessHoursDistribution = new LinkedHashMap<>();

    @Convert(converter = JpaMapConverter.class)
    @Lob
    @Column(name = "access_days_distribution_json", columnDefinition = "TEXT")
    @Builder.Default
    private Map<String, Object> accessDaysDistribution = new LinkedHashMap<>();

    @Convert(converter = JpaMapConverter.class)
    @Lob
    @Column(name = "operating_system_distribution_json", columnDefinition = "TEXT")
    @Builder.Default
    private Map<String, Object> operatingSystemDistribution = new LinkedHashMap<>();

    @Column(name = "generated_at")
    private LocalDateTime generatedAt;

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

    @PrePersist
    void prePersist() {
        LocalDateTime now = LocalDateTime.now();
        if (status == null || status.isBlank()) {
            status = STATUS_PENDING;
        }
        if (attemptCount == null) {
            attemptCount = 0;
        }
        if (createdAt == null) {
            createdAt = now;
        }
        if (updatedAt == null) {
            updatedAt = now;
        }
    }

    @PreUpdate
    void preUpdate() {
        if (status == null || status.isBlank()) {
            status = STATUS_PENDING;
        }
        if (attemptCount == null) {
            attemptCount = 0;
        }
        updatedAt = LocalDateTime.now();
    }

    public static BaselineSignalOutboxRecord initialize(LocalDate periodStart) {
        return BaselineSignalOutboxRecord.builder()
                .signalId(periodStart != null ? periodStart.toString() : null)
                .periodStart(periodStart)
                .status(STATUS_PENDING)
                .attemptCount(0)
                .build();
    }

    public void updateSnapshot(
            String industryCategory,
            long organizationBaselineCount,
            long userBaselineCount,
            Map<String, Long> accessHoursDistribution,
            Map<String, Long> accessDaysDistribution,
            Map<String, Long> operatingSystemDistribution,
            LocalDateTime generatedAt) {
        this.industryCategory = industryCategory;
        this.organizationBaselineCount = organizationBaselineCount;
        this.userBaselineCount = userBaselineCount;
        this.accessHoursDistribution = copyDistribution(accessHoursDistribution);
        this.accessDaysDistribution = copyDistribution(accessDaysDistribution);
        this.operatingSystemDistribution = copyDistribution(operatingSystemDistribution);
        this.generatedAt = generatedAt;
        resetDispatchState();
    }

    public BaselineSignalPayload toPayload() {
        return BaselineSignalPayload.builder()
                .signalId(signalId)
                .periodStart(periodStart)
                .industryCategory(industryCategory)
                .organizationBaselineCount(organizationBaselineCount)
                .userBaselineCount(userBaselineCount)
                .accessHoursDistribution(readDistribution(accessHoursDistribution))
                .accessDaysDistribution(readDistribution(accessDaysDistribution))
                .operatingSystemDistribution(readDistribution(operatingSystemDistribution))
                .generatedAt(generatedAt != null ? generatedAt : LocalDateTime.now())
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

    private Map<String, Object> copyDistribution(Map<String, Long> distribution) {
        LinkedHashMap<String, Object> copy = new LinkedHashMap<>();
        if (distribution != null) {
            distribution.forEach(copy::put);
        }
        return copy;
    }

    private Map<String, Long> readDistribution(Map<String, Object> source) {
        LinkedHashMap<String, Long> copy = new LinkedHashMap<>();
        if (source == null || source.isEmpty()) {
            return copy;
        }
        source.forEach((key, value) -> {
            if (key != null && value instanceof Number number) {
                copy.put(key, number.longValue());
            }
        });
        return copy;
    }

    private String truncate(String message) {
        if (message == null) {
            return null;
        }
        return message.length() > 2000 ? message.substring(0, 2000) : message;
    }
}
