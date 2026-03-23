package io.contexa.contexacore.domain.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Entity
@Table(name = "security_decision_forwarding_outbox", indexes = {
        @Index(name = "uk_security_decision_forwarding_outbox_correlation_id", columnList = "correlation_id", unique = true),
        @Index(name = "idx_security_decision_forwarding_outbox_dispatch", columnList = "status,next_attempt_at,created_at")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EntityListeners(AuditingEntityListener.class)
public class SecurityDecisionForwardingOutboxRecord {

    public static final String STATUS_PENDING = "PENDING";
    public static final String STATUS_DISPATCHING = "DISPATCHING";
    public static final String STATUS_DELIVERED = "DELIVERED";
    public static final String STATUS_FAILED = "FAILED";
    public static final String STATUS_DEAD_LETTER = "DEAD_LETTER";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "correlation_id", nullable = false, length = 64)
    private String correlationId;

    @Column(name = "tenant_external_ref", nullable = false, length = 128)
    private String tenantExternalRef;

    @Lob
    @Column(name = "payload_json", nullable = false, columnDefinition = "TEXT")
    private String payloadJson;

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

    private String truncate(String message) {
        if (message == null) {
            return null;
        }
        return message.length() > 2000 ? message.substring(0, 2000) : message;
    }
}
