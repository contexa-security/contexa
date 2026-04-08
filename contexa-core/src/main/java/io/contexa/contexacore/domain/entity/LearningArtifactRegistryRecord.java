package io.contexa.contexacore.domain.entity;

import io.contexa.contexacore.utils.JpaListConverter;
import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(name = "learning_artifact_registry", indexes = {
        @Index(name = "uk_learning_artifact_registry_identity", columnList = "tenant_id, artifact_type, artifact_key", unique = true),
        @Index(name = "idx_learning_artifact_registry_tenant_updated", columnList = "tenant_id, updated_at"),
        @Index(name = "idx_learning_artifact_registry_artifact_updated", columnList = "artifact_type, artifact_key, updated_at")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EntityListeners(AuditingEntityListener.class)
public class LearningArtifactRegistryRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "tenant_id", nullable = false, length = 120)
    private String tenantId;

    @Column(name = "artifact_type", nullable = false, length = 64)
    private String artifactType;

    @Column(name = "artifact_key", nullable = false, length = 255)
    private String artifactKey;

    @Column(name = "artifact_version", length = 160)
    private String artifactVersion;

    @Column(name = "release_state", nullable = false, length = 64)
    private String releaseState;

    @Column(name = "policy_state", length = 128)
    private String policyState;

    @Column(name = "latest_event_type", nullable = false, length = 64)
    private String latestEventType;

    @Column(name = "kill_switch_active", nullable = false)
    @Builder.Default
    private boolean killSwitchActive = false;

    @Column(name = "runtime_eligible", nullable = false)
    @Builder.Default
    private boolean runtimeEligible = false;

    @Column(name = "runtime_suppressed", nullable = false)
    @Builder.Default
    private boolean runtimeSuppressed = false;

    @Column(name = "actor", nullable = false, length = 160)
    private String actor;

    @Column(name = "reason", nullable = false, length = 2000)
    private String reason;

    @Column(name = "canary_outcome", length = 160)
    private String canaryOutcome;

    @Column(name = "rollback_target_state", length = 64)
    private String rollbackTargetState;

    @Convert(converter = JpaListConverter.class)
    @Column(name = "facts_json", columnDefinition = "TEXT")
    @Builder.Default
    private List<String> facts = List.of();

    @Column(name = "first_registered_at", nullable = false)
    private LocalDateTime firstRegisteredAt;

    @Column(name = "last_ledger_at", nullable = false)
    private LocalDateTime lastLedgerAt;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;
}