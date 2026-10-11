package io.contexa.contexacore.domain.entity.prompt;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
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

@Entity
@Table(name = "prompt_governance_rollback_ledger", indexes = {
        @Index(name = "idx_prompt_governance_rollback_identity", columnList = "registry_scope,prompt_key,prompt_version", unique = true),
        @Index(name = "idx_prompt_governance_rollback_current", columnList = "registry_scope,prompt_key,updated_at")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EntityListeners(AuditingEntityListener.class)
public class PromptGovernanceRollbackRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "registry_scope", nullable = false, length = 128)
    private String registryScope;

    @Column(name = "prompt_key", nullable = false, length = 128)
    private String promptKey;

    @Column(name = "prompt_version", nullable = false, length = 128)
    private String promptVersion;

    @Column(name = "rollback_reference", nullable = false, length = 256)
    private String rollbackReference;

    @Column(name = "rollback_target_prompt_version", nullable = false, length = 128)
    private String rollbackTargetPromptVersion;

    @Column(name = "rollback_state", nullable = false, length = 64)
    private String rollbackState;

    @Column(name = "rollback_readiness_state", nullable = false, length = 64)
    private String rollbackReadinessState;

    @Column(name = "rollback_strategy", nullable = false, length = 64)
    private String rollbackStrategy;

    @Column(name = "rollback_reason", nullable = false, length = 2000)
    private String rollbackReason;

    @Column(name = "prepared_by", nullable = false, length = 128)
    private String preparedBy;

    @Column(name = "registration_source", nullable = false, length = 128)
    private String registrationSource;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    void prePersist() {
        LocalDateTime now = LocalDateTime.now();
        if (createdAt == null) {
            createdAt = now;
        }
        if (updatedAt == null) {
            updatedAt = now;
        }
    }

    @PreUpdate
    void preUpdate() {
        if (updatedAt == null) {
            updatedAt = LocalDateTime.now();
        }
    }
}
