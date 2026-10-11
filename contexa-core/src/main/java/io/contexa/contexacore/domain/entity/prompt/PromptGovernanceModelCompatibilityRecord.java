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
@Table(name = "prompt_governance_model_compatibility", indexes = {
        @Index(name = "idx_prompt_model_compatibility_identity", columnList = "registry_scope,prompt_key,prompt_version,model_profile_key", unique = true),
        @Index(name = "idx_prompt_model_compatibility_current", columnList = "registry_scope,prompt_key,updated_at")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EntityListeners(AuditingEntityListener.class)
public class PromptGovernanceModelCompatibilityRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "registry_scope", nullable = false, length = 128)
    private String registryScope;

    @Column(name = "prompt_key", nullable = false, length = 128)
    private String promptKey;

    @Column(name = "prompt_version", nullable = false, length = 128)
    private String promptVersion;

    @Column(name = "model_profile_key", nullable = false, length = 256)
    private String modelProfileKey;

    @Column(name = "profile_category", nullable = false, length = 128)
    private String profileCategory;

    @Column(name = "provider_scope", nullable = false, length = 256)
    private String providerScope;

    @Column(name = "compatibility_state", nullable = false, length = 128)
    private String compatibilityState;

    @Column(name = "token_counting_policy_key", nullable = false, length = 256)
    private String tokenCountingPolicyKey;

    @Column(name = "cache_policy_key", nullable = false, length = 256)
    private String cachePolicyKey;

    @Column(name = "compaction_policy_key", nullable = false, length = 256)
    private String compactionPolicyKey;

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
