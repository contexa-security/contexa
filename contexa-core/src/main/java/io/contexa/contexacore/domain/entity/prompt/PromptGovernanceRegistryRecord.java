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
@Table(name = "prompt_governance_registry", indexes = {
        @Index(name = "idx_prompt_governance_registry_identity", columnList = "registry_scope,prompt_key,prompt_version", unique = true),
        @Index(name = "idx_prompt_governance_registry_current", columnList = "registry_scope,prompt_key,updated_at"),
        @Index(name = "idx_prompt_governance_registry_release", columnList = "registry_scope,release_status,updated_at")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EntityListeners(AuditingEntityListener.class)
public class PromptGovernanceRegistryRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "registry_scope", nullable = false, length = 128)
    private String registryScope;

    @Column(name = "prompt_key", nullable = false, length = 128)
    private String promptKey;

    @Column(name = "template_key", nullable = false, length = 128)
    private String templateKey;

    @Column(name = "prompt_version", nullable = false, length = 128)
    private String promptVersion;

    @Column(name = "contract_version", nullable = false, length = 128)
    private String contractVersion;

    @Column(name = "prompt_artifact_hash_sha256", nullable = false, length = 64)
    private String promptArtifactHashSha256;

    @Column(name = "release_status", nullable = false, length = 64)
    private String releaseStatus;

    @Column(name = "owner_name", nullable = false, length = 128)
    private String owner;

    @Column(name = "release_approval_reference", length = 256)
    private String releaseApprovalReference;

    @Column(name = "evaluation_baseline_reference", length = 256)
    private String evaluationBaselineReference;

    @Column(name = "rollback_prompt_version", length = 128)
    private String rollbackPromptVersion;

    @Column(name = "change_summary", length = 2000)
    private String changeSummary;

    @Column(name = "template_class_name", nullable = false, length = 512)
    private String templateClassName;

    @Column(name = "registration_source", nullable = false, length = 128)
    private String registrationSource;

    @Column(name = "supported_model_profiles_json", length = 8000)
    private String supportedModelProfilesJson;

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
