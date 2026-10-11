package io.contexa.contexacore.domain.entity.prompt;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Entity
@Table(name = "prompt_governance_release_workflow", indexes = {
        @Index(name = "idx_prompt_release_workflow_scope_created", columnList = "registry_scope, created_at"),
        @Index(name = "idx_prompt_release_workflow_prompt_created", columnList = "registry_scope, prompt_key, created_at")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EntityListeners(AuditingEntityListener.class)
public class PromptGovernanceReleaseWorkflowRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "registry_scope", nullable = false, length = 128)
    private String registryScope;

    @Column(name = "prompt_key", nullable = false, length = 128)
    private String promptKey;

    @Column(name = "prompt_version", nullable = false, length = 128)
    private String promptVersion;

    @Column(name = "current_release_status", nullable = false, length = 64)
    private String currentReleaseStatus;

    @Column(name = "target_release_status", nullable = false, length = 64)
    private String targetReleaseStatus;

    @Column(name = "workflow_state", nullable = false, length = 64)
    private String workflowState;

    @Column(name = "gate_state", nullable = false, length = 64)
    private String gateState;

    @Column(name = "approval_channel", nullable = false, length = 128)
    private String approvalChannel;

    @Column(name = "actor_name", nullable = false, length = 128)
    private String actor;

    @Column(name = "rationale", nullable = false, length = 2000)
    private String rationale;

    @Column(name = "blockers_json", length = 8000)
    private String blockersJson;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    void prePersist() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
    }
}
