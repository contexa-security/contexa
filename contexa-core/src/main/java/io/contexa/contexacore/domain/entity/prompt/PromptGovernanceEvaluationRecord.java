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
@Table(name = "prompt_governance_eval_ledger", indexes = {
        @Index(name = "idx_prompt_governance_eval_identity", columnList = "registry_scope,prompt_key,prompt_version", unique = true),
        @Index(name = "idx_prompt_governance_eval_current", columnList = "registry_scope,prompt_key,updated_at")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@EntityListeners(AuditingEntityListener.class)
public class PromptGovernanceEvaluationRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "registry_scope", nullable = false, length = 128)
    private String registryScope;

    @Column(name = "prompt_key", nullable = false, length = 128)
    private String promptKey;

    @Column(name = "prompt_version", nullable = false, length = 128)
    private String promptVersion;

    @Column(name = "evaluation_reference", nullable = false, length = 256)
    private String evaluationReference;

    @Column(name = "evaluation_mode", nullable = false, length = 64)
    private String evaluationMode;

    @Column(name = "evaluation_state", nullable = false, length = 64)
    private String evaluationState;

    @Column(name = "empirical_evidence_state", nullable = false, length = 64)
    private String empiricalEvidenceState;

    @Column(name = "prompt_injection_state", nullable = false, length = 64)
    private String promptInjectionState;

    @Column(name = "scenario_coverage_state", nullable = false, length = 64)
    private String scenarioCoverageState;

    @Column(name = "covered_scenario_count", nullable = false)
    private int coveredScenarioCount;

    @Column(name = "required_scenario_count", nullable = false)
    private int requiredScenarioCount;

    @Column(name = "covered_scenario_families_json", length = 4000)
    private String coveredScenarioFamiliesJson;

    @Column(name = "tevv_gate_state", nullable = false, length = 64)
    private String tevvGateState;

    @Column(name = "quality_gate_state", nullable = false, length = 64)
    private String qualityGateState;

    @Column(name = "latency_gate_state", nullable = false, length = 64)
    private String latencyGateState;

    @Column(name = "cost_gate_state", nullable = false, length = 64)
    private String costGateState;

    @Column(name = "evaluation_summary", nullable = false, length = 2000)
    private String evaluationSummary;

    @Column(name = "evaluated_by", nullable = false, length = 128)
    private String evaluatedBy;

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
