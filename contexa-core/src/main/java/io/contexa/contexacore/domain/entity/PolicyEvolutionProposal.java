package io.contexa.contexacore.domain.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.contexa.contexacore.autonomous.domain.LearningMetadata;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Entity
@Table(name = "policy_evolution_proposals")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class PolicyEvolutionProposal {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 255)
    private String title;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 50)
    private ProposalType proposalType;

    @Column(name = "source_event_id", length = 100)
    private String sourceEventId;

    @Column(name = "analysis_lab_id", length = 100)
    private String analysisLabId;

    @Column(name = "ai_reasoning", columnDefinition = "TEXT")
    private String aiReasoning;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "evidence_context", columnDefinition = "jsonb")
    @Builder.Default
    private Map<String, Object> evidenceContext = new HashMap<>();

    @Column(name = "spel_expression", columnDefinition = "TEXT")
    private String spelExpression;

    @Column(name = "policy_content", columnDefinition = "TEXT")
    private String policyContent;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "action_payload", columnDefinition = "jsonb")
    @Builder.Default
    private Map<String, Object> actionPayload = new HashMap<>();

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 50)
    @Builder.Default
    private ProposalStatus status = ProposalStatus.PENDING;

    @Column(name = "created_at", nullable = false)
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(name = "reviewed_at")
    private LocalDateTime reviewedAt;

    @Column(name = "activated_at")
    private LocalDateTime activatedAt;

    @Column(name = "deactivated_at")
    private LocalDateTime deactivatedAt;

    @Column(name = "activated_by", length = 100)
    private String activatedBy;

    @Column(name = "created_by", length = 100)
    private String createdBy;

    @Column(name = "rationale", columnDefinition = "TEXT")
    private String rationale;

    @Column(name = "policy_id")
    private Long policyId;

    @Column(name = "approved_at")
    private LocalDateTime approvedAt;

    @Column(name = "rejected_at")
    private LocalDateTime rejectedAt;

    @Column(name = "rejected_by", length = 100)
    private String rejectedBy;

    @Column(name = "expires_at")
    private LocalDateTime expiresAt;

    @Column(name = "reviewed_by", length = 100)
    private String reviewedBy;

    @Column(name = "approved_by", length = 100)
    private String approvedBy;

    @Column(name = "rejection_reason", columnDefinition = "TEXT")
    private String rejectionReason;

    @Column(name = "confidence_score")
    private Double confidenceScore;

    @Column(name = "expected_impact")
    private Double expectedImpact;

    @Column(name = "actual_impact")
    private Double actualImpact;

    @Enumerated(EnumType.STRING)
    @Column(name = "learning_type", length = 50)
    private LearningMetadata.LearningType learningType;

    @Enumerated(EnumType.STRING)
    @Column(name = "impact_level", length = 20)
    @Builder.Default
    private ProposalImpactLevel impactLevel = ProposalImpactLevel.MEDIUM;

    @Column(name = "version_id")
    private Long versionId;

    @Column(name = "parent_proposal_id")
    private Long parentProposalId;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    @Builder.Default
    private Map<String, Object> metadata = new HashMap<>();

    public enum ProposalType {
        
        CREATE_POLICY,

        UPDATE_POLICY,

        DELETE_POLICY,

        REVOKE_ACCESS,

        GRANT_ACCESS,

        OPTIMIZE_RULE,

        MODIFY_CONFIG,

        CREATE_ALERT,

        SUGGEST_TRAINING,

        ADJUST_THRESHOLD,

        ACCESS_CONTROL,

        THREAT_RESPONSE,

        INCIDENT_RESPONSE,

        COMPLIANCE,

        OPTIMIZATION,

        USER_BEHAVIOR,

        ANOMALY_RESPONSE,

        DATA_PROTECTION
    }

    public enum ProposalStatus {
        
        DRAFT,

        PENDING_APPROVAL,

        PENDING,

        UNDER_REVIEW,

        APPROVED,

        REJECTED,

        ACTIVATED,

        DEACTIVATED,

        ON_HOLD,

        EXPIRED,

        ROLLED_BACK;

        public boolean canTransitionTo(ProposalStatus target) {
            return switch (this) {
                case DRAFT -> target == PENDING_APPROVAL || target == PENDING || target == REJECTED;
                case PENDING, PENDING_APPROVAL ->
                        target == UNDER_REVIEW || target == APPROVED || target == REJECTED || target == ON_HOLD;
                case UNDER_REVIEW -> target == APPROVED || target == REJECTED || target == ON_HOLD;
                case APPROVED -> target == ACTIVATED || target == REJECTED;
                case ACTIVATED -> target == DEACTIVATED || target == EXPIRED || target == ROLLED_BACK;
                case REJECTED, DEACTIVATED, EXPIRED -> false;
                case ON_HOLD -> target == UNDER_REVIEW || target == REJECTED;
                default -> false;
            };
        }
    }

    public void approve(String approver) {
        if (!status.canTransitionTo(ProposalStatus.APPROVED)) {
            throw new IllegalStateException(
                String.format("Cannot approve proposal in status: %s", status)
            );
        }
        this.status = ProposalStatus.APPROVED;
        this.approvedBy = approver;
        this.reviewedAt = LocalDateTime.now();
        this.approvedAt = LocalDateTime.now();
    }

    public void reject(String reviewer, String reason) {
        if (!status.canTransitionTo(ProposalStatus.REJECTED)) {
            throw new IllegalStateException(
                String.format("Cannot reject proposal in status: %s", status)
            );
        }
        this.status = ProposalStatus.REJECTED;
        this.reviewedBy = reviewer;
        this.rejectionReason = reason;
        this.reviewedAt = LocalDateTime.now();
    }

    public void activate() {
        if (!status.canTransitionTo(ProposalStatus.ACTIVATED)) {
            throw new IllegalStateException(
                String.format("Cannot activate proposal in status: %s", status)
            );
        }
        this.status = ProposalStatus.ACTIVATED;
        this.activatedAt = LocalDateTime.now();
    }

    public void deactivate() {
        if (!status.canTransitionTo(ProposalStatus.DEACTIVATED)) {
            throw new IllegalStateException(
                String.format("Cannot deactivate proposal in status: %s", status)
            );
        }
        this.status = ProposalStatus.DEACTIVATED;
    }

    public void updateActualImpact(Double impact) {
        if (status != ProposalStatus.ACTIVATED) {
            throw new IllegalStateException(
                "Can only update impact for activated proposals"
            );
        }
        this.actualImpact = impact;
    }

    @JsonIgnore
    public boolean canAutoApprove() {
        return impactLevel == ProposalImpactLevel.LOW &&
               confidenceScore != null &&
               confidenceScore >= 0.9;
    }

    @JsonIgnore
    public boolean isExpired() {
        return expiresAt != null &&
               LocalDateTime.now().isAfter(expiresAt);
    }

    public void addMetadata(String key, Object value) {
        if (metadata == null) {
            metadata = new HashMap<>();
        }
        metadata.put(key, value);
    }
}