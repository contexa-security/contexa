package io.contexa.contexacoreenterprise.domain.dto;

import io.contexa.contexacoreenterprise.repository.SynthesisPolicyRepository;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PolicyDTO {

    private Long policyId;
    private Long proposalId;
    private String policyName;
    private String policyType;
    private String spelExpression;
    private SynthesisPolicyRepository.PolicyStatus status;
    private int version;
    private LocalDateTime createdAt;
    private LocalDateTime activatedAt;

    private Long id;
    private String name;
    private String description;
    private PolicySource source;
    private ApprovalStatus approvalStatus;
    private Double confidence;
    private Double confidenceScore;
    private String aiModel;
    private Integer priority;
    private Boolean isActive;
    private PolicyEffect effect;

    public enum PolicySource {
        AI_GENERATED,
        MANUAL,
        IMPORTED,
        EVOLVED,
        AI_EVOLVED  
    }

    public enum ApprovalStatus {
        PENDING,
        APPROVED,
        REJECTED,
        AUTO_APPROVED
    }

    public enum PolicyEffect {
        PERMIT,
        DENY
    }
}