package io.contexa.contexacoreenterprise.domain.dto;

import io.contexa.contexacoreenterprise.repository.SynthesisPolicyRepository;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * 정책 DTO
 * 
 * @author contexa
 * @since 1.0.0
 */
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

    // PolicyChangeEvent에서 사용하는 추가 필드들
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

    /**
     * 정책 소스 열거형
     */
    public enum PolicySource {
        AI_GENERATED,
        MANUAL,
        IMPORTED,
        EVOLVED,
        AI_EVOLVED  // PolicyChangeEvent에서 사용
    }

    /**
     * 승인 상태 열거형
     */
    public enum ApprovalStatus {
        PENDING,
        APPROVED,
        REJECTED,
        AUTO_APPROVED
    }

    /**
     * 정책 효과 열거형
     */
    public enum PolicyEffect {
        PERMIT,
        DENY
    }
}