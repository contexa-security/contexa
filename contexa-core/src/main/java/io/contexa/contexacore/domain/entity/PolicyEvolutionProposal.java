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

/**
 * 정책 진화 제안 엔티티
 * 
 * AI가 생성한 정책 제안을 저장하고 관리합니다.
 * 이 엔티티는 제안의 전체 생명주기를 추적합니다.
 * 
 * @author AI3Security
 * @since 1.0.0
 */
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
    
    // ==================== 제안 정보 ====================
    
    /**
     * 제안 제목
     */
    @Column(nullable = false, length = 255)
    private String title;
    
    /**
     * 제안 설명
     */
    @Column(columnDefinition = "TEXT")
    private String description;
    
    /**
     * 제안 유형
     */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 50)
    private ProposalType proposalType;
    
    // ==================== 근거 및 추론 ====================
    
    /**
     * 원본 이벤트 ID
     * 이 제안을 생성하게 된 SecurityEvent의 ID
     */
    @Column(name = "source_event_id", length = 100)
    private String sourceEventId;
    
    /**
     * 분석 Lab ID
     * 이 제안을 생성한 Lab의 ID
     */
    @Column(name = "analysis_lab_id", length = 100)
    private String analysisLabId;
    
    /**
     * AI 추론 근거
     * AI가 이 제안을 한 이유를 자연어로 설명
     */
    @Column(name = "ai_reasoning", columnDefinition = "TEXT")
    private String aiReasoning;
    
    /**
     * 증거 컨텍스트
     * 제안의 근거가 된 상세 정보 (JSON)
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "evidence_context", columnDefinition = "jsonb")
    @Builder.Default
    private Map<String, Object> evidenceContext = new HashMap<>();
    
    // ==================== 실행 정보 ====================
    
    /**
     * SpEL 표현식
     * AdvancedPolicyGenerationLab이 생성한 실행 가능한 정책 표현식
     */
    @Column(name = "spel_expression", columnDefinition = "TEXT")
    private String spelExpression;
    
    /**
     * 정책 컨텐츠
     * 실제 적용할 정책의 상세 내용
     */
    @Column(name = "policy_content", columnDefinition = "TEXT")
    private String policyContent;
    
    /**
     * 액션 페이로드
     * 실행에 필요한 추가 데이터 (JSON)
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "action_payload", columnDefinition = "jsonb")
    @Builder.Default
    private Map<String, Object> actionPayload = new HashMap<>();
    
    // ==================== 상태 관리 ====================
    
    /**
     * 제안 상태
     */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 50)
    @Builder.Default
    private ProposalStatus status = ProposalStatus.PENDING;
    
    /**
     * 생성 시간
     */
    @Column(name = "created_at", nullable = false)
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();
    
    /**
     * 검토 시간
     */
    @Column(name = "reviewed_at")
    private LocalDateTime reviewedAt;
    
    /**
     * 활성화 시간
     */
    @Column(name = "activated_at")
    private LocalDateTime activatedAt;
    
    /**
     * 비활성화 시간
     */
    @Column(name = "deactivated_at")
    private LocalDateTime deactivatedAt;
    
    /**
     * 활성화자
     */
    @Column(name = "activated_by", length = 100)
    private String activatedBy;
    
    /**
     * 생성자
     */
    @Column(name = "created_by", length = 100)
    private String createdBy;
    
    /**
     * 근거/이유
     */
    @Column(name = "rationale", columnDefinition = "TEXT")
    private String rationale;
    
    /**
     * 연결된 정책 ID
     */
    @Column(name = "policy_id")
    private Long policyId;
    
    /**
     * 승인 시간
     */
    @Column(name = "approved_at")
    private LocalDateTime approvedAt;
    
    /**
     * 거부 시간
     */
    @Column(name = "rejected_at")
    private LocalDateTime rejectedAt;
    
    /**
     * 거부자
     */
    @Column(name = "rejected_by", length = 100)
    private String rejectedBy;
    
    /**
     * 만료 시간
     */
    @Column(name = "expires_at")
    private LocalDateTime expiresAt;
    
    // ==================== 승인 정보 ====================
    
    /**
     * 검토자
     */
    @Column(name = "reviewed_by", length = 100)
    private String reviewedBy;
    
    /**
     * 승인자
     */
    @Column(name = "approved_by", length = 100)
    private String approvedBy;
    
    /**
     * 거부 사유
     */
    @Column(name = "rejection_reason", columnDefinition = "TEXT")
    private String rejectionReason;
    
    // ==================== 효과 측정 ====================
    
    /**
     * 신뢰도 점수 (0.0 ~ 1.0)
     * AI의 제안 신뢰도
     */
    @Column(name = "confidence_score")
    private Double confidenceScore;
    
    /**
     * 예상 영향도 (0.0 ~ 1.0)
     * 이 제안이 적용될 경우 예상되는 보안 향상 효과
     */
    @Column(name = "expected_impact")
    private Double expectedImpact;
    
    /**
     * 실제 영향도 (0.0 ~ 1.0)
     * 활성화 후 측정된 실제 효과
     */
    @Column(name = "actual_impact")
    private Double actualImpact;
    
    // ==================== 추가 메타데이터 ====================
    
    /**
     * 학습 유형
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "learning_type", length = 50)
    private LearningMetadata.LearningType learningType;
    
    /**
     * 위험 수준
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "risk_level", length = 20)
    @Builder.Default
    private RiskLevel riskLevel = RiskLevel.MEDIUM;
    
    /**
     * 버전 ID
     * PolicyVersionManager에서 관리하는 버전 ID
     */
    @Column(name = "version_id")
    private Long versionId;
    
    /**
     * 부모 제안 ID
     * 이 제안이 다른 제안으로부터 파생된 경우
     */
    @Column(name = "parent_proposal_id")
    private Long parentProposalId;
    
    /**
     * 추가 메타데이터
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    @Builder.Default
    private Map<String, Object> metadata = new HashMap<>();
    
    // ==================== 열거형 정의 ====================
    
    /**
     * 제안 유형
     */
    public enum ProposalType {
        /**
         * 새로운 정책 생성
         */
        CREATE_POLICY,
        
        /**
         * 기존 정책 수정
         */
        UPDATE_POLICY,
        
        /**
         * 정책 삭제
         */
        DELETE_POLICY,
        
        /**
         * 권한 회수
         */
        REVOKE_ACCESS,
        
        /**
         * 권한 부여
         */
        GRANT_ACCESS,
        
        /**
         * 규칙 최적화
         */
        OPTIMIZE_RULE,
        
        /**
         * 시스템 설정 변경
         */
        MODIFY_CONFIG,
        
        /**
         * 경고 규칙 생성
         */
        CREATE_ALERT,
        
        /**
         * 보안 교육 제안
         */
        SUGGEST_TRAINING,
        
        /**
         * 임계값 조정
         */
        ADJUST_THRESHOLD,
        
        /**
         * 접근 제어
         */
        ACCESS_CONTROL,
        
        /**
         * 위협 대응
         */
        THREAT_RESPONSE,
        
        /**
         * 사고 대응
         */
        INCIDENT_RESPONSE,
        
        /**
         * 컴플라이언스
         */
        COMPLIANCE,
        
        /**
         * 최적화
         */
        OPTIMIZATION,
        
        /**
         * 사용자 행동
         */
        USER_BEHAVIOR,
        
        /**
         * 이상 징후 대응
         */
        ANOMALY_RESPONSE,
        
        /**
         * 데이터 보호
         */
        DATA_PROTECTION
    }
    
    /**
     * 제안 상태
     */
    public enum ProposalStatus {
        /**
         * 초안 상태
         */
        DRAFT,
        
        /**
         * 승인 대기
         */
        PENDING_APPROVAL,
        
        /**
         * 대기 중
         */
        PENDING,
        
        /**
         * 검토 중
         */
        UNDER_REVIEW,
        
        /**
         * 승인됨
         */
        APPROVED,
        
        /**
         * 거부됨
         */
        REJECTED,
        
        /**
         * 활성화됨
         */
        ACTIVATED,
        
        /**
         * 비활성화됨
         */
        DEACTIVATED,
        
        /**
         * 보류
         */
        ON_HOLD,
        
        /**
         * 만료됨
         */
        EXPIRED,
        
        /**
         * 롤백됨
         */
        ROLLED_BACK;
        
        /**
         * 상태 전환 가능 여부
         */
        public boolean canTransitionTo(ProposalStatus target) {
            switch (this) {
                case DRAFT:
                    return target == PENDING_APPROVAL || target == PENDING || target == REJECTED;
                case PENDING:
                case PENDING_APPROVAL:
                    return target == UNDER_REVIEW || target == APPROVED || target == REJECTED || target == ON_HOLD;
                case UNDER_REVIEW:
                    return target == APPROVED || target == REJECTED || target == ON_HOLD;
                case APPROVED:
                    return target == ACTIVATED || target == REJECTED;
                case ACTIVATED:
                    return target == DEACTIVATED || target == EXPIRED;
                case REJECTED:
                case DEACTIVATED:
                case EXPIRED:
                    return false;
                case ON_HOLD:
                    return target == UNDER_REVIEW || target == REJECTED;
                default:
                    return false;
            }
        }
    }
    
    /**
     * 위험 수준
     */
    public enum RiskLevel {
        /**
         * 낮음 - 자동 승인 가능
         */
        LOW,
        
        /**
         * 중간 - 관리자 검토 필요
         */
        MEDIUM,
        
        /**
         * 높음 - 다단계 승인 필요
         */
        HIGH,
        
        /**
         * 치명적 - 특별 승인 필요
         */
        CRITICAL
    }
    
    // ==================== 비즈니스 메서드 ====================
    
    /**
     * 제안 승인
     */
    public void approve(String approver) {
        if (!status.canTransitionTo(ProposalStatus.APPROVED)) {
            throw new IllegalStateException(
                String.format("Cannot approve proposal in status: %s", status)
            );
        }
        this.status = ProposalStatus.APPROVED;
        this.approvedBy = approver;
        this.reviewedAt = LocalDateTime.now();
    }
    
    /**
     * 제안 거부
     */
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
    
    /**
     * 제안 활성화
     */
    public void activate() {
        if (!status.canTransitionTo(ProposalStatus.ACTIVATED)) {
            throw new IllegalStateException(
                String.format("Cannot activate proposal in status: %s", status)
            );
        }
        this.status = ProposalStatus.ACTIVATED;
        this.activatedAt = LocalDateTime.now();
    }
    
    /**
     * 제안 비활성화
     */
    public void deactivate() {
        if (!status.canTransitionTo(ProposalStatus.DEACTIVATED)) {
            throw new IllegalStateException(
                String.format("Cannot deactivate proposal in status: %s", status)
            );
        }
        this.status = ProposalStatus.DEACTIVATED;
    }
    
    /**
     * 실제 영향도 업데이트
     */
    public void updateActualImpact(Double impact) {
        if (status != ProposalStatus.ACTIVATED) {
            throw new IllegalStateException(
                "Can only update impact for activated proposals"
            );
        }
        this.actualImpact = impact;
    }
    
    /**
     * 자동 승인 가능 여부
     */
    @JsonIgnore
    public boolean canAutoApprove() {
        return riskLevel == RiskLevel.LOW &&
               confidenceScore != null &&
               confidenceScore >= 0.9;
    }

    /**
     * 만료 여부 확인
     */
    @JsonIgnore
    public boolean isExpired() {
        return expiresAt != null &&
               LocalDateTime.now().isAfter(expiresAt);
    }
    
    /**
     * 메타데이터 추가
     */
    public void addMetadata(String key, Object value) {
        if (metadata == null) {
            metadata = new HashMap<>();
        }
        metadata.put(key, value);
    }
}