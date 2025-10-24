package io.contexa.contexaiam.domain.entity.policy;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Entity
@Getter @Setter @Builder
@NoArgsConstructor @AllArgsConstructor
@Table(name = "POLICY")
public class Policy implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String name;

    private String description;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Effect effect;

    @Column(nullable = false)
    private int priority;

    @OneToMany(mappedBy = "policy", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @Builder.Default
    private Set<PolicyTarget> targets = new HashSet<>();

    @OneToMany(mappedBy = "policy", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @Builder.Default
    private Set<PolicyRule> rules = new HashSet<>();

    @Column(length = 2048)
    private String friendlyDescription;

    /**
     * 정책 생성 출처
     * MANUAL: 관리자가 수동으로 생성
     * AI_GENERATED: AI가 자동 생성
     * AI_EVOLVED: AI가 기존 정책을 진화시켜 생성
     * IMPORTED: 외부 시스템에서 가져옴
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "source", length = 50)
    @Builder.Default
    private PolicySource source = PolicySource.MANUAL;

    /**
     * AI 생성 정책의 승인 상태
     * PENDING: 승인 대기 중
     * APPROVED: 승인됨
     * REJECTED: 거부됨
     * NOT_REQUIRED: 승인 불필요 (수동 생성 정책)
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "approval_status", length = 50)
    @Builder.Default
    private ApprovalStatus approvalStatus = ApprovalStatus.NOT_REQUIRED;

    /**
     * 정책 승인자
     */
    @Column(name = "approved_by", length = 255)
    private String approvedBy;

    /**
     * 정책 승인 시간
     */
    @Column(name = "approved_at")
    private LocalDateTime approvedAt;

    /**
     * AI 생성 정책의 신뢰도 점수 (0.0 ~ 1.0)
     */
    @Column(name = "confidence_score")
    private Double confidenceScore;

    /**
     * AI 모델 정보 (정책을 생성한 AI 모델)
     */
    @Column(name = "ai_model", length = 255)
    private String aiModel;

    /**
     * 정책 생성 시간
     */
    @Column(name = "created_at", nullable = false, updatable = false)
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    /**
     * 정책 수정 시간
     */
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    /**
     * 정책 활성화 여부
     */
    @Column(name = "is_active", nullable = false)
    @Builder.Default
    private Boolean isActive = true;

    /**
     * isActive getter - null 안전성 보장
     */
    public boolean getIsActive() {
        return this.isActive != null ? this.isActive : true;
    }

    /**
     * isActive setter - null 안전성 보장
     */
    public void setIsActive(Boolean isActive) {
        this.isActive = isActive != null ? isActive : true;
    }

    public enum Effect { ALLOW, DENY }

    /**
     * 정책 생성 출처 열거형
     */
    public enum PolicySource {
        /**
         * 관리자가 수동으로 생성
         */
        MANUAL,

        /**
         * AI가 자동 생성
         */
        AI_GENERATED,

        /**
         * AI가 기존 정책을 진화시켜 생성
         */
        AI_EVOLVED,

        /**
         * 외부 시스템에서 가져옴
         */
        IMPORTED
    }

    /**
     * 승인 상태 열거형
     */
    public enum ApprovalStatus {
        /**
         * 승인 대기 중
         */
        PENDING,

        /**
         * 승인됨
         */
        APPROVED,

        /**
         * 거부됨
         */
        REJECTED,

        /**
         * 승인 불필요 (수동 생성 정책)
         */
        NOT_REQUIRED
    }

    // [신규] 양방향 관계 설정을 위한 편의 메서드 추가
    public void addTarget(PolicyTarget target) {
        this.targets.add(target);
        target.setPolicy(this);
    }

    // [신규] 양방향 관계 설정을 위한 편의 메서드 추가
    public void addRule(PolicyRule rule) {
        this.rules.add(rule);
        rule.setPolicy(this);
    }

    /**
     * AI 생성 정책 여부 확인
     */
    public boolean isAIGenerated() {
        return source == PolicySource.AI_GENERATED || source == PolicySource.AI_EVOLVED;
    }

    /**
     * 승인 필요 여부 확인
     */
    public boolean requiresApproval() {
        return isAIGenerated() && approvalStatus == ApprovalStatus.PENDING;
    }

    /**
     * 정책 승인 처리
     */
    public void approve(String approver) {
        this.approvalStatus = ApprovalStatus.APPROVED;
        this.approvedBy = approver;
        this.approvedAt = LocalDateTime.now();
        this.updatedAt = LocalDateTime.now();
    }

    /**
     * 정책 거부 처리
     */
    public void reject(String rejector) {
        this.approvalStatus = ApprovalStatus.REJECTED;
        this.approvedBy = rejector;
        this.approvedAt = LocalDateTime.now();
        this.setIsActive(false);
        this.updatedAt = LocalDateTime.now();
    }

    /**
     * 정책 활성화
     */
    public void activate() {
        if (approvalStatus == ApprovalStatus.APPROVED || approvalStatus == ApprovalStatus.NOT_REQUIRED) {
            this.setIsActive(true);
            this.updatedAt = LocalDateTime.now();
        }
    }

    /**
     * 정책 비활성화
     */
    public void deactivate() {
        this.setIsActive(false);
        this.updatedAt = LocalDateTime.now();
    }

    /**
     * 정책 생성 시 타임스탬프 설정
     */
    @PrePersist
    protected void onCreate() {
        if (this.createdAt == null) {
            this.createdAt = LocalDateTime.now();
        }
        // isActive null 안전성 보장
        if (this.isActive == null) {
            this.isActive = true;
        }
    }

    /**
     * 정책 업데이트 시 타임스탬프 갱신
     */
    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }
}