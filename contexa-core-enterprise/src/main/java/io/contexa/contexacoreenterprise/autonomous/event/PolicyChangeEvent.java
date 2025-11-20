package io.contexa.contexacoreenterprise.autonomous.event;

import io.contexa.contexacoreenterprise.domain.dto.PolicyDTO;
import lombok.Getter;
import org.springframework.context.ApplicationEvent;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Policy Change Event
 *
 * 정책이 변경(생성, 수정, 삭제, 승인)될 때 발행되는 이벤트입니다.
 * 자율 보안 시스템의 정책 변경 사항을 추적하고 동기화합니다.
 *
 * @author contexa
 * @since 3.1.0
 */
@Getter
public class PolicyChangeEvent extends ApplicationEvent {

    /**
     * 변경 타입
     */
    private final ChangeType changeType;

    /**
     * 정책 ID
     */
    private final Long policyId;

    /**
     * 정책 이름
     */
    private final String policyName;

    /**
     * 정책 출처
     */
    private final PolicyDTO.PolicySource policySource;

    /**
     * 승인 상태
     */
    private final PolicyDTO.ApprovalStatus approvalStatus;

    /**
     * 변경 사용자
     */
    private final String changedBy;

    /**
     * 변경 시간
     */
    private final LocalDateTime changedAt;

    /**
     * 변경 이유
     */
    private final String changeReason;

    /**
     * 이전 정책 상태 (UPDATE 시에만 사용)
     */
    private final PolicyDTO previousPolicy;

    /**
     * 현재 정책 상태
     */
    private final PolicyDTO currentPolicy;

    /**
     * AI 신뢰도 점수 (AI 생성 정책인 경우)
     */
    private final Double confidenceScore;

    /**
     * AI 모델 정보 (AI 생성 정책인 경우)
     */
    private final String aiModel;

    /**
     * 추가 메타데이터
     */
    private final Map<String, Object> metadata;

    /**
     * 변경 타입 열거형
     */
    public enum ChangeType {
        /**
         * 정책 생성
         */
        CREATED,

        /**
         * 정책 수정
         */
        UPDATED,

        /**
         * 정책 삭제
         */
        DELETED,

        /**
         * 정책 승인
         */
        APPROVED,

        /**
         * 정책 거부
         */
        REJECTED,

        /**
         * 정책 활성화
         */
        ACTIVATED,

        /**
         * 정책 비활성화
         */
        DEACTIVATED,

        /**
         * AI 진화 (기존 정책을 AI가 개선)
         */
        AI_EVOLVED
    }

    /**
     * 정책 생성 이벤트 생성자
     */
    public PolicyChangeEvent(Object source, PolicyDTO policy, ChangeType changeType, String changedBy) {
        this(source, policy, null, changeType, changedBy, null);
    }

    /**
     * 정책 변경 이벤트 생성자 (이전 상태 포함)
     */
    public PolicyChangeEvent(Object source, PolicyDTO currentPolicy, PolicyDTO previousPolicy,
                            ChangeType changeType, String changedBy, String changeReason) {
        super(source);
        this.changeType = changeType;
        this.currentPolicy = currentPolicy;
        this.previousPolicy = previousPolicy;
        this.changedBy = changedBy;
        this.changeReason = changeReason;
        this.changedAt = LocalDateTime.now();

        // 현재 정책에서 정보 추출
        if (currentPolicy != null) {
            this.policyId = currentPolicy.getId();
            this.policyName = currentPolicy.getName();
            this.policySource = currentPolicy.getSource();
            this.approvalStatus = currentPolicy.getApprovalStatus();
            this.confidenceScore = currentPolicy.getConfidenceScore();
            this.aiModel = currentPolicy.getAiModel();
        } else if (previousPolicy != null) {
            // 삭제의 경우 이전 정책에서 정보 추출
            this.policyId = previousPolicy.getId();
            this.policyName = previousPolicy.getName();
            this.policySource = previousPolicy.getSource();
            this.approvalStatus = previousPolicy.getApprovalStatus();
            this.confidenceScore = previousPolicy.getConfidenceScore();
            this.aiModel = previousPolicy.getAiModel();
        } else {
            this.policyId = null;
            this.policyName = null;
            this.policySource = null;
            this.approvalStatus = null;
            this.confidenceScore = null;
            this.aiModel = null;
        }

        this.metadata = new HashMap<>();
    }

    /**
     * 메타데이터 추가
     */
    public void addMetadata(String key, Object value) {
        this.metadata.put(key, value);
    }

    /**
     * AI 생성 정책 이벤트인지 확인
     */
    public boolean isAIGeneratedPolicyEvent() {
        return policySource == PolicyDTO.PolicySource.AI_GENERATED ||
               policySource == PolicyDTO.PolicySource.AI_EVOLVED;
    }

    /**
     * 승인 관련 이벤트인지 확인
     */
    public boolean isApprovalRelatedEvent() {
        return changeType == ChangeType.APPROVED || changeType == ChangeType.REJECTED;
    }

    /**
     * 중요 변경 사항인지 확인
     */
    public boolean isCriticalChange() {
        return changeType == ChangeType.DELETED ||
               changeType == ChangeType.APPROVED ||
               changeType == ChangeType.AI_EVOLVED ||
               (changeType == ChangeType.CREATED && isAIGeneratedPolicyEvent());
    }

    /**
     * 이벤트 요약 정보 생성
     */
    public Map<String, Object> getSummary() {
        Map<String, Object> summary = new HashMap<>();
        summary.put("changeType", changeType);
        summary.put("policyId", policyId);
        summary.put("policyName", policyName);
        summary.put("policySource", policySource);
        summary.put("approvalStatus", approvalStatus);
        summary.put("changedBy", changedBy);
        summary.put("changedAt", changedAt);
        summary.put("changeReason", changeReason);
        summary.put("isAIGenerated", isAIGeneratedPolicyEvent());
        summary.put("isCritical", isCriticalChange());

        if (confidenceScore != null) {
            summary.put("confidenceScore", confidenceScore);
        }
        if (aiModel != null) {
            summary.put("aiModel", aiModel);
        }
        if (!metadata.isEmpty()) {
            summary.put("metadata", metadata);
        }

        return summary;
    }

    @Override
    public String toString() {
        return String.format(
            "PolicyChangeEvent{type=%s, policy=%s, source=%s, changedBy=%s, time=%s}",
            changeType, policyName, policySource, changedBy, changedAt
        );
    }
}