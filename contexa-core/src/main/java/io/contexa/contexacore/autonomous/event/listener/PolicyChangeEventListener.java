package io.contexa.contexacore.autonomous.event.listener;

import io.contexa.contexacore.autonomous.event.PolicyChangeEvent;
import io.contexa.contexacore.autonomous.evolution.PolicyEvolutionEngine;
import io.contexa.contexacore.autonomous.governance.ApprovalService;
import io.contexa.contexacore.autonomous.notification.NotificationService;
import io.contexa.contexacore.autonomous.domain.PolicyDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Policy Change Event Listener
 *
 * 정책 변경 이벤트를 수신하고 처리하는 리스너입니다.
 * 정책 변경 사항을 추적하고, AI 생성 정책의 승인 프로세스를 관리하며,
 * 정책 진화를 트리거합니다.
 *
 * @author contexa
 * @since 3.1.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class PolicyChangeEventListener {

    private final PolicyEvolutionEngine policyEvolutionEngine;
    private final ApprovalService approvalService;
    private final NotificationService notificationService;

    /**
     * 정책 변경 이력 캐시
     * Key: policyId, Value: 변경 이력
     */
    private final Map<Long, PolicyChangeHistory> policyHistoryCache = new ConcurrentHashMap<>();

    /**
     * 정책 변경 이벤트 처리
     */
    @EventListener
    @Async
    @Transactional
    public void handlePolicyChangeEvent(PolicyChangeEvent event) {
        log.info("정책 변경 이벤트 수신: {}", event.toString());

        try {
            // 1. 감사 로그 기록
            recordAuditLog(event);

            // 2. 변경 이력 캐시 업데이트
            updatePolicyHistory(event);

            // 3. 변경 타입별 처리
            switch (event.getChangeType()) {
                case CREATED:
                    handlePolicyCreated(event);
                    break;
                case UPDATED:
                    handlePolicyUpdated(event);
                    break;
                case DELETED:
                    handlePolicyDeleted(event);
                    break;
                case APPROVED:
                    handlePolicyApproved(event);
                    break;
                case REJECTED:
                    handlePolicyRejected(event);
                    break;
                case AI_EVOLVED:
                    handlePolicyEvolved(event);
                    break;
                case ACTIVATED:
                case DEACTIVATED:
                    handlePolicyStatusChanged(event);
                    break;
                default:
                    log.warn("알 수 없는 정책 변경 타입: {}", event.getChangeType());
            }

            // 4. 중요 변경사항 알림
            if (event.isCriticalChange()) {
                notifyCriticalChange(event);
            }

            // 5. AI 정책 진화 트리거 검사
            if (shouldTriggerEvolution(event)) {
                triggerPolicyEvolution(event);
            }

        } catch (Exception e) {
            log.error("정책 변경 이벤트 처리 실패: {}", event, e);
            handleEventProcessingError(event, e);
        }
    }

    /**
     * 정책 생성 처리
     */
    private void handlePolicyCreated(PolicyChangeEvent event) {
        log.info("정책 생성 처리: {}", event.getPolicyName());

        if (event.isAIGeneratedPolicyEvent()) {
            // AI 생성 정책인 경우 승인 프로세스 시작
            initiateApprovalProcess(event);
        }

        // 정책 생성 알림
        Map<String, Object> notificationData = new HashMap<>();
        notificationData.put("policyName", event.getPolicyName());
        notificationData.put("policySource", event.getPolicySource());
        notificationData.put("createdBy", event.getChangedBy());

        notificationService.sendNotification(
            "POLICY_CREATED",
            "새로운 정책 생성: " + event.getPolicyName(),
            notificationData,
            NotificationService.Priority.MEDIUM
        );
    }

    /**
     * 정책 수정 처리
     */
    private void handlePolicyUpdated(PolicyChangeEvent event) {
        log.info("정책 수정 처리: {}", event.getPolicyName());

        // 중요한 변경사항 검사
        if (isSignificantChange(event)) {
            // 재승인 필요 여부 검사
            if (requiresReapproval(event)) {
                initiateReapprovalProcess(event);
            }
        }

        // 정책 수정 알림
        Map<String, Object> notificationData = new HashMap<>();
        notificationData.put("policyName", event.getPolicyName());
        notificationData.put("changedBy", event.getChangedBy());
        notificationData.put("changeReason", event.getChangeReason());

        notificationService.sendNotification(
            "POLICY_UPDATED",
            "정책 수정: " + event.getPolicyName(),
            notificationData,
            NotificationService.Priority.LOW
        );
    }

    /**
     * 정책 삭제 처리
     */
    private void handlePolicyDeleted(PolicyChangeEvent event) {
        log.warn("정책 삭제 처리: {}", event.getPolicyName());

        // 삭제 이력 보관
        archivePolicyDeletion(event);

        // 정책 삭제 알림 (중요)
        Map<String, Object> notificationData = new HashMap<>();
        notificationData.put("policyName", event.getPolicyName());
        notificationData.put("deletedBy", event.getChangedBy());
        notificationData.put("deleteReason", event.getChangeReason());

        notificationService.sendNotification(
            "POLICY_DELETED",
            "정책 삭제: " + event.getPolicyName(),
            notificationData,
            NotificationService.Priority.HIGH
        );
    }

    /**
     * 정책 승인 처리
     */
    private void handlePolicyApproved(PolicyChangeEvent event) {
        log.info("정책 승인 처리: {}", event.getPolicyName());

        // 승인된 AI 정책 활성화
        if (event.isAIGeneratedPolicyEvent()) {
            activateApprovedPolicy(event);
        }

        // 승인 알림
        Map<String, Object> notificationData = new HashMap<>();
        notificationData.put("policyName", event.getPolicyName());
        notificationData.put("approvedBy", event.getChangedBy());
        notificationData.put("confidenceScore", event.getConfidenceScore());

        notificationService.sendNotification(
            "POLICY_APPROVED",
            "정책 승인: " + event.getPolicyName(),
            notificationData,
            NotificationService.Priority.MEDIUM
        );
    }

    /**
     * 정책 거부 처리
     */
    private void handlePolicyRejected(PolicyChangeEvent event) {
        log.info("정책 거부 처리: {}", event.getPolicyName());

        // 거부된 정책에서 학습
        if (event.isAIGeneratedPolicyEvent()) {
            learnFromRejection(event);
        }

        // 거부 알림
        Map<String, Object> notificationData = new HashMap<>();
        notificationData.put("policyName", event.getPolicyName());
        notificationData.put("rejectedBy", event.getChangedBy());
        notificationData.put("rejectReason", event.getChangeReason());

        notificationService.sendNotification(
            "POLICY_REJECTED",
            "정책 거부: " + event.getPolicyName(),
            notificationData,
            NotificationService.Priority.MEDIUM
        );
    }

    /**
     * AI 정책 진화 처리
     */
    private void handlePolicyEvolved(PolicyChangeEvent event) {
        log.info("AI 정책 진화 처리: {}", event.getPolicyName());

        // 진화된 정책 승인 프로세스 시작
        initiateApprovalProcess(event);

        // 진화 알림
        Map<String, Object> notificationData = new HashMap<>();
        notificationData.put("originalPolicy", event.getPreviousPolicy() != null ?
            event.getPreviousPolicy().getName() : "Unknown");
        notificationData.put("evolvedPolicy", event.getPolicyName());
        notificationData.put("aiModel", event.getAiModel());
        notificationData.put("confidenceScore", event.getConfidenceScore());

        notificationService.sendNotification(
            "POLICY_EVOLVED",
            "AI 정책 진화: " + event.getPolicyName(),
            notificationData,
            NotificationService.Priority.HIGH
        );
    }

    /**
     * 정책 상태 변경 처리
     */
    private void handlePolicyStatusChanged(PolicyChangeEvent event) {
        log.info("정책 상태 변경: {} - {}", event.getPolicyName(), event.getChangeType());

        // 상태 변경 알림
        Map<String, Object> notificationData = new HashMap<>();
        notificationData.put("policyName", event.getPolicyName());
        notificationData.put("newStatus", event.getChangeType());
        notificationData.put("changedBy", event.getChangedBy());

        notificationService.sendNotification(
            "POLICY_STATUS_CHANGED",
            String.format("정책 %s: %s",
                event.getChangeType() == PolicyChangeEvent.ChangeType.ACTIVATED ? "활성화" : "비활성화",
                event.getPolicyName()),
            notificationData,
            NotificationService.Priority.LOW
        );
    }

    /**
     * 승인 프로세스 시작
     */
    private void initiateApprovalProcess(PolicyChangeEvent event) {
        if (event.getCurrentPolicy() == null) {
            return;
        }

        Map<String, Object> approvalData = new HashMap<>();
        approvalData.put("policyId", event.getPolicyId());
        approvalData.put("policyName", event.getPolicyName());
        approvalData.put("policySource", event.getPolicySource());
        approvalData.put("confidenceScore", event.getConfidenceScore());
        approvalData.put("aiModel", event.getAiModel());

        // 승인 프로세스는 ApprovalService에서 직접 처리
        // 실제 구현에서는 ApprovalService의 적절한 메서드 호출
        log.info("정책 승인 요청 시작: {}", event.getPolicyName());
    }

    /**
     * 재승인 프로세스 시작
     */
    private void initiateReapprovalProcess(PolicyChangeEvent event) {
        Map<String, Object> approvalData = new HashMap<>();
        approvalData.put("policyId", event.getPolicyId());
        approvalData.put("policyName", event.getPolicyName());
        approvalData.put("changeReason", event.getChangeReason());
        approvalData.put("previousPolicy", event.getPreviousPolicy());
        approvalData.put("currentPolicy", event.getCurrentPolicy());

        // 재승인 프로세스는 ApprovalService에서 직접 처리
        // 실제 구현에서는 ApprovalService의 적절한 메서드 호출
        log.info("정책 재승인 요청 시작: {}", event.getPolicyName());
    }

    /**
     * 승인된 정책 활성화
     */
    private void activateApprovedPolicy(PolicyChangeEvent event) {
        log.info("승인된 AI 정책 활성화: {}", event.getPolicyName());
        // 실제 활성화 로직은 Policy 서비스에서 처리
    }

    /**
     * 거부로부터 학습
     */
    private void learnFromRejection(PolicyChangeEvent event) {
        log.info("거부된 정책으로부터 학습: {}", event.getPolicyName());

        // PolicyEvolutionEngine에 거부 피드백 전달
        if (event.getCurrentPolicy() != null) {
            policyEvolutionEngine.learnFromRejection(
                event.getCurrentPolicy(),
                event.getChangeReason()
            );
        }
    }

    /**
     * 정책 진화 트리거
     */
    private void triggerPolicyEvolution(PolicyChangeEvent event) {
        log.info("정책 진화 트리거: {}", event.getPolicyName());

        // PolicyEvolutionEngine에 진화 요청
        if (event.getCurrentPolicy() != null) {
            policyEvolutionEngine.requestEvolution(
                event.getCurrentPolicy(),
                event.getSummary()
            );
        }
    }

    /**
     * 감사 로그 기록
     */
    private void recordAuditLog(PolicyChangeEvent event) {
        // 감사 로그 기록 (실제 구현에서는 AuditLog 서비스 사용)
        log.info("AUDIT: PolicyChange - Type: {}, Policy: {}, User: {}, Time: {}",
                 event.getChangeType(), event.getPolicyName(), event.getChangedBy(), event.getChangedAt());

        // 중요 변경사항은 별도 로깅
        if (event.isCriticalChange()) {
            log.warn("CRITICAL POLICY CHANGE: {}", event.getSummary());
        }
    }

    /**
     * 정책 변경 이력 업데이트
     */
    private void updatePolicyHistory(PolicyChangeEvent event) {
        if (event.getPolicyId() == null) {
            return;
        }

        PolicyChangeHistory history = policyHistoryCache.computeIfAbsent(
            event.getPolicyId(),
            k -> new PolicyChangeHistory(event.getPolicyId())
        );

        history.addChange(event);
    }

    /**
     * 정책 삭제 아카이브
     */
    private void archivePolicyDeletion(PolicyChangeEvent event) {
        // 삭제된 정책 정보를 아카이브
        Map<String, Object> archiveData = new HashMap<>();
        archiveData.put("policy", event.getPreviousPolicy());
        archiveData.put("deletedBy", event.getChangedBy());
        archiveData.put("deletedAt", event.getChangedAt());
        archiveData.put("deleteReason", event.getChangeReason());

        // 아카이브 로직 (별도 테이블 또는 파일로 저장)
        log.info("정책 삭제 아카이브: {}", archiveData);
    }

    /**
     * 중요 변경사항 알림
     */
    private void notifyCriticalChange(PolicyChangeEvent event) {
        Map<String, Object> notificationData = event.getSummary();

        notificationService.sendNotification(
            "CRITICAL_POLICY_CHANGE",
            "중요 정책 변경: " + event.getPolicyName(),
            notificationData,
            NotificationService.Priority.CRITICAL
        );
    }

    /**
     * 중요한 변경사항인지 확인
     */
    private boolean isSignificantChange(PolicyChangeEvent event) {
        if (event.getPreviousPolicy() == null || event.getCurrentPolicy() == null) {
            return false;
        }

        PolicyDTO prev = event.getPreviousPolicy();
        PolicyDTO curr = event.getCurrentPolicy();

        // Effect 변경, Priority 변경 등은 중요한 변경
        return !prev.getEffect().equals(curr.getEffect()) ||
               prev.getPriority() != curr.getPriority();
    }

    /**
     * 재승인 필요 여부 확인
     */
    private boolean requiresReapproval(PolicyChangeEvent event) {
        // AI 생성 정책이고 중요한 변경사항이 있으면 재승인 필요
        return event.isAIGeneratedPolicyEvent() && isSignificantChange(event);
    }

    /**
     * 정책 진화 트리거 여부 확인
     */
    private boolean shouldTriggerEvolution(PolicyChangeEvent event) {
        // 정책이 여러 번 거부되었거나, 자주 수정되는 경우 진화 트리거
        if (event.getPolicyId() == null) {
            return false;
        }

        PolicyChangeHistory history = policyHistoryCache.get(event.getPolicyId());
        if (history == null) {
            return false;
        }

        // 최근 30일 내 3회 이상 거부 또는 5회 이상 수정된 경우
        return history.getRecentRejectionCount(30) >= 3 ||
               history.getRecentUpdateCount(30) >= 5;
    }

    /**
     * 이벤트 처리 에러 핸들링
     */
    private void handleEventProcessingError(PolicyChangeEvent event, Exception error) {
        log.error("정책 변경 이벤트 처리 중 오류 발생", error);

        // 에러 알림
        Map<String, Object> errorData = new HashMap<>();
        errorData.put("event", event.getSummary());
        errorData.put("error", error.getMessage());

        notificationService.sendNotification(
            "POLICY_EVENT_ERROR",
            "정책 변경 이벤트 처리 실패",
            errorData,
            NotificationService.Priority.HIGH
        );
    }

    /**
     * 정책 변경 이력 내부 클래스
     */
    private static class PolicyChangeHistory {
        private final Long policyId;
        private final Map<LocalDateTime, PolicyChangeEvent> changes = new ConcurrentHashMap<>();

        public PolicyChangeHistory(Long policyId) {
            this.policyId = policyId;
        }

        public void addChange(PolicyChangeEvent event) {
            changes.put(event.getChangedAt(), event);
        }

        public int getRecentRejectionCount(int days) {
            LocalDateTime threshold = LocalDateTime.now().minusDays(days);
            return (int) changes.values().stream()
                .filter(e -> e.getChangedAt().isAfter(threshold))
                .filter(e -> e.getChangeType() == PolicyChangeEvent.ChangeType.REJECTED)
                .count();
        }

        public int getRecentUpdateCount(int days) {
            LocalDateTime threshold = LocalDateTime.now().minusDays(days);
            return (int) changes.values().stream()
                .filter(e -> e.getChangedAt().isAfter(threshold))
                .filter(e -> e.getChangeType() == PolicyChangeEvent.ChangeType.UPDATED)
                .count();
        }
    }
}