package io.contexa.contexacoreenterprise.autonomous.event.listener;

import io.contexa.contexacoreenterprise.autonomous.event.PolicyChangeEvent;
import io.contexa.contexacoreenterprise.autonomous.evolution.PolicyEvolutionEngine;
import io.contexa.contexacoreenterprise.autonomous.governance.PolicyApprovalService;
import io.contexa.contexacore.autonomous.notification.NotificationService;
import io.contexa.contexacoreenterprise.domain.dto.PolicyDTO;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;


@Slf4j
@RequiredArgsConstructor
public class PolicyChangeEventListener {

    private final PolicyEvolutionEngine policyEvolutionEngine;
    private final PolicyApprovalService approvalService;
    private final NotificationService notificationService;

    
    private final Map<Long, PolicyChangeHistory> policyHistoryCache = new ConcurrentHashMap<>();

    
    @EventListener
    @Async
    @Transactional
    public void handlePolicyChangeEvent(PolicyChangeEvent event) {
        log.info("정책 변경 이벤트 수신: {}", event.toString());

        try {
            
            recordAuditLog(event);

            
            updatePolicyHistory(event);

            
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

            
            if (event.isCriticalChange()) {
                notifyCriticalChange(event);
            }

            
            if (shouldTriggerEvolution(event)) {
                triggerPolicyEvolution(event);
            }

        } catch (Exception e) {
            log.error("정책 변경 이벤트 처리 실패: {}", event, e);
            handleEventProcessingError(event, e);
        }
    }

    
    private void handlePolicyCreated(PolicyChangeEvent event) {
        log.info("정책 생성 처리: {}", event.getPolicyName());

        if (event.isAIGeneratedPolicyEvent()) {
            
            initiateApprovalProcess(event);
        }

        
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

    
    private void handlePolicyUpdated(PolicyChangeEvent event) {
        log.info("정책 수정 처리: {}", event.getPolicyName());

        
        if (isSignificantChange(event)) {
            
            if (requiresReapproval(event)) {
                initiateReapprovalProcess(event);
            }
        }

        
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

    
    private void handlePolicyDeleted(PolicyChangeEvent event) {
        log.warn("정책 삭제 처리: {}", event.getPolicyName());

        
        archivePolicyDeletion(event);

        
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

    
    private void handlePolicyApproved(PolicyChangeEvent event) {
        log.info("정책 승인 처리: {}", event.getPolicyName());

        
        if (event.isAIGeneratedPolicyEvent()) {
            activateApprovedPolicy(event);
        }

        
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

    
    private void handlePolicyRejected(PolicyChangeEvent event) {
        log.info("정책 거부 처리: {}", event.getPolicyName());

        
        if (event.isAIGeneratedPolicyEvent()) {
            learnFromRejection(event);
        }

        
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

    
    private void handlePolicyEvolved(PolicyChangeEvent event) {
        log.info("AI 정책 진화 처리: {}", event.getPolicyName());

        
        initiateApprovalProcess(event);

        
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

    
    private void handlePolicyStatusChanged(PolicyChangeEvent event) {
        log.info("정책 상태 변경: {} - {}", event.getPolicyName(), event.getChangeType());

        
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

        
        
        log.info("정책 승인 요청 시작: {}", event.getPolicyName());
    }

    
    private void initiateReapprovalProcess(PolicyChangeEvent event) {
        Map<String, Object> approvalData = new HashMap<>();
        approvalData.put("policyId", event.getPolicyId());
        approvalData.put("policyName", event.getPolicyName());
        approvalData.put("changeReason", event.getChangeReason());
        approvalData.put("previousPolicy", event.getPreviousPolicy());
        approvalData.put("currentPolicy", event.getCurrentPolicy());

        
        
        log.info("정책 재승인 요청 시작: {}", event.getPolicyName());
    }

    
    private void activateApprovedPolicy(PolicyChangeEvent event) {
        log.info("승인된 AI 정책 활성화: {}", event.getPolicyName());
        
    }

    
    private void learnFromRejection(PolicyChangeEvent event) {
        log.info("거부된 정책으로부터 학습: {}", event.getPolicyName());

        
        if (event.getCurrentPolicy() != null) {
            policyEvolutionEngine.learnFromRejection(
                event.getCurrentPolicy(),
                event.getChangeReason()
            );
        }
    }

    
    private void triggerPolicyEvolution(PolicyChangeEvent event) {
        log.info("정책 진화 트리거: {}", event.getPolicyName());

        
        if (event.getCurrentPolicy() != null) {
            policyEvolutionEngine.requestEvolution(
                event.getCurrentPolicy(),
                event.getSummary()
            );
        }
    }

    
    private void recordAuditLog(PolicyChangeEvent event) {
        
        log.info("AUDIT: PolicyChange - Type: {}, Policy: {}, User: {}, Time: {}",
                 event.getChangeType(), event.getPolicyName(), event.getChangedBy(), event.getChangedAt());

        
        if (event.isCriticalChange()) {
            log.warn("CRITICAL POLICY CHANGE: {}", event.getSummary());
        }
    }

    
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

    
    private void archivePolicyDeletion(PolicyChangeEvent event) {
        
        Map<String, Object> archiveData = new HashMap<>();
        archiveData.put("policy", event.getPreviousPolicy());
        archiveData.put("deletedBy", event.getChangedBy());
        archiveData.put("deletedAt", event.getChangedAt());
        archiveData.put("deleteReason", event.getChangeReason());

        
        log.info("정책 삭제 아카이브: {}", archiveData);
    }

    
    private void notifyCriticalChange(PolicyChangeEvent event) {
        Map<String, Object> notificationData = event.getSummary();

        notificationService.sendNotification(
            "CRITICAL_POLICY_CHANGE",
            "중요 정책 변경: " + event.getPolicyName(),
            notificationData,
            NotificationService.Priority.CRITICAL
        );
    }

    
    private boolean isSignificantChange(PolicyChangeEvent event) {
        if (event.getPreviousPolicy() == null || event.getCurrentPolicy() == null) {
            return false;
        }

        PolicyDTO prev = event.getPreviousPolicy();
        PolicyDTO curr = event.getCurrentPolicy();

        
        return !prev.getEffect().equals(curr.getEffect()) ||
               prev.getPriority() != curr.getPriority();
    }

    
    private boolean requiresReapproval(PolicyChangeEvent event) {
        
        return event.isAIGeneratedPolicyEvent() && isSignificantChange(event);
    }

    
    private boolean shouldTriggerEvolution(PolicyChangeEvent event) {
        
        if (event.getPolicyId() == null) {
            return false;
        }

        PolicyChangeHistory history = policyHistoryCache.get(event.getPolicyId());
        if (history == null) {
            return false;
        }

        
        return history.getRecentRejectionCount(30) >= 3 ||
               history.getRecentUpdateCount(30) >= 5;
    }

    
    private void handleEventProcessingError(PolicyChangeEvent event, Exception error) {
        log.error("정책 변경 이벤트 처리 중 오류 발생", error);

        
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