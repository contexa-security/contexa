package io.contexa.contexacoreenterprise.autonomous.orchestrator.strategy;

import io.contexa.contexacore.autonomous.domain.NotificationResult;
import io.contexa.contexacoreenterprise.domain.dto.PolicyDTO;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.SecurityEventContext;
import io.contexa.contexacoreenterprise.autonomous.event.PolicyChangeEvent;
import io.contexa.contexacore.autonomous.security.processor.ProcessingResult;
import io.contexa.contexacore.autonomous.service.ISoarNotifier;
import io.contexa.contexacore.autonomous.tiered.routing.ProcessingMode;
import io.contexa.contexacore.autonomous.orchestrator.strategy.ProcessingStrategy;
import io.contexa.contexacore.domain.ApprovalRequest;
import io.contexa.contexacore.soar.approval.ApprovalService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;

/**
 * Await Approval 처리 전략
 *
 * 고위험 작업 또는 정책 변경에 대한 인간 승인 대기
 * 크리티컬 작업의 인간 개입 관리
 *
 * @author contexa
 * @since 1.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AwaitApprovalStrategy implements ProcessingStrategy {

    private final RedisTemplate<String, Object> redisTemplate;
    private final ApplicationEventPublisher eventPublisher;

    @Autowired(required = false)
    private ApprovalService approvalService;

    @Autowired(required = false)
    private ISoarNotifier soarNotifier;

    @Override
    public ProcessingResult process(SecurityEventContext context) {
        SecurityEvent event = context.getSecurityEvent();
        log.warn("[AwaitApprovalStrategy] Approval required for event: {}", event.getEventId());

        List<String> executedActions = new ArrayList<>();
        Map<String, Object> metadata = new HashMap<>();

        try {
            // 1. 승인 요청 생성
            ApprovalRequest approvalRequest = createApprovalRequest(event, context);
            executedActions.add("APPROVAL_REQUEST_CREATED");

            // 2. 승인 요청 저장 및 큐잉
            String approvalId = queueApprovalRequest(approvalRequest, context);
            metadata.put("approvalId", approvalId);
            executedActions.add("APPROVAL_QUEUED");

            // 3. 알림 발송
            if (soarNotifier != null) {
                NotificationResult notifyResult = sendApprovalNotification(
                    event, approvalRequest, approvalId);
                if (notifyResult.isSuccess()) {
                    executedActions.add("APPROVAL_NOTIFICATION_SENT");
                }
            }

            // 4. 임시 차단/완화 조치 (승인 대기 중)
            applyTemporaryMitigation(event, context, executedActions);

            // 5. 승인 타임아웃 설정
            setupApprovalTimeout(approvalId, context);

            // 6. 정책 제안 준비 (해당하는 경우)
            if (shouldProposePolicyChange(context)) {
                PolicyDTO policyProposal = preparePolicyProposal(event, context);
                metadata.put("policyProposal", policyProposal);
                executedActions.add("POLICY_PROPOSAL_PREPARED");
            }

            // 7. 컨텍스트 업데이트
            context.updateProcessingStatus(SecurityEventContext.ProcessingStatus.AWAITING_APPROVAL);
            context.addMetadata("approvalRequired", true);
            context.addMetadata("approvalId", approvalId);

            metadata.put("approvalRequestedAt", System.currentTimeMillis());
            metadata.put("approvalTimeout", 300000); // 5분
            metadata.put("approvalLevel", determineApprovalLevel(context));

            log.info("[AwaitApprovalStrategy] Approval request created for event: {}, approvalId: {}",
                event.getEventId(), approvalId);

            return ProcessingResult.builder()
                .success(true)
                .processingPath(ProcessingResult.ProcessingPath.COLD_PATH)
                .executedActions(executedActions)
                .metadata(metadata)
                .message("Awaiting human approval - ID: " + approvalId)
                .build();

        } catch (Exception e) {
            log.error("[AwaitApprovalStrategy] Error creating approval request: {}",
                event.getEventId(), e);
            return ProcessingResult.builder()
                .success(false)
                .processingPath(ProcessingResult.ProcessingPath.COLD_PATH)
                .executedActions(executedActions)
                .message("Approval request error: " + e.getMessage())
                .build();
        }
    }

    /**
     * 승인 요청 생성
     */
    private ApprovalRequest createApprovalRequest(SecurityEvent event, SecurityEventContext context) {
        ApprovalRequest.ApprovalRequestBuilder builder = ApprovalRequest.builder();

        // 기본 정보 설정
        builder.requestId(UUID.randomUUID().toString());
        builder.incidentId(event.getEventId());
        builder.requestedBy(event.getUserId());
        builder.organizationId("DEFAULT_ORG");

        // AI 분석 결과 포함
        if (context.getAiAnalysisResult() != null) {
            SecurityEventContext.AIAnalysisResult aiResult = context.getAiAnalysisResult();

            // 메타데이터에 추가 정보 저장
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("threatLevel", aiResult.getThreatLevel());
            metadata.put("confidence", aiResult.getConfidence());

            // 권장 액션
            if (aiResult.getRecommendedActions() != null) {
                metadata.put("recommendedActions", new ArrayList<>(aiResult.getRecommendedActions().keySet()));
            }
        }

        // 승인 이유 설정
        builder.requestReason(determineApprovalReason(context));

        // 위험 수준 설정 - enum 사용
        builder.riskLevel(context.isHighRisk() ?
            ApprovalRequest.RiskLevel.CRITICAL :
            ApprovalRequest.RiskLevel.HIGH);

        // 요청 액션 설정
        List<String> requestedActions = determineRequestedActions(context);
        Map<String, Object> actionParams = new HashMap<>();
        actionParams.put("requestedActions", requestedActions);
        actionParams.put("eventType", event.getEventType());
        actionParams.put("sourceIp", event.getSourceIp());
        builder.toolParameters(actionParams);

        // 액션 설명 설정
        builder.actionDescription("Security response actions for event: " + event.getEventId());

        // 승인 타입 설정
        builder.approvalType(ApprovalRequest.ApprovalType.MANUAL);

        // 상태 설정
        builder.status(ApprovalRequest.ApprovalStatus.PENDING);

        // 잠재적 영향 설정
        builder.potentialImpact(determinePotentialImpact(context));

        // 타임아웃 설정 (5분)
        builder.timeoutMinutes(5);

        return builder.build();
    }

    /**
     * 승인 요청 큐잉
     */
    private String queueApprovalRequest(ApprovalRequest request, SecurityEventContext context) {
        String approvalId = UUID.randomUUID().toString();

        if (approvalService != null) {
            // ApprovalService 사용
            // ApprovalService의 requestApproval 메서드는 CompletableFuture<Boolean>을 반환
            // 여기서는 approvalId를 request의 requestId로 사용
            approvalId = request.getRequestId();
            approvalService.requestApproval(request); // 비동기 처리
        } else {
            // Redis에 직접 저장
            String approvalKey = "security:approvals:pending:" + approvalId;
            Map<String, Object> approvalData = new HashMap<>();
            approvalData.put("request", request);
            approvalData.put("context", context);
            approvalData.put("createdAt", System.currentTimeMillis());
            approvalData.put("status", "PENDING");

            redisTemplate.opsForHash().putAll(approvalKey, approvalData);
            redisTemplate.expire(approvalKey, Duration.ofMinutes(30));
        }

        log.debug("[AwaitApprovalStrategy] Approval request queued: {}", approvalId);
        return approvalId;
    }

    /**
     * 승인 알림 발송
     */
    private NotificationResult sendApprovalNotification(SecurityEvent event,
                                                         ApprovalRequest request,
                                                         String approvalId) {
        try {
            Map<String, Object> notificationData = new HashMap<>();
            notificationData.put("severity", "CRITICAL");
            notificationData.put("eventId", event.getEventId());
            notificationData.put("approvalId", approvalId);
            notificationData.put("eventType", event.getEventType());
            notificationData.put("userId", event.getUserId());
            notificationData.put("sourceIp", event.getSourceIp());
            notificationData.put("riskLevel", request.getRiskLevel());
            // parameters에서 requestedActions 가져오기
            if (request.getParameters() != null && request.getParameters().containsKey("requestedActions")) {
                notificationData.put("requestedActions", request.getParameters().get("requestedActions"));
            }
            notificationData.put("message", "CRITICAL: Human approval required for security action");

            return soarNotifier.notifyApprovalRequired(event, notificationData);
        } catch (Exception e) {
            log.error("[AwaitApprovalStrategy] Failed to send approval notification", e);
            return NotificationResult.failure("notification-failed", "Notification failed: " + e.getMessage());
        }
    }

    /**
     * 임시 완화 조치 적용
     */
    private void applyTemporaryMitigation(SecurityEvent event, SecurityEventContext context,
                                           List<String> executedActions) {
        try {
            // 세션 일시 정지
            if (event.getSessionId() != null) {
                String suspendKey = "security:suspended:sessions:" + event.getSessionId();
                redisTemplate.opsForValue().set(suspendKey, true, Duration.ofMinutes(5));
                context.addResponseAction("SESSION_SUSPENDED",
                    "Session temporarily suspended pending approval");
                executedActions.add("SESSION_SUSPENDED");
            }

            // 사용자 액션 제한
            if (event.getUserId() != null) {
                String restrictKey = "security:restricted:users:" + event.getUserId();
                redisTemplate.opsForValue().set(restrictKey, "PENDING_APPROVAL", Duration.ofMinutes(5));
                context.addResponseAction("USER_RESTRICTED",
                    "User actions restricted pending approval");
                executedActions.add("USER_RESTRICTED");
            }

            log.debug("[AwaitApprovalStrategy] Temporary mitigation applied");
        } catch (Exception e) {
            log.error("[AwaitApprovalStrategy] Failed to apply temporary mitigation", e);
        }
    }

    /**
     * 승인 타임아웃 설정
     */
    private void setupApprovalTimeout(String approvalId, SecurityEventContext context) {
        try {
            String timeoutKey = "security:approvals:timeout:" + approvalId;
            Map<String, Object> timeoutData = new HashMap<>();
            timeoutData.put("approvalId", approvalId);
            timeoutData.put("eventId", context.getSecurityEvent().getEventId());
            timeoutData.put("timeoutAt", System.currentTimeMillis() + 300000); // 5분
            timeoutData.put("defaultAction", "DENY"); // 타임아웃 시 기본 액션

            redisTemplate.opsForHash().putAll(timeoutKey, timeoutData);
            redisTemplate.expire(timeoutKey, Duration.ofMinutes(6));

            log.debug("[AwaitApprovalStrategy] Approval timeout set: {}", approvalId);
        } catch (Exception e) {
            log.error("[AwaitApprovalStrategy] Failed to set approval timeout", e);
        }
    }

    /**
     * 정책 변경 제안 필요 여부 판단
     */
    private boolean shouldProposePolicyChange(SecurityEventContext context) {
        // AI 분석 결과에 정책 변경 권장사항이 있는 경우
        if (context.getAiAnalysisResult() != null &&
            context.getAiAnalysisResult().getRecommendedActions() != null) {
            return context.getAiAnalysisResult().getRecommendedActions()
                .containsKey("POLICY_UPDATE");
        }

        // 반복적인 패턴이 감지된 경우
        Object patternCount = context.getMetadata().get("patternRepeatCount");
        if (patternCount != null && (Integer) patternCount > 3) {
            return true;
        }

        return false;
    }

    /**
     * 정책 제안 준비
     */
    private PolicyDTO preparePolicyProposal(SecurityEvent event, SecurityEventContext context) {
        PolicyDTO.PolicyDTOBuilder builder = PolicyDTO.builder();

        // 정책 기본 정보 설정
        builder.name("AUTO_GENERATED_" + event.getEventType());
        builder.description("Auto-generated policy based on event: " + event.getEventId());

        // AI 권장사항 기반 설정
        if (context.getAiAnalysisResult() != null) {
            builder.confidenceScore(context.getAiAnalysisResult().getConfidence());
            builder.aiModel("SecurityPlaneAgent");
        }

        // 정책 효과 설정
        builder.effect(PolicyDTO.PolicyEffect.DENY); // 기본적으로 차단

        // 정책 출처 설정
        builder.source(PolicyDTO.PolicySource.AI_GENERATED);

        // 승인 상태 설정
        builder.approvalStatus(PolicyDTO.ApprovalStatus.PENDING);

        // 우선순위 설정 (높은 위험도일수록 높은 우선순위)
        builder.priority(context.isHighRisk() ? 100 : 50);

        // 시간 정보 설정
        builder.createdAt(LocalDateTime.now());
        builder.isActive(false); // 승인 전까지 비활성화

        PolicyDTO policy = builder.build();

        // 정책 변경 이벤트 발행
        eventPublisher.publishEvent(new PolicyChangeEvent(
            this,
            policy,
            PolicyChangeEvent.ChangeType.CREATED,
            "SecurityPlaneAgent"
        ));

        return policy;
    }

    /**
     * 승인 이유 판단
     */
    private String determineApprovalReason(SecurityEventContext context) {
        StringBuilder reason = new StringBuilder("Human approval required: ");

        if (context.isHighRisk()) {
            reason.append("High risk event; ");
        }

        if (context.getAiAnalysisResult() != null) {
            SecurityEventContext.AIAnalysisResult aiResult = context.getAiAnalysisResult();
            if (aiResult.getThreatLevel() >= 8.0) {
                reason.append("Critical threat level; ");
            }
            if (aiResult.getConfidence() < 0.5) {
                reason.append("Low AI confidence; ");
            }
        }

        Object criticalAction = context.getMetadata().get("criticalAction");
        if (criticalAction != null && (Boolean) criticalAction) {
            reason.append("Critical action requested; ");
        }

        return reason.toString();
    }

    /**
     * 요청 액션 결정
     */
    private List<String> determineRequestedActions(SecurityEventContext context) {
        List<String> actions = new ArrayList<>();

        // AI 권장 액션
        if (context.getAiAnalysisResult() != null &&
            context.getAiAnalysisResult().getRecommendedActions() != null) {
            actions.addAll(context.getAiAnalysisResult().getRecommendedActions().keySet());
        }

        // 기본 크리티컬 액션
        if (context.isHighRisk()) {
            if (!actions.contains("BLOCK_USER")) {
                actions.add("BLOCK_USER");
            }
            if (!actions.contains("ISOLATE_SYSTEM")) {
                actions.add("ISOLATE_SYSTEM");
            }
        }

        return actions;
    }

    /**
     * 승인 레벨 결정
     */
    private String determineApprovalLevel(SecurityEventContext context) {
        if (context.getAiAnalysisResult() != null) {
            double threatLevel = context.getAiAnalysisResult().getThreatLevel();
            if (threatLevel >= 9.0) {
                return "EXECUTIVE"; // C-레벨 승인 필요
            } else if (threatLevel >= 7.0) {
                return "MANAGER"; // 관리자 승인 필요
            }
        }
        return "OPERATOR"; // 운영자 승인 가능
    }

    /**
     * 잠재적 영향 판단
     */
    private String determinePotentialImpact(SecurityEventContext context) {
        StringBuilder impact = new StringBuilder();

        if (context.isHighRisk()) {
            impact.append("Critical security impact: potential data breach or system compromise. ");
        }

        if (context.getMetadata().containsKey("affectedSystems")) {
            impact.append("Affected systems: ")
                  .append(context.getMetadata().get("affectedSystems"))
                  .append(". ");
        }

        if (context.getMetadata().containsKey("estimatedUsers")) {
            impact.append("Estimated affected users: ")
                  .append(context.getMetadata().get("estimatedUsers"))
                  .append(". ");
        }

        if (context.getAiAnalysisResult() != null) {
            double threatLevel = context.getAiAnalysisResult().getThreatLevel();
            if (threatLevel >= 8.0) {
                impact.append("Severity: CRITICAL. Immediate action required. ");
            } else if (threatLevel >= 5.0) {
                impact.append("Severity: HIGH. Prompt action recommended. ");
            }
        }

        return impact.length() > 0 ? impact.toString() : "Security action requires approval";
    }

    @Override
    public ProcessingMode getSupportedMode() {
        return ProcessingMode.AWAIT_APPROVAL;
    }
}