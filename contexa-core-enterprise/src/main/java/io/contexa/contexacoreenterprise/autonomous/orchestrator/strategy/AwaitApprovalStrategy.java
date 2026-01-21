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

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;

@Slf4j
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
            
            ApprovalRequest approvalRequest = createApprovalRequest(event, context);
            executedActions.add("APPROVAL_REQUEST_CREATED");

            String approvalId = queueApprovalRequest(approvalRequest, context);
            metadata.put("approvalId", approvalId);
            executedActions.add("APPROVAL_QUEUED");

            if (soarNotifier != null) {
                NotificationResult notifyResult = sendApprovalNotification(
                    event, approvalRequest, approvalId);
                if (notifyResult.isSuccess()) {
                    executedActions.add("APPROVAL_NOTIFICATION_SENT");
                }
            }

            applyTemporaryMitigation(event, context, executedActions);

            setupApprovalTimeout(approvalId, context);

            if (shouldProposePolicyChange(context)) {
                PolicyDTO policyProposal = preparePolicyProposal(event, context);
                metadata.put("policyProposal", policyProposal);
                executedActions.add("POLICY_PROPOSAL_PREPARED");
            }

            context.updateProcessingStatus(SecurityEventContext.ProcessingStatus.AWAITING_APPROVAL);
            context.addMetadata("approvalRequired", true);
            context.addMetadata("approvalId", approvalId);

            metadata.put("approvalRequestedAt", System.currentTimeMillis());
            metadata.put("approvalTimeout", 300000); 
            metadata.put("approvalLevel", determineApprovalLevel(context));

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

    private ApprovalRequest createApprovalRequest(SecurityEvent event, SecurityEventContext context) {
        ApprovalRequest.ApprovalRequestBuilder builder = ApprovalRequest.builder();

        builder.requestId(UUID.randomUUID().toString());
        builder.incidentId(event.getEventId());
        builder.requestedBy(event.getUserId());
        builder.organizationId("DEFAULT_ORG");

        if (context.getAiAnalysisResult() != null) {
            SecurityEventContext.AIAnalysisResult aiResult = context.getAiAnalysisResult();

            Map<String, Object> metadata = new HashMap<>();
            metadata.put("threatLevel", aiResult.getThreatLevel());
            metadata.put("confidence", aiResult.getConfidence());

            if (aiResult.getRecommendedActions() != null) {
                metadata.put("recommendedActions", new ArrayList<>(aiResult.getRecommendedActions().keySet()));
            }
        }

        builder.requestReason(determineApprovalReason(context));

        boolean highRisk = context.getAiAnalysisResult() != null &&
                          context.getAiAnalysisResult().getThreatLevel() >= 0.7;
        builder.riskLevel(highRisk ?
            ApprovalRequest.RiskLevel.CRITICAL :
            ApprovalRequest.RiskLevel.HIGH);

        List<String> requestedActions = determineRequestedActions(context);
        Map<String, Object> actionParams = new HashMap<>();
        actionParams.put("requestedActions", requestedActions);
        actionParams.put("severity", event.getSeverity());
        actionParams.put("sourceIp", event.getSourceIp());
        builder.toolParameters(actionParams);

        builder.actionDescription("Security response actions for event: " + event.getEventId());

        builder.approvalType(ApprovalRequest.ApprovalType.MANUAL);

        builder.status(ApprovalRequest.ApprovalStatus.PENDING);

        builder.potentialImpact(determinePotentialImpact(context));

        builder.timeoutMinutes(5);

        return builder.build();
    }

    private String queueApprovalRequest(ApprovalRequest request, SecurityEventContext context) {
        String approvalId = UUID.randomUUID().toString();

        if (approvalService != null) {

            approvalId = request.getRequestId();
            approvalService.requestApproval(request); 
        } else {
            
            String approvalKey = "security:approvals:pending:" + approvalId;
            Map<String, Object> approvalData = new HashMap<>();
            approvalData.put("request", request);
            approvalData.put("context", context);
            approvalData.put("createdAt", System.currentTimeMillis());
            approvalData.put("status", "PENDING");

            redisTemplate.opsForHash().putAll(approvalKey, approvalData);
            redisTemplate.expire(approvalKey, Duration.ofMinutes(30));
        }

                return approvalId;
    }

    private NotificationResult sendApprovalNotification(SecurityEvent event,
                                                         ApprovalRequest request,
                                                         String approvalId) {
        try {
            Map<String, Object> notificationData = new HashMap<>();
            notificationData.put("alertLevel", "CRITICAL");
            notificationData.put("eventId", event.getEventId());
            notificationData.put("approvalId", approvalId);
            notificationData.put("eventSeverity", event.getSeverity());
            notificationData.put("userId", event.getUserId());
            notificationData.put("sourceIp", event.getSourceIp());
            notificationData.put("riskLevel", request.getRiskLevel());
            
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

    private void applyTemporaryMitigation(SecurityEvent event, SecurityEventContext context,
                                           List<String> executedActions) {
        try {
            
            if (event.getSessionId() != null) {
                String suspendKey = "security:suspended:sessions:" + event.getSessionId();
                redisTemplate.opsForValue().set(suspendKey, true, Duration.ofMinutes(5));
                context.addResponseAction("SESSION_SUSPENDED",
                    "Session temporarily suspended pending approval");
                executedActions.add("SESSION_SUSPENDED");
            }

            if (event.getUserId() != null) {
                String restrictKey = "security:restricted:users:" + event.getUserId();
                redisTemplate.opsForValue().set(restrictKey, "PENDING_APPROVAL", Duration.ofMinutes(5));
                context.addResponseAction("USER_RESTRICTED",
                    "User actions restricted pending approval");
                executedActions.add("USER_RESTRICTED");
            }

                    } catch (Exception e) {
            log.error("[AwaitApprovalStrategy] Failed to apply temporary mitigation", e);
        }
    }

    private void setupApprovalTimeout(String approvalId, SecurityEventContext context) {
        try {
            String timeoutKey = "security:approvals:timeout:" + approvalId;
            Map<String, Object> timeoutData = new HashMap<>();
            timeoutData.put("approvalId", approvalId);
            timeoutData.put("eventId", context.getSecurityEvent().getEventId());
            timeoutData.put("timeoutAt", System.currentTimeMillis() + 300000); 
            timeoutData.put("defaultAction", "DENY"); 

            redisTemplate.opsForHash().putAll(timeoutKey, timeoutData);
            redisTemplate.expire(timeoutKey, Duration.ofMinutes(6));

                    } catch (Exception e) {
            log.error("[AwaitApprovalStrategy] Failed to set approval timeout", e);
        }
    }

    private boolean shouldProposePolicyChange(SecurityEventContext context) {
        
        if (context.getAiAnalysisResult() != null &&
            context.getAiAnalysisResult().getRecommendedActions() != null) {
            return context.getAiAnalysisResult().getRecommendedActions()
                .containsKey("POLICY_UPDATE");
        }

        Object patternCount = context.getMetadata().get("patternRepeatCount");
        if (patternCount != null && (Integer) patternCount > 3) {
            return true;
        }

        return false;
    }

    private PolicyDTO preparePolicyProposal(SecurityEvent event, SecurityEventContext context) {
        PolicyDTO.PolicyDTOBuilder builder = PolicyDTO.builder();

        builder.name("AUTO_GENERATED_" + event.getSeverity());
        builder.description("Auto-generated policy based on event: " + event.getEventId());

        if (context.getAiAnalysisResult() != null) {
            builder.confidenceScore(context.getAiAnalysisResult().getConfidence());
            builder.aiModel("SecurityPlaneAgent");
        }

        builder.effect(PolicyDTO.PolicyEffect.DENY); 

        builder.source(PolicyDTO.PolicySource.AI_GENERATED);

        builder.approvalStatus(PolicyDTO.ApprovalStatus.PENDING);

        boolean highRiskPriority = context.getAiAnalysisResult() != null &&
                                   context.getAiAnalysisResult().getThreatLevel() >= 0.7;
        builder.priority(highRiskPriority ? 100 : 50);

        builder.createdAt(LocalDateTime.now());
        builder.isActive(false); 

        PolicyDTO policy = builder.build();

        eventPublisher.publishEvent(new PolicyChangeEvent(
            this,
            policy,
            PolicyChangeEvent.ChangeType.CREATED,
            "SecurityPlaneAgent"
        ));

        return policy;
    }

    private String determineApprovalReason(SecurityEventContext context) {
        StringBuilder reason = new StringBuilder("Human approval required: ");

        if (context.getAiAnalysisResult() != null && context.getAiAnalysisResult().getThreatLevel() >= 0.7) {
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

    private List<String> determineRequestedActions(SecurityEventContext context) {
        List<String> actions = new ArrayList<>();

        if (context.getAiAnalysisResult() != null &&
            context.getAiAnalysisResult().getRecommendedActions() != null) {
            actions.addAll(context.getAiAnalysisResult().getRecommendedActions().keySet());
        }

        boolean highRiskActions = context.getAiAnalysisResult() != null &&
                                  context.getAiAnalysisResult().getThreatLevel() >= 0.7;
        if (highRiskActions) {
            if (!actions.contains("BLOCK_USER")) {
                actions.add("BLOCK_USER");
            }
            if (!actions.contains("ISOLATE_SYSTEM")) {
                actions.add("ISOLATE_SYSTEM");
            }
        }

        return actions;
    }

    private String determineApprovalLevel(SecurityEventContext context) {
        if (context.getAiAnalysisResult() != null) {
            double threatLevel = context.getAiAnalysisResult().getThreatLevel();
            if (threatLevel >= 9.0) {
                return "EXECUTIVE"; 
            } else if (threatLevel >= 7.0) {
                return "MANAGER"; 
            }
        }
        return "OPERATOR"; 
    }

    private String determinePotentialImpact(SecurityEventContext context) {
        StringBuilder impact = new StringBuilder();

        if (context.getAiAnalysisResult() != null && context.getAiAnalysisResult().getThreatLevel() >= 0.7) {
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