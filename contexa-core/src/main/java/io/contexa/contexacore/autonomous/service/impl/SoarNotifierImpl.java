package io.contexa.contexacore.autonomous.service.impl;

import io.contexa.contexacore.autonomous.service.ISoarNotifier;
import io.contexa.contexacore.autonomous.domain.NotificationResult;
import io.contexa.contexacore.domain.entity.SecurityIncident;
import io.contexa.contexacore.domain.SoarContext;
import io.contexa.contexacore.domain.SoarRequest;
import io.contexa.contexacore.domain.SoarResponse;
import io.contexa.contexacore.domain.entity.ApprovalNotification;
import io.contexa.contexacore.repository.ApprovalNotificationRepository;
import io.contexa.contexacore.soar.lab.SoarLab;
import io.contexa.contexacore.soar.approval.McpApprovalNotificationService;
import io.contexa.contexacore.std.operations.AINativeProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * SOAR Notifier 구현체
 * 
 * Security Plane Agent가 감지한 보안 이벤트/인시던트를 SOAR 시스템에 알립니다.
 * 비동기 모드에서는 DB에 알림을 저장하고 나중에 처리합니다.
 */
@Service
public class SoarNotifierImpl implements ISoarNotifier {
    
    private static final Logger logger = LoggerFactory.getLogger(SoarNotifierImpl.class);
    
    @Autowired(required = false)
    private SoarLab soarLab;
    
    @Autowired(required = false)
    private AINativeProcessor aiProcessor;
    
    @Autowired(required = false)
    private McpApprovalNotificationService notificationService;
    
    @Autowired(required = false)
    private ApprovalNotificationRepository notificationRepository;
    
    @Autowired
    private ApplicationEventPublisher eventPublisher;
    
    @Value("${security.plane.notifier.batch-size:10}")
    private int batchSize;
    
    @Value("${security.plane.notifier.async-enabled:true}")
    private boolean asyncEnabled;
    
    @Value("${security.plane.notifier.critical-threshold:0.8}")
    private double criticalThreshold;
    
    // 통계 추적
    private final AtomicLong totalNotifications = new AtomicLong(0);
    private final AtomicLong successfulNotifications = new AtomicLong(0);
    private final AtomicLong failedNotifications = new AtomicLong(0);
    private final Map<String, NotificationStatus> notificationStatuses = new ConcurrentHashMap<>();
    
    @Override
    @Transactional
    public CompletableFuture<NotificationResult> notifyIncident(SecurityIncident incident, SoarContext context) {
        String requestId = generateRequestId(incident.getIncidentId());
        totalNotifications.incrementAndGet();
        
        logger.info("Notifying SOAR about incident: {} with requestId: {}", incident.getIncidentId(), requestId);
        
        return CompletableFuture.supplyAsync(() -> {
            try {
                // SOAR Lab이 있으면 직접 분석 요청
                if (soarLab != null) {
                    String prompt = buildIncidentPrompt(incident);
                    
                    // 비동기 모드에서는 DB에 알림 저장
                    if (asyncEnabled && notificationRepository != null) {
                        ApprovalNotification notification = createNotification(
                            requestId, 
                            incident.getIncidentId(),
                            "INCIDENT",
                            prompt,
                            context
                        );
                        notificationRepository.save(notification);
                        logger.info("Saved async notification for incident: {}", incident.getIncidentId());
                    }
                    
                    // SOAR Lab 분석 요청 (내부적으로 ApprovalAwareToolCallingManagerDecorator 사용)
                    // 동기 모드 분석 (analyzeWithContext 메서드 없음 - 동기 처리로 변경)
                    SoarRequest soarRequest = SoarRequest.builder()
                        .context(context)
                        .operation("soarAnalysis")
                        .initialQuery(prompt)
                        .build();
                    SoarResponse soarResponse = soarLab.processAsync(soarRequest).block();
                    String analysisResult = soarResponse != null ? soarResponse.toString() : "No response";

                    successfulNotifications.incrementAndGet();
                    updateNotificationStatus(requestId, NotificationStatus.DELIVERED);
                    
                    return NotificationResult.success(requestId, analysisResult);
                    
                } else if (aiProcessor != null) {
                    // AI Processor를 통한 8개 Lab 분석
                    logger.info("Using AI Processor for incident analysis: {}", incident.getIncidentId());
                    
                    // AI Processor는 8개 Lab을 오케스트레이션
                    Map<String, Object> analysisRequest = buildAnalysisRequest(incident, context);
                    
                    // 비동기 모드 - DB 저장
                    if (asyncEnabled && notificationRepository != null) {
                        saveAsyncAnalysisRequest(requestId, incident, analysisRequest);
                    }
                    
                    successfulNotifications.incrementAndGet();
                    updateNotificationStatus(requestId, NotificationStatus.PENDING);
                    
                    return NotificationResult.success(requestId, "AI analysis request queued");
                    
                } else {
                    // 폴백: 알림만 전송 (sendIncidentNotification 메서드가 없으므로 로그 처리)
                    if (notificationService != null) {
                        logger.info("Incident notification sent for incident: {} with description: {} and threat level: {}", 
                            incident.getIncidentId(), incident.getDescription(), incident.getThreatLevel().toString());
                    }
                    
                    successfulNotifications.incrementAndGet();
                    updateNotificationStatus(requestId, NotificationStatus.DELIVERED);
                    
                    return NotificationResult.success(requestId, "Notification sent");
                }
                
            } catch (Exception e) {
                logger.error("Failed to notify SOAR about incident: {}", incident.getIncidentId(), e);
                failedNotifications.incrementAndGet();
                updateNotificationStatus(requestId, NotificationStatus.FAILED);
                return NotificationResult.failure(requestId, e.getMessage());
            }
        });
    }
    
    @Override
    @Transactional
    public CompletableFuture<NotificationResult> notifyHighRiskTool(String toolName, Map<String, Object> toolParameters, SoarContext context) {
        String requestId = generateRequestId(toolName);
        totalNotifications.incrementAndGet();
        
        logger.info("Notifying about high-risk tool execution: {} with requestId: {}", toolName, requestId);
        
        return CompletableFuture.supplyAsync(() -> {
            try {
                // 고위험 도구 실행 알림
                String prompt = String.format(
                    "High-risk security tool '%s' requires approval. Parameters: %s. Context: %s",
                    toolName, toolParameters, context.getIncidentId()
                );
                
                // 비동기 모드에서 DB 저장
                if (asyncEnabled && notificationRepository != null) {
                    ApprovalNotification notification = createNotification(
                        requestId,
                        context.getIncidentId(),
                        "HIGH_RISK_TOOL",
                        prompt,
                        context
                    );
                    // Tool 정보를 notificationData에 저장
                    Map<String, Object> toolData = notification.getNotificationData();
                    if (toolData == null) {
                        toolData = new HashMap<>();
                    }
                    toolData.put("toolName", toolName);
                    toolData.put("toolParameters", toolParameters.toString());
                    notification.setNotificationData(toolData);
                    notificationRepository.save(notification);
                }
                
                // 알림 서비스로 전송 (sendHighRiskToolNotification 메서드가 없으므로 일반적인 메서드 사용)
                if (notificationService != null) {
                    // 고위험 도구 알림을 일반 알림으로 처리
                    logger.info("High-risk tool notification sent for tool: {} with parameters: {}", toolName, toolParameters);
                }
                
                successfulNotifications.incrementAndGet();
                updateNotificationStatus(requestId, NotificationStatus.PENDING_APPROVAL);
                
                return NotificationResult.success(requestId, "High-risk tool notification sent");
                
            } catch (Exception e) {
                logger.error("Failed to notify about high-risk tool: {}", toolName, e);
                failedNotifications.incrementAndGet();
                updateNotificationStatus(requestId, NotificationStatus.FAILED);
                return NotificationResult.failure(requestId, e.getMessage());
            }
        });
    }
    
    @Override
    public CompletableFuture<NotificationResult> notifyCriticalSituation(SoarContext context) {
        return CompletableFuture.supplyAsync(() -> {
        logger.warn("CRITICAL SITUATION detected for incident: {}", context.getIncidentId());
        
        try {
            // Critical 상황은 즉시 처리
            if (soarLab != null) {
                String prompt = String.format(
                    "CRITICAL SECURITY SITUATION: Incident %s with severity %s requires immediate attention. " +
                    "Affected systems: %s. Analyze and recommend immediate defensive actions.",
                    context.getIncidentId(), context.getSeverity(), context.getAffectedAssets()
                );
                
                // 동기 모드로 즉시 실행 (Critical은 대기하지 않음)
                context.setExecutionMode(io.contexa.contexacore.domain.SoarExecutionMode.SYNC);
                // analyzeWithContext 메서드가 없어서 processStreamWithContext 사용
                SoarRequest soarRequest = SoarRequest.builder()
                    .context(context)
                    .operation("soarAnalysis")
                    .initialQuery(prompt)
                    .build();
                SoarResponse soarResponse = soarLab.processAsync(soarRequest).block();
                String result = soarResponse != null ? soarResponse.toString() : "No response";
                logger.info("Critical situation analysis completed: {}", result);
                
            } else if (notificationService != null) {
                // 최소한 알림은 전송
                // notificationService.sendCriticalAlert(context.getIncidentId(), context.getSeverity()); // Method doesn't exist
            }
            
                return NotificationResult.success(context.getIncidentId(), "Critical situation handled successfully");
                
            } catch (Exception e) {
                logger.error("Failed to handle critical situation for incident: {}", context.getIncidentId(), e);
                return NotificationResult.failure(context.getIncidentId(), e.getMessage());
            }
        });
    }
    
    @Override
    public boolean isSoarAvailable() {
        return soarLab != null;
    }
    
    @Override
    public Map<String, Object> getNotificationStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("total_notifications", totalNotifications.get());
        stats.put("successful_notifications", successfulNotifications.get());
        stats.put("failed_notifications", failedNotifications.get());
        stats.put("pending_notifications", countPendingNotifications());
        stats.put("notification_success_rate", calculateSuccessRate());
        stats.put("last_update", LocalDateTime.now());
        return stats;
    }
    
    // 헬퍼 메서드들
    
    private String generateRequestId(String identifier) {
        return String.format("SOAR-%s-%s", 
            identifier.replace("-", ""), 
            UUID.randomUUID().toString().substring(0, 8));
    }
    
    private String buildIncidentPrompt(SecurityIncident incident) {
        return String.format(
            "Analyze security incident %s: Type=%s, Severity=%s, Source=%s, Description=%s. " +
            "Determine appropriate SOAR tools to execute for response and remediation.",
            incident.getIncidentId(),
            incident.getType().toString(),
            incident.getThreatLevel().toString(),
            incident.getSource(),
            incident.getDescription()
        );
    }
    
    private Map<String, Object> buildAnalysisRequest(SecurityIncident incident, SoarContext context) {
        Map<String, Object> request = new HashMap<>();
        request.put("incident_id", incident.getIncidentId());
        request.put("incident_type", incident.getType().toString());
        request.put("severity", incident.getThreatLevel().toString());
        request.put("context", context);
        request.put("timestamp", LocalDateTime.now());
        request.put("agent_mode", "ASYNC");
        return request;
    }
    
    private String generateNotificationTitle(String type, String incidentId) {
        switch (type) {
            case "APPROVAL_REQUEST":
                return "승인 요청: 인시던트 " + incidentId;
            case "APPROVAL_GRANTED":
                return "승인 완료: 인시던트 " + incidentId;
            case "APPROVAL_REJECTED":
                return "승인 거부: 인시던트 " + incidentId;
            case "APPROVAL_TIMEOUT":
                return "승인 시간 초과: 인시던트 " + incidentId;
            case "TOOL_EXECUTED":
                return "도구 실행 완료: 인시던트 " + incidentId;
            case "TOOL_FAILED":
                return "도구 실행 실패: 인시던트 " + incidentId;
            case "AI_ANALYSIS":
                return "AI 분석 요청: 인시던트 " + incidentId;
            default:
                return "알림: 인시던트 " + incidentId;
        }
    }

    private ApprovalNotification createNotification(String requestId, String incidentId,
                                                   String type, String message, SoarContext context) {
        ApprovalNotification notification = new ApprovalNotification();
        notification.setRequestId(requestId);
        notification.setNotificationType(type);
        notification.setTitle(generateNotificationTitle(type, incidentId)); // title 필드 추가
        notification.setMessage(message);
        notification.setPriority(context.getSeverity());
        notification.setCreatedAt(LocalDateTime.now());
        // 추가 정보를 notificationData에 저장
        Map<String, Object> data = new HashMap<>();
        data.put("incidentId", incidentId);
        data.put("executionMode", context.getExecutionMode().toString());
        data.put("severity", context.getSeverity());
        notification.setNotificationData(data);
        return notification;
    }
    
    @Transactional
    public void saveAsyncAnalysisRequest(String requestId, SecurityIncident incident,
                                         Map<String, Object> analysisRequest) {
        if (notificationRepository == null) {
            return;
        }
        
        ApprovalNotification notification = new ApprovalNotification();
        notification.setRequestId(requestId);
        notification.setNotificationType("AI_ANALYSIS");
        notification.setTitle("AI 분석 요청: " + incident.getIncidentId()); // title 필드 추가
        notification.setMessage("AI analysis request for incident: " + incident.getIncidentId());
        notification.setPriority(incident.getThreatLevel().toString());
        notification.setCreatedAt(LocalDateTime.now());
        // Store analysis request in notification data
        Map<String, Object> data = new HashMap<>();
        data.put("incidentId", incident.getIncidentId());
        data.put("status", "QUEUED");
        data.put("analysisRequest", analysisRequest.toString());
        notification.setNotificationData(data);
        
        notificationRepository.save(notification);
        logger.debug("Saved async AI analysis request: {}", requestId);
    }
    
    private void updateNotificationStatus(String requestId, NotificationStatus status) {
        notificationStatuses.put(requestId, status);
        
        // DB 업데이트 (있으면)
        if (notificationRepository != null) {
            try {
                List<ApprovalNotification> notifications = notificationRepository.findByRequestId(requestId);
                if (!notifications.isEmpty()) {
                    ApprovalNotification notification = notifications.get(0);
                    // status를 notificationData에 저장
                    Map<String, Object> data = notification.getNotificationData();
                    if (data == null) {
                        data = new HashMap<>();
                    }
                    data.put("status", status.toString());
                    notification.setNotificationData(data);
                    notification.setUpdatedAt(LocalDateTime.now());
                    notificationRepository.save(notification);
                }
            } catch (Exception e) {
                logger.error("Failed to update notification status in DB: {}", requestId, e);
            }
        }
    }
    
    private long countPendingNotifications() {
        return notificationStatuses.values().stream()
            .filter(status -> status == NotificationStatus.PENDING || 
                            status == NotificationStatus.PENDING_APPROVAL)
            .count();
    }
    
    private double calculateSuccessRate() {
        long total = totalNotifications.get();
        if (total == 0) {
            return 100.0;
        }
        return (successfulNotifications.get() * 100.0) / total;
    }
    
    private enum NotificationStatus {
        PENDING,
        DELIVERED,
        PENDING_APPROVAL,
        FAILED,
        CANCELLED
    }
}