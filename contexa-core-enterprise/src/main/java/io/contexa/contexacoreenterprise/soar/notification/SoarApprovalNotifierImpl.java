package io.contexa.contexacoreenterprise.soar.notification;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.notification.SoarApprovalNotifier;
import io.contexa.contexacoreenterprise.config.NotificationConfig.NotificationTargetManager;
import io.contexa.contexacore.domain.ApprovalRequest;
import io.contexa.contexacore.domain.ApprovalRequest.ApprovalStatus;
import io.contexa.contexacoreenterprise.soar.approval.McpApprovalNotificationService;
import io.contexa.contexacoreenterprise.soar.approval.ApprovalRequestFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.scheduling.annotation.Async;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

/**
 * SOAR 승인 알림 처리기 구현체
 * 다중 채널(WebSocket, Email, SSE)을 통한 승인 알림을 처리합니다.
 */
@Slf4j
@RequiredArgsConstructor
public class SoarApprovalNotifierImpl implements SoarApprovalNotifier {
    
    private final @Qualifier("brokerMessagingTemplate") SimpMessagingTemplate brokerMessagingTemplate;
    private final SoarEmailService emailService;
    private final McpApprovalNotificationService mcpNotificationService;
    private final NotificationTargetManager targetManager;
    
    @Autowired
    private ApprovalRequestFactory approvalRequestFactory;
    
    @Value("${soar.notification.websocket.enabled:true}")
    private boolean webSocketEnabled;
    
    @Value("${soar.notification.sse.enabled:true}")
    private boolean sseEnabled;
    
    @Value("${soar.notification.websocket.topic-prefix:/topic/soar}")
    private String topicPrefix;

    /**
     * 승인 요청 알림 전송 (모든 채널)
     */
    @Async
    public void notifyApprovalRequest(ApprovalNotification notification) {
        log.info("다중 채널 승인 요청 알림 시작: {}", notification.getApprovalId());
        
        // 알림 대상 결정
        List<NotificationTarget> targets = determineNotificationTargets(notification);
        
        if (targets.isEmpty()) {
            log.warn("알림 대상이 없습니다: {}", notification.getApprovalId());
            // 기본 대상에게 알림
            targets = getDefaultTargets();
        }
        
        // 위험도별 채널 결정
        Set<NotificationTarget.NotificationChannel> channels = 
            determineChannelsByRiskLevel(notification.getRiskLevel());
        
        // 각 채널별 알림 전송
        List<CompletableFuture<Void>> futures = new ArrayList<>();
        
        if (channels.contains(NotificationTarget.NotificationChannel.WEBSOCKET)) {
            futures.add(sendWebSocketNotification(notification, targets));
        }
        
        if (channels.contains(NotificationTarget.NotificationChannel.EMAIL)) {
//            futures.add(sendEmailNotifications(notification, targets));
        }
        
        if (channels.contains(NotificationTarget.NotificationChannel.SSE)) {
            futures.add(sendSSENotification(notification));
        }
        
        // 모든 알림 완료 대기
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
            .whenComplete((result, error) -> {
                if (error != null) {
                    log.error("일부 알림 전송 실패: {}", notification.getApprovalId(), error);
                } else {
                    log.info("모든 알림 전송 완료: {}", notification.getApprovalId());
                }
            });
    }
    
    /**
     * WebSocket 알림 전송
     */
    private CompletableFuture<Void> sendWebSocketNotification(ApprovalNotification notification, 
                                                              List<NotificationTarget> targets) {
        return CompletableFuture.runAsync(() -> {
            if (!webSocketEnabled) {
                log.debug("WebSocket 알림이 비활성화되어 있습니다.");
                return;
            }
            
            try {
                // 승인 요청 메시지 생성
                Map<String, Object> message = buildApprovalRequestMessage(notification);
                
                // 브로드캐스트 (모든 구독자에게)
                String topic = topicPrefix + "/approvals";
                brokerMessagingTemplate.convertAndSend(topic, message);
                log.info("WebSocket 알림 전송: {} -> {}", notification.getApprovalId(), topic);
                
                // 특정 사용자에게 개별 알림
                for (NotificationTarget target : targets) {
                    if (target.canReceiveWebSocket()) {
                        String userTopic = "/user/" + target.getTargetId() + "/queue/approval";
                        brokerMessagingTemplate.convertAndSendToUser(target.getTargetId(), "/queue/approval", message);
                        log.debug("WebSocket 개별 알림: {} -> {}", notification.getApprovalId(), target.getTargetId());
                    }
                }
                
            } catch (Exception e) {
                log.error("WebSocket 알림 전송 실패: {}", notification.getApprovalId(), e);
                throw new RuntimeException("WebSocket 알림 실패", e);
            }
        });
    }
    
    /**
     * 이메일 알림 전송
     */
    private CompletableFuture<Void> sendEmailNotifications(ApprovalNotification notification,
                                                          List<NotificationTarget> targets) {
        return CompletableFuture.runAsync(() -> {
            List<NotificationTarget> emailTargets = targets.stream()
                .filter(NotificationTarget::canReceiveEmail)
                .collect(Collectors.toList());
            
            if (emailTargets.isEmpty()) {
                log.debug("이메일 수신 가능한 대상이 없습니다.");
                return;
            }
            
            for (NotificationTarget target : emailTargets) {
                try {
                    emailService.sendApprovalRequestEmail(target, notification);
                    log.info("✉️ 이메일 알림 전송: {} -> {}", notification.getApprovalId(), target.getEmail());
                } catch (Exception e) {
                    log.error("이메일 전송 실패: {} -> {}", notification.getApprovalId(), target.getEmail(), e);
                }
            }
        });
    }
    
    /**
     * SSE 알림 전송
     */
    private CompletableFuture<Void> sendSSENotification(ApprovalNotification notification) {
        return CompletableFuture.runAsync(() -> {
            if (!sseEnabled) {
                log.debug("SSE 알림이 비활성화되어 있습니다.");
                return;
            }
            
            try {
                // McpApprovalNotificationService를 통한 SSE 전송
                io.contexa.contexacore.domain.ApprovalRequest request = convertToApprovalRequest(notification);
                mcpNotificationService.sendApprovalRequest(request);
                log.info("📻 SSE 알림 전송: {}", notification.getApprovalId());
            } catch (Exception e) {
                log.error("SSE 알림 전송 실패: {}", notification.getApprovalId(), e);
            }
        });
    }
    
    /**
     * 승인 완료 알림 전송
     */
    @Async
    public void notifyApprovalCompleted(String approvalId, boolean approved, String reason) {
        log.info("승인 완료 알림: {} - 승인: {}, 사유: {}", approvalId, approved, reason);
        
        // WebSocket 알림
        if (webSocketEnabled) {
            Map<String, Object> message = Map.of(
                "type", "APPROVAL_COMPLETED",
                "approvalId", approvalId,
                "approved", approved,
                "reason", reason,
                "timestamp", LocalDateTime.now()
            );
            
            String topic = topicPrefix + "/approvals";
            brokerMessagingTemplate.convertAndSend(topic, message);
        }
        
        // SSE 알림
        if (sseEnabled) {
            if (approved) {
                mcpNotificationService.sendApprovalGranted(approvalId);
            } else {
                mcpNotificationService.sendApprovalDenied(approvalId);
            }
        }
        
        // 이메일 알림 (요청자에게만)
        // TODO: 원래 요청자 정보를 저장하고 조회하는 로직 필요
    }
    
    /**
     * 승인 타임아웃 알림 전송
     */
    @Async
    public void notifyApprovalTimeout(String approvalId) {
        log.warn("⏰ 승인 타임아웃 알림: {}", approvalId);
        
        // WebSocket 알림
        if (webSocketEnabled) {
            Map<String, Object> message = Map.of(
                "type", "APPROVAL_TIMEOUT",
                "approvalId", approvalId,
                "timestamp", LocalDateTime.now()
            );
            
            String topic = topicPrefix + "/approvals";
            brokerMessagingTemplate.convertAndSend(topic, message);
        }
        
        // SSE 알림
        if (sseEnabled) {
            mcpNotificationService.sendApprovalTimeout(approvalId);
        }
    }
    
    /**
     * 알림 대상 결정
     */
    private List<NotificationTarget> determineNotificationTargets(ApprovalNotification notification) {
        List<NotificationTarget> targets = new ArrayList<>();
        
        // 1. 조직 관리자
        NotificationTarget adminTarget = targetManager.getTarget("admin");
        if (adminTarget != null) {
            targets.add(adminTarget);
        }
        
        // 2. 위험도별 대상
        String riskLevel = notification.getRiskLevel();
        if ("CRITICAL".equals(riskLevel) || "HIGH".equals(riskLevel)) {
            // 보안팀 추가
            targets.addAll(targetManager.getTargetsByRole("ROLE_SECURITY"));
            // SOC팀 추가
            targets.addAll(targetManager.getTargetsByRole("ROLE_SOC"));
        }
        
        // 3. 승인자 역할을 가진 모든 사용자
        targets.addAll(targetManager.getTargetsByRole("ROLE_APPROVER"));
        
        // 중복 제거
        return targets.stream()
            .distinct()
            .collect(Collectors.toList());
    }
    
    /**
     * 기본 알림 대상
     */
    private List<NotificationTarget> getDefaultTargets() {
        // 초기화되지 않은 경우를 대비한 기본 타겟
        NotificationTarget defaultTarget = NotificationTarget.createDefault(
            "system",
            "System Administrator",
            "admin@contexa.com"
        );
        return List.of(defaultTarget);
    }
    
    /**
     * 위험도별 알림 채널 결정
     */
    private Set<NotificationTarget.NotificationChannel> determineChannelsByRiskLevel(String riskLevel) {
        return switch (riskLevel) {
            case "CRITICAL", "HIGH" -> 
                Set.of(NotificationTarget.NotificationChannel.EMAIL,
                      NotificationTarget.NotificationChannel.WEBSOCKET,
                      NotificationTarget.NotificationChannel.SSE);
            case "MEDIUM" -> 
                Set.of(NotificationTarget.NotificationChannel.WEBSOCKET,
                      NotificationTarget.NotificationChannel.SSE);
            default -> 
                Set.of(NotificationTarget.NotificationChannel.WEBSOCKET);
        };
    }
    
    /**
     * 승인 요청 메시지 생성
     */
    private Map<String, Object> buildApprovalRequestMessage(ApprovalNotification notification) {
        Map<String, Object> message = new HashMap<>();
        message.put("type", "APPROVAL_REQUEST");
        message.put("approvalId", notification.getApprovalId());
        message.put("toolName", notification.getToolName());
        message.put("description", notification.getDescription());
        message.put("incidentId", notification.getIncidentId());
        message.put("organizationId", notification.getOrganizationId());
        message.put("riskLevel", notification.getRiskLevel());
        message.put("toolArguments", notification.getToolArguments());
        message.put("requestedAt", notification.getRequestedAt());
        message.put("requestedBy", notification.getRequestedBy());
        message.put("timeoutSeconds", notification.getTimeoutSeconds());
        message.put("timestamp", LocalDateTime.now());
        return message;
    }
    
    /**
     * Redis Pub/Sub 메시지 수신 핸들러
     * UnifiedRedisConfiguration에서 호출됩니다.
     */
    public void receiveApprovalNotification(ApprovalNotification notification) {
        log.info("Redis Pub/Sub으로 승인 알림 수신: {}", notification.getApprovalId());
        // 비동기로 알림 처리
        notifyApprovalRequest(notification);
    }
    
    /**
     * ApprovalNotification을 ApprovalRequest로 변환
     */
    private io.contexa.contexacore.domain.ApprovalRequest convertToApprovalRequest(ApprovalNotification notification) {
        // Factory를 사용하여 ApprovalRequest 생성
        ApprovalRequest request = approvalRequestFactory.createFromNotification(
            notification.getToolName(),
            notification.getDescription(),
            notification.getIncidentId(),
            notification.getRiskLevel(),
            notification.getToolArguments()
        );
        
        // 추가 필드 설정
        request.setRequestId(notification.getApprovalId());
        request.setOrganizationId(notification.getOrganizationId());
        request.setRequestedBy(notification.getRequestedBy());
        
        // status 확인 (Factory에서 이미 설정되지만 확실히 함)
        if (request.getStatus() == null) {
            request.setStatus(ApprovalStatus.PENDING);
            log.debug("Set status to PENDING for notification conversion");
        }
        
        return request;
    }

    /**
     * Core 인터페이스 구현: Redis 메시지를 수신하여 SOAR 승인 알림 처리
     * JSON 메시지를 파싱하여 ApprovalNotification 객체로 변환 후 처리
     */
    @Override
    public void receiveApprovalNotification(String message) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            ApprovalNotification notification = mapper.readValue(message, ApprovalNotification.class);
            receiveApprovalNotification(notification);
        } catch (Exception e) {
            log.error("승인 알림 메시지 파싱 실패: {}", message, e);
        }
    }

    /**
     * Core 인터페이스 구현: 승인 대기 중인 요청에 대해 재알림 전송
     */
    @Override
    public void sendApprovalReminder(String approvalId) {
        log.info("승인 재알림 전송: {}", approvalId);

        Map<String, Object> message = Map.of(
            "type", "APPROVAL_REMINDER",
            "approvalId", approvalId,
            "timestamp", LocalDateTime.now()
        );

        if (webSocketEnabled) {
            String topic = topicPrefix + "/approvals";
            brokerMessagingTemplate.convertAndSend(topic, message);
        }

        if (sseEnabled) {
            mcpNotificationService.sendApprovalReminder(approvalId);
        }
    }
}