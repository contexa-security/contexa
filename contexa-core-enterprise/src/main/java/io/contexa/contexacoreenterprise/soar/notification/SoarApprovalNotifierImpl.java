package io.contexa.contexacoreenterprise.soar.notification;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.autonomous.notification.SoarApprovalNotifier;
import io.contexa.contexacore.domain.ApprovalRequest;
import io.contexa.contexacore.domain.ApprovalRequest.ApprovalStatus;
import io.contexa.contexacoreenterprise.soar.approval.McpApprovalNotificationService;
import io.contexa.contexacoreenterprise.properties.SoarProperties;
import io.contexa.contexacoreenterprise.soar.approval.ApprovalRequestFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.scheduling.annotation.Async;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

@Slf4j
@RequiredArgsConstructor
public class SoarApprovalNotifierImpl implements SoarApprovalNotifier {

    private final @Qualifier("brokerMessagingTemplate") SimpMessagingTemplate brokerMessagingTemplate;
    private final SoarEmailService emailService;
    private final McpApprovalNotificationService mcpNotificationService;
    private final NotificationTargetManager targetManager;
    private final SoarProperties soarProperties;

    @Autowired
    private ApprovalRequestFactory approvalRequestFactory;

    @Async
    public void notifyApprovalRequest(ApprovalNotification notification) {

        List<NotificationTarget> targets = determineNotificationTargets(notification);

        if (targets.isEmpty()) {
            log.error("No notification targets found: {}", notification.getApprovalId());

            targets = getDefaultTargets();
        }

        Set<NotificationTarget.NotificationChannel> channels =
            determineChannelsByRiskLevel(notification.getRiskLevel());

        List<CompletableFuture<Void>> futures = new ArrayList<>();

        if (channels.contains(NotificationTarget.NotificationChannel.WEBSOCKET)) {
            futures.add(sendWebSocketNotification(notification, targets));
        }

        if (channels.contains(NotificationTarget.NotificationChannel.EMAIL)) {
            futures.add(sendEmailNotifications(notification, targets));
        }

        if (channels.contains(NotificationTarget.NotificationChannel.SSE)) {
            futures.add(sendSSENotification(notification));
        }

        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
            .whenComplete((result, error) -> {
                if (error != null) {
                    log.error("Partial notification delivery failure: {}", notification.getApprovalId(), error);
                }
            });
    }

    private CompletableFuture<Void> sendWebSocketNotification(ApprovalNotification notification,
                                                              List<NotificationTarget> targets) {
        return CompletableFuture.runAsync(() -> {
            if (!soarProperties.getNotification().getWebsocket().isEnabled()) {
                return;
            }

            try {

                Map<String, Object> message = buildApprovalRequestMessage(notification);

                String topic = soarProperties.getNotification().getWebsocket().getTopicPrefix() + "/approvals";
                brokerMessagingTemplate.convertAndSend(topic, (Object)message);

                for (NotificationTarget target : targets) {
                    if (target.canReceiveWebSocket()) {
                        brokerMessagingTemplate.convertAndSendToUser(target.getTargetId(), "/queue/approval", message);
                    }
                }

            } catch (Exception e) {
                log.error("WebSocket notification delivery failed: {}", notification.getApprovalId(), e);
                throw new RuntimeException("WebSocket notification failed", e);
            }
        });
    }

    private CompletableFuture<Void> sendEmailNotifications(ApprovalNotification notification,
                                                          List<NotificationTarget> targets) {
        return CompletableFuture.runAsync(() -> {
            List<NotificationTarget> emailTargets = targets.stream()
                .filter(NotificationTarget::canReceiveEmail)
                .collect(Collectors.toList());

            if (emailTargets.isEmpty()) {
                return;
            }

            for (NotificationTarget target : emailTargets) {
                try {
                    emailService.sendApprovalRequestEmail(target, notification);
                } catch (Exception e) {
                    log.error("Email delivery failed: {} -> {}", notification.getApprovalId(), target.getEmail(), e);
                }
            }
        });
    }

    private CompletableFuture<Void> sendSSENotification(ApprovalNotification notification) {
        return CompletableFuture.runAsync(() -> {
            if (!soarProperties.getNotification().getSse().isEnabled()) {
                return;
            }

            try {

                ApprovalRequest request = convertToApprovalRequest(notification);
                mcpNotificationService.sendApprovalRequest(request);
            } catch (Exception e) {
                log.error("SSE notification delivery failed: {}", notification.getApprovalId(), e);
            }
        });
    }

    @Async
    public void notifyApprovalCompleted(String approvalId, boolean approved, String reason) {

        if (soarProperties.getNotification().getWebsocket().isEnabled()) {
            Map<String, Object> message = Map.of(
                "type", "APPROVAL_COMPLETED",
                "approvalId", approvalId,
                "approved", approved,
                "reason", reason,
                "timestamp", LocalDateTime.now()
            );

            String topic = soarProperties.getNotification().getWebsocket().getTopicPrefix() + "/approvals";
            brokerMessagingTemplate.convertAndSend(topic, (Object)message);
        }

        if (soarProperties.getNotification().getSse().isEnabled()) {
            if (approved) {
                mcpNotificationService.sendApprovalGranted(approvalId);
            } else {
                mcpNotificationService.sendApprovalDenied(approvalId);
            }
        }

    }

    @Async
    public void notifyApprovalTimeout(String approvalId) {
        log.error("Approval timeout notification: {}", approvalId);

        if (soarProperties.getNotification().getWebsocket().isEnabled()) {
            Map<String, Object> message = Map.of(
                "type", "APPROVAL_TIMEOUT",
                "approvalId", approvalId,
                "timestamp", LocalDateTime.now()
            );

            String topic = soarProperties.getNotification().getWebsocket().getTopicPrefix() + "/approvals";
            brokerMessagingTemplate.convertAndSend(topic, (Object)message);
        }

        if (soarProperties.getNotification().getSse().isEnabled()) {
            mcpNotificationService.sendApprovalTimeout(approvalId);
        }
    }

    private List<NotificationTarget> determineNotificationTargets(ApprovalNotification notification) {
        List<NotificationTarget> targets = new ArrayList<>();

        NotificationTarget adminTarget = targetManager.getTarget("admin");
        if (adminTarget != null) {
            targets.add(adminTarget);
        }

        String riskLevel = notification.getRiskLevel();
        if ("CRITICAL".equals(riskLevel) || "HIGH".equals(riskLevel)) {

            targets.addAll(targetManager.getTargetsByRole("ROLE_SECURITY"));

            targets.addAll(targetManager.getTargetsByRole("ROLE_SOC"));
        }

        targets.addAll(targetManager.getTargetsByRole("ROLE_APPROVER"));

        return targets.stream()
            .distinct()
            .collect(Collectors.toList());
    }

    private List<NotificationTarget> getDefaultTargets() {

        NotificationTarget defaultTarget = NotificationTarget.createDefault(
            "system",
            "System Administrator",
            "admin@contexa.com"
        );
        return List.of(defaultTarget);
    }

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

    public void receiveApprovalNotification(ApprovalNotification notification) {

        notifyApprovalRequest(notification);
    }

    private ApprovalRequest convertToApprovalRequest(ApprovalNotification notification) {

        ApprovalRequest request = approvalRequestFactory.createFromNotification(
            notification.getToolName(),
            notification.getDescription(),
            notification.getIncidentId(),
            notification.getRiskLevel(),
            notification.getToolArguments()
        );

        request.setRequestId(notification.getApprovalId());
        request.setOrganizationId(notification.getOrganizationId());
        request.setRequestedBy(notification.getRequestedBy());

        if (request.getStatus() == null) {
            request.setStatus(ApprovalStatus.PENDING);
        }

        return request;
    }

    @Override
    public void receiveApprovalNotification(String message) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            ApprovalNotification notification = mapper.readValue(message, ApprovalNotification.class);
            receiveApprovalNotification(notification);
        } catch (Exception e) {
            log.error("Failed to parse approval notification message: {}", message, e);
        }
    }

    @Override
    public void sendApprovalReminder(String approvalId) {

        Map<String, Object> message = Map.of(
            "type", "APPROVAL_REMINDER",
            "approvalId", approvalId,
            "timestamp", LocalDateTime.now()
        );

        if (soarProperties.getNotification().getWebsocket().isEnabled()) {
            String topic = soarProperties.getNotification().getWebsocket().getTopicPrefix() + "/approvals";
            brokerMessagingTemplate.convertAndSend(topic, (Object)message);
        }

        if (soarProperties.getNotification().getSse().isEnabled()) {
            mcpNotificationService.sendApprovalReminder(approvalId);
        }
    }
}
