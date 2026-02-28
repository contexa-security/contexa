package io.contexa.contexacoreenterprise.soar.notification;

import io.contexa.contexacoreenterprise.properties.SoarProperties;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.messaging.MessagingException;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Retryable;
import org.springframework.scheduling.annotation.Async;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Slf4j
@RequiredArgsConstructor
public class SoarEmailService {
    
    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;
    private final SoarProperties soarProperties;
    
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    @Async
    @Retryable(retryFor = {MessagingException.class, RuntimeException.class}, maxAttempts = 3, backoff = @Backoff(delay = 1000))
    public void sendApprovalRequestEmail(NotificationTarget target, ApprovalNotification notification) {
        if (!soarProperties.getNotification().getEmail().isEnabled()) {
                        return;
        }
        
        try {
            String subject = buildApprovalRequestSubject(notification);
            String htmlContent = buildApprovalRequestHtml(notification, target);
            
            sendHtmlEmail(target.getEmail(), subject, htmlContent);

        } catch (Exception e) {
            log.error("Approval request email send failed: {} -> {}", notification.getApprovalId(), target.getEmail(), e);
            throw new RuntimeException("Email send failed", e);
        }
    }

    @Async
    @Retryable(retryFor = MessagingException.class, maxAttempts = 3, backoff = @Backoff(delay = 1000))
    public void sendApprovalCompletedEmail(NotificationTarget target, String approvalId, 
                                          boolean approved, String reviewer, String comment) {
        if (!soarProperties.getNotification().getEmail().isEnabled()) {
                        return;
        }
        
        try {
            String subject = String.format("[SOAR] Approval request %s: %s",
                approved ? "Approved" : "Denied", approvalId);
            
            Context context = new Context();
            context.setVariable("approvalId", approvalId);
            context.setVariable("approved", approved);
            context.setVariable("reviewer", reviewer);
            context.setVariable("comment", comment);
            context.setVariable("timestamp", LocalDateTime.now().format(DATE_FORMATTER));
            context.setVariable("soarProperties.getNotification().getEmail().getBaseUrl()", soarProperties.getNotification().getEmail().getBaseUrl());
            
            String htmlContent = templateEngine.process("email/approval-completed", context);
            
            sendHtmlEmail(target.getEmail(), subject, htmlContent);

        } catch (Exception e) {
            log.error("Approval completion email send failed: {} -> {}", approvalId, target.getEmail(), e);
        }
    }

    @Async
    public void sendApprovalTimeoutEmail(NotificationTarget target, String approvalId, String toolName) {
        if (!soarProperties.getNotification().getEmail().isEnabled()) {
            return;
        }
        
        try {
            String subject = String.format("[SOAR] Approval request timeout: %s", toolName);
            
            Context context = new Context();
            context.setVariable("approvalId", approvalId);
            context.setVariable("toolName", toolName);
            context.setVariable("timestamp", LocalDateTime.now().format(DATE_FORMATTER));
            context.setVariable("soarProperties.getNotification().getEmail().getBaseUrl()", soarProperties.getNotification().getEmail().getBaseUrl());
            
            String htmlContent = templateEngine.process("email/approval-timeout", context);
            
            sendHtmlEmail(target.getEmail(), subject, htmlContent);

        } catch (Exception e) {
            log.error("Timeout email send failed: {} -> {}", approvalId, target.getEmail(), e);
        }
    }

    public void sendEmail(String to, String subject, String content) {
        if (!soarProperties.getNotification().getEmail().isEnabled()) {
                        return;
        }
        
        try {
            sendHtmlEmail(to, subject, content);
                    } catch (Exception e) {
            log.error("Email send failed: {} -> {}", subject, to, e);
            throw new RuntimeException("Email send failed", e);
        }
    }

    private void sendHtmlEmail(String to, String subject, String htmlContent) throws MessagingException, jakarta.mail.MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
        
        helper.setFrom(soarProperties.getNotification().getEmail().getFromAddress());
        helper.setTo(to);
        helper.setSubject(subject);
        helper.setText(htmlContent, true);
        
        mailSender.send(message);
    }

    private String buildApprovalRequestSubject(ApprovalNotification notification) {
        String riskIndicator = getRiskIndicator(notification.getRiskLevel());
        return String.format("[SOAR] %s Approval request: %s", riskIndicator, notification.getToolName());
    }

    private String buildApprovalRequestHtml(ApprovalNotification notification, NotificationTarget target) {
        Context context = new Context();

        context.setVariable("recipientName", target.getName());
        context.setVariable("approvalId", notification.getApprovalId());
        context.setVariable("toolName", notification.getToolName());
        context.setVariable("description", notification.getDescription());
        context.setVariable("incidentId", notification.getIncidentId());
        context.setVariable("riskLevel", notification.getRiskLevel());
        context.setVariable("riskColor", getRiskColor(notification.getRiskLevel()));
        context.setVariable("requestedBy", notification.getRequestedBy());
        context.setVariable("requestedAt", notification.getRequestedAt().toString());

        context.setVariable("toolArguments", notification.getToolArguments());

        String approveUrl = String.format("%s/api/soar/approval/%s/approve", soarProperties.getNotification().getEmail().getBaseUrl(), notification.getApprovalId());
        String rejectUrl = String.format("%s/api/soar/approval/%s/reject", soarProperties.getNotification().getEmail().getBaseUrl(), notification.getApprovalId());
        context.setVariable("approveUrl", approveUrl);
        context.setVariable("rejectUrl", rejectUrl);

        long timeoutMinutes = notification.getTimeoutSeconds() / 60;
        context.setVariable("timeoutMinutes", timeoutMinutes);

        context.setVariable("soarProperties.getNotification().getEmail().getBaseUrl()", soarProperties.getNotification().getEmail().getBaseUrl());
        context.setVariable("timestamp", LocalDateTime.now().format(DATE_FORMATTER));
        
        return templateEngine.process("email/approval-request", context);
    }

    private String getRiskIndicator(String riskLevel) {
        return switch (riskLevel) {
            case "CRITICAL" -> "[CRITICAL]";
            case "HIGH" -> "[HIGH]";
            case "MEDIUM" -> "[MEDIUM]";
            case "LOW" -> "[LOW]";
            default -> "[INFO]";
        };
    }

    private String getRiskColor(String riskLevel) {
        return switch (riskLevel) {
            case "CRITICAL" -> "#dc2626";
            case "HIGH" -> "#ea580c";
            case "MEDIUM" -> "#ca8a04";
            case "LOW" -> "#16a34a";
            default -> "#6b7280";
        };
    }

}