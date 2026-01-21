package io.contexa.contexacoreenterprise.soar.notification;

import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
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
    
    @Value("${spring.mail.username:noreply@contexa.com}")
    private String fromAddress;
    
    @Value("${soar.notification.email.enabled:true}")
    private boolean emailEnabled;
    
    @Value("${soar.notification.email.base-url:http://localhost:8080}")
    private String baseUrl;
    
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    @Async
    @Retryable(value = MessagingException.class, maxAttempts = 3, backoff = @Backoff(delay = 1000))
    public void sendApprovalRequestEmail(NotificationTarget target, ApprovalNotification notification) {
        if (!emailEnabled) {
                        return;
        }
        
        try {
            String subject = buildApprovalRequestSubject(notification);
            String htmlContent = buildApprovalRequestHtml(notification, target);
            
            sendHtmlEmail(target.getEmail(), subject, htmlContent);

        } catch (Exception e) {
            log.error("승인 요청 이메일 전송 실패: {} -> {}", notification.getApprovalId(), target.getEmail(), e);
            throw new RuntimeException("이메일 전송 실패", e);
        }
    }

    @Async
    @Retryable(retryFor = MessagingException.class, maxAttempts = 3, backoff = @Backoff(delay = 1000))
    public void sendApprovalCompletedEmail(NotificationTarget target, String approvalId, 
                                          boolean approved, String reviewer, String comment) {
        if (!emailEnabled) {
                        return;
        }
        
        try {
            String subject = String.format("[SOAR] 승인 요청 %s: %s", 
                approved ? "승인됨" : "거부됨", approvalId);
            
            Context context = new Context();
            context.setVariable("approvalId", approvalId);
            context.setVariable("approved", approved);
            context.setVariable("reviewer", reviewer);
            context.setVariable("comment", comment);
            context.setVariable("timestamp", LocalDateTime.now().format(DATE_FORMATTER));
            context.setVariable("baseUrl", baseUrl);
            
            String htmlContent = templateEngine.process("email/approval-completed", context);
            
            sendHtmlEmail(target.getEmail(), subject, htmlContent);

        } catch (Exception e) {
            log.error("승인 완료 이메일 전송 실패: {} -> {}", approvalId, target.getEmail(), e);
        }
    }

    @Async
    public void sendApprovalTimeoutEmail(NotificationTarget target, String approvalId, String toolName) {
        if (!emailEnabled) {
            return;
        }
        
        try {
            String subject = String.format("[SOAR] 승인 요청 타임아웃: %s", toolName);
            
            Context context = new Context();
            context.setVariable("approvalId", approvalId);
            context.setVariable("toolName", toolName);
            context.setVariable("timestamp", LocalDateTime.now().format(DATE_FORMATTER));
            context.setVariable("baseUrl", baseUrl);
            
            String htmlContent = templateEngine.process("email/approval-timeout", context);
            
            sendHtmlEmail(target.getEmail(), subject, htmlContent);

        } catch (Exception e) {
            log.error("타임아웃 이메일 전송 실패: {} -> {}", approvalId, target.getEmail(), e);
        }
    }

    public void sendEmail(String to, String subject, String content) {
        if (!emailEnabled) {
                        return;
        }
        
        try {
            sendHtmlEmail(to, subject, content);
                    } catch (Exception e) {
            log.error("이메일 전송 실패: {} -> {}", subject, to, e);
            throw new RuntimeException("이메일 전송 실패", e);
        }
    }

    private void sendHtmlEmail(String to, String subject, String htmlContent) throws MessagingException, jakarta.mail.MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
        
        helper.setFrom(fromAddress);
        helper.setTo(to);
        helper.setSubject(subject);
        helper.setText(htmlContent, true);
        
        mailSender.send(message);
    }

    private String buildApprovalRequestSubject(ApprovalNotification notification) {
        String riskIndicator = getRiskIndicator(notification.getRiskLevel());
        return String.format("[SOAR] %s 승인 요청: %s", riskIndicator, notification.getToolName());
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

        String approveUrl = String.format("%s/api/soar/approval/%s/approve", baseUrl, notification.getApprovalId());
        String rejectUrl = String.format("%s/api/soar/approval/%s/reject", baseUrl, notification.getApprovalId());
        context.setVariable("approveUrl", approveUrl);
        context.setVariable("rejectUrl", rejectUrl);

        long timeoutMinutes = notification.getTimeoutSeconds() / 60;
        context.setVariable("timeoutMinutes", timeoutMinutes);

        context.setVariable("baseUrl", baseUrl);
        context.setVariable("timestamp", LocalDateTime.now().format(DATE_FORMATTER));
        
        return templateEngine.process("email/approval-request", context);
    }

    private String getRiskIndicator(String riskLevel) {
        return switch (riskLevel) {
            case "CRITICAL" -> "🔴";
            case "HIGH" -> "🟠";
            case "MEDIUM" -> "🟡";
            case "LOW" -> "🟢";
            default -> "⚪";
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

    public boolean isEmailEnabled() {
        return emailEnabled;
    }

    public void validateEmailConfiguration() {
        if (emailEnabled && mailSender == null) {
            log.warn("이메일이 활성화되어 있지만 JavaMailSender가 구성되지 않았습니다.");
            emailEnabled = false;
        }
    }
}