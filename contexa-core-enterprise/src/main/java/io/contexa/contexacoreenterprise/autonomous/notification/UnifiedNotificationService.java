package io.contexa.contexacoreenterprise.autonomous.notification;

import io.contexa.contexacore.domain.SoarResponse;
import io.contexa.contexacore.domain.ApprovalRequest;
import io.contexa.contexacoreenterprise.soar.notification.SoarEmailService;
import io.contexa.contexacoreenterprise.soar.approval.McpApprovalNotificationService;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatIndicators;
import io.contexa.contexacore.autonomous.domain.NotificationResult;
import io.contexa.contexacore.autonomous.service.ISoarNotifier;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import reactor.util.retry.Retry;

import jakarta.annotation.PostConstruct;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;


@Slf4j
@RequiredArgsConstructor
public class UnifiedNotificationService {
    
    
    private final SoarEmailService emailService;
    private final McpApprovalNotificationService websocketService;
    
    
    private final SlackNotificationAdapter slackAdapter;
    private final SmsNotificationAdapter smsAdapter;
    
    
    private final RedisTemplate<String, Object> redisTemplate;
    
    
    @Value("${notification.enabled.email:true}")
    private boolean emailEnabled;
    
    @Value("${notification.enabled.websocket:true}")
    private boolean websocketEnabled;
    
    @Value("${notification.enabled.slack:false}")
    private boolean slackEnabled;
    
    @Value("${notification.enabled.sms:false}")
    private boolean smsEnabled;
    
    @Value("${notification.retry.max-attempts:3}")
    private int maxRetryAttempts;
    
    @Value("${notification.retry.delay-seconds:5}")
    private int retryDelaySeconds;
    
    @Value("${notification.priority.threshold:HIGH}")
    private String priorityThreshold;
    
    @Value("${notification.batch.size:100}")
    private int batchSize;
    
    @Value("${notification.batch.delay-ms:1000}")
    private int batchDelayMs;
    
    
    private final Map<NotificationChannel, Integer> channelPriorities = new ConcurrentHashMap<>();
    
    
    private final Map<String, NotificationTemplate> templates = new ConcurrentHashMap<>();
    
    
    private final AtomicLong totalNotificationsSent = new AtomicLong(0);
    private final AtomicLong failedNotifications = new AtomicLong(0);
    private final Map<NotificationChannel, AtomicLong> channelMetrics = new ConcurrentHashMap<>();
    
    
    private final List<PendingNotification> notificationQueue = Collections.synchronizedList(new ArrayList<>());
    
    @PostConstruct
    public void initialize() {
        log.info("통합 알림 서비스 초기화 시작");
        
        
        initializeChannelPriorities();
        
        
        loadNotificationTemplates();
        
        
        startBatchProcessor();
        
        log.info("통합 알림 서비스 초기화 완료 - Email: {}, WebSocket: {}, Slack: {}, SMS: {}", 
            emailEnabled, websocketEnabled, slackEnabled, smsEnabled);
    }
    
    
    public Mono<NotificationResult> sendApprovalRequest(ApprovalRequest request) {
        log.info("승인 요청 알림 발송 시작 - Request ID: {}, Tool: {}", 
            request.getRequestId(), request.getToolName());
        
        List<Mono<ChannelResult>> notifications = new ArrayList<>();
        
        
        if (emailEnabled && shouldNotifyByEmail(request)) {
            notifications.add(
                sendEmailNotification(request)
                    .map(success -> new ChannelResult(NotificationChannel.EMAIL, success, null))
                    .onErrorResume(error -> {
                        log.error("이메일 발송 실패", error);
                        return Mono.just(new ChannelResult(NotificationChannel.EMAIL, false, error.getMessage()));
                    })
            );
        }
        
        
        if (websocketEnabled) {
            notifications.add(
                sendWebSocketNotification(request)
                    .map(success -> new ChannelResult(NotificationChannel.WEBSOCKET, success, null))
                    .onErrorResume(error -> {
                        log.error("WebSocket 발송 실패", error);
                        return Mono.just(new ChannelResult(NotificationChannel.WEBSOCKET, false, error.getMessage()));
                    })
            );
        }
        
        
        if (slackEnabled && shouldNotifyBySlack(request)) {
            notifications.add(
                sendSlackNotification(request)
                    .map(success -> new ChannelResult(NotificationChannel.SLACK, success, null))
                    .onErrorResume(error -> {
                        log.error("Slack 발송 실패", error);
                        return Mono.just(new ChannelResult(NotificationChannel.SLACK, false, error.getMessage()));
                    })
            );
        }
        
        
        if (smsEnabled && isUrgentRequest(request)) {
            notifications.add(
                sendSmsNotification(request)
                    .map(success -> new ChannelResult(NotificationChannel.SMS, success, null))
                    .onErrorResume(error -> {
                        log.error("SMS 발송 실패", error);
                        return Mono.just(new ChannelResult(NotificationChannel.SMS, false, error.getMessage()));
                    })
            );
        }
        
        
        return Flux.merge(notifications)
            .collectList()
            .map(results -> {
                NotificationResult result = new NotificationResult();
                result.setRequestId(request.getRequestId());
                result.setTimestamp(LocalDateTime.now());
                result.setChannelResults(results);
                result.setSuccess(results.stream().anyMatch(ChannelResult::isSuccess));
                
                
                updateMetrics(results);
                
                return result;
            });
    }
    
    
    public Mono<NotificationResult> sendSecurityEventNotification(SecurityEvent event, ThreatIndicators indicators) {
        log.info("보안 이벤트 알림 발송 - Event: {}, Risk Level: {}", 
            event.getEventId(), indicators.getRiskLevel());
        
        NotificationPriority priority = calculatePriority(indicators);
        Set<NotificationChannel> channels = selectChannels(priority, event.getSeverity().name());
        
        List<Mono<ChannelResult>> notifications = new ArrayList<>();
        
        for (NotificationChannel channel : channels) {
            notifications.add(
                sendToChannel(channel, event, indicators, priority)
                    .retryWhen(Retry.backoff(maxRetryAttempts, Duration.ofSeconds(retryDelaySeconds)))
            );
        }
        
        return Flux.merge(notifications)
            .collectList()
            .map(results -> createNotificationResult(event.getEventId(), results));
    }
    
    
    public Mono<NotificationResult> sendCompletionNotification(String requestId, SoarResponse response) {
        log.info("SOAR 분석 완료 알림 발송 - Request ID: {}", requestId);
        
        Map<String, Object> context = new HashMap<>();
        context.put("requestId", requestId);
        context.put("recommendations", response.getRecommendations());
        context.put("riskLevel", response.getThreatLevel() != null ? response.getThreatLevel().toString() : "MEDIUM");
        context.put("completedAt", LocalDateTime.now());
        
        return sendMultiChannelNotification(
            "SOAR_COMPLETION",
            "SOAR 분석 완료",
            context,
            NotificationPriority.MEDIUM
        );
    }
    
    
    public Mono<List<NotificationResult>> sendBatchNotifications(List<NotificationRequest> requests) {
        log.info("배치 알림 발송 시작 - {} 건", requests.size());
        
        return Flux.fromIterable(requests)
            .window(batchSize)
            .flatMap(batch -> 
                batch.flatMap(request -> 
                    sendNotification(request)
                        .delayElement(Duration.ofMillis(batchDelayMs))
                )
                .collectList()
            )
            .flatMapIterable(list -> list)
            .collectList();
    }
    
    
    private Mono<NotificationResult> sendNotification(NotificationRequest request) {
        return sendMultiChannelNotification(
            request.getType(),
            request.getSubject(),
            request.getContext(),
            request.getPriority()
        );
    }
    
    
    private Mono<NotificationResult> sendMultiChannelNotification(
        String type, 
        String subject, 
        Map<String, Object> context,
        NotificationPriority priority
    ) {
        Set<NotificationChannel> channels = selectChannels(priority, type);
        
        List<Mono<ChannelResult>> notifications = new ArrayList<>();
        
        for (NotificationChannel channel : channels) {
            NotificationTemplate template = templates.get(type);
            if (template == null) {
                template = createDefaultTemplate(type);
            }
            
            String content = template.render(context);
            
            notifications.add(
                sendToChannel(channel, subject, content, context, priority)
            );
        }
        
        return Flux.merge(notifications)
            .collectList()
            .map(results -> createNotificationResult(UUID.randomUUID().toString(), results));
    }
    
    
    private Mono<ChannelResult> sendToChannel(
        NotificationChannel channel,
        SecurityEvent event,
        ThreatIndicators indicators,
        NotificationPriority priority
    ) {
        Map<String, Object> context = new HashMap<>();
        context.put("event", event);
        context.put("indicators", indicators);
        context.put("priority", priority);
        
        String subject = String.format("[%s] 보안 이벤트 감지 - %s",
            indicators.getRiskLevel(), event.getSeverity());
        
        NotificationTemplate template = templates.get("SECURITY_EVENT");
        String content = template != null ? template.render(context) : createDefaultContent(event, indicators);
        
        return sendToChannel(channel, subject, content, context, priority);
    }
    
    
    private Mono<ChannelResult> sendToChannel(
        NotificationChannel channel,
        String subject,
        String content,
        Map<String, Object> context,
        NotificationPriority priority
    ) {
        return (switch (channel) {
            case EMAIL -> sendEmail(subject, content, context)
                .map(success -> new ChannelResult(channel, success, null));
            
            case WEBSOCKET -> sendWebSocket(subject, content, context)
                .map(success -> new ChannelResult(channel, success, null));
            
            case SLACK -> slackAdapter.sendMessage(subject, content, priority)
                .map(success -> new ChannelResult(channel, success, null));
            
            case SMS -> smsAdapter.sendSms(subject, content, priority)
                .map(success -> new ChannelResult(channel, success, null));
            
            default -> Mono.just(new ChannelResult(channel, false, "Unsupported channel"));
        })
        .onErrorResume(error -> {
            log.error("채널 {} 발송 실패", channel, error);
            failedNotifications.incrementAndGet();
            return Mono.just(new ChannelResult(channel, false, error.getMessage()));
        })
        .doOnSuccess(result -> {
            if (result.isSuccess()) {
                totalNotificationsSent.incrementAndGet();
                channelMetrics.computeIfAbsent(channel, k -> new AtomicLong()).incrementAndGet();
            }
        });
    }
    
    
    private Mono<Boolean> sendEmailNotification(ApprovalRequest request) {
        return Mono.fromRunnable(() -> {
            String subject = String.format("승인 요청: %s", request.getToolName());
            String content = String.format(
                "승인 요청 ID: %s\n도구: %s\n위험 수준: %s\n요청자: %s\n사유: %s",
                request.getRequestId(),
                request.getToolName(),
                request.getRiskLevel(),
                request.getRequestedBy(),
                request.getReason()
            );
            emailService.sendEmail(
                request.getRequesterEmail(),
                subject,
                content
            );
        })
        .thenReturn(true)
        .subscribeOn(Schedulers.boundedElastic());
    }
    
    
    private Mono<Boolean> sendWebSocketNotification(ApprovalRequest request) {
        return Mono.fromRunnable(() -> 
            websocketService.sendApprovalRequest(request)
        )
        .thenReturn(true)
        .subscribeOn(Schedulers.boundedElastic());
    }
    
    
    private Mono<Boolean> sendSlackNotification(ApprovalRequest request) {
        Map<String, Object> slackContext = new HashMap<>();
        slackContext.put("requestId", request.getRequestId());
        slackContext.put("toolName", request.getToolName());
        slackContext.put("riskLevel", request.getRiskLevel());
        slackContext.put("userId", request.getUserId());
        
        return slackAdapter.sendToChannel(
            "#security-approvals",
            "도구 실행 승인 요청",
            slackContext,
            NotificationPriority.HIGH
        );
    }
    
    
    private Mono<Boolean> sendSmsNotification(ApprovalRequest request) {
        String message = String.format(
            "[긴급] %s 도구 실행 승인 필요. 위험도: %s. ID: %s",
            request.getToolName(),
            request.getRiskLevel(),
            request.getRequestId().substring(0, 8)
        );
        
        return smsAdapter.sendToPhone(
            request.getRequesterPhone(),
            message,
            NotificationPriority.URGENT
        );
    }
    
    
    private Mono<Boolean> sendEmail(String subject, String content, Map<String, Object> context) {
        String recipients = (String) context.getOrDefault("recipients", "security@contexa.com");
        
        return Mono.fromRunnable(() -> 
            emailService.sendEmail(recipients, subject, content)
        )
        .thenReturn(true)
        .subscribeOn(Schedulers.boundedElastic());
    }
    
    
    private Mono<Boolean> sendWebSocket(String subject, String content, Map<String, Object> context) {
        return Mono.fromRunnable(() -> {
            Map<String, Object> message = new HashMap<>();
            message.put("type", "SECURITY_ALERT");
            message.put("subject", subject);
            message.put("content", content);
            message.put("context", context);
            message.put("timestamp", LocalDateTime.now());
            
            websocketService.broadcastMessage(message);
        })
        .thenReturn(true)
        .subscribeOn(Schedulers.boundedElastic());
    }
    
    
    private NotificationPriority calculatePriority(ThreatIndicators indicators) {
        int urgency = indicators.getUrgencyLevel();
        
        if (urgency >= 5) return NotificationPriority.URGENT;
        if (urgency >= 4) return NotificationPriority.HIGH;
        if (urgency >= 3) return NotificationPriority.MEDIUM;
        if (urgency >= 2) return NotificationPriority.LOW;
        return NotificationPriority.INFO;
    }
    
    
    private Set<NotificationChannel> selectChannels(NotificationPriority priority, String eventType) {
        Set<NotificationChannel> channels = new HashSet<>();
        
        
        switch (priority) {
            case URGENT:
                if (smsEnabled) channels.add(NotificationChannel.SMS);
                if (slackEnabled) channels.add(NotificationChannel.SLACK);
                
            case HIGH:
                if (emailEnabled) channels.add(NotificationChannel.EMAIL);
                
            case MEDIUM:
                if (websocketEnabled) channels.add(NotificationChannel.WEBSOCKET);
                
            case LOW:
            case INFO:
                
                if (websocketEnabled) channels.add(NotificationChannel.WEBSOCKET);
                break;
        }
        
        
        if (eventType != null) {
            if (eventType.contains("CRITICAL") || eventType.contains("BREACH")) {
                if (smsEnabled) channels.add(NotificationChannel.SMS);
            }
            if (eventType.contains("POLICY") || eventType.contains("COMPLIANCE")) {
                if (emailEnabled) channels.add(NotificationChannel.EMAIL);
            }
        }
        
        return channels;
    }
    
    
    private boolean isUrgentRequest(ApprovalRequest request) {
        return "CRITICAL".equals(request.getRiskLevel()) || 
               "HIGH".equals(request.getRiskLevel());
    }
    
    
    private boolean shouldNotifyByEmail(ApprovalRequest request) {
        return request.getRequesterEmail() != null && !request.getRequesterEmail().isEmpty();
    }
    
    
    private boolean shouldNotifyBySlack(ApprovalRequest request) {
        return request.getRiskLevel() != null && 
               (request.getRiskLevel().equals("HIGH") || request.getRiskLevel().equals("CRITICAL"));
    }
    
    
    private String createDefaultContent(SecurityEvent event, ThreatIndicators indicators) {
        StringBuilder content = new StringBuilder();
        content.append("보안 이벤트 상세:\n");
        content.append("- 이벤트 ID: ").append(event.getEventId()).append("\n");
        content.append("- 이벤트 심각도: ").append(event.getSeverity()).append("\n");
        content.append("- 위험 수준: ").append(indicators.getRiskLevel()).append("\n");
        content.append("- 위협 점수: ").append(indicators.calculateThreatScore()).append("\n");
        content.append("- 감지 시각: ").append(event.getTimestamp()).append("\n");
        
        if (!indicators.generateRecommendations().isEmpty()) {
            content.append("\n권장 조치:\n");
            indicators.generateRecommendations().forEach(rec -> 
                content.append("- ").append(rec).append("\n")
            );
        }
        
        return content.toString();
    }
    
    
    public Mono<Boolean> sendApprovalReminder(String approvalId) {
        log.info("승인 알림 재전송 시작: approvalId={}", approvalId);
        
        return Mono.fromCallable(() -> {
            
            Map<String, Object> reminderContext = new HashMap<>();
            reminderContext.put("approvalId", approvalId);
            reminderContext.put("type", "APPROVAL_REMINDER");
            reminderContext.put("timestamp", LocalDateTime.now());
            reminderContext.put("reminderCount", getReminderCount(approvalId));
            
            
            Set<NotificationChannel> channels = selectChannels(NotificationPriority.HIGH, "APPROVAL_REMINDER");
            
            String subject = String.format("[재알림] 승인 요청 대기 중 - ID: %s", 
                approvalId.length() > 8 ? approvalId.substring(0, 8) : approvalId);
            
            String content = String.format(
                "승인 요청이 대기 중입니다.\n" +
                "승인 ID: %s\n" +
                "재알림 횟수: %d\n" +
                "처리 방법: 승인 콘솔에서 확인하시거나 API를 통해 처리하세요.",
                approvalId,
                getReminderCount(approvalId)
            );
            
            
            List<Mono<Boolean>> notifications = new ArrayList<>();
            
            for (NotificationChannel channel : channels) {
                notifications.add(sendReminderToChannel(channel, subject, content, reminderContext));
            }
            
            
            incrementReminderCount(approvalId);
            
            return true;
        })
        .flatMap(success -> {
            if (success) {
                log.info("승인 알림 재전송 완료: approvalId={}", approvalId);
                return Mono.just(true);
            } else {
                log.warn("승인 알림 재전송 실패: approvalId={}", approvalId);
                return Mono.just(false);
            }
        })
        .onErrorResume(error -> {
            log.error("승인 알림 재전송 중 오류 발생: approvalId={}", approvalId, error);
            return Mono.just(false);
        });
    }
    
    
    private Mono<Boolean> sendReminderToChannel(NotificationChannel channel, String subject, 
                                                String content, Map<String, Object> context) {
        return (switch (channel) {
            case EMAIL -> sendEmail(subject, content, context);
            case WEBSOCKET -> sendWebSocket(subject, content, context);
            case SLACK -> slackAdapter.sendMessage(subject, content, NotificationPriority.HIGH);
            case SMS -> smsAdapter.sendSms(subject, content, NotificationPriority.HIGH);
            default -> Mono.just(false);
        })
        .onErrorResume(error -> {
            log.error("리마인더 발송 실패 - 채널: {}", channel, error);
            return Mono.just(false);
        });
    }
    
    
    private int getReminderCount(String approvalId) {
        String key = "approval:reminder:count:" + approvalId;
        Object countObj = redisTemplate.opsForValue().get(key);
        String count = countObj != null ? countObj.toString() : "0";
        return count != null ? Integer.parseInt(count) : 0;
    }
    
    
    private void incrementReminderCount(String approvalId) {
        String key = "approval:reminder:count:" + approvalId;
        redisTemplate.opsForValue().increment(key);
        redisTemplate.expire(key, Duration.ofHours(24));
    }
    
    
    private void initializeChannelPriorities() {
        channelPriorities.put(NotificationChannel.SMS, 1);        
        channelPriorities.put(NotificationChannel.SLACK, 2);
        channelPriorities.put(NotificationChannel.EMAIL, 3);
        channelPriorities.put(NotificationChannel.WEBSOCKET, 4);  
    }
    
    
    private void loadNotificationTemplates() {
        
        templates.put("SECURITY_EVENT", new NotificationTemplate(
            "보안 이벤트 알림",
            "이벤트 ID: ${event.eventId}\n" +
            "유형: ${event.eventType}\n" +
            "위험도: ${indicators.riskLevel}\n" +
            "권장사항: ${indicators.recommendations}"
        ));
        
        
        templates.put("SOAR_COMPLETION", new NotificationTemplate(
            "SOAR 분석 완료",
            "요청 ID: ${requestId}\n" +
            "권장사항: ${recommendations}\n" +
            "위험도: ${riskLevel}\n" +
            "완료 시간: ${completedAt}"
        ));
        
        
        templates.put("APPROVAL_REQUEST", new NotificationTemplate(
            "도구 실행 승인 요청",
            "도구: ${toolName}\n" +
            "위험도: ${riskLevel}\n" +
            "요청 ID: ${requestId}\n" +
            "승인 링크: ${approvalLink}"
        ));
    }
    
    
    private NotificationTemplate createDefaultTemplate(String type) {
        return new NotificationTemplate(
            type,
            "Type: " + type + "\nContext: ${context}"
        );
    }
    
    
    private void startBatchProcessor() {
        Schedulers.parallel().schedulePeriodically(() -> {
            if (!notificationQueue.isEmpty()) {
                List<PendingNotification> batch;
                synchronized (notificationQueue) {
                    batch = new ArrayList<>(notificationQueue);
                    notificationQueue.clear();
                }
                
                processBatch(batch);
            }
        }, batchDelayMs, batchDelayMs, java.util.concurrent.TimeUnit.MILLISECONDS);
    }
    
    
    private void processBatch(List<PendingNotification> batch) {
        log.debug("배치 알림 처리 시작 - {} 건", batch.size());
        
        Flux.fromIterable(batch)
            .flatMap(notification -> 
                sendMultiChannelNotification(
                    notification.getType(),
                    notification.getSubject(),
                    notification.getContext(),
                    notification.getPriority()
                )
            )
            .subscribe(
                result -> log.debug("알림 발송 완료: {}", result),
                error -> log.error("배치 알림 처리 실패", error)
            );
    }
    
    
    private NotificationResult createNotificationResult(String id, List<ChannelResult> channelResults) {
        NotificationResult result = new NotificationResult();
        result.setRequestId(id);
        result.setTimestamp(LocalDateTime.now());
        result.setChannelResults(channelResults);
        result.setSuccess(channelResults.stream().anyMatch(ChannelResult::isSuccess));
        
        return result;
    }
    
    
    private void updateMetrics(List<ChannelResult> results) {
        results.forEach(result -> {
            if (result.isSuccess()) {
                totalNotificationsSent.incrementAndGet();
                channelMetrics.computeIfAbsent(result.getChannel(), k -> new AtomicLong())
                    .incrementAndGet();
            } else {
                failedNotifications.incrementAndGet();
            }
        });
    }
    
    
    public Map<String, Object> getMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        metrics.put("totalSent", totalNotificationsSent.get());
        metrics.put("totalFailed", failedNotifications.get());
        
        Map<String, Long> channelStats = new HashMap<>();
        channelMetrics.forEach((channel, count) -> 
            channelStats.put(channel.name(), count.get())
        );
        metrics.put("channelStats", channelStats);
        
        metrics.put("queueSize", notificationQueue.size());
        
        return metrics;
    }
    
    
    
    
    public enum NotificationChannel {
        EMAIL, WEBSOCKET, SLACK, SMS
    }
    
    
    public enum NotificationPriority {
        URGENT, HIGH, MEDIUM, LOW, INFO
    }
    
    
    @lombok.Data
    public static class NotificationResult {
        private String requestId;
        private LocalDateTime timestamp;
        private boolean success;
        private List<ChannelResult> channelResults;
        private Map<String, Object> metadata;
    }
    
    
    @lombok.Data
    @lombok.AllArgsConstructor
    public static class ChannelResult {
        private NotificationChannel channel;
        private boolean success;
        private String errorMessage;
    }
    
    
    @lombok.Data
    @lombok.Builder
    public static class NotificationRequest {
        private String type;
        private String subject;
        private Map<String, Object> context;
        private NotificationPriority priority;
        private Set<NotificationChannel> channels;
    }
    
    
    @lombok.Data
    @lombok.AllArgsConstructor
    private static class PendingNotification {
        private String type;
        private String subject;
        private Map<String, Object> context;
        private NotificationPriority priority;
    }
    
    
    @lombok.AllArgsConstructor
    private static class NotificationTemplate {
        private final String name;
        private final String template;
        
        public String render(Map<String, Object> context) {
            String rendered = template;
            
            
            for (Map.Entry<String, Object> entry : context.entrySet()) {
                String placeholder = "${" + entry.getKey() + "}";
                rendered = rendered.replace(placeholder, String.valueOf(entry.getValue()));
            }
            
            return rendered;
        }
    }
}