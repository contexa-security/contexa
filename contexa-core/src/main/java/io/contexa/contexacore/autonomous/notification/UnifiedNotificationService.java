package io.contexa.contexacore.autonomous.notification;

import io.contexa.contexacore.domain.SoarResponse;
import io.contexa.contexacore.domain.ApprovalRequest;
import io.contexa.contexacore.soar.notification.SoarEmailService;
import io.contexa.contexacore.soar.approval.McpApprovalNotificationService;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.domain.ThreatIndicators;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
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

/**
 * UnifiedNotificationService - 통합 알림 서비스
 * 
 * Email, WebSocket, SMS, Slack 등 다양한 채널을 통해
 * 보안 알림을 전송하는 통합 서비스입니다.
 * 
 * @author contexa
 * @since 1.0
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UnifiedNotificationService {
    
    // 기존 서비스 재사용
    private final SoarEmailService emailService;
    private final McpApprovalNotificationService websocketService;
    
    // 새로운 어댑터
    private final SlackNotificationAdapter slackAdapter;
    private final SmsNotificationAdapter smsAdapter;
    
    // Redis Template
    private final RedisTemplate<String, Object> redisTemplate;
    
    // 설정값
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
    
    // 알림 채널 우선순위
    private final Map<NotificationChannel, Integer> channelPriorities = new ConcurrentHashMap<>();
    
    // 알림 템플릿
    private final Map<String, NotificationTemplate> templates = new ConcurrentHashMap<>();
    
    // 메트릭
    private final AtomicLong totalNotificationsSent = new AtomicLong(0);
    private final AtomicLong failedNotifications = new AtomicLong(0);
    private final Map<NotificationChannel, AtomicLong> channelMetrics = new ConcurrentHashMap<>();
    
    // 알림 큐 (배치 처리용)
    private final List<PendingNotification> notificationQueue = Collections.synchronizedList(new ArrayList<>());
    
    @PostConstruct
    public void initialize() {
        log.info("통합 알림 서비스 초기화 시작");
        
        // 채널 우선순위 설정
        initializeChannelPriorities();
        
        // 기본 템플릿 로드
        loadNotificationTemplates();
        
        // 배치 프로세서 시작
        startBatchProcessor();
        
        log.info("통합 알림 서비스 초기화 완료 - Email: {}, WebSocket: {}, Slack: {}, SMS: {}", 
            emailEnabled, websocketEnabled, slackEnabled, smsEnabled);
    }
    
    /**
     * 승인 요청 알림 발송 (모든 채널)
     * 
     * @param request 승인 요청
     * @return 발송 결과
     */
    public Mono<NotificationResult> sendApprovalRequest(ApprovalRequest request) {
        log.info("승인 요청 알림 발송 시작 - Request ID: {}, Tool: {}", 
            request.getRequestId(), request.getToolName());
        
        List<Mono<ChannelResult>> notifications = new ArrayList<>();
        
        // 이메일 발송
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
        
        // WebSocket 발송
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
        
        // Slack 발송
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
        
        // SMS 발송 (긴급한 경우만)
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
        
        // 모든 채널 결과 수집
        return Flux.merge(notifications)
            .collectList()
            .map(results -> {
                NotificationResult result = new NotificationResult();
                result.setRequestId(request.getRequestId());
                result.setTimestamp(LocalDateTime.now());
                result.setChannelResults(results);
                result.setSuccess(results.stream().anyMatch(ChannelResult::isSuccess));
                
                // 메트릭 업데이트
                updateMetrics(results);
                
                return result;
            });
    }
    
    /**
     * 보안 이벤트 알림
     */
    public Mono<NotificationResult> sendSecurityEventNotification(SecurityEvent event, ThreatIndicators indicators) {
        log.info("보안 이벤트 알림 발송 - Event: {}, Risk Level: {}", 
            event.getEventId(), indicators.getRiskLevel());
        
        NotificationPriority priority = calculatePriority(indicators);
        Set<NotificationChannel> channels = selectChannels(priority, event.getEventType().name());
        
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
    
    /**
     * 완료 알림
     */
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
    
    /**
     * 배치 알림 발송
     */
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
    
    /**
     * 개별 알림 발송
     */
    private Mono<NotificationResult> sendNotification(NotificationRequest request) {
        return sendMultiChannelNotification(
            request.getType(),
            request.getSubject(),
            request.getContext(),
            request.getPriority()
        );
    }
    
    /**
     * 멀티채널 알림 발송
     */
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
    
    /**
     * 채널별 발송
     */
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
            indicators.getRiskLevel(), event.getEventType());
        
        NotificationTemplate template = templates.get("SECURITY_EVENT");
        String content = template != null ? template.render(context) : createDefaultContent(event, indicators);
        
        return sendToChannel(channel, subject, content, context, priority);
    }
    
    /**
     * 채널별 발송 구현
     */
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
    
    /**
     * 이메일 발송
     */
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
    
    /**
     * WebSocket 발송
     */
    private Mono<Boolean> sendWebSocketNotification(ApprovalRequest request) {
        return Mono.fromRunnable(() -> 
            websocketService.sendApprovalRequest(request)
        )
        .thenReturn(true)
        .subscribeOn(Schedulers.boundedElastic());
    }
    
    /**
     * Slack 발송
     */
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
    
    /**
     * SMS 발송
     */
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
    
    /**
     * 일반 이메일 발송
     */
    private Mono<Boolean> sendEmail(String subject, String content, Map<String, Object> context) {
        String recipients = (String) context.getOrDefault("recipients", "security@contexa.com");
        
        return Mono.fromRunnable(() -> 
            emailService.sendEmail(recipients, subject, content)
        )
        .thenReturn(true)
        .subscribeOn(Schedulers.boundedElastic());
    }
    
    /**
     * WebSocket 메시지 발송
     */
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
    
    /**
     * 우선순위 계산
     */
    private NotificationPriority calculatePriority(ThreatIndicators indicators) {
        int urgency = indicators.getUrgencyLevel();
        
        if (urgency >= 5) return NotificationPriority.URGENT;
        if (urgency >= 4) return NotificationPriority.HIGH;
        if (urgency >= 3) return NotificationPriority.MEDIUM;
        if (urgency >= 2) return NotificationPriority.LOW;
        return NotificationPriority.INFO;
    }
    
    /**
     * 채널 선택
     */
    private Set<NotificationChannel> selectChannels(NotificationPriority priority, String eventType) {
        Set<NotificationChannel> channels = new HashSet<>();
        
        // 우선순위에 따른 채널 선택
        switch (priority) {
            case URGENT:
                if (smsEnabled) channels.add(NotificationChannel.SMS);
                if (slackEnabled) channels.add(NotificationChannel.SLACK);
                // fall through
            case HIGH:
                if (emailEnabled) channels.add(NotificationChannel.EMAIL);
                // fall through
            case MEDIUM:
                if (websocketEnabled) channels.add(NotificationChannel.WEBSOCKET);
                // fall through
            case LOW:
            case INFO:
                // 최소한 WebSocket은 항상 사용
                if (websocketEnabled) channels.add(NotificationChannel.WEBSOCKET);
                break;
        }
        
        // 이벤트 타입별 추가 채널
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
    
    /**
     * 긴급 요청 판별
     */
    private boolean isUrgentRequest(ApprovalRequest request) {
        return "CRITICAL".equals(request.getRiskLevel()) || 
               "HIGH".equals(request.getRiskLevel());
    }
    
    /**
     * 이메일 알림 필요 여부
     */
    private boolean shouldNotifyByEmail(ApprovalRequest request) {
        return request.getRequesterEmail() != null && !request.getRequesterEmail().isEmpty();
    }
    
    /**
     * Slack 알림 필요 여부
     */
    private boolean shouldNotifyBySlack(ApprovalRequest request) {
        return request.getRiskLevel() != null && 
               (request.getRiskLevel().equals("HIGH") || request.getRiskLevel().equals("CRITICAL"));
    }
    
    /**
     * 기본 컨텐츠 생성
     */
    private String createDefaultContent(SecurityEvent event, ThreatIndicators indicators) {
        StringBuilder content = new StringBuilder();
        content.append("보안 이벤트 상세:\n");
        content.append("- 이벤트 ID: ").append(event.getEventId()).append("\n");
        content.append("- 이벤트 유형: ").append(event.getEventType()).append("\n");
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
    
    /**
     * 승인 알림 재전송
     * SecurityPlaneAgent에서 호출되어 대기 중인 승인을 재알림합니다.
     * 
     * @param approvalId 승인 요청 ID
     * @return 알림 발송 성공 여부
     */
    public Mono<Boolean> sendApprovalReminder(String approvalId) {
        log.info("승인 알림 재전송 시작: approvalId={}", approvalId);
        
        return Mono.fromCallable(() -> {
            // ApprovalRequest 조회 (Repository를 통해 조회해야 하지만, 현재는 간단히 처리)
            Map<String, Object> reminderContext = new HashMap<>();
            reminderContext.put("approvalId", approvalId);
            reminderContext.put("type", "APPROVAL_REMINDER");
            reminderContext.put("timestamp", LocalDateTime.now());
            reminderContext.put("reminderCount", getReminderCount(approvalId));
            
            // 알림 채널 선택 (리마인더는 높은 우선순위)
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
            
            // 각 채널로 알림 발송
            List<Mono<Boolean>> notifications = new ArrayList<>();
            
            for (NotificationChannel channel : channels) {
                notifications.add(sendReminderToChannel(channel, subject, content, reminderContext));
            }
            
            // 리마인더 카운터 증가
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
    
    /**
     * 리마인더를 특정 채널로 발송
     */
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
    
    /**
     * 리마인더 카운트 조회
     */
    private int getReminderCount(String approvalId) {
        String key = "approval:reminder:count:" + approvalId;
        Object countObj = redisTemplate.opsForValue().get(key);
        String count = countObj != null ? countObj.toString() : "0";
        return count != null ? Integer.parseInt(count) : 0;
    }
    
    /**
     * 리마인더 카운트 증가
     */
    private void incrementReminderCount(String approvalId) {
        String key = "approval:reminder:count:" + approvalId;
        redisTemplate.opsForValue().increment(key);
        redisTemplate.expire(key, Duration.ofHours(24));
    }
    
    /**
     * 채널 우선순위 초기화
     */
    private void initializeChannelPriorities() {
        channelPriorities.put(NotificationChannel.SMS, 1);        // 가장 높은 우선순위
        channelPriorities.put(NotificationChannel.SLACK, 2);
        channelPriorities.put(NotificationChannel.EMAIL, 3);
        channelPriorities.put(NotificationChannel.WEBSOCKET, 4);  // 가장 낮은 우선순위
    }
    
    /**
     * 알림 템플릿 로드
     */
    private void loadNotificationTemplates() {
        // 보안 이벤트 템플릿
        templates.put("SECURITY_EVENT", new NotificationTemplate(
            "보안 이벤트 알림",
            "이벤트 ID: ${event.eventId}\n" +
            "유형: ${event.eventType}\n" +
            "위험도: ${indicators.riskLevel}\n" +
            "권장사항: ${indicators.recommendations}"
        ));
        
        // SOAR 완료 템플릿
        templates.put("SOAR_COMPLETION", new NotificationTemplate(
            "SOAR 분석 완료",
            "요청 ID: ${requestId}\n" +
            "권장사항: ${recommendations}\n" +
            "위험도: ${riskLevel}\n" +
            "완료 시간: ${completedAt}"
        ));
        
        // 승인 요청 템플릿
        templates.put("APPROVAL_REQUEST", new NotificationTemplate(
            "도구 실행 승인 요청",
            "도구: ${toolName}\n" +
            "위험도: ${riskLevel}\n" +
            "요청 ID: ${requestId}\n" +
            "승인 링크: ${approvalLink}"
        ));
    }
    
    /**
     * 기본 템플릿 생성
     */
    private NotificationTemplate createDefaultTemplate(String type) {
        return new NotificationTemplate(
            type,
            "Type: " + type + "\nContext: ${context}"
        );
    }
    
    /**
     * 배치 프로세서 시작
     */
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
    
    /**
     * 배치 처리
     */
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
    
    /**
     * 알림 결과 생성
     */
    private NotificationResult createNotificationResult(String id, List<ChannelResult> channelResults) {
        NotificationResult result = new NotificationResult();
        result.setRequestId(id);
        result.setTimestamp(LocalDateTime.now());
        result.setChannelResults(channelResults);
        result.setSuccess(channelResults.stream().anyMatch(ChannelResult::isSuccess));
        
        return result;
    }
    
    /**
     * 메트릭 업데이트
     */
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
    
    /**
     * 메트릭 조회
     */
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
    
    // 내부 클래스들
    
    /**
     * 알림 채널
     */
    public enum NotificationChannel {
        EMAIL, WEBSOCKET, SLACK, SMS
    }
    
    /**
     * 알림 우선순위
     */
    public enum NotificationPriority {
        URGENT, HIGH, MEDIUM, LOW, INFO
    }
    
    /**
     * 알림 결과
     */
    @lombok.Data
    public static class NotificationResult {
        private String requestId;
        private LocalDateTime timestamp;
        private boolean success;
        private List<ChannelResult> channelResults;
        private Map<String, Object> metadata;
    }
    
    /**
     * 채널별 결과
     */
    @lombok.Data
    @lombok.AllArgsConstructor
    public static class ChannelResult {
        private NotificationChannel channel;
        private boolean success;
        private String errorMessage;
    }
    
    /**
     * 알림 요청
     */
    @lombok.Data
    @lombok.Builder
    public static class NotificationRequest {
        private String type;
        private String subject;
        private Map<String, Object> context;
        private NotificationPriority priority;
        private Set<NotificationChannel> channels;
    }
    
    /**
     * 대기 중인 알림
     */
    @lombok.Data
    @lombok.AllArgsConstructor
    private static class PendingNotification {
        private String type;
        private String subject;
        private Map<String, Object> context;
        private NotificationPriority priority;
    }
    
    /**
     * 알림 템플릿
     */
    @lombok.AllArgsConstructor
    private static class NotificationTemplate {
        private final String name;
        private final String template;
        
        public String render(Map<String, Object> context) {
            String rendered = template;
            
            // 간단한 템플릿 렌더링 (실제로는 더 복잡한 템플릿 엔진 사용)
            for (Map.Entry<String, Object> entry : context.entrySet()) {
                String placeholder = "${" + entry.getKey() + "}";
                rendered = rendered.replace(placeholder, String.valueOf(entry.getValue()));
            }
            
            return rendered;
        }
    }
}