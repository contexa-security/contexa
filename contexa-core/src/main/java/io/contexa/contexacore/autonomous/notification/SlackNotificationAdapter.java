package io.contexa.contexacore.autonomous.notification;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import jakarta.annotation.PostConstruct;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * SlackNotificationAdapter - Slack 알림 어댑터
 * 
 * Slack API를 통해 보안 알림을 전송하는 어댑터입니다.
 * Webhook과 Web API를 모두 지원합니다.
 * 
 * @author contexa
 * @since 1.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SlackNotificationAdapter {
    
    private final ObjectMapper objectMapper;
    
    // WebClient (Reactive)
    private WebClient slackWebClient;
    
    // 설정값
    @Value("${slack.webhook.url:}")
    private String webhookUrl;
    
    @Value("${slack.api.token:}")
    private String apiToken;
    
    @Value("${slack.channel.default:#security-alerts}")
    private String defaultChannel;
    
    @Value("${slack.channel.urgent:#security-urgent}")
    private String urgentChannel;
    
    @Value("${slack.channel.approval:#security-approvals}")
    private String approvalChannel;
    
    @Value("${slack.username:contexa Bot}")
    private String botUsername;
    
    @Value("${slack.icon.emoji::shield:}")
    private String botIconEmoji;
    
    @Value("${slack.retry.max-attempts:3}")
    private int maxRetryAttempts;
    
    @Value("${slack.retry.delay-seconds:2}")
    private int retryDelaySeconds;
    
    @Value("${slack.rate-limit.messages-per-minute:20}")
    private int rateLimitPerMinute;
    
    @Value("${slack.enabled:false}")
    private boolean slackEnabled;
    
    // 메시지 템플릿
    private final Map<String, MessageTemplate> messageTemplates = new ConcurrentHashMap<>();
    
    // 메트릭
    private final AtomicLong totalMessagesSent = new AtomicLong(0);
    private final AtomicLong failedMessages = new AtomicLong(0);
    private final Map<String, AtomicLong> channelMetrics = new ConcurrentHashMap<>();
    
    // Rate limiting
    private final List<Long> messageTimes = Collections.synchronizedList(new ArrayList<>());
    
    @PostConstruct
    public void initialize() {
        if (!slackEnabled) {
            log.info("Slack 알림 비활성화됨");
            return;
        }
        
        log.info("Slack 알림 어댑터 초기화 시작");
        
        // WebClient 초기화
        initializeWebClient();
        
        // 메시지 템플릿 로드
        loadMessageTemplates();
        
        // 연결 테스트
        testConnection().subscribe(
            success -> log.info("Slack 연결 테스트 성공"),
            error -> log.error("Slack 연결 테스트 실패", error)
        );
        
        log.info("Slack 알림 어댑터 초기화 완료");
    }
    
    /**
     * 채널에 메시지 전송
     */
    public Mono<Boolean> sendToChannel(String channel, String title, Map<String, Object> context, UnifiedNotificationService.NotificationPriority priority) {
        if (!slackEnabled) {
            return Mono.just(false);
        }
        
        return checkRateLimit()
            .flatMap(allowed -> {
                if (!allowed) {
                    log.warn("Slack rate limit 초과");
                    return Mono.just(false);
                }
                
                SlackMessage message = buildMessage(title, context, priority);
                message.setChannel(channel != null ? channel : selectChannel(priority));
                
                return sendMessage(message);
            });
    }
    
    /**
     * 메시지 전송 (간단한 텍스트)
     */
    public Mono<Boolean> sendMessage(String text, String content, UnifiedNotificationService.NotificationPriority priority) {
        if (!slackEnabled) {
            return Mono.just(false);
        }
        
        String channel = selectChannel(priority);
        
        SlackMessage message = SlackMessage.builder()
            .channel(channel)
            .username(botUsername)
            .iconEmoji(botIconEmoji)
            .text(text)
            .blocks(createTextBlocks(text, content, priority))
            .build();
        
        return sendMessage(message);
    }
    
    /**
     * 승인 요청 메시지 전송
     */
    public Mono<Boolean> sendApprovalRequest(String requestId, String toolName, String riskLevel, Map<String, Object> context) {
        if (!slackEnabled) {
            return Mono.just(false);
        }
        
        List<Block> blocks = new ArrayList<>();
        
        // 헤더
        blocks.add(Block.header("🔐 도구 실행 승인 요청"));
        
        // 섹션
        blocks.add(Block.section(
            String.format("*도구:* %s\n*위험도:* %s\n*요청 ID:* `%s`", 
                toolName, riskLevel, requestId)
        ));
        
        // 컨텍스트 정보
        if (context != null && !context.isEmpty()) {
            StringBuilder contextText = new StringBuilder();
            context.forEach((key, value) -> 
                contextText.append(String.format("• %s: %s\n", key, value))
            );
            blocks.add(Block.section("*상세 정보:*\n" + contextText.toString()));
        }
        
        // 액션 버튼
        blocks.add(Block.actions(Arrays.asList(
            Button.approve(requestId),
            Button.reject(requestId),
            Button.moreInfo(requestId)
        )));
        
        // 타임스탬프
        blocks.add(Block.context(
            String.format("요청 시간: %s", LocalDateTime.now())
        ));
        
        SlackMessage message = SlackMessage.builder()
            .channel(approvalChannel)
            .username(botUsername)
            .iconEmoji(":warning:")
            .text("도구 실행 승인이 필요합니다")
            .blocks(blocks)
            .build();
        
        return sendMessage(message);
    }
    
    /**
     * 보안 알림 메시지 전송
     */
    public Mono<Boolean> sendSecurityAlert(String title, String severity, Map<String, String> details, List<String> recommendations) {
        if (!slackEnabled) {
            return Mono.just(false);
        }
        
        List<Block> blocks = new ArrayList<>();
        
        // 알림 색상 결정
        String color = getColorForSeverity(severity);
        
        // 헤더
        blocks.add(Block.header(String.format("%s", title)));
        
        // 심각도 섹션
        blocks.add(Block.section(
            String.format("*심각도:* %s %s", getEmojiForSeverity(severity), severity)
        ));
        
        // 상세 정보
        if (details != null && !details.isEmpty()) {
            StringBuilder detailText = new StringBuilder("*상세 정보:*\n");
            details.forEach((key, value) -> 
                detailText.append(String.format("• %s: %s\n", key, value))
            );
            blocks.add(Block.section(detailText.toString()));
        }
        
        // 권장 조치
        if (recommendations != null && !recommendations.isEmpty()) {
            StringBuilder recText = new StringBuilder("*권장 조치:*\n");
            recommendations.forEach(rec -> 
                recText.append(String.format("✓ %s\n", rec))
            );
            blocks.add(Block.section(recText.toString()));
        }
        
        // 구분선
        blocks.add(Block.divider());
        
        // 타임스탬프와 액션
        blocks.add(Block.context(
            String.format("감지 시간: %s | ", LocalDateTime.now())
        ));
        
        SlackMessage message = SlackMessage.builder()
            .channel("CRITICAL".equals(severity) ? urgentChannel : defaultChannel)
            .username(botUsername)
            .iconEmoji(":rotating_light:")
            .text(title)
            .blocks(blocks)
            .attachments(Collections.singletonList(
                Attachment.builder()
                    .color(color)
                    .fallback(title)
                    .build()
            ))
            .build();
        
        return sendMessage(message);
    }
    
    /**
     * 메시지 전송 (내부)
     */
    private Mono<Boolean> sendMessage(SlackMessage message) {
        // Webhook URL이 설정된 경우 Webhook 사용
        if (webhookUrl != null && !webhookUrl.isEmpty()) {
            return sendViaWebhook(message);
        }
        
        // API Token이 설정된 경우 Web API 사용
        if (apiToken != null && !apiToken.isEmpty()) {
            return sendViaApi(message);
        }
        
        log.error("Slack Webhook URL 또는 API Token이 설정되지 않음");
        return Mono.just(false);
    }
    
    /**
     * Webhook을 통한 전송
     */
    private Mono<Boolean> sendViaWebhook(SlackMessage message) {
        return slackWebClient.post()
            .uri(webhookUrl)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(message)
            .retrieve()
            .bodyToMono(String.class)
            .map(response -> {
                totalMessagesSent.incrementAndGet();
                channelMetrics.computeIfAbsent(message.getChannel(), k -> new AtomicLong())
                    .incrementAndGet();
                recordMessageTime();
                log.debug("Slack 메시지 전송 성공: {}", message.getChannel());
                return true;
            })
            .retryWhen(Retry.backoff(maxRetryAttempts, Duration.ofSeconds(retryDelaySeconds)))
            .onErrorResume(error -> {
                failedMessages.incrementAndGet();
                log.error("Slack 메시지 전송 실패", error);
                return Mono.just(false);
            });
    }
    
    /**
     * Web API를 통한 전송
     */
    private Mono<Boolean> sendViaApi(SlackMessage message) {
        return slackWebClient.post()
            .uri("https://slack.com/api/chat.postMessage")
            .header(HttpHeaders.AUTHORIZATION, "Bearer " + apiToken)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(message)
            .retrieve()
            .bodyToMono(SlackApiResponse.class)
            .map(response -> {
                if (response.isOk()) {
                    totalMessagesSent.incrementAndGet();
                    channelMetrics.computeIfAbsent(message.getChannel(), k -> new AtomicLong())
                        .incrementAndGet();
                    recordMessageTime();
                    log.debug("Slack API 메시지 전송 성공: {}", message.getChannel());
                    return true;
                } else {
                    log.error("Slack API 오류: {}", response.getError());
                    failedMessages.incrementAndGet();
                    return false;
                }
            })
            .retryWhen(Retry.backoff(maxRetryAttempts, Duration.ofSeconds(retryDelaySeconds)))
            .onErrorResume(error -> {
                failedMessages.incrementAndGet();
                log.error("Slack API 메시지 전송 실패", error);
                return Mono.just(false);
            });
    }
    
    /**
     * WebClient 초기화
     */
    private void initializeWebClient() {
        WebClient.Builder builder = WebClient.builder();
        
        // Webhook URL이 있으면 기본 URL 설정
        if (webhookUrl != null && !webhookUrl.isEmpty()) {
            builder.baseUrl(webhookUrl);
        }
        
        slackWebClient = builder
            .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .build();
    }
    
    /**
     * 메시지 템플릿 로드
     */
    private void loadMessageTemplates() {
        // 보안 이벤트 템플릿
        messageTemplates.put("SECURITY_EVENT", new MessageTemplate(
            ":warning: 보안 이벤트 감지",
            "이벤트: ${eventType}\n위험도: ${riskLevel}\n시간: ${timestamp}"
        ));
        
        // 승인 요청 템플릿
        messageTemplates.put("APPROVAL_REQUEST", new MessageTemplate(
            ":lock: 승인 필요",
            "도구: ${toolName}\n위험도: ${riskLevel}\nID: ${requestId}"
        ));
        
        // 인시던트 템플릿
        messageTemplates.put("INCIDENT", new MessageTemplate(
            ":rotating_light: 보안 인시던트",
            "유형: ${incidentType}\n심각도: ${severity}\n영향: ${impact}"
        ));
    }
    
    /**
     * 메시지 구성
     */
    private SlackMessage buildMessage(String title, Map<String, Object> context, UnifiedNotificationService.NotificationPriority priority) {
        List<Block> blocks = new ArrayList<>();
        
        // 헤더
        blocks.add(Block.header(title));
        
        // 컨텍스트 정보를 섹션으로 추가
        if (context != null && !context.isEmpty()) {
            StringBuilder text = new StringBuilder();
            context.forEach((key, value) -> {
                text.append(String.format("*%s:* %s\n", key, value));
            });
            blocks.add(Block.section(text.toString()));
        }
        
        // 우선순위 표시
        blocks.add(Block.context(
            String.format("우선순위: %s | 시간: %s", priority, LocalDateTime.now())
        ));
        
        return SlackMessage.builder()
            .username(botUsername)
            .iconEmoji(botIconEmoji)
            .text(title)
            .blocks(blocks)
            .build();
    }
    
    /**
     * 텍스트 블록 생성
     */
    private List<Block> createTextBlocks(String title, String content, UnifiedNotificationService.NotificationPriority priority) {
        List<Block> blocks = new ArrayList<>();
        
        blocks.add(Block.header(title));
        blocks.add(Block.section(content));
        blocks.add(Block.context(
            String.format("우선순위: %s | 시간: %s", priority, LocalDateTime.now())
        ));
        
        return blocks;
    }
    
    /**
     * 채널 선택
     */
    private String selectChannel(UnifiedNotificationService.NotificationPriority priority) {
        return switch (priority) {
            case URGENT -> urgentChannel;
            case HIGH -> urgentChannel;
            default -> defaultChannel;
        };
    }
    
    /**
     * 심각도별 색상
     */
    private String getColorForSeverity(String severity) {
        return switch (severity) {
            case "CRITICAL" -> "#FF0000";  // 빨강
            case "HIGH" -> "#FF9900";       // 주황
            case "MEDIUM" -> "#FFCC00";     // 노랑
            case "LOW" -> "#00CC00";        // 초록
            default -> "#808080";           // 회색
        };
    }
    
    /**
     * 심각도별 이모지
     */
    private String getEmojiForSeverity(String severity) {
        return switch (severity) {
            case "CRITICAL" -> "🔴";
            case "HIGH" -> "🟠";
            case "MEDIUM" -> "🟡";
            case "LOW" -> "🟢";
            default -> "⚪";
        };
    }
    
    /**
     * Rate limit 확인
     */
    private Mono<Boolean> checkRateLimit() {
        return Mono.fromCallable(() -> {
            long now = System.currentTimeMillis();
            long oneMinuteAgo = now - 60000;
            
            // 1분 이상 된 메시지 시간 제거
            messageTimes.removeIf(time -> time < oneMinuteAgo);
            
            // Rate limit 확인
            if (messageTimes.size() >= rateLimitPerMinute) {
                return false;
            }
            
            return true;
        });
    }
    
    /**
     * 메시지 시간 기록
     */
    private void recordMessageTime() {
        messageTimes.add(System.currentTimeMillis());
    }
    
    /**
     * 연결 테스트
     */
    private Mono<Boolean> testConnection() {
        if (webhookUrl != null && !webhookUrl.isEmpty()) {
            // Webhook 테스트는 실제 메시지 전송을 피하기 위해 스킵
            return Mono.just(true);
        }
        
        if (apiToken != null && !apiToken.isEmpty()) {
            // API 테스트
            return slackWebClient.get()
                .uri("https://slack.com/api/auth.test")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + apiToken)
                .retrieve()
                .bodyToMono(SlackApiResponse.class)
                .map(SlackApiResponse::isOk)
                .onErrorReturn(false);
        }
        
        return Mono.just(false);
    }
    
    /**
     * 메트릭 조회
     */
    public Map<String, Object> getMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        metrics.put("enabled", slackEnabled);
        metrics.put("totalSent", totalMessagesSent.get());
        metrics.put("totalFailed", failedMessages.get());
        
        Map<String, Long> channelStats = new HashMap<>();
        channelMetrics.forEach((channel, count) -> 
            channelStats.put(channel, count.get())
        );
        metrics.put("channelStats", channelStats);
        
        metrics.put("currentRateUsage", messageTimes.size());
        metrics.put("rateLimit", rateLimitPerMinute);
        
        return metrics;
    }
    
    // 내부 클래스들
    
    /**
     * Slack 메시지
     */
    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    private static class SlackMessage {
        private String channel;
        private String username;
        @com.fasterxml.jackson.annotation.JsonProperty("icon_emoji")
        private String iconEmoji;
        private String text;
        private List<Block> blocks;
        private List<Attachment> attachments;
    }
    
    /**
     * Slack Block
     */
    @lombok.Data
    @lombok.AllArgsConstructor
    private static class Block {
        private String type;
        private Map<String, Object> text;
        private List<Map<String, Object>> elements;
        
        public static Block header(String text) {
            Map<String, Object> textObj = new HashMap<>();
            textObj.put("type", "plain_text");
            textObj.put("text", text);
            
            Block block = new Block();
            block.type = "header";
            block.text = textObj;
            return block;
        }
        
        public static Block section(String text) {
            Map<String, Object> textObj = new HashMap<>();
            textObj.put("type", "mrkdwn");
            textObj.put("text", text);
            
            Block block = new Block();
            block.type = "section";
            block.text = textObj;
            return block;
        }
        
        public static Block divider() {
            Block block = new Block();
            block.type = "divider";
            return block;
        }
        
        public static Block context(String text) {
            Map<String, Object> element = new HashMap<>();
            element.put("type", "mrkdwn");
            element.put("text", text);
            
            Block block = new Block();
            block.type = "context";
            block.elements = Collections.singletonList(element);
            return block;
        }
        
        public static Block actions(List<Button> buttons) {
            Block block = new Block();
            block.type = "actions";
            block.elements = buttons.stream()
                .map(Button::toMap)
                .collect(java.util.stream.Collectors.toList());
            return block;
        }
        
        public Block() {
            // 기본 생성자
        }
    }
    
    /**
     * Slack 버튼
     */
    @lombok.Data
    @lombok.Builder
    private static class Button {
        private String type;
        private Map<String, Object> text;
        private String style;
        private String value;
        private String actionId;
        
        public static Button approve(String requestId) {
            return Button.builder()
                .type("button")
                .text(Map.of("type", "plain_text", "text", "승인"))
                .style("primary")
                .value(requestId)
                .actionId("approve_" + requestId)
                .build();
        }
        
        public static Button reject(String requestId) {
            return Button.builder()
                .type("button")
                .text(Map.of("type", "plain_text", "text", "거부"))
                .style("danger")
                .value(requestId)
                .actionId("reject_" + requestId)
                .build();
        }
        
        public static Button moreInfo(String requestId) {
            return Button.builder()
                .type("button")
                .text(Map.of("type", "plain_text", "text", "상세 정보"))
                .value(requestId)
                .actionId("info_" + requestId)
                .build();
        }
        
        public Map<String, Object> toMap() {
            Map<String, Object> map = new HashMap<>();
            map.put("type", type);
            map.put("text", text);
            if (style != null) map.put("style", style);
            if (value != null) map.put("value", value);
            if (actionId != null) map.put("action_id", actionId);
            return map;
        }
    }
    
    /**
     * Slack Attachment
     */
    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    private static class Attachment {
        private String color;
        private String fallback;
        private List<Map<String, Object>> fields;
        private String footer;
        @com.fasterxml.jackson.annotation.JsonProperty("footer_icon")
        private String footerIcon;
        private Long ts;
    }
    
    /**
     * Slack API 응답
     */
    @lombok.Data
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    private static class SlackApiResponse {
        private boolean ok;
        private String error;
        private String warning;
        private Map<String, Object> responseMetadata;
    }
    
    /**
     * 메시지 템플릿
     */
    @lombok.AllArgsConstructor
    private static class MessageTemplate {
        private final String title;
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