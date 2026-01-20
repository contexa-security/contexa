package io.contexa.contexacoreenterprise.autonomous.notification;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import jakarta.annotation.PostConstruct;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;


@Slf4j
@RequiredArgsConstructor
public class SlackNotificationAdapter {
    
    private final ObjectMapper objectMapper;
    
    
    private WebClient slackWebClient;
    
    
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
    
    
    private final Map<String, MessageTemplate> messageTemplates = new ConcurrentHashMap<>();
    
    
    private final AtomicLong totalMessagesSent = new AtomicLong(0);
    private final AtomicLong failedMessages = new AtomicLong(0);
    private final Map<String, AtomicLong> channelMetrics = new ConcurrentHashMap<>();
    
    
    private final List<Long> messageTimes = Collections.synchronizedList(new ArrayList<>());
    
    @PostConstruct
    public void initialize() {
        if (!slackEnabled) {
            log.info("Slack 알림 비활성화됨");
            return;
        }
        
        log.info("Slack 알림 어댑터 초기화 시작");
        
        
        initializeWebClient();
        
        
        loadMessageTemplates();
        
        
        testConnection().subscribe(
            success -> log.info("Slack 연결 테스트 성공"),
            error -> log.error("Slack 연결 테스트 실패", error)
        );
        
        log.info("Slack 알림 어댑터 초기화 완료");
    }
    
    
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
    
    
    public Mono<Boolean> sendApprovalRequest(String requestId, String toolName, String riskLevel, Map<String, Object> context) {
        if (!slackEnabled) {
            return Mono.just(false);
        }
        
        List<Block> blocks = new ArrayList<>();
        
        
        blocks.add(Block.header("🔐 도구 실행 승인 요청"));
        
        
        blocks.add(Block.section(
            String.format("*도구:* %s\n*위험도:* %s\n*요청 ID:* `%s`", 
                toolName, riskLevel, requestId)
        ));
        
        
        if (context != null && !context.isEmpty()) {
            StringBuilder contextText = new StringBuilder();
            context.forEach((key, value) -> 
                contextText.append(String.format("• %s: %s\n", key, value))
            );
            blocks.add(Block.section("*상세 정보:*\n" + contextText.toString()));
        }
        
        
        blocks.add(Block.actions(Arrays.asList(
            Button.approve(requestId),
            Button.reject(requestId),
            Button.moreInfo(requestId)
        )));
        
        
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
    
    
    public Mono<Boolean> sendSecurityAlert(String title, String severity, Map<String, String> details, List<String> recommendations) {
        if (!slackEnabled) {
            return Mono.just(false);
        }
        
        List<Block> blocks = new ArrayList<>();
        
        
        String color = getColorForSeverity(severity);
        
        
        blocks.add(Block.header(String.format("%s", title)));
        
        
        blocks.add(Block.section(
            String.format("*심각도:* %s %s", getEmojiForSeverity(severity), severity)
        ));
        
        
        if (details != null && !details.isEmpty()) {
            StringBuilder detailText = new StringBuilder("*상세 정보:*\n");
            details.forEach((key, value) -> 
                detailText.append(String.format("• %s: %s\n", key, value))
            );
            blocks.add(Block.section(detailText.toString()));
        }
        
        
        if (recommendations != null && !recommendations.isEmpty()) {
            StringBuilder recText = new StringBuilder("*권장 조치:*\n");
            recommendations.forEach(rec -> 
                recText.append(String.format("✓ %s\n", rec))
            );
            blocks.add(Block.section(recText.toString()));
        }
        
        
        blocks.add(Block.divider());
        
        
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
    
    
    private Mono<Boolean> sendMessage(SlackMessage message) {
        
        if (webhookUrl != null && !webhookUrl.isEmpty()) {
            return sendViaWebhook(message);
        }
        
        
        if (apiToken != null && !apiToken.isEmpty()) {
            return sendViaApi(message);
        }
        
        log.error("Slack Webhook URL 또는 API Token이 설정되지 않음");
        return Mono.just(false);
    }
    
    
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
    
    
    private void initializeWebClient() {
        WebClient.Builder builder = WebClient.builder();
        
        
        if (webhookUrl != null && !webhookUrl.isEmpty()) {
            builder.baseUrl(webhookUrl);
        }
        
        slackWebClient = builder
            .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .build();
    }
    
    
    private void loadMessageTemplates() {
        
        messageTemplates.put("SECURITY_EVENT", new MessageTemplate(
            ":warning: 보안 이벤트 감지",
            "이벤트: ${eventType}\n위험도: ${riskLevel}\n시간: ${timestamp}"
        ));
        
        
        messageTemplates.put("APPROVAL_REQUEST", new MessageTemplate(
            ":lock: 승인 필요",
            "도구: ${toolName}\n위험도: ${riskLevel}\nID: ${requestId}"
        ));
        
        
        messageTemplates.put("INCIDENT", new MessageTemplate(
            ":rotating_light: 보안 인시던트",
            "유형: ${incidentType}\n심각도: ${severity}\n영향: ${impact}"
        ));
    }
    
    
    private SlackMessage buildMessage(String title, Map<String, Object> context, UnifiedNotificationService.NotificationPriority priority) {
        List<Block> blocks = new ArrayList<>();
        
        
        blocks.add(Block.header(title));
        
        
        if (context != null && !context.isEmpty()) {
            StringBuilder text = new StringBuilder();
            context.forEach((key, value) -> {
                text.append(String.format("*%s:* %s\n", key, value));
            });
            blocks.add(Block.section(text.toString()));
        }
        
        
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
    
    
    private List<Block> createTextBlocks(String title, String content, UnifiedNotificationService.NotificationPriority priority) {
        List<Block> blocks = new ArrayList<>();
        
        blocks.add(Block.header(title));
        blocks.add(Block.section(content));
        blocks.add(Block.context(
            String.format("우선순위: %s | 시간: %s", priority, LocalDateTime.now())
        ));
        
        return blocks;
    }
    
    
    private String selectChannel(UnifiedNotificationService.NotificationPriority priority) {
        return switch (priority) {
            case URGENT -> urgentChannel;
            case HIGH -> urgentChannel;
            default -> defaultChannel;
        };
    }
    
    
    private String getColorForSeverity(String severity) {
        return switch (severity) {
            case "CRITICAL" -> "#FF0000";  
            case "HIGH" -> "#FF9900";       
            case "MEDIUM" -> "#FFCC00";     
            case "LOW" -> "#00CC00";        
            default -> "#808080";           
        };
    }
    
    
    private String getEmojiForSeverity(String severity) {
        return switch (severity) {
            case "CRITICAL" -> "🔴";
            case "HIGH" -> "🟠";
            case "MEDIUM" -> "🟡";
            case "LOW" -> "🟢";
            default -> "⚪";
        };
    }
    
    
    private Mono<Boolean> checkRateLimit() {
        return Mono.fromCallable(() -> {
            long now = System.currentTimeMillis();
            long oneMinuteAgo = now - 60000;
            
            
            messageTimes.removeIf(time -> time < oneMinuteAgo);
            
            
            if (messageTimes.size() >= rateLimitPerMinute) {
                return false;
            }
            
            return true;
        });
    }
    
    
    private void recordMessageTime() {
        messageTimes.add(System.currentTimeMillis());
    }
    
    
    private Mono<Boolean> testConnection() {
        if (webhookUrl != null && !webhookUrl.isEmpty()) {
            
            return Mono.just(true);
        }
        
        if (apiToken != null && !apiToken.isEmpty()) {
            
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
            
        }
    }
    
    
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
    
    
    @lombok.Data
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    private static class SlackApiResponse {
        private boolean ok;
        private String error;
        private String warning;
        private Map<String, Object> responseMetadata;
    }
    
    
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