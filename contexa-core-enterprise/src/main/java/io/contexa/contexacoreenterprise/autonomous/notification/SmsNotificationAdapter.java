package io.contexa.contexacoreenterprise.autonomous.notification;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacoreenterprise.properties.SmsProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import jakarta.annotation.PostConstruct;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

@Slf4j
@RequiredArgsConstructor
public class SmsNotificationAdapter {
    
    private final ObjectMapper objectMapper;
    private final SmsProperties smsProperties;

    private WebClient smsWebClient;

    public enum SmsProvider {
        TWILIO, AWS_SNS, ALIGO, COOLSMS, CUSTOM
    }

    private final Map<String, RecipientInfo> recipientRegistry = new ConcurrentHashMap<>();

    private final Map<String, SmsTemplate> templates = new ConcurrentHashMap<>();

    private final AtomicLong totalSmsSent = new AtomicLong(0);
    private final AtomicLong failedSms = new AtomicLong(0);
    private final Map<String, AtomicLong> providerMetrics = new ConcurrentHashMap<>();

    private final List<Long> smsTimes = Collections.synchronizedList(new ArrayList<>());

    private static final Pattern PHONE_PATTERN = Pattern.compile("^\\+?[1-9]\\d{1,14}$");
    private static final Pattern KOREAN_PHONE_PATTERN = Pattern.compile("^(010|011|016|017|018|019)-?\\d{3,4}-?\\d{4}$");
    
    @PostConstruct
    public void initialize() {
        if (!smsProperties.isEnabled()) {
                        return;
        }

        initializeWebClient();

        loadSmsTemplates();

        loadRecipients();

        if (!smsProperties.isEmergencyOnly()) {
            testConnection().subscribe(
                    success -> log.info("SMS 게이트웨이 연결 테스트 성공"),
                    error -> log.error("SMS 게이트웨이 연결 테스트 실패", error)
            );
        }

    }

    public Mono<Boolean> sendToPhone(String phoneNumber, String message, UnifiedNotificationService.NotificationPriority priority) {
        if (!smsProperties.isEnabled()) {
            return Mono.just(false);
        }

        if (smsProperties.isEmergencyOnly() && priority != UnifiedNotificationService.NotificationPriority.URGENT) {
                        return Mono.just(false);
        }
        
        return validatePhoneNumber(phoneNumber)
            .flatMap(validNumber -> checkRateLimit()
                .flatMap(allowed -> {
                    if (!allowed) {
                        log.warn("SMS rate limit 초과");
                        return Mono.just(false);
                    }
                    
                    String truncatedMessage = truncateMessage(message);
                    return sendSmsMessage(validNumber, truncatedMessage, priority);
                })
            );
    }

    public Mono<Boolean> sendSms(String subject, String content, UnifiedNotificationService.NotificationPriority priority) {
        if (!smsProperties.isEnabled()) {
            return Mono.just(false);
        }

        List<String> recipients = getRecipientsForPriority(priority);
        
        if (recipients.isEmpty()) {
            log.warn("SMS 수신자가 없음 - Priority: {}", priority);
            return Mono.just(false);
        }
        
        String message = formatSmsMessage(subject, content);

        return Flux.fromIterable(recipients)
            .flatMap(phone -> sendToPhone(phone, message, priority))
            .reduce(false, (a, b) -> a || b);  
    }

    public Mono<Boolean> sendSecurityAlert(String alertType, String severity, String description, String action) {
        if (!smsProperties.isEnabled()) {
            return Mono.just(false);
        }
        
        SmsTemplate template = templates.get("SECURITY_ALERT");
        if (template == null) {
            template = createDefaultSecurityTemplate();
        }
        
        Map<String, Object> context = new HashMap<>();
        context.put("type", alertType);
        context.put("severity", severity);
        context.put("description", description);
        context.put("action", action);
        context.put("time", LocalDateTime.now().toString());
        
        String message = template.render(context);
        
        UnifiedNotificationService.NotificationPriority priority = 
            "CRITICAL".equals(severity) ? UnifiedNotificationService.NotificationPriority.URGENT : 
            UnifiedNotificationService.NotificationPriority.HIGH;
        
        return sendSms("보안 알림", message, priority);
    }

    public Mono<Boolean> sendApprovalRequest(String requestId, String toolName, String riskLevel, String approverPhone) {
        if (!smsProperties.isEnabled()) {
            return Mono.just(false);
        }
        
        String message = String.format(
            "[contexa] 승인요청\n도구:%s\n위험:%s\nID:%s\n승인링크:https://ai3sec.com/approve/%s",
            toolName,
            riskLevel,
            requestId.substring(0, 8),
            requestId
        );
        
        return sendToPhone(approverPhone, message, UnifiedNotificationService.NotificationPriority.HIGH);
    }

    public Mono<List<SmsResult>> sendBatchSms(List<SmsRequest> requests) {
        if (!smsProperties.isEnabled()) {
            return Mono.just(Collections.emptyList());
        }
        
        return Flux.fromIterable(requests)
            .flatMap(request -> 
                sendToPhone(request.getPhoneNumber(), request.getMessage(), request.getPriority())
                    .map(success -> new SmsResult(request.getPhoneNumber(), success, 
                        success ? null : "Failed to send"))
            )
            .collectList();
    }

    private Mono<Boolean> sendSmsMessage(String phoneNumber, String message, UnifiedNotificationService.NotificationPriority priority) {
        recordSmsTime();
        
        SmsProvider provider = SmsProvider.valueOf(smsProperties.getProvider());
        return (switch (provider) {
            case TWILIO -> sendViaTwilio(phoneNumber, message);
            case AWS_SNS -> sendViaAwsSns(phoneNumber, message);
            case ALIGO -> sendViaAligo(phoneNumber, message);
            case COOLSMS -> sendViaCoolSms(phoneNumber, message);
            case CUSTOM -> sendViaCustom(phoneNumber, message);
        })
        .doOnSuccess(success -> {
            if (success) {
                totalSmsSent.incrementAndGet();
                providerMetrics.computeIfAbsent(provider.name(), k -> new AtomicLong())
                    .incrementAndGet();
                            } else {
                failedSms.incrementAndGet();
            }
        })
        .retryWhen(Retry.backoff(smsProperties.getRetry().getMaxAttempts(), Duration.ofSeconds(smsProperties.getRetry().getDelaySeconds())))
        .onErrorResume(error -> {
            failedSms.incrementAndGet();
            log.error("SMS 발송 실패 - To: {}", maskPhoneNumber(phoneNumber), error);
            return Mono.just(false);
        });
    }

    private Mono<Boolean> sendViaTwilio(String phoneNumber, String message) {
        Map<String, String> body = new HashMap<>();
        body.put("To", phoneNumber);
        body.put("From", smsProperties.getSender().getNumber());
        body.put("Body", message);
        
        String auth = Base64.getEncoder().encodeToString(
            (smsProperties.getApi().getKey() + ":" + smsProperties.getApi().getSecret()).getBytes()
        );
        
        return smsWebClient.post()
            .uri("/2010-04-01/Accounts/" + smsProperties.getApi().getKey() + "/Messages.json")
            .header(HttpHeaders.AUTHORIZATION, "Basic " + auth)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .bodyValue(body)
            .retrieve()
            .bodyToMono(TwilioResponse.class)
            .map(response -> response.getStatus() != null && !response.getStatus().equals("failed"));
    }

    private Mono<Boolean> sendViaAwsSns(String phoneNumber, String message) {
        Map<String, Object> request = new HashMap<>();
        request.put("PhoneNumber", phoneNumber);
        request.put("Message", message);
        request.put("MessageAttributes", Map.of(
            "AWS.SNS.SMS.SenderID", Map.of("DataType", "String", "StringValue", smsProperties.getSender().getId()),
            "AWS.SNS.SMS.SMSType", Map.of("DataType", "String", "StringValue", "Transactional")
        ));
        
        return smsWebClient.post()
            .uri("/")
            .header("X-Amz-Target", "AmazonSNS.Publish")
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(request)
            .retrieve()
            .bodyToMono(AwsSnsResponse.class)
            .map(response -> response.getMessageId() != null);
    }

    private Mono<Boolean> sendViaAligo(String phoneNumber, String message) {
        Map<String, String> params = new HashMap<>();
        params.put("key", smsProperties.getApi().getKey());
        params.put("user_id", smsProperties.getApi().getSecret());
        params.put("sender", smsProperties.getSender().getNumber());
        params.put("receiver", phoneNumber);
        params.put("msg", message);
        params.put("testmode_yn", "N");
        
        return smsWebClient.post()
            .uri("/send/")
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .bodyValue(params)
            .retrieve()
            .bodyToMono(AligoResponse.class)
            .map(response -> response.getResultCode() == 1);
    }

    private Mono<Boolean> sendViaCoolSms(String phoneNumber, String message) {
        Map<String, Object> params = new HashMap<>();
        params.put("to", phoneNumber);
        params.put("from", smsProperties.getSender().getNumber());
        params.put("text", message);
        params.put("type", "SMS");
        
        return smsWebClient.post()
            .uri("/messages/v4/send")
            .header(HttpHeaders.AUTHORIZATION, "HMAC-SHA256 apiKey=" + smsProperties.getApi().getKey() + ", date=" +
                LocalDateTime.now() + ", salt=" + UUID.randomUUID())
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(params)
            .retrieve()
            .bodyToMono(CoolSmsResponse.class)
            .map(response -> "2000".equals(response.getStatusCode()));
    }

    private Mono<Boolean> sendViaCustom(String phoneNumber, String message) {
        Map<String, Object> request = new HashMap<>();
        request.put("to", phoneNumber);
        request.put("from", smsProperties.getSender().getNumber());
        request.put("message", message);
        request.put("apiKey", smsProperties.getApi().getKey());
        
        return smsWebClient.post()
            .uri(smsProperties.getApi().getUrl())
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(request)
            .retrieve()
            .bodyToMono(Map.class)
            .map(response -> {
                Object success = response.get("success");
                return success != null && (boolean) success;
            });
    }

    private void initializeWebClient() {
        SmsProvider provider = SmsProvider.valueOf(smsProperties.getProvider());
        String clientBaseUrl = switch (provider) {
            case TWILIO -> "https://api.twilio.com";
            case AWS_SNS -> "https://sns." + getAwsRegion() + ".amazonaws.com";
            case ALIGO -> "https://apis.aligo.in";
            case COOLSMS -> "https://api.coolsms.co.kr";
            case CUSTOM -> smsProperties.getApi().getUrl();
        };
        
        smsWebClient = WebClient.builder()
            .baseUrl(clientBaseUrl)
            .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .build();
    }

    private void loadSmsTemplates() {
        
        templates.put("SECURITY_ALERT", new SmsTemplate(
            "[CONTEXA] ${severity} ${type}\n${description}\n조치:${action}"
        ));

        templates.put("APPROVAL", new SmsTemplate(
            "[CONTEXA] 승인필요\n${toolName}\n위험:${riskLevel}\nID:${requestId}"
        ));

        templates.put("INCIDENT", new SmsTemplate(
            "[긴급] 보안인시던트\n${incidentType}\n즉시확인필요"
        ));
    }

    private void loadRecipients() {

        recipientRegistry.put("security_team", new RecipientInfo(
            "Security Team",
            Arrays.asList("+821012345678", "+821087654321"),
            EnumSet.of(UnifiedNotificationService.NotificationPriority.URGENT, 
                       UnifiedNotificationService.NotificationPriority.HIGH)
        ));
        
        recipientRegistry.put("on_call", new RecipientInfo(
            "On-Call Engineer",
            Collections.singletonList("+821098765432"),
            EnumSet.allOf(UnifiedNotificationService.NotificationPriority.class)
        ));
    }

    private Mono<String> validatePhoneNumber(String phoneNumber) {
        return Mono.fromCallable(() -> {
            if (phoneNumber == null || phoneNumber.isEmpty()) {
                throw new IllegalArgumentException("전화번호가 없음");
            }
            
            String cleaned = phoneNumber.replaceAll("[\\s\\-\\(\\)]", "");

            if (KOREAN_PHONE_PATTERN.matcher(cleaned).matches()) {
                
                cleaned = "+82" + cleaned.substring(1).replaceAll("-", "");
            }

            if (!PHONE_PATTERN.matcher(cleaned).matches()) {
                throw new IllegalArgumentException("유효하지 않은 전화번호: " + phoneNumber);
            }
            
            return cleaned;
        });
    }

    private String truncateMessage(String message) {
        if (message == null) return "";
        
        if (message.length() <= smsProperties.getMax().getLength()) {
            return message;
        }
        
        return message.substring(0, smsProperties.getMax().getLength() - 3) + "...";
    }

    private String formatSmsMessage(String subject, String content) {
        String formatted = String.format("[CONTEXA] %s\n%s", subject, content);
        return truncateMessage(formatted);
    }

    private List<String> getRecipientsForPriority(UnifiedNotificationService.NotificationPriority priority) {
        List<String> recipients = new ArrayList<>();
        
        recipientRegistry.values().stream()
            .filter(info -> info.getPriorities().contains(priority))
            .forEach(info -> recipients.addAll(info.getPhoneNumbers()));
        
        return recipients;
    }

    private Mono<Boolean> checkRateLimit() {
        return Mono.fromCallable(() -> {
            long now = System.currentTimeMillis();
            long oneHourAgo = now - 3600000;

            smsTimes.removeIf(time -> time < oneHourAgo);

            if (smsTimes.size() >= smsProperties.getRateLimit().getMessagesPerHour()) {
                return false;
            }
            
            return true;
        });
    }

    private void recordSmsTime() {
        smsTimes.add(System.currentTimeMillis());
    }

    private String maskPhoneNumber(String phoneNumber) {
        if (phoneNumber == null || phoneNumber.length() < 8) {
            return "****";
        }
        
        int len = phoneNumber.length();
        return phoneNumber.substring(0, 3) + "****" + phoneNumber.substring(len - 4);
    }

    private String getAwsRegion() {
        
        return System.getenv().getOrDefault("AWS_REGION", "ap-northeast-2");
    }

    private SmsTemplate createDefaultSecurityTemplate() {
        return new SmsTemplate("[CONTEXA] ${severity} 보안알림\n${description}");
    }

    private Mono<Boolean> testConnection() {
        
        SmsProvider provider = SmsProvider.valueOf(smsProperties.getProvider());
        return switch (provider) {
            case TWILIO -> testTwilioConnection();
            case AWS_SNS -> testAwsSnsConnection();
            case ALIGO, COOLSMS, CUSTOM -> Mono.just(true);
        };
    }

    private Mono<Boolean> testTwilioConnection() {
        String auth = Base64.getEncoder().encodeToString(
            (smsProperties.getApi().getKey() + ":" + smsProperties.getApi().getSecret()).getBytes()
        );
        
        return smsWebClient.get()
            .uri("/2010-04-01/Accounts/" + smsProperties.getApi().getKey() + ".json")
            .header(HttpHeaders.AUTHORIZATION, "Basic " + auth)
            .retrieve()
            .bodyToMono(Map.class)
            .map(response -> response != null)
            .onErrorReturn(false);
    }

    private Mono<Boolean> testAwsSnsConnection() {
        return smsWebClient.post()
            .uri("/")
            .header("X-Amz-Target", "AmazonSNS.GetSMSAttributes")
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(Map.of())
            .retrieve()
            .bodyToMono(Map.class)
            .map(response -> response != null)
            .onErrorReturn(false);
    }

    public Map<String, Object> getMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        metrics.put("enabled", smsProperties.isEnabled());
        metrics.put("provider", smsProperties.getProvider());
        metrics.put("totalSent", totalSmsSent.get());
        metrics.put("totalFailed", failedSms.get());
        
        Map<String, Long> providerStats = new HashMap<>();
        providerMetrics.forEach((prov, count) -> 
            providerStats.put(prov, count.get())
        );
        metrics.put("providerStats", providerStats);
        
        metrics.put("currentHourUsage", smsTimes.size());
        metrics.put("hourlyLimit", smsProperties.getRateLimit().getMessagesPerHour());
        metrics.put("recipientGroups", recipientRegistry.size());
        
        return metrics;
    }

    @lombok.Data
    @lombok.Builder
    public static class SmsRequest {
        private String phoneNumber;
        private String message;
        private UnifiedNotificationService.NotificationPriority priority;
    }

    @lombok.Data
    @lombok.AllArgsConstructor
    public static class SmsResult {
        private String phoneNumber;
        private boolean success;
        private String errorMessage;
    }

    @lombok.Data
    @lombok.AllArgsConstructor
    private static class RecipientInfo {
        private String name;
        private List<String> phoneNumbers;
        private Set<UnifiedNotificationService.NotificationPriority> priorities;
    }

    @lombok.AllArgsConstructor
    private static class SmsTemplate {
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

    @lombok.Data
    private static class TwilioResponse {
        private String sid;
        private String status;
        private String errorCode;
        private String errorMessage;
    }
    
    @lombok.Data
    private static class AwsSnsResponse {
        private String messageId;
        private Map<String, Object> responseMetadata;
    }
    
    @lombok.Data
    private static class AligoResponse {
        private int resultCode;
        private String message;
        private String msgId;
    }
    
    @lombok.Data
    private static class CoolSmsResponse {
        private String statusCode;
        private String statusMessage;
        private String groupId;
    }
}