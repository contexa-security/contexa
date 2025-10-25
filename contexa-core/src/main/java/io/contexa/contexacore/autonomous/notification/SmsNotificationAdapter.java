package io.contexa.contexacore.autonomous.notification;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
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

/**
 * SmsNotificationAdapter - SMS 알림 어댑터
 * 
 * SMS 게이트웨이를 통해 긴급 보안 알림을 전송하는 어댑터입니다.
 * Twilio, AWS SNS, 국내 SMS 서비스 등을 지원합니다.
 * 
 * @author contexa
 * @since 1.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SmsNotificationAdapter {
    
    private final ObjectMapper objectMapper;
    
    // WebClient for SMS Gateway
    private WebClient smsWebClient;
    
    // SMS 제공자 타입
    public enum SmsProvider {
        TWILIO, AWS_SNS, ALIGO, COOLSMS, CUSTOM
    }
    
    // 설정값
    @Value("${sms.provider:TWILIO}")
    private SmsProvider provider;
    
    @Value("${sms.api.url:}")
    private String apiUrl;
    
    @Value("${sms.api.key:}")
    private String apiKey;
    
    @Value("${sms.api.secret:}")
    private String apiSecret;
    
    @Value("${sms.sender.number:}")
    private String senderNumber;
    
    @Value("${sms.sender.id:contexa}")
    private String senderId;
    
    @Value("${sms.max.length:140}")
    private int maxMessageLength;
    
    @Value("${sms.retry.max-attempts:2}")
    private int maxRetryAttempts;
    
    @Value("${sms.retry.delay-seconds:3}")
    private int retryDelaySeconds;
    
    @Value("${sms.rate-limit.messages-per-hour:100}")
    private int rateLimitPerHour;
    
    @Value("${sms.enabled:false}")
    private boolean smsEnabled;
    
    @Value("${sms.emergency.only:true}")
    private boolean emergencyOnly;
    
    // 수신자 관리
    private final Map<String, RecipientInfo> recipientRegistry = new ConcurrentHashMap<>();
    
    // 메시지 템플릿
    private final Map<String, SmsTemplate> templates = new ConcurrentHashMap<>();
    
    // 메트릭
    private final AtomicLong totalSmsSent = new AtomicLong(0);
    private final AtomicLong failedSms = new AtomicLong(0);
    private final Map<String, AtomicLong> providerMetrics = new ConcurrentHashMap<>();
    
    // Rate limiting (시간별)
    private final List<Long> smsTimes = Collections.synchronizedList(new ArrayList<>());
    
    // 전화번호 검증 패턴
    private static final Pattern PHONE_PATTERN = Pattern.compile("^\\+?[1-9]\\d{1,14}$");
    private static final Pattern KOREAN_PHONE_PATTERN = Pattern.compile("^(010|011|016|017|018|019)-?\\d{3,4}-?\\d{4}$");
    
    @PostConstruct
    public void initialize() {
        if (!smsEnabled) {
            log.info("SMS 알림 비활성화됨");
            return;
        }
        
        log.info("SMS 알림 어댑터 초기화 시작 - Provider: {}", provider);
        
        // WebClient 초기화
        initializeWebClient();
        
        // 템플릿 로드
        loadSmsTemplates();
        
        // 수신자 로드
        loadRecipients();
        
        // 연결 테스트
        if (!emergencyOnly) {
            testConnection().subscribe(
                success -> log.info("SMS 게이트웨이 연결 테스트 성공"),
                error -> log.error("SMS 게이트웨이 연결 테스트 실패", error)
            );
        }
        
        log.info("SMS 알림 어댑터 초기화 완료");
    }
    
    /**
     * 전화번호로 SMS 발송
     */
    public Mono<Boolean> sendToPhone(String phoneNumber, String message, UnifiedNotificationService.NotificationPriority priority) {
        if (!smsEnabled) {
            return Mono.just(false);
        }
        
        // 긴급 전용 모드 체크
        if (emergencyOnly && priority != UnifiedNotificationService.NotificationPriority.URGENT) {
            log.debug("긴급 전용 모드 - 우선순위 불충족: {}", priority);
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
    
    /**
     * SMS 발송 (간단한 인터페이스)
     */
    public Mono<Boolean> sendSms(String subject, String content, UnifiedNotificationService.NotificationPriority priority) {
        if (!smsEnabled) {
            return Mono.just(false);
        }
        
        // 긴급 알림 수신자 목록 가져오기
        List<String> recipients = getRecipientsForPriority(priority);
        
        if (recipients.isEmpty()) {
            log.warn("SMS 수신자가 없음 - Priority: {}", priority);
            return Mono.just(false);
        }
        
        String message = formatSmsMessage(subject, content);
        
        // 모든 수신자에게 발송
        return Flux.fromIterable(recipients)
            .flatMap(phone -> sendToPhone(phone, message, priority))
            .reduce(false, (a, b) -> a || b);  // 하나라도 성공하면 true
    }
    
    /**
     * 보안 알림 SMS 발송
     */
    public Mono<Boolean> sendSecurityAlert(String alertType, String severity, String description, String action) {
        if (!smsEnabled) {
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
    
    /**
     * 승인 요청 SMS 발송
     */
    public Mono<Boolean> sendApprovalRequest(String requestId, String toolName, String riskLevel, String approverPhone) {
        if (!smsEnabled) {
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
    
    /**
     * 배치 SMS 발송
     */
    public Mono<List<SmsResult>> sendBatchSms(List<SmsRequest> requests) {
        if (!smsEnabled) {
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
    
    /**
     * 실제 SMS 발송 (Provider별 구현)
     */
    private Mono<Boolean> sendSmsMessage(String phoneNumber, String message, UnifiedNotificationService.NotificationPriority priority) {
        recordSmsTime();
        
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
                log.info("SMS 발송 성공 - To: {}, Priority: {}", maskPhoneNumber(phoneNumber), priority);
            } else {
                failedSms.incrementAndGet();
            }
        })
        .retryWhen(Retry.backoff(maxRetryAttempts, Duration.ofSeconds(retryDelaySeconds)))
        .onErrorResume(error -> {
            failedSms.incrementAndGet();
            log.error("SMS 발송 실패 - To: {}", maskPhoneNumber(phoneNumber), error);
            return Mono.just(false);
        });
    }
    
    /**
     * Twilio SMS 발송
     */
    private Mono<Boolean> sendViaTwilio(String phoneNumber, String message) {
        Map<String, String> body = new HashMap<>();
        body.put("To", phoneNumber);
        body.put("From", senderNumber);
        body.put("Body", message);
        
        String auth = Base64.getEncoder().encodeToString(
            (apiKey + ":" + apiSecret).getBytes()
        );
        
        return smsWebClient.post()
            .uri("/2010-04-01/Accounts/" + apiKey + "/Messages.json")
            .header(HttpHeaders.AUTHORIZATION, "Basic " + auth)
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .bodyValue(body)
            .retrieve()
            .bodyToMono(TwilioResponse.class)
            .map(response -> response.getStatus() != null && !response.getStatus().equals("failed"));
    }
    
    /**
     * AWS SNS SMS 발송
     */
    private Mono<Boolean> sendViaAwsSns(String phoneNumber, String message) {
        Map<String, Object> request = new HashMap<>();
        request.put("PhoneNumber", phoneNumber);
        request.put("Message", message);
        request.put("MessageAttributes", Map.of(
            "AWS.SNS.SMS.SenderID", Map.of("DataType", "String", "StringValue", senderId),
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
    
    /**
     * 알리고 SMS 발송 (국내)
     */
    private Mono<Boolean> sendViaAligo(String phoneNumber, String message) {
        Map<String, String> params = new HashMap<>();
        params.put("key", apiKey);
        params.put("user_id", apiSecret);
        params.put("sender", senderNumber);
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
    
    /**
     * CoolSMS 발송 (국내)
     */
    private Mono<Boolean> sendViaCoolSms(String phoneNumber, String message) {
        Map<String, Object> params = new HashMap<>();
        params.put("to", phoneNumber);
        params.put("from", senderNumber);
        params.put("text", message);
        params.put("type", "SMS");
        
        return smsWebClient.post()
            .uri("/messages/v4/send")
            .header(HttpHeaders.AUTHORIZATION, "HMAC-SHA256 apiKey=" + apiKey + ", date=" + 
                LocalDateTime.now() + ", salt=" + UUID.randomUUID())
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(params)
            .retrieve()
            .bodyToMono(CoolSmsResponse.class)
            .map(response -> "2000".equals(response.getStatusCode()));
    }
    
    /**
     * 커스텀 게이트웨이 발송
     */
    private Mono<Boolean> sendViaCustom(String phoneNumber, String message) {
        Map<String, Object> request = new HashMap<>();
        request.put("to", phoneNumber);
        request.put("from", senderNumber);
        request.put("message", message);
        request.put("apiKey", apiKey);
        
        return smsWebClient.post()
            .uri(apiUrl)
            .contentType(MediaType.APPLICATION_JSON)
            .bodyValue(request)
            .retrieve()
            .bodyToMono(Map.class)
            .map(response -> {
                Object success = response.get("success");
                return success != null && (boolean) success;
            });
    }
    
    /**
     * WebClient 초기화
     */
    private void initializeWebClient() {
        String baseUrl = switch (provider) {
            case TWILIO -> "https://api.twilio.com";
            case AWS_SNS -> "https://sns." + getAwsRegion() + ".amazonaws.com";
            case ALIGO -> "https://apis.aligo.in";
            case COOLSMS -> "https://api.coolsms.co.kr";
            case CUSTOM -> apiUrl;
        };
        
        smsWebClient = WebClient.builder()
            .baseUrl(baseUrl)
            .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .build();
    }
    
    /**
     * SMS 템플릿 로드
     */
    private void loadSmsTemplates() {
        // 보안 알림 템플릿
        templates.put("SECURITY_ALERT", new SmsTemplate(
            "[CONTEXA] ${severity} ${type}\n${description}\n조치:${action}"
        ));
        
        // 승인 요청 템플릿
        templates.put("APPROVAL", new SmsTemplate(
            "[CONTEXA] 승인필요\n${toolName}\n위험:${riskLevel}\nID:${requestId}"
        ));
        
        // 인시던트 템플릿
        templates.put("INCIDENT", new SmsTemplate(
            "[긴급] 보안인시던트\n${incidentType}\n즉시확인필요"
        ));
    }
    
    /**
     * 수신자 로드
     */
    private void loadRecipients() {
        // 설정 파일이나 DB에서 수신자 정보 로드
        // 예시로 하드코딩
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
    
    /**
     * 전화번호 검증
     */
    private Mono<String> validatePhoneNumber(String phoneNumber) {
        return Mono.fromCallable(() -> {
            if (phoneNumber == null || phoneNumber.isEmpty()) {
                throw new IllegalArgumentException("전화번호가 없음");
            }
            
            String cleaned = phoneNumber.replaceAll("[\\s\\-\\(\\)]", "");
            
            // 한국 번호 체크
            if (KOREAN_PHONE_PATTERN.matcher(cleaned).matches()) {
                // 국제 형식으로 변환
                cleaned = "+82" + cleaned.substring(1).replaceAll("-", "");
            }
            
            // 국제 형식 체크
            if (!PHONE_PATTERN.matcher(cleaned).matches()) {
                throw new IllegalArgumentException("유효하지 않은 전화번호: " + phoneNumber);
            }
            
            return cleaned;
        });
    }
    
    /**
     * 메시지 길이 제한
     */
    private String truncateMessage(String message) {
        if (message == null) return "";
        
        if (message.length() <= maxMessageLength) {
            return message;
        }
        
        return message.substring(0, maxMessageLength - 3) + "...";
    }
    
    /**
     * SMS 메시지 포맷팅
     */
    private String formatSmsMessage(String subject, String content) {
        String formatted = String.format("[CONTEXA] %s\n%s", subject, content);
        return truncateMessage(formatted);
    }
    
    /**
     * 우선순위별 수신자 목록
     */
    private List<String> getRecipientsForPriority(UnifiedNotificationService.NotificationPriority priority) {
        List<String> recipients = new ArrayList<>();
        
        recipientRegistry.values().stream()
            .filter(info -> info.getPriorities().contains(priority))
            .forEach(info -> recipients.addAll(info.getPhoneNumbers()));
        
        return recipients;
    }
    
    /**
     * Rate limit 체크
     */
    private Mono<Boolean> checkRateLimit() {
        return Mono.fromCallable(() -> {
            long now = System.currentTimeMillis();
            long oneHourAgo = now - 3600000;
            
            // 1시간 이상 된 기록 제거
            smsTimes.removeIf(time -> time < oneHourAgo);
            
            // Rate limit 체크
            if (smsTimes.size() >= rateLimitPerHour) {
                return false;
            }
            
            return true;
        });
    }
    
    /**
     * SMS 시간 기록
     */
    private void recordSmsTime() {
        smsTimes.add(System.currentTimeMillis());
    }
    
    /**
     * 전화번호 마스킹
     */
    private String maskPhoneNumber(String phoneNumber) {
        if (phoneNumber == null || phoneNumber.length() < 8) {
            return "****";
        }
        
        int len = phoneNumber.length();
        return phoneNumber.substring(0, 3) + "****" + phoneNumber.substring(len - 4);
    }
    
    /**
     * AWS 리전 가져오기
     */
    private String getAwsRegion() {
        // 환경변수나 설정에서 가져오기
        return System.getenv().getOrDefault("AWS_REGION", "ap-northeast-2");
    }
    
    /**
     * 기본 보안 템플릿 생성
     */
    private SmsTemplate createDefaultSecurityTemplate() {
        return new SmsTemplate("[CONTEXA] ${severity} 보안알림\n${description}");
    }
    
    /**
     * 연결 테스트
     */
    private Mono<Boolean> testConnection() {
        // Provider별 연결 테스트
        return switch (provider) {
            case TWILIO -> testTwilioConnection();
            case AWS_SNS -> testAwsSnsConnection();
            case ALIGO, COOLSMS, CUSTOM -> Mono.just(true);  // 실제 테스트는 비용 발생
        };
    }
    
    /**
     * Twilio 연결 테스트
     */
    private Mono<Boolean> testTwilioConnection() {
        String auth = Base64.getEncoder().encodeToString(
            (apiKey + ":" + apiSecret).getBytes()
        );
        
        return smsWebClient.get()
            .uri("/2010-04-01/Accounts/" + apiKey + ".json")
            .header(HttpHeaders.AUTHORIZATION, "Basic " + auth)
            .retrieve()
            .bodyToMono(Map.class)
            .map(response -> response != null)
            .onErrorReturn(false);
    }
    
    /**
     * AWS SNS 연결 테스트
     */
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
    
    /**
     * 메트릭 조회
     */
    public Map<String, Object> getMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        metrics.put("enabled", smsEnabled);
        metrics.put("provider", provider.name());
        metrics.put("totalSent", totalSmsSent.get());
        metrics.put("totalFailed", failedSms.get());
        
        Map<String, Long> providerStats = new HashMap<>();
        providerMetrics.forEach((prov, count) -> 
            providerStats.put(prov, count.get())
        );
        metrics.put("providerStats", providerStats);
        
        metrics.put("currentHourUsage", smsTimes.size());
        metrics.put("hourlyLimit", rateLimitPerHour);
        metrics.put("recipientGroups", recipientRegistry.size());
        
        return metrics;
    }
    
    // 내부 클래스들
    
    /**
     * SMS 요청
     */
    @lombok.Data
    @lombok.Builder
    public static class SmsRequest {
        private String phoneNumber;
        private String message;
        private UnifiedNotificationService.NotificationPriority priority;
    }
    
    /**
     * SMS 결과
     */
    @lombok.Data
    @lombok.AllArgsConstructor
    public static class SmsResult {
        private String phoneNumber;
        private boolean success;
        private String errorMessage;
    }
    
    /**
     * 수신자 정보
     */
    @lombok.Data
    @lombok.AllArgsConstructor
    private static class RecipientInfo {
        private String name;
        private List<String> phoneNumbers;
        private Set<UnifiedNotificationService.NotificationPriority> priorities;
    }
    
    /**
     * SMS 템플릿
     */
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
    
    // Provider별 응답 클래스들
    
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