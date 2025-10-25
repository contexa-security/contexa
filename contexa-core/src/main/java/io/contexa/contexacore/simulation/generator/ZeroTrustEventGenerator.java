package io.contexa.contexacore.simulation.generator;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.domain.AuthenticationSuccessEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Zero Trust 이벤트 생성기
 * 
 * Zero Trust 보안 모델 기반의 인증 이벤트를 생성합니다.
 * 비정상 로그인 패턴, 계정 탈취 시나리오, 권한 남용 등을 시뮬레이션합니다.
 * 
 * @author contexa
 * @since 1.0.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ZeroTrustEventGenerator {
    
    private final ApplicationEventPublisher eventPublisher;
    
    // 사용자 계정 풀
    private static final List<String> USER_ACCOUNTS = Arrays.asList(
        "admin", "john.doe", "jane.smith", "bob.johnson",
        "alice.williams", "charlie.brown", "david.miller",
        "service_account", "api_user", "contractor_01"
    );
    
    // IP 주소 풀
    private static final List<String> NORMAL_IPS = Arrays.asList(
        "192.168.1.100", "192.168.1.101", "192.168.1.102",
        "10.0.0.50", "10.0.0.51", "172.16.0.10"
    );
    
    private static final List<String> SUSPICIOUS_IPS = Arrays.asList(
        "45.142.120.0", "185.220.101.0", "199.87.154.255",  // Tor exit nodes
        "104.248.0.0", "159.65.0.0",                        // VPN ranges
        "192.0.2.1", "198.51.100.1", "203.0.113.1"         // TEST-NET
    );
    
    // 디바이스 타입
    private static final List<String> DEVICE_TYPES = Arrays.asList(
        "Windows-Desktop", "MacOS-Laptop", "Linux-Server",
        "iOS-Mobile", "Android-Mobile", "Unknown-Device"
    );
    
    // 위치 정보
    private static final Map<String, String> LOCATIONS = Map.of(
        "Seoul", "Korea",
        "New York", "USA",
        "London", "UK",
        "Moscow", "Russia",
        "Beijing", "China",
        "Unknown", "Unknown"
    );
    
    /**
     * Zero Trust 인증 이벤트 타입
     */
    public enum ZeroTrustEventType {
        NORMAL_LOGIN("정상 로그인", 2.0),
        SUSPICIOUS_LOCATION("의심스러운 위치", 5.0),
        IMPOSSIBLE_TRAVEL("불가능한 이동", 7.5),
        BRUTE_FORCE_ATTEMPT("무차별 대입 시도", 6.5),
        CREDENTIAL_STUFFING("크리덴셜 스터핑", 7.0),
        ACCOUNT_TAKEOVER("계정 탈취", 8.5),
        PRIVILEGE_ABUSE("권한 남용", 8.0),
        LATERAL_MOVEMENT("측면 이동", 7.5),
        DORMANT_ACCOUNT_ACCESS("휴면 계정 접근", 6.0),
        SERVICE_ACCOUNT_MISUSE("서비스 계정 오용", 7.0),
        MFA_BYPASS_ATTEMPT("MFA 우회 시도", 8.5),
        SESSION_HIJACKING("세션 하이재킹", 8.0);
        
        private final String description;
        private final double baseRiskScore;
        
        ZeroTrustEventType(String description, double baseRiskScore) {
            this.description = description;
            this.baseRiskScore = baseRiskScore;
        }
        
        public String getDescription() { return description; }
        public double getBaseRiskScore() { return baseRiskScore; }
    }
    
    /**
     * 정상 로그인 이벤트 생성
     */
    public SecurityEvent generateNormalLogin() {
        String username = getRandomItem(USER_ACCOUNTS);
        String sourceIp = getRandomItem(NORMAL_IPS);
        String deviceType = getRandomItem(DEVICE_TYPES);
        String location = getRandomLocation();
        
        Map<String, Object> details = new HashMap<>();
        details.put("eventType", ZeroTrustEventType.NORMAL_LOGIN.name());
        details.put("username", username);
        details.put("sourceIp", sourceIp);
        details.put("deviceType", deviceType);
        details.put("location", location);
        details.put("authMethod", "password");
        details.put("mfaEnabled", ThreadLocalRandom.current().nextBoolean());
        details.put("trustScore", 0.85 + ThreadLocalRandom.current().nextDouble(0.15));
        
        SecurityEvent event = SecurityEvent.builder()
            .eventId(UUID.randomUUID().toString())
            .eventType(SecurityEvent.EventType.AUTH_SUCCESS)
            .severity(SecurityEvent.Severity.LOW)
            .sourceIp(sourceIp)
            .targetSystem("auth-service")
            .description(String.format("정상 로그인: %s from %s (%s)", username, sourceIp, location))
            .riskScore(ZeroTrustEventType.NORMAL_LOGIN.getBaseRiskScore())
            .confidenceScore(0.95)
            .timestamp(LocalDateTime.now())
            .details(details)
            .build();
        
        // Spring ApplicationEvent 발행 (ZeroTrustAuthenticationEventListener가 처리)
        publishAuthenticationEvent(event);
        
        return event;
    }
    
    /**
     * 의심스러운 위치에서의 로그인
     */
    public SecurityEvent generateSuspiciousLocationLogin() {
        String username = getRandomItem(USER_ACCOUNTS);
        String sourceIp = getRandomItem(SUSPICIOUS_IPS);
        String location = "Moscow, Russia";  // 의심스러운 위치
        
        Map<String, Object> details = new HashMap<>();
        details.put("eventType", ZeroTrustEventType.SUSPICIOUS_LOCATION.name());
        details.put("username", username);
        details.put("sourceIp", sourceIp);
        details.put("location", location);
        details.put("deviceType", "Unknown-Device");
        details.put("previousLocation", "Seoul, Korea");
        details.put("timeSinceLastLogin", "5 minutes");
        details.put("vpnDetected", true);
        details.put("torDetected", ThreadLocalRandom.current().nextBoolean());
        details.put("trustScore", 0.3 + ThreadLocalRandom.current().nextDouble(0.2));
        
        return SecurityEvent.builder()
            .eventId(UUID.randomUUID().toString())
            .eventType(SecurityEvent.EventType.SUSPICIOUS_ACTIVITY)
            .severity(SecurityEvent.Severity.MEDIUM)
            .sourceIp(sourceIp)
            .targetSystem("auth-service")
            .description(String.format("의심스러운 위치 로그인: %s from %s", username, location))
            .riskScore(ZeroTrustEventType.SUSPICIOUS_LOCATION.getBaseRiskScore())
            .confidenceScore(0.80)
            .timestamp(LocalDateTime.now())
            .details(details)
            .build();
    }
    
    /**
     * 불가능한 이동 감지 (Impossible Travel)
     */
    public SecurityEvent generateImpossibleTravel() {
        String username = getRandomItem(USER_ACCOUNTS);
        
        Map<String, Object> details = new HashMap<>();
        details.put("eventType", ZeroTrustEventType.IMPOSSIBLE_TRAVEL.name());
        details.put("username", username);
        details.put("firstLocation", "Seoul, Korea");
        details.put("firstLoginTime", LocalDateTime.now().minusMinutes(30));
        details.put("firstIp", "211.234.10.20");
        details.put("secondLocation", "New York, USA");
        details.put("secondLoginTime", LocalDateTime.now());
        details.put("secondIp", "74.125.224.72");
        details.put("distanceKm", 10965);
        details.put("timeDifferenceMinutes", 30);
        details.put("physicallyImpossible", true);
        details.put("trustScore", 0.15);
        
        return SecurityEvent.builder()
            .eventId(UUID.randomUUID().toString())
            .eventType(SecurityEvent.EventType.ANOMALY_DETECTED)
            .severity(SecurityEvent.Severity.HIGH)
            .sourceIp("74.125.224.72")
            .targetSystem("auth-service")
            .description(String.format("불가능한 이동 감지: %s - Seoul→New York in 30분", username))
            .riskScore(ZeroTrustEventType.IMPOSSIBLE_TRAVEL.getBaseRiskScore())
            .confidenceScore(0.95)
            .timestamp(LocalDateTime.now())
            .details(details)
            .build();
    }
    
    /**
     * 계정 탈취 시도
     */
    public SecurityEvent generateAccountTakeover() {
        String username = getRandomItem(USER_ACCOUNTS);
        String attackerIp = getRandomItem(SUSPICIOUS_IPS);
        
        Map<String, Object> details = new HashMap<>();
        details.put("eventType", ZeroTrustEventType.ACCOUNT_TAKEOVER.name());
        details.put("username", username);
        details.put("attackerIp", attackerIp);
        details.put("legitimateUserIp", getRandomItem(NORMAL_IPS));
        details.put("passwordChanged", true);
        details.put("mfaDisabled", true);
        details.put("emailChanged", true);
        details.put("suspiciousActivities", Arrays.asList(
            "Password reset from new device",
            "MFA disabled",
            "Email changed to attacker domain",
            "API keys generated",
            "Data export initiated"
        ));
        details.put("trustScore", 0.05);
        
        return SecurityEvent.builder()
            .eventId(UUID.randomUUID().toString())
            .eventType(SecurityEvent.EventType.INTRUSION_SUCCESS)
            .severity(SecurityEvent.Severity.CRITICAL)
            .sourceIp(attackerIp)
            .targetSystem("auth-service")
            .description(String.format("계정 탈취 감지: %s - 의심스러운 계정 변경 활동", username))
            .riskScore(ZeroTrustEventType.ACCOUNT_TAKEOVER.getBaseRiskScore())
            .confidenceScore(0.92)
            .timestamp(LocalDateTime.now())
            .details(details)
            .build();
    }
    
    /**
     * 권한 남용 감지
     */
    public SecurityEvent generatePrivilegeAbuse() {
        String username = getRandomItem(USER_ACCOUNTS);
        
        Map<String, Object> details = new HashMap<>();
        details.put("eventType", ZeroTrustEventType.PRIVILEGE_ABUSE.name());
        details.put("username", username);
        details.put("normalRole", "user");
        details.put("elevatedRole", "admin");
        details.put("unusualActions", Arrays.asList(
            "Accessing admin panel",
            "Modifying system configurations",
            "Exporting large datasets",
            "Creating new admin accounts",
            "Disabling audit logs"
        ));
        details.put("timeOfDay", "02:30 AM");
        details.put("afterHours", true);
        details.put("trustScore", 0.25);
        
        return SecurityEvent.builder()
            .eventId(UUID.randomUUID().toString())
            .eventType(SecurityEvent.EventType.PRIVILEGE_ESCALATION)
            .severity(SecurityEvent.Severity.HIGH)
            .sourceIp(getRandomItem(NORMAL_IPS))
            .targetSystem("admin-panel")
            .description(String.format("권한 남용 감지: %s - 비정상적인 관리자 활동", username))
            .riskScore(ZeroTrustEventType.PRIVILEGE_ABUSE.getBaseRiskScore())
            .confidenceScore(0.88)
            .timestamp(LocalDateTime.now())
            .details(details)
            .build();
    }
    
    /**
     * 휴면 계정 접근
     */
    public SecurityEvent generateDormantAccountAccess() {
        String username = "old_employee_" + ThreadLocalRandom.current().nextInt(100);
        
        Map<String, Object> details = new HashMap<>();
        details.put("eventType", ZeroTrustEventType.DORMANT_ACCOUNT_ACCESS.name());
        details.put("username", username);
        details.put("lastLoginDays", ThreadLocalRandom.current().nextInt(90, 365));
        details.put("accountCreated", LocalDateTime.now().minusYears(2));
        details.put("employeeStatus", "terminated");
        details.put("accessAttempted", Arrays.asList(
            "Email system",
            "File server",
            "Database",
            "Source code repository"
        ));
        details.put("trustScore", 0.10);
        
        return SecurityEvent.builder()
            .eventId(UUID.randomUUID().toString())
            .eventType(SecurityEvent.EventType.SUSPICIOUS_ACTIVITY)
            .severity(SecurityEvent.Severity.HIGH)
            .sourceIp(getRandomItem(SUSPICIOUS_IPS))
            .targetSystem("auth-service")
            .description(String.format("휴면 계정 접근 시도: %s - 퇴사자 계정", username))
            .riskScore(ZeroTrustEventType.DORMANT_ACCOUNT_ACCESS.getBaseRiskScore())
            .confidenceScore(0.90)
            .timestamp(LocalDateTime.now())
            .details(details)
            .build();
    }
    
    /**
     * MFA 우회 시도
     */
    public SecurityEvent generateMfaBypassAttempt() {
        String username = getRandomItem(USER_ACCOUNTS);
        
        Map<String, Object> details = new HashMap<>();
        details.put("eventType", ZeroTrustEventType.MFA_BYPASS_ATTEMPT.name());
        details.put("username", username);
        details.put("bypassMethod", getRandomItem(Arrays.asList(
            "SMS interception",
            "SIM swapping",
            "Phishing for OTP",
            "Session cookie theft",
            "Man-in-the-middle"
        )));
        details.put("mfaType", "TOTP");
        details.put("failedAttempts", ThreadLocalRandom.current().nextInt(3, 10));
        details.put("sourceIp", getRandomItem(SUSPICIOUS_IPS));
        details.put("trustScore", 0.08);
        
        return SecurityEvent.builder()
            .eventId(UUID.randomUUID().toString())
            .eventType(SecurityEvent.EventType.AUTH_FAILURE)
            .severity(SecurityEvent.Severity.CRITICAL)
            .sourceIp(getRandomItem(SUSPICIOUS_IPS))
            .targetSystem("auth-service")
            .description(String.format("MFA 우회 시도 감지: %s", username))
            .riskScore(ZeroTrustEventType.MFA_BYPASS_ATTEMPT.getBaseRiskScore())
            .confidenceScore(0.85)
            .timestamp(LocalDateTime.now())
            .details(details)
            .build();
    }
    
    /**
     * 서비스 계정 오용
     */
    public SecurityEvent generateServiceAccountMisuse() {
        String serviceAccount = "svc_" + getRandomItem(Arrays.asList(
            "api", "backup", "monitoring", "deployment", "integration"
        ));
        
        Map<String, Object> details = new HashMap<>();
        details.put("eventType", ZeroTrustEventType.SERVICE_ACCOUNT_MISUSE.name());
        details.put("serviceAccount", serviceAccount);
        details.put("expectedUsage", "API calls only");
        details.put("actualUsage", Arrays.asList(
            "Interactive login",
            "Console access",
            "Manual file operations",
            "Database queries",
            "System configuration changes"
        ));
        details.put("sourceIp", getRandomItem(NORMAL_IPS));
        details.put("apiKeyAge", ThreadLocalRandom.current().nextInt(30, 365) + " days");
        details.put("trustScore", 0.20);
        
        return SecurityEvent.builder()
            .eventId(UUID.randomUUID().toString())
            .eventType(SecurityEvent.EventType.ACCESS_CONTROL_VIOLATION)
            .severity(SecurityEvent.Severity.HIGH)
            .sourceIp(getRandomItem(NORMAL_IPS))
            .targetSystem("api-gateway")
            .description(String.format("서비스 계정 오용 감지: %s - 대화형 로그인", serviceAccount))
            .riskScore(ZeroTrustEventType.SERVICE_ACCOUNT_MISUSE.getBaseRiskScore())
            .confidenceScore(0.87)
            .timestamp(LocalDateTime.now())
            .details(details)
            .build();
    }
    
    /**
     * 측면 이동 (Lateral Movement) 감지
     */
    public SecurityEvent generateLateralMovement() {
        String username = getRandomItem(USER_ACCOUNTS);
        
        Map<String, Object> details = new HashMap<>();
        details.put("eventType", ZeroTrustEventType.LATERAL_MOVEMENT.name());
        details.put("username", username);
        details.put("sourceSystem", "workstation-01");
        details.put("targetSystems", Arrays.asList(
            "file-server-01",
            "db-server-02",
            "backup-server-01",
            "admin-server-01"
        ));
        details.put("accessMethod", "RDP");
        details.put("unusualPattern", true);
        details.put("timeWindow", "10 minutes");
        details.put("systemsAccessed", 4);
        details.put("trustScore", 0.18);
        
        return SecurityEvent.builder()
            .eventId(UUID.randomUUID().toString())
            .eventType(SecurityEvent.EventType.LATERAL_MOVEMENT)
            .severity(SecurityEvent.Severity.HIGH)
            .sourceIp("192.168.1.50")
            .targetSystem("multiple")
            .description(String.format("측면 이동 감지: %s - 다중 시스템 접근", username))
            .riskScore(ZeroTrustEventType.LATERAL_MOVEMENT.getBaseRiskScore())
            .confidenceScore(0.83)
            .timestamp(LocalDateTime.now())
            .details(details)
            .build();
    }
    
    /**
     * 복합 Zero Trust 시나리오 생성
     */
    public List<SecurityEvent> generateComplexZeroTrustScenario() {
        List<SecurityEvent> scenario = new ArrayList<>();
        String targetUser = getRandomItem(USER_ACCOUNTS);
        String attackerIp = getRandomItem(SUSPICIOUS_IPS);
        
        // 1단계: 크리덴셜 스터핑
        SecurityEvent credentialStuffing = generateCredentialStuffing(targetUser, attackerIp);
        scenario.add(credentialStuffing);
        
        // 2단계: MFA 우회 시도
        SecurityEvent mfaBypass = generateMfaBypassAttempt();
        mfaBypass.getDetails().put("username", targetUser);
        mfaBypass.getDetails().put("sourceIp", attackerIp);
        scenario.add(mfaBypass);
        
        // 3단계: 계정 탈취
        SecurityEvent accountTakeover = generateAccountTakeover();
        accountTakeover.getDetails().put("username", targetUser);
        accountTakeover.getDetails().put("attackerIp", attackerIp);
        scenario.add(accountTakeover);
        
        // 4단계: 측면 이동
        SecurityEvent lateralMovement = generateLateralMovement();
        lateralMovement.getDetails().put("username", targetUser);
        scenario.add(lateralMovement);
        
        // 5단계: 데이터 유출 (AttackScenarioGenerator의 메서드 활용 가능)
        
        // 캠페인 ID 부여
        String campaignId = "ZT-CAMPAIGN-" + UUID.randomUUID().toString().substring(0, 8);
        scenario.forEach(event -> {
            event.getDetails().put("zeroCampaignId", campaignId);
            event.getDetails().put("targetUser", targetUser);
        });
        
        log.info("Zero Trust 복합 시나리오 생성: {} 단계, 대상: {}", scenario.size(), targetUser);
        
        return scenario;
    }
    
    /**
     * 크리덴셜 스터핑 공격
     */
    private SecurityEvent generateCredentialStuffing(String username, String sourceIp) {
        Map<String, Object> details = new HashMap<>();
        details.put("eventType", ZeroTrustEventType.CREDENTIAL_STUFFING.name());
        details.put("username", username);
        details.put("sourceIp", sourceIp);
        details.put("attemptCount", ThreadLocalRandom.current().nextInt(100, 1000));
        details.put("credentialSource", "leaked_database");
        details.put("successRate", "0.1%");
        details.put("trustScore", 0.05);
        
        return SecurityEvent.builder()
            .eventId(UUID.randomUUID().toString())
            .eventType(SecurityEvent.EventType.CREDENTIAL_STUFFING)
            .severity(SecurityEvent.Severity.HIGH)
            .sourceIp(sourceIp)
            .targetSystem("auth-service")
            .description(String.format("크리덴셜 스터핑 공격: %s", username))
            .riskScore(ZeroTrustEventType.CREDENTIAL_STUFFING.getBaseRiskScore())
            .confidenceScore(0.91)
            .timestamp(LocalDateTime.now())
            .details(details)
            .build();
    }
    
    /**
     * 무작위 Zero Trust 이벤트 생성
     */
    public SecurityEvent generateRandomZeroTrustEvent() {
        ZeroTrustEventType[] types = ZeroTrustEventType.values();
        ZeroTrustEventType selectedType = types[ThreadLocalRandom.current().nextInt(types.length)];
        
        switch (selectedType) {
            case NORMAL_LOGIN:
                return generateNormalLogin();
            case SUSPICIOUS_LOCATION:
                return generateSuspiciousLocationLogin();
            case IMPOSSIBLE_TRAVEL:
                return generateImpossibleTravel();
            case ACCOUNT_TAKEOVER:
                return generateAccountTakeover();
            case PRIVILEGE_ABUSE:
                return generatePrivilegeAbuse();
            case DORMANT_ACCOUNT_ACCESS:
                return generateDormantAccountAccess();
            case MFA_BYPASS_ATTEMPT:
                return generateMfaBypassAttempt();
            case SERVICE_ACCOUNT_MISUSE:
                return generateServiceAccountMisuse();
            case LATERAL_MOVEMENT:
                return generateLateralMovement();
            default:
                return generateNormalLogin();
        }
    }
    
    /**
     * Spring ApplicationEvent 발행
     */
    private void publishAuthenticationEvent(SecurityEvent event) {
        try {
            // AuthenticationSuccessEvent 생성 및 발행
            AuthenticationSuccessEvent authEvent = AuthenticationSuccessEvent.builder()
                .username((String) event.getDetails().get("username"))
                .sourceIp(event.getSourceIp())
                .sessionId(UUID.randomUUID().toString())
                .deviceId((String) event.getDetails().get("deviceType"))
                .trustScore(event.getRiskScore())
                .eventTimestamp(event.getTimestamp())
                .build();
            
            eventPublisher.publishEvent(authEvent);
            
            log.debug("Zero Trust 인증 이벤트 발행: {}", authEvent.getUsername());
            
        } catch (Exception e) {
            log.error("인증 이벤트 발행 실패", e);
        }
    }
    
    // 유틸리티 메서드
    private <T> T getRandomItem(List<T> list) {
        return list.get(ThreadLocalRandom.current().nextInt(list.size()));
    }
    
    private String getRandomLocation() {
        List<String> cities = new ArrayList<>(LOCATIONS.keySet());
        String city = cities.get(ThreadLocalRandom.current().nextInt(cities.size()));
        return city + ", " + LOCATIONS.get(city);
    }
}