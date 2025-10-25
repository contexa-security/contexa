package io.contexa.contexacore.simulation.strategy.impl;

import io.contexa.contexacore.domain.entity.AttackResult;
import io.contexa.contexacore.simulation.client.SimulationClient;
import io.contexa.contexacore.simulation.domain.LoginAttempt;
import io.contexa.contexacore.simulation.strategy.IAuthenticationAttack;
import io.contexa.contexacore.simulation.publisher.SimulationEventPublisher;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 크리덴셜 스터핑 공격 전략 구현
 * 
 * 유출된 계정 정보 데이터베이스를 사용하여 대량의 계정을 시도하는 공격을 시뮬레이션합니다.
 * 실제 데이터 유출 사고에서 획득한 계정 정보를 재사용하는 공격 패턴을 모방합니다.
 * 
 * @author contexa
 * @since 1.0.0
 */
@Slf4j
@Component
public class CredentialStuffingStrategy implements IAuthenticationAttack {

    private SimulationClient simulationClient;
    private SimulationEventPublisher eventPublisher;
    
    public CredentialStuffingStrategy() {
        // 기본 생성자
    }
    
    public CredentialStuffingStrategy(SimulationClient simulationClient) {
        this.simulationClient = simulationClient;
    }
    
    @Value("${simulation.attack.credential-stuffing.delay-ms:500}")
    private int delayMs;
    
    @Value("${simulation.attack.credential-stuffing.max-attempts:100}")
    private int maxAttempts;
    
    @Value("${simulation.attack.credential-stuffing.distributed:true}")
    private boolean distributedMode;
    
    // 유출된 계정 정보 시뮬레이션 (실제로는 더 큰 데이터셋)
    private static final List<Credential> LEAKED_DATABASE = generateLeakedDatabase();
    
    @Override
    public void setEventPublisher(SimulationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    // 다양한 IP 주소 풀 (분산 공격 시뮬레이션)
    private static final List<String> PROXY_IPS = Arrays.asList(
        generateRandomIP(), generateRandomIP(), generateRandomIP(),
        "203.0.113.10", "198.51.100.20", "203.0.113.30",
        generateRandomIP(), generateRandomIP(), generateRandomIP() // Dynamic IPs instead of Tor nodes
    );
    
    @Override
    public AttackResult execute(AttackContext context) {
        log.warn("=== 크리덴셜 스터핑 공격 시작 ===");
        
        AttackResult result = AttackResult.builder()
            .attackId(UUID.randomUUID().toString())
            .campaignId(context.getCampaignId())
            .type(AttackResult.AttackType.CREDENTIAL_STUFFING)
            .attackName("Credential Stuffing Attack")
            .executionTime(LocalDateTime.now())
            .attackVector("login")
            .sourceIp(distributedMode ? getRandomProxyIP() : generateRandomIP())
            .targetUser(context.getTargetUser())
            .build();
        
        long startTime = System.currentTimeMillis();
        List<String> successfulAccounts = new ArrayList<>();
        Map<String, Object> attackPayload = new HashMap<>();
        
        try {
            // 공격 대상 도메인
            String targetDomain = context.getParameter("domain", String.class);
            if (targetDomain == null) {
                targetDomain = extractDomain(context.getTargetEndpoint());
            }
            
            // 유출 데이터베이스에서 관련 계정 필터링
            List<Credential> targetCredentials = filterCredentialsForDomain(targetDomain);
            
            log.info("타겟 도메인: {}, 시도할 계정 수: {}", targetDomain, targetCredentials.size());
            
            int attemptCount = 0;
            int successCount = 0;
            
            for (Credential cred : targetCredentials) {
                if (attemptCount >= maxAttempts) {
                    log.info("최대 시도 횟수 도달: {}", maxAttempts);
                    break;
                }
                
                // 분산 모드일 경우 IP 변경
                if (distributedMode && attemptCount % 5 == 0) {
                    changeSourceIP();
                }
                
                // 로그인 시도
                LoginAttempt attempt = attemptLoginWithLeakedCredential(cred);
                attempt.setAttackId(result.getAttackId());
                attempt.setThreatCategory("credential_stuffing");
                
                if (attempt.isSuccessful()) {
                    log.error("!!! 크리덴셜 스터핑 성공: username={}, source={}",
                        cred.getUsername(), cred.getSource());
                    successfulAccounts.add(cred.getUsername());
                    successCount++;

                    // 성공 이벤트 발행 (비정상적 로그인 - 유출된 자격증명 사용)
                    if (eventPublisher != null) {
                        eventPublisher.publishAuthenticationSuccess(
                            result,
                            cred.getUsername(),
                            distributedMode ? getRandomProxyIP() : result.getSourceIp(),
                            UUID.randomUUID().toString(),
                            true, // anomaly detected
                            0.1 // very low trust score
                        );
                    }

                    // 성공한 계정으로 추가 활동 (데이터 수집)
                    performPostLoginActivities(cred.getUsername());
                } else {
                    // 실패 이벤트 발행
                    if (eventPublisher != null) {
                        eventPublisher.publishAuthenticationFailure(
                            result,
                            cred.getUsername(),
                            distributedMode ? getRandomProxyIP() : result.getSourceIp(),
                            "Invalid credentials - credential stuffing attempt",
                            attemptCount + 1
                        );
                    }
                }
                
                attemptCount++;
                
                // 지능형 지연 (봇 탐지 회피)
                applyAntiDetectionDelay(attemptCount);
                
                // 주기적으로 세션 초기화
                if (attemptCount % 20 == 0) {
                    simulationClient.clearSession();
                    log.debug("세션 초기화 및 User-Agent 변경");
                }
            }
            
            result.setAttemptCount(attemptCount);
            result.setDuration(System.currentTimeMillis() - startTime);
            result.setAttackSuccessful(successCount > 0);
            
            // 공격 페이로드 기록
            attackPayload.put("total_attempts", attemptCount);
            attackPayload.put("successful_accounts", successfulAccounts);
            attackPayload.put("success_rate", (double) successCount / attemptCount);
            attackPayload.put("leaked_db_source", "simulated_breach_2024");
            result.setAttackPayload(attackPayload);
            
            // 위험도 평가
            calculateRiskScore(result, attemptCount, successCount);
            
            // 데이터 유출 시뮬레이션
            if (successCount > 0) {
                long exfiltratedData = simulateDataExfiltration(successfulAccounts);
                result.setDataExfiltratedBytes(exfiltratedData);
            }
            
        } catch (Exception e) {
            log.error("크리덴셜 스터핑 공격 중 오류: {}", e.getMessage(), e);
            result.setFailureReason(e.getMessage());
        }
        
        log.warn("=== 크리덴셜 스터핑 공격 종료: attempts={}, success={}, duration={}ms ===",
            result.getAttemptCount(), 
            attackPayload.get("successful_accounts") != null ? 
                ((List<?>) attackPayload.get("successful_accounts")).size() : 0,
            result.getDuration());
        
        return result;
    }
    
    @Override
    public LoginAttempt attemptLogin(String username, String password) {
        return attemptLoginWithLeakedCredential(new Credential(username, password, null, "manual"));
    }
    
    /**
     * 유출된 계정으로 로그인 시도
     */
    private LoginAttempt attemptLoginWithLeakedCredential(Credential credential) {
        LoginAttempt attempt = LoginAttempt.builder()
            .attemptId(UUID.randomUUID().toString())
            .username(credential.getUsername())
            .password(credential.getPassword())
            .timestamp(LocalDateTime.now())
            .sourceIp(distributedMode ? getRandomProxyIP() : simulationClient.getBaseUrl())
            .deviceFingerprint(generateRandomDeviceFingerprint())
            .userAgent(generateRandomUserAgent())
            .build();
        
        try {
            // 실제 로그인 시도
            ResponseEntity<String> response = simulationClient.loginJson(
                credential.getUsername(), 
                credential.getPassword()
            );
            
            attempt.setSuccessful(response.getStatusCode() == HttpStatus.OK);
            
            if (!attempt.isSuccessful()) {
                attempt.setFailureReason(response.getStatusCode().toString());
            }
            
            // 컨텍스트 데이터 추가
            Map<String, Object> contextData = new HashMap<>();
            contextData.put("leaked_database_match", true);
            contextData.put("credential_source", credential.getSource());
            contextData.put("breach_date", "2024-01-15"); // 시뮬레이션
            attempt.setContextData(contextData);
            
            // 위험 평가
            attempt.setRiskScore(0.9); // 크리덴셜 스터핑은 매우 높은 위험
            attempt.setRiskLevel("CRITICAL");
            attempt.setIsAnomaly(true);
            attempt.setAnomalyType("credential_stuffing");
            
        } catch (Exception e) {
            attempt.setSuccessful(false);
            attempt.setFailureReason(e.getMessage());
        }
        
        return attempt;
    }
    
    @Override
    public List<LoginAttempt> attemptMultipleLogins(List<Credential> credentials) {
        List<LoginAttempt> attempts = new ArrayList<>();
        
        for (Credential cred : credentials) {
            attempts.add(attemptLoginWithLeakedCredential(cred));
            
            try {
                // 봇 탐지 회피를 위한 랜덤 지연
                Thread.sleep(ThreadLocalRandom.current().nextInt(200, 1000));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        
        return attempts;
    }
    
    /**
     * 유출 데이터베이스 생성 (시뮬레이션)
     */
    private static List<Credential> generateLeakedDatabase() {
        List<Credential> database = new ArrayList<>();
        
        // LinkedIn 유출 시뮬레이션
        database.add(new Credential("john.doe@example.com", "John123!", "example.com", "linkedin_breach"));
        database.add(new Credential("jane.smith@example.com", "Jane@456", "example.com", "linkedin_breach"));
        database.add(new Credential("admin@example.com", "Admin@2024", "example.com", "linkedin_breach"));
        
        // Facebook 유출 시뮬레이션
        database.add(new Credential("user001", "Pass123!", null, "facebook_breach"));
        database.add(new Credential("testuser", "Test1234", null, "facebook_breach"));
        database.add(new Credential("michael.j", "Mj123456", null, "facebook_breach"));
        
        // Yahoo 유출 시뮬레이션
        database.add(new Credential("sarah.w@yahoo.com", "Sarah2024", "yahoo.com", "yahoo_breach"));
        database.add(new Credential("robert.brown", "Robert123", null, "yahoo_breach"));
        
        // Collection #1 시뮬레이션
        database.add(new Credential("developer@company.com", "Dev@2024", "company.com", "collection1"));
        database.add(new Credential("manager@company.com", "Manager123!", "company.com", "collection1"));
        
        // 추가 랜덤 데이터
        String[] domains = {"gmail.com", "outlook.com", "company.com", "example.org"};
        String[] names = {"alice", "bob", "charlie", "david", "emma", "frank", "grace", "henry"};
        String[] passwords = {"Password1", "Welcome123", "Summer2024", "Qwerty123", "Admin123"};
        
        for (String name : names) {
            for (String domain : domains) {
                String email = name + "@" + domain;
                String password = passwords[ThreadLocalRandom.current().nextInt(passwords.length)];
                database.add(new Credential(email, password, domain, "mixed_breach"));
            }
        }
        
        return database;
    }
    
    /**
     * 도메인별 계정 필터링
     */
    private List<Credential> filterCredentialsForDomain(String targetDomain) {
        if (targetDomain == null || targetDomain.isEmpty()) {
            return LEAKED_DATABASE;
        }
        
        List<Credential> filtered = new ArrayList<>();
        
        for (Credential cred : LEAKED_DATABASE) {
            // 도메인이 일치하거나 도메인 정보가 없는 경우 포함
            if (cred.getDomain() == null || 
                cred.getDomain().equals(targetDomain) ||
                cred.getUsername().contains(targetDomain)) {
                filtered.add(cred);
            }
        }
        
        // 필터링된 결과가 너무 적으면 전체 사용
        if (filtered.size() < 10) {
            return LEAKED_DATABASE;
        }
        
        return filtered;
    }
    
    /**
     * 도메인 추출
     */
    private String extractDomain(String endpoint) {
        if (endpoint == null) return null;
        
        // URL에서 도메인 추출 로직
        if (endpoint.contains("://")) {
            String[] parts = endpoint.split("://")[1].split("/")[0].split(":");
            return parts[0];
        }
        
        return endpoint;
    }
    
    /**
     * 소스 IP 변경 (프록시 시뮬레이션)
     */
    private void changeSourceIP() {
        String newIP = getRandomProxyIP();
        log.debug("IP 변경: {}", newIP);
        // 실제로는 SimulationClient에 IP 변경 기능 추가 필요
    }
    
    /**
     * 랜덤 프록시 IP 선택
     */
    private String getRandomProxyIP() {
        return PROXY_IPS.get(ThreadLocalRandom.current().nextInt(PROXY_IPS.size()));
    }
    
    /**
     * 로그인 성공 후 활동
     */
    private void performPostLoginActivities(String username) {
        try {
            // 프로필 정보 수집
            simulationClient.get("/api/user/profile", null, null);
            Thread.sleep(500);
            
            // 민감한 데이터 접근 시도
            simulationClient.get("/api/user/financial", null, null);
            Thread.sleep(500);
            
            // 다른 사용자 정보 열람 시도 (IDOR)
            simulationClient.get("/api/user/1234/profile", null, null);
            
            log.debug("계정 {} 탈취 후 데이터 수집 완료", username);
            
        } catch (Exception e) {
            log.debug("후속 활동 중 오류: {}", e.getMessage());
        }
    }
    
    /**
     * 봇 탐지 회피 지연
     */
    private void applyAntiDetectionDelay(int attemptCount) throws InterruptedException {
        if (attemptCount % 10 == 0) {
            // 10회마다 긴 휴식
            Thread.sleep(ThreadLocalRandom.current().nextInt(5000, 15000));
        } else if (attemptCount % 3 == 0) {
            // 3회마다 중간 휴식
            Thread.sleep(ThreadLocalRandom.current().nextInt(1000, 3000));
        } else {
            // 기본 지연
            Thread.sleep(ThreadLocalRandom.current().nextInt(200, delayMs));
        }
    }
    
    /**
     * 데이터 유출 시뮬레이션
     */
    private long simulateDataExfiltration(List<String> accounts) {
        // 계정당 평균 10MB 데이터 유출 시뮬레이션
        return accounts.size() * 10 * 1024 * 1024L;
    }
    
    /**
     * 위험도 계산
     */
    private void calculateRiskScore(AttackResult result, int attempts, int successes) {
        double riskScore;
        
        if (successes > 0) {
            riskScore = 1.0; // 성공한 크리덴셜 스터핑은 최고 위험
        } else if (attempts > 50) {
            riskScore = 0.8; // 대량 시도는 높은 위험
        } else if (distributedMode) {
            riskScore = 0.7; // 분산 공격은 추가 위험
        } else {
            riskScore = 0.6;
        }
        
        result.setRiskScore(riskScore);
        result.setRiskLevel(AttackResult.RiskLevel.fromScore(riskScore).name());
        result.setImpactAssessment("Potential account takeover and data breach");
    }
    
    /**
     * 랜덤 장치 지문 생성
     */
    private String generateRandomDeviceFingerprint() {
        return "device-" + UUID.randomUUID().toString().substring(0, 8);
    }
    
    /**
     * 랜덤 User-Agent 생성
     */
    private String generateRandomUserAgent() {
        List<String> agents = Arrays.asList(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Mobile/15E148",
            "Mozilla/5.0 (Android 14; Mobile) Firefox/120.0",
            "python-requests/2.31.0", // 봇 시뮬레이션
            "curl/8.4.0"
        );
        return agents.get(ThreadLocalRandom.current().nextInt(agents.size()));
    }
    
    // 인터페이스 구현 메서드들
    
    @Override
    public AttackResult.AttackType getType() {
        return AttackResult.AttackType.CREDENTIAL_STUFFING;
    }
    
    @Override
    public int getPriority() {
        return 85; // 높은 우선순위
    }
    
    @Override
    public AttackCategory getCategory() {
        return AttackCategory.AUTHENTICATION;
    }
    
    @Override
    public boolean validateContext(AttackContext context) {
        // 크리덴셜 스터핑은 특정 사용자 타겟 불필요
        return true;
    }
    
    @Override
    public long getEstimatedDuration() {
        return maxAttempts * delayMs;
    }
    
    @Override
    public String getDescription() {
        return "Credential stuffing attack using leaked credential databases";
    }
    
    @Override
    public RequiredPrivilege getRequiredPrivilege() {
        return RequiredPrivilege.NONE;
    }
    
    @Override
    public String getSuccessCriteria() {
        return "Successfully compromise accounts using leaked credentials";
    }
    
    // 추가 인터페이스 메서드들
    
    @Override
    public String manipulateSessionToken(String sessionToken) {
        return sessionToken; // 크리덴셜 스터핑은 세션 조작 불필요
    }
    
    @Override
    public boolean attemptMfaBypass(String username, String mfaCode) {
        return false; // MFA 우회는 별도 전략
    }
    
    @Override
    public int analyzePasswordComplexity(String password) {
        // 유출된 패스워드는 보통 중간 복잡도
        return 50;
    }
    
    @Override
    public List<LoginAttempt> generateLoginPattern(LoginPatternType patternType) {
        List<LoginAttempt> attempts = new ArrayList<>();
        
        if (patternType == LoginPatternType.DISTRIBUTED) {
            // 분산 패턴 생성
            for (int i = 0; i < 10; i++) {
                LoginAttempt attempt = LoginAttempt.builder()
                    .sourceIp(getRandomProxyIP())
                    .timestamp(LocalDateTime.now().plusSeconds(i * 30))
                    .build();
                attempts.add(attempt);
            }
        }
        
        return attempts;
    }

    private static String generateRandomIP() {
        Random random = new Random();
        int a = random.nextInt(256);
        int b = random.nextInt(256);
        int c = random.nextInt(256);
        int d = random.nextInt(256);
        return String.format("%d.%d.%d.%d", a, b, c, d);
    }
}