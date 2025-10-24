package io.contexa.contexacore.simulation.strategy.impl;

import io.contexa.contexacore.domain.entity.AttackResult;
import io.contexa.contexacore.simulation.client.SimulationClient;
import io.contexa.contexacore.simulation.domain.LoginAttempt;
import io.contexa.contexacore.simulation.strategy.IAuthenticationAttack;
import io.contexa.contexacore.simulation.publisher.SimulationEventPublisher;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * Token Replay Attack 전략
 *
 * 만료되었거나 탈취한 토큰을 재사용하여 인증을 우회하려는 공격
 */
@Slf4j
@Component
public class TokenReplayStrategy implements IAuthenticationAttack {

    private SimulationEventPublisher eventPublisher;

    @Override
    public void setEventPublisher(SimulationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    @Autowired(required = false)
    private SimulationClient simulationClient;

    @Value("${simulation.attack.token-replay.max-attempts:20}")
    private int maxAttempts;

    @Value("${simulation.attack.token-replay.delay-ms:500}")
    private int delayMs;

    private static final List<String> TOKEN_TYPES = Arrays.asList(
        "JWT", "SESSION", "OAUTH", "API_KEY", "REFRESH", "ACCESS"
    );

    @Override
    public AttackResult.AttackType getType() {
        return AttackResult.AttackType.TOKEN_REPLAY;
    }

    @Override
    public int getPriority() {
        return 80; // High priority attack
    }

    @Override
    public AttackCategory getCategory() {
        return AttackCategory.AUTHENTICATION;
    }

    @Override
    public boolean validateContext(AttackContext context) {
        if (context == null) return false;
        if (context.getTargetUser() == null || context.getTargetUser().isEmpty()) return false;
        if (context.getParameters() == null) return false;
        return true;
    }

    @Override
    public long getEstimatedDuration() {
        return maxAttempts * delayMs + 2000; // Total time for all attempts plus overhead
    }

    @Override
    public String getDescription() {
        return "Token Replay Attack - Attempts to reuse expired or stolen tokens to bypass authentication";
    }

    @Override
    public RequiredPrivilege getRequiredPrivilege() {
        return RequiredPrivilege.NONE; // No special privileges needed
    }

    @Override
    public String getSuccessCriteria() {
        return "Successfully authenticate using an expired or stolen token";
    }

    @Override
    public List<LoginAttempt> generateLoginPattern(LoginPatternType patternType) {
        List<LoginAttempt> attempts = new ArrayList<>();
        LocalDateTime now = LocalDateTime.now();
        String[] targetUsers = {"admin", "user1", "service", "api_user", "system"};

        switch (patternType) {
            case RAPID_FIRE:
                // 짧은 시간에 집중적인 토큰 재사용 시도
                for (int i = 0; i < 8; i++) {
                    LoginAttempt attempt = new LoginAttempt();
                    attempt.setUsername(targetUsers[i % targetUsers.length]);
                    attempt.setTimestamp(now.plusSeconds(i * 5));
                    attempt.setSourceIp("203.0.113." + (10 + i));
                    attempts.add(attempt);
                }
                break;

            case DISTRIBUTED:
                // IP와 시간을 분산한 토큰 재사용
                String[] ips = {generateRandomIP(), generateRandomIP(), "203.0.113.1", "198.51.100.1"};
                for (int i = 0; i < 12; i++) {
                    LoginAttempt attempt = new LoginAttempt();
                    attempt.setUsername(targetUsers[i % targetUsers.length]);
                    attempt.setTimestamp(now.plusMinutes(i * 10));
                    attempt.setSourceIp(ips[i % ips.length]);
                    attempts.add(attempt);
                }
                break;

            case SLOW_AND_STEADY:
            default:
                // 느린 속도의 지속적인 토큰 재사용
                for (int i = 0; i < 6; i++) {
                    LoginAttempt attempt = new LoginAttempt();
                    attempt.setUsername(targetUsers[i % targetUsers.length]);
                    attempt.setTimestamp(now.plusHours(i * 2));
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

        // 토큰 기반 인증 시도 (암호를 토큰으로 해석)
        if (password != null && (password.startsWith("eyJ") || password.startsWith("Bearer"))) {
            // JWT 또는 Bearer 토큰으로 인식
            TokenAnalysisResult tokenResult = analyzeToken(password);
            attempt.setSuccess(tokenResult.isValid() && !tokenResult.isExpired());
            attempt.setResponseTimeMs(tokenResult.getAnalysisTimeMs());
            attempt.setFailureReason(tokenResult.getFailureReason());
            attempt.setBlocked(tokenResult.isBlocked());

            log.debug("Token-based login attempt for {}: {} ({}ms)", username,
                tokenResult.isValid() ? "SUCCESS" : "FAILED", tokenResult.getAnalysisTimeMs());
        } else {
            // 일반 인증 시도
            attempt.setSuccess(false);
            attempt.setResponseTimeMs(200L);
            attempt.setFailureReason("INVALID_TOKEN_FORMAT");
        }

        return attempt;
    }

    @Override
    public List<LoginAttempt> attemptMultipleLogins(List<Credential> credentials) {
        List<LoginAttempt> attempts = new ArrayList<>();
        Map<String, List<String>> userTokens = new HashMap<>();

        for (Credential credential : credentials) {
            LoginAttempt attempt = attemptLogin(credential.getUsername(), credential.getPassword());
            attempts.add(attempt);

            // 사용자별 토큰 수집
            userTokens.computeIfAbsent(credential.getUsername(), k -> new ArrayList<>())
                     .add(credential.getPassword());

            // 토큰 재사용 간격
            try {
                Thread.sleep(delayMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }

            // 성공한 토큰에 대해 추가 분석 수행
            if (attempt.isSuccess()) {
                performAdditionalTokenAnalysis(credential.getPassword(), attempts);
            }
        }

        // 사용자별 토큰 패턴 분석
        analyzeTokenPatternsPerUser(userTokens, attempts);

        return attempts;
    }

    @Override
    public String manipulateSessionToken(String sessionToken) {
        if (sessionToken == null || sessionToken.isEmpty()) {
            return sessionToken;
        }

        // 토큰 유형 판별 및 조작
        if (sessionToken.startsWith("eyJ")) {
            // JWT 토큰 조작
            return manipulateJWTToken(sessionToken);
        } else if (sessionToken.startsWith("Bearer ")) {
            // Bearer 토큰 조작
            return manipulateBearerToken(sessionToken);
        } else if (sessionToken.contains("=")) {
            // 세션 쿠키 조작
            return manipulateSessionCookie(sessionToken);
        } else {
            // 일반 토큰 조작
            return manipulateGenericToken(sessionToken);
        }
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

        // 토큰인 경우 다른 기준으로 평가
        if (password.startsWith("eyJ") || password.startsWith("Bearer")) {
            return analyzeTokenSecurity(password);
        }

        // 일반 패스워드 복잡도 분석
        int score = 0;
        int length = password.length();

        // 길이 점수
        if (length >= 16) score += 25;
        else if (length >= 12) score += 20;
        else if (length >= 8) score += 15;
        else score += 10;

        // 문자 다양성
        if (password.matches(".*[a-z].*")) score += 15;
        if (password.matches(".*[A-Z].*")) score += 15;
        if (password.matches(".*\\d.*")) score += 15;
        if (password.matches(".*[!@#$%^&*(),.?\":{}|<>].*")) score += 15;

        // 일반적인 패턴 감점
        if (password.toLowerCase().contains("password")) score -= 20;
        if (password.matches("\\d+")) score -= 25;
        if (password.matches("[a-zA-Z]+")) score -= 20;

        return Math.max(0, Math.min(100, score));
    }

    @Override
    public AttackResult execute(AttackContext context) {
        log.warn("=== Token Replay Attack 시작: target={} ===", context.getTargetUser());

        String primarySourceIp = context.getSourceIp() != null ? context.getSourceIp() : generateRandomIP();

        AttackResult result = AttackResult.builder()
            .attackId(UUID.randomUUID().toString())
            .campaignId(context.getCampaignId())
            .type(AttackResult.AttackType.TOKEN_REPLAY)
            .attackName("Token Replay Attack")
            .executionTime(LocalDateTime.now())
            .targetUser(context.getTargetUser())
            .attackVector("authentication")
            .build();

        long startTime = System.currentTimeMillis();
        List<String> attackLog = new ArrayList<>();

        try {
            // 1. 토큰 획득 또는 생성
            String tokenType = context.getParameters().getOrDefault("tokenType", "JWT").toString();
            int tokenAge = Integer.parseInt(context.getParameters().getOrDefault("tokenAge", "48").toString());

            attackLog.add("Token type: " + tokenType);
            attackLog.add("Token age: " + tokenAge + " hours");

            // 2. 만료된 토큰 생성
            String expiredToken = generateExpiredToken(context.getTargetUser(), tokenType, tokenAge);
            attackLog.add("Generated expired token: " + expiredToken.substring(0, Math.min(30, expiredToken.length())) + "...");

            // 3. 다양한 IP에서 토큰 재사용 시도
            List<String> sourceIps = generateSourceIps();
            int successCount = 0;

            for (int i = 0; i < Math.min(maxAttempts, sourceIps.size()); i++) {
                String sourceIp = sourceIps.get(i);

                if (simulationClient != null) {
                    try {
                        // 실제 토큰 재사용 시도
                        var response = simulationClient.requestWithManipulatedToken(
                            "/api/protected/resource",
                            expiredToken
                        );

                        if (response.getStatusCode().is2xxSuccessful()) {
                            successCount++;
                            attackLog.add("[SUCCESS] Token accepted from IP: " + sourceIp);
                            result.setSuccessful(true);
                            result.setRiskScore(0.9);
                        } else {
                            attackLog.add("[FAILED] Token rejected from IP: " + sourceIp);
                        }

                    } catch (Exception e) {
                        attackLog.add("[ERROR] Request failed from IP: " + sourceIp + " - " + e.getMessage());
                    }
                } else {
                    // 시뮬레이션 모드
                    boolean accepted = simulateTokenValidation(expiredToken, tokenAge, sourceIp);
                    if (accepted) {
                        successCount++;
                        attackLog.add("[SIMULATED] Token accepted from IP: " + sourceIp);
                    } else {
                        attackLog.add("[SIMULATED] Token rejected from IP: " + sourceIp);
                    }
                }

                // 딜레이 적용
                if (i < maxAttempts - 1) {
                    Thread.sleep(delayMs);
                }
            }

            // 4. 결과 평가 및 이벤트 발행
            primarySourceIp = context.getSourceIp() != null ? context.getSourceIp() : sourceIps.get(0);

            if (successCount > 0) {
                result.setSuccessful(true);
                result.setRiskScore(Math.min(1.0, 0.5 + (successCount * 0.1)));
                attackLog.add("Token replay successful: " + successCount + " times");

                // 토큰 재사용 성공 이벤트 발행 (인증 성공이지만 의심스러운 활동)
                if (eventPublisher != null) {
                    eventPublisher.publishAuthenticationSuccess(
                        result,
                        context.getTargetUser(),
                        primarySourceIp,
                        expiredToken.substring(0, Math.min(16, expiredToken.length())), // sessionId로 토큰 일부 사용
                        true, // anomalyDetected - 만료된 토큰 재사용은 이상 행위
                        0.15 // trustScore - 매우 낮은 신뢰도 (만료된 토큰 사용)
                    );
                }
            } else {
                result.setSuccessful(false);
                result.setRiskScore(0.3);
                attackLog.add("Token replay failed - all attempts blocked");

                // 토큰 재사용 실패 이벤트 발행
                if (eventPublisher != null) {
                    eventPublisher.publishAuthenticationFailure(
                        result,
                        context.getTargetUser(),
                        primarySourceIp,
                        "Token replay attack failed - expired " + tokenType + " token rejected",
                        sourceIps.size()
                    );
                }
            }

            // 탐지 가능성 평가
            result.setDetected(successCount == 0 || tokenAge > 72);
            result.setBlocked(successCount == 0);

        } catch (Exception e) {
            log.error("Token replay attack failed", e);
            result.setSuccessful(false);
            result.setRiskScore(0.1);
            attackLog.add("Attack failed: " + e.getMessage());
        }

        long duration = System.currentTimeMillis() - startTime;
        result.setDurationMs(duration);
        result.setSourceIp(primarySourceIp);
        result.setDetails(Map.of(
            "attackLog", attackLog,
            "tokenType", context.getParameters().getOrDefault("tokenType", "JWT"),
            "attempts", attackLog.size()
        ));

        log.info("Token Replay Attack 완료: Success={}, Risk={}, Duration={}ms",
            result.isSuccessful(), result.getRiskScore(), duration);

        return result;
    }

    private String generateExpiredToken(String user, String tokenType, int hoursAgo) {
        LocalDateTime expiry = LocalDateTime.now().minus(hoursAgo, ChronoUnit.HOURS);

        switch (tokenType) {
            case "JWT":
                return generateJWT(user, expiry);
            case "SESSION":
                return generateSessionToken(user, expiry);
            case "OAUTH":
                return generateOAuthToken(user, expiry);
            case "API_KEY":
                return generateAPIKey(user);
            default:
                return generateGenericToken(user, expiry);
        }
    }

    private String generateJWT(String user, LocalDateTime expiry) {
        String header = Base64.getEncoder().encodeToString(
            "{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes()
        );

        String payload = Base64.getEncoder().encodeToString(
            String.format("{\"sub\":\"%s\",\"exp\":%d,\"iat\":%d}",
                user,
                expiry.toEpochSecond(java.time.ZoneOffset.UTC),
                expiry.minus(1, ChronoUnit.HOURS).toEpochSecond(java.time.ZoneOffset.UTC)
            ).getBytes()
        );

        String signature = Base64.getEncoder().encodeToString(
            UUID.randomUUID().toString().getBytes()
        );

        return header + "." + payload + "." + signature;
    }

    private String generateSessionToken(String user, LocalDateTime expiry) {
        return "JSESSIONID=" + UUID.randomUUID().toString() +
               ";expires=" + expiry.toString();
    }

    private String generateOAuthToken(String user, LocalDateTime expiry) {
        return "oauth_" + Base64.getEncoder().encodeToString(
            (user + ":" + expiry.toString()).getBytes()
        );
    }

    private String generateAPIKey(String user) {
        return "apikey_" + user + "_" + UUID.randomUUID().toString().replace("-", "");
    }

    private String generateGenericToken(String user, LocalDateTime expiry) {
        return Base64.getEncoder().encodeToString(
            (user + ":" + expiry.toString() + ":" + UUID.randomUUID()).getBytes()
        );
    }

    private List<String> generateSourceIps() {
        return Arrays.asList(
            generateRandomIP(),
            generateRandomIP(),
            generateRandomIP(),
            "203.0.113.10",  // Different geographic location
            "198.51.100.20", // Different ISP
            generateRandomIP(),
            "127.0.0.1",      // Localhost
            "::1"             // IPv6 localhost
        );
    }

    private String generateRandomIP() {
        Random random = new Random();
        int a = random.nextInt(256);
        int b = random.nextInt(256);
        int c = random.nextInt(256);
        int d = random.nextInt(256);
        return String.format("%d.%d.%d.%d", a, b, c, d);
    }

    private boolean simulateTokenValidation(String token, int hoursOld, String sourceIp) {
        // 실제 토큰 검증 로직으로 대체
        TokenValidationResult validation = performTokenValidation(token, hoursOld, sourceIp);
        return validation.isValid();
    }

    private static class TokenAnalysisResult {
        private boolean valid = false;
        private boolean expired = false;
        private boolean blocked = false;
        private long analysisTimeMs = 100;
        private String failureReason = "INVALID_TOKEN";

        public boolean isValid() { return valid; }
        public void setValid(boolean valid) { this.valid = valid; }
        public boolean isExpired() { return expired; }
        public void setExpired(boolean expired) { this.expired = expired; }
        public boolean isBlocked() { return blocked; }
        public void setBlocked(boolean blocked) { this.blocked = blocked; }
        public long getAnalysisTimeMs() { return analysisTimeMs; }
        public void setAnalysisTimeMs(long analysisTimeMs) { this.analysisTimeMs = analysisTimeMs; }
        public String getFailureReason() { return failureReason; }
        public void setFailureReason(String failureReason) { this.failureReason = failureReason; }
    }

    private static class TokenValidationResult {
        private boolean valid = false;
        private String reason = "UNKNOWN";

        public boolean isValid() { return valid; }
        public void setValid(boolean valid) { this.valid = valid; }
        public String getReason() { return reason; }
        public void setReason(String reason) { this.reason = reason; }
    }

    private TokenAnalysisResult analyzeToken(String token) {
        TokenAnalysisResult result = new TokenAnalysisResult();
        long startTime = System.currentTimeMillis();

        try {
            if (token.startsWith("eyJ")) {
                // JWT 토큰 분석
                result = analyzeJWTToken(token);
            } else if (token.startsWith("Bearer ")) {
                // Bearer 토큰 분석
                result = analyzeBearerToken(token.substring(7));
            } else {
                result.setValid(false);
                result.setFailureReason("UNSUPPORTED_TOKEN_TYPE");
            }
        } catch (Exception e) {
            result.setValid(false);
            result.setFailureReason("TOKEN_ANALYSIS_ERROR: " + e.getMessage());
        }

        result.setAnalysisTimeMs(System.currentTimeMillis() - startTime);
        return result;
    }

    private TokenAnalysisResult analyzeJWTToken(String jwt) {
        TokenAnalysisResult result = new TokenAnalysisResult();

        try {
            // JWT 구조 검증 (header.payload.signature)
            String[] parts = jwt.split("\\.");
            if (parts.length != 3) {
                result.setValid(false);
                result.setFailureReason("INVALID_JWT_STRUCTURE");
                return result;
            }

            // Payload 디코딩 및 분석
            String payload = new String(Base64.getDecoder().decode(parts[1]));

            // 만료 시간 확인 (실제 구현에서는 JSON 파싱 필요)
            if (payload.contains("\"exp\":")) {
                long currentTime = System.currentTimeMillis() / 1000;
                // 간단한 만료 시간 추출 (실제로는 JSON 파서 사용)
                try {
                    String expStr = payload.substring(payload.indexOf("\"exp\":") + 6);
                    expStr = expStr.substring(0, expStr.indexOf(",") > 0 ? expStr.indexOf(",") : expStr.indexOf("}"));
                    long expTime = Long.parseLong(expStr.trim());

                    if (expTime < currentTime) {
                        result.setValid(false);
                        result.setExpired(true);
                        result.setFailureReason("JWT_EXPIRED");
                        return result;
                    }
                } catch (Exception e) {
                    result.setValid(false);
                    result.setFailureReason("JWT_EXP_PARSE_ERROR");
                    return result;
                }
            }

            // 서명 검증 (시뮬레이션)
            if (isValidJWTSignature(parts[0], parts[1], parts[2])) {
                result.setValid(true);
                result.setFailureReason("JWT_VALID");
            } else {
                result.setValid(false);
                result.setFailureReason("JWT_INVALID_SIGNATURE");
            }

        } catch (Exception e) {
            result.setValid(false);
            result.setFailureReason("JWT_DECODE_ERROR");
        }

        return result;
    }

    private TokenAnalysisResult analyzeBearerToken(String bearerToken) {
        TokenAnalysisResult result = new TokenAnalysisResult();

        // Bearer 토큰 형식 검증
        if (bearerToken.length() < 20) {
            result.setValid(false);
            result.setFailureReason("BEARER_TOKEN_TOO_SHORT");
            return result;
        }

        // API 키 패턴 검증
        if (bearerToken.matches("[a-zA-Z0-9_\\-]{20,}")) {
            // 활성 토큰 데이터베이스 확인 시뮬레이션
            if (isActiveAPIKey(bearerToken)) {
                result.setValid(true);
                result.setFailureReason("BEARER_TOKEN_VALID");
            } else {
                result.setValid(false);
                result.setFailureReason("BEARER_TOKEN_REVOKED_OR_INVALID");
            }
        } else {
            result.setValid(false);
            result.setFailureReason("BEARER_TOKEN_INVALID_FORMAT");
        }

        return result;
    }

    private boolean isValidJWTSignature(String header, String payload, String signature) {
        // JWT 서명 검증 시뮬레이션
        // 실제 구현에서는 HMAC, RSA 등의 알고리즘으로 검증

        // 알려진 취약한 서명 패턴 확인
        String[] weakSignatures = {
            "INVALID", "NONE", "NULL", "", "WEAK_SIGNATURE"
        };

        for (String weak : weakSignatures) {
            if (signature.contains(weak)) {
                return false;
            }
        }

        // 길이 기반 간단 검증
        return signature.length() >= 20;
    }

    private boolean isActiveAPIKey(String apiKey) {
        // 활성 API 키 확인 시뮬레이션
        // 실제 구현에서는 데이터베이스나 캐시에서 확인

        // 알려진 테스트 키들
        Set<String> validTestKeys = Set.of(
            "test_api_key_12345",
            "demo_key_abcdef",
            "valid_bearer_token_xyz"
        );

        return validTestKeys.contains(apiKey) ||
               (apiKey.startsWith("valid_") && apiKey.length() > 10);
    }

    private TokenValidationResult performTokenValidation(String token, int hoursOld, String sourceIp) {
        TokenValidationResult result = new TokenValidationResult();

        // 토큰 나이 기반 검증
        if (hoursOld > 72) { // 3일 이상 된 토큰
            result.setValid(false);
            result.setReason("TOKEN_TOO_OLD");
            return result;
        }

        // IP 기반 검증
        if (sourceIp.startsWith("127.") || sourceIp.equals("::1")) {
            // 로컬 IP는 추가 검증 필요
            result.setValid(hoursOld < 24); // 24시간 이내만 허용
            result.setReason(result.isValid() ? "LOCAL_IP_ACCEPTED" : "LOCAL_IP_EXPIRED");
            return result;
        }

        // 토큰 형식 기반 검증
        if (token.startsWith("eyJ")) {
            TokenAnalysisResult jwtResult = analyzeJWTToken(token);
            result.setValid(jwtResult.isValid() && !jwtResult.isExpired());
            result.setReason(jwtResult.getFailureReason());
        } else {
            result.setValid(hoursOld < 48); // 일반 토큰은 48시간
            result.setReason(result.isValid() ? "TOKEN_VALID" : "TOKEN_EXPIRED");
        }

        return result;
    }

    private String manipulateJWTToken(String jwt) {
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length != 3) {
                return jwt; // 잘못된 JWT는 그대로 반환
            }

            // Payload 조작 (만료 시간 연장 시도)
            String payload = new String(Base64.getDecoder().decode(parts[1]));

            // 만료 시간을 미래로 변경 시도
            if (payload.contains("\"exp\":")) {
                long futureTime = (System.currentTimeMillis() / 1000) + 86400; // 24시간 후
                String newPayload = payload.replaceFirst("\"exp\":\\s*\\d+", "\"exp\":" + futureTime);
                String encodedPayload = Base64.getEncoder().encodeToString(newPayload.getBytes());

                return parts[0] + "." + encodedPayload + "." + parts[2] + "_MANIPULATED";
            }

            return jwt + "_MANIPULATED";
        } catch (Exception e) {
            log.debug("JWT manipulation failed: {}", e.getMessage());
            return jwt + "_MANIPULATION_FAILED";
        }
    }

    private String manipulateBearerToken(String bearerToken) {
        String token = bearerToken.startsWith("Bearer ") ? bearerToken.substring(7) : bearerToken;

        // 토큰 변조 시도
        StringBuilder manipulated = new StringBuilder(token);

        // 끝 문자 변경
        if (manipulated.length() > 0) {
            char lastChar = manipulated.charAt(manipulated.length() - 1);
            manipulated.setCharAt(manipulated.length() - 1,
                lastChar == 'a' ? 'b' : 'a');
        }

        // 중간 문자 변경
        if (manipulated.length() > 10) {
            char midChar = manipulated.charAt(manipulated.length() / 2);
            manipulated.setCharAt(manipulated.length() / 2,
                Character.isDigit(midChar) ? 'X' : '9');
        }

        return "Bearer " + manipulated.toString() + "_MANIPULATED";
    }

    private String manipulateSessionCookie(String sessionToken) {
        // 세션 쿠키 조작
        if (sessionToken.contains("JSESSIONID=")) {
            return sessionToken.replaceFirst("JSESSIONID=", "JSESSIONID=MANIPULATED_");
        } else if (sessionToken.contains("=")) {
            // 일반적인 키=값 형태
            String[] parts = sessionToken.split("=", 2);
            return parts[0] + "=MANIPULATED_" + parts[1];
        }

        return sessionToken + "_MANIPULATED";
    }

    private String manipulateGenericToken(String token) {
        // 일반 토큰 조작
        if (token.length() > 10) {
            // 중간 부분에 문자 삽입
            int midPoint = token.length() / 2;
            return token.substring(0, midPoint) + "MANIP" + token.substring(midPoint);
        } else {
            return "MANIPULATED_" + token;
        }
    }

    private int analyzeTokenSecurity(String token) {
        int score = 0;

        if (token.startsWith("eyJ")) {
            // JWT 보안 분석
            try {
                String[] parts = token.split("\\.");
                if (parts.length == 3) {
                    // Header 분석
                    String header = new String(Base64.getDecoder().decode(parts[0]));
                    if (header.contains("\"alg\":\"none\"")) {
                        score = 10; // 매우 취약
                    } else if (header.contains("\"alg\":\"HS256\"")) {
                        score = 60; // 보통
                    } else if (header.contains("\"alg\":\"RS256\"")) {
                        score = 80; // 강함
                    } else {
                        score = 40; // 알 수 없음
                    }

                    // Payload 분석
                    String payload = new String(Base64.getDecoder().decode(parts[1]));
                    if (payload.contains("\"exp\":")) score += 10; // 만료 시간 있음
                    if (payload.contains("\"iat\":")) score += 5;  // 발급 시간 있음
                    if (payload.contains("\"jti\":")) score += 5;  // JWT ID 있음

                    // Signature 분석
                    if (parts[2].length() > 20) score += 10;
                    else score -= 20;
                }
            } catch (Exception e) {
                score = 20; // 파싱 불가
            }
        } else if (token.startsWith("Bearer ")) {
            // Bearer 토큰 분석
            String bearerPart = token.substring(7);
            if (bearerPart.length() >= 32) score += 30;
            if (bearerPart.matches(".*[A-Z].*")) score += 10;
            if (bearerPart.matches(".*[0-9].*")) score += 10;
            if (bearerPart.matches(".*[_\\-].*")) score += 5;

            // 패턴 기반 강도 평가
            if (bearerPart.matches("[a-zA-Z0-9_\\-]{40,}")) score += 20;
            else score -= 10;
        } else {
            // 일반 토큰 분석
            score = Math.min(80, token.length() * 3);
        }

        return Math.max(0, Math.min(100, score));
    }

    private void performAdditionalTokenAnalysis(String successfulToken, List<LoginAttempt> attempts) {
        // 성공한 토큰에 대한 추가 분석
        log.debug("Performing additional analysis on successful token: {}",
            successfulToken.substring(0, Math.min(20, successfulToken.length())) + "...");

        // 토큰 만료까지의 시간 분석
        if (successfulToken.startsWith("eyJ")) {
            analyzeJWTExpiration(successfulToken);
        }

        // 토큰 재사용 가능 기간 추정
        estimateTokenReplayWindow(successfulToken);
    }

    private void analyzeJWTExpiration(String jwt) {
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length == 3) {
                String payload = new String(Base64.getDecoder().decode(parts[1]));
                if (payload.contains("\"exp\":")) {
                    // 만료 시간 분석 로직
                    log.debug("JWT contains expiration claim");
                }
            }
        } catch (Exception e) {
            log.debug("JWT expiration analysis failed: {}", e.getMessage());
        }
    }

    private void estimateTokenReplayWindow(String token) {
        // 토큰 재사용 가능한 시간 창 추정
        long estimatedWindow = 3600000; // 기본 1시간

        if (token.startsWith("eyJ")) {
            estimatedWindow = 86400000; // JWT는 보통 24시간
        } else if (token.contains("session")) {
            estimatedWindow = 1800000; // 세션은 30분
        }

        log.debug("Estimated token replay window: {}ms", estimatedWindow);
    }

    private void analyzeTokenPatternsPerUser(Map<String, List<String>> userTokens, List<LoginAttempt> attempts) {
        for (Map.Entry<String, List<String>> entry : userTokens.entrySet()) {
            String username = entry.getKey();
            List<String> tokens = entry.getValue();

            // 사용자별 토큰 패턴 분석
            if (tokens.size() > 1) {
                analyzeTokenSequencePatterns(username, tokens);
            }

            // 성공률 분석
            long successCount = attempts.stream()
                .filter(a -> a.getUsername().equals(username) && a.isSuccess())
                .count();

            if (successCount > 0) {
                log.debug("User {} had {} successful token replays out of {} attempts",
                    username, successCount, tokens.size());
            }
        }
    }

    private void analyzeTokenSequencePatterns(String username, List<String> tokens) {
        // 토큰 시퀀스 패턴 분석
        log.debug("Analyzing token sequence patterns for user {}: {} tokens", username, tokens.size());

        // 토큰 길이 패턴 분석
        tokens.stream()
            .mapToInt(String::length)
            .distinct()
            .forEach(length -> log.debug("Token length pattern: {}", length));

        // 토큰 타입 분포 분석
        long jwtCount = tokens.stream().filter(t -> t.startsWith("eyJ")).count();
        long bearerCount = tokens.stream().filter(t -> t.startsWith("Bearer")).count();

        log.debug("Token type distribution for {}: JWT={}, Bearer={}, Other={}",
            username, jwtCount, bearerCount, tokens.size() - jwtCount - bearerCount);
    }
}