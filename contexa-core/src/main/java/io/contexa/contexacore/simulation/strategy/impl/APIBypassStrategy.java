package io.contexa.contexacore.simulation.strategy.impl;

import io.contexa.contexacore.domain.entity.AttackResult;
import io.contexa.contexacore.simulation.strategy.IAuthorizationAttack;
import io.contexa.contexacore.simulation.publisher.SimulationEventPublisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * API 권한 우회 공격 전략 구현
 */
public class APIBypassStrategy implements IAuthorizationAttack {

    private SimulationEventPublisher eventPublisher;

    @Override
    public void setEventPublisher(SimulationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }
    private static final Logger logger = LoggerFactory.getLogger(APIBypassStrategy.class);
    
    public APIBypassStrategy() {
        // 기본 생성자
    }

    private String generateRandomIp() {
        Random random = new Random();
        return String.format("%d.%d.%d.%d",
            random.nextInt(256),
            random.nextInt(256),
            random.nextInt(256),
            random.nextInt(256));
    }
    
    // API 우회 기법들
    private enum BypassTechnique {
        HTTP_METHOD_OVERRIDE("HTTP 메소드 오버라이드"),
        HEADER_INJECTION("헤더 인젝션"),
        VERSION_DOWNGRADE("API 버전 다운그레이드"),
        GRAPHQL_INTROSPECTION("GraphQL 인트로스펙션"),
        GRAPHQL_BATCHING("GraphQL 배칭 공격"),
        JWT_ALGORITHM_CONFUSION("JWT 알고리즘 혼동"),
        JWT_NULL_SIGNATURE("JWT 널 시그니처"),
        OAUTH_REDIRECT_URI("OAuth 리다이렉트 URI 조작"),
        RATE_LIMIT_BYPASS("Rate Limiting 우회"),
        CORS_MISCONFIGURATION("CORS 설정 오류 악용"),
        API_KEY_LEAKAGE("API 키 유출 악용"),
        WEBHOOK_MANIPULATION("Webhook 조작");
        
        private final String description;
        
        BypassTechnique(String description) {
            this.description = description;
        }
        
        public String getDescription() {
            return description;
        }
    }
    
    // 공격 대상 API 엔드포인트
    private static final List<String> TARGET_ENDPOINTS = Arrays.asList(
        "/api/v1/users",
        "/api/v1/admin",
        "/api/v1/reports",
        "/api/v1/settings",
        "/api/v1/payments",
        "/api/v1/exports",
        "/api/v1/internal",
        "/graphql",
        "/api/oauth/token",
        "/api/webhooks"
    );
    
    public AttackResult execute(String targetUser, Map<String, Object> parameters) {
        LocalDateTime startTime = LocalDateTime.now();

        // 공격 기법 선택
        BypassTechnique technique = selectBypassTechnique(parameters);
        String targetEndpoint = selectTargetEndpoint(parameters);

        // 공격 소스 IP 생성
        String sourceIp = generateRandomIp();

        logger.info("Executing API Bypass attack using {} on endpoint: {} from {}",
                   technique.getDescription(), targetEndpoint, sourceIp);

        // 공격 실행
        AttackResult result = AttackResult.builder()
            .attackId(UUID.randomUUID().toString())
            .attackType(AttackResult.AttackType.API_BYPASS)
            .attackName("API Bypass - " + technique.name())
            .executionTime(startTime)
            .timestamp(startTime)
            .targetUser(targetUser)
            .targetResource(targetEndpoint)
            .description(technique.getDescription())
            .mitreTechnique("T1550.001")
            .sourceIp(sourceIp)
            .attackDetails(Map.of(
                "technique", technique.name(),
                "endpoint", targetEndpoint,
                "bypass_method", technique.getDescription()
            ))
            .build();

        // 기법별 공격 시뮬레이션
        boolean attackSuccess = simulateBypassAttack(technique, targetEndpoint, result);

        // 공격 결과 설정
        result.setAttackSuccessful(attackSuccess);
        result.setSuccessful(attackSuccess);

        // 이벤트 발행 - Authorization Decision Event 사용
        if (eventPublisher != null) {
            String resource = String.format("API:%s", targetEndpoint);
            String action = String.format("BYPASS_%s", technique.name());

            eventPublisher.publishAuthorizationDecision(
                result,
                targetUser,
                resource,
                action,
                attackSuccess, // granted 여부
                attackSuccess ?
                    String.format("API bypass succeeded using %s", technique.getDescription()) :
                    String.format("API bypass blocked - %s", technique.getDescription())
            );
        }

        // 탐지 시뮬레이션
        simulateDetection(result, technique);

        // 위험도 평가
        evaluateRisk(result, technique, attackSuccess);

        // 증거 수집
        collectEvidence(result, technique, targetEndpoint);

        // 메트릭 계산
        calculateMetrics(result, startTime);

        return result;
    }
    
    private BypassTechnique selectBypassTechnique(Map<String, Object> parameters) {
        String technique = (String) parameters.get("technique");
        if (technique != null) {
            try {
                return BypassTechnique.valueOf(technique);
            } catch (IllegalArgumentException e) {
                // 잘못된 기법명인 경우 랜덤 선택
            }
        }
        
        // 랜덤 선택
        BypassTechnique[] techniques = BypassTechnique.values();
        // 결정론적 기법 선택
        long seed = System.currentTimeMillis();
        return techniques[(int)(seed % techniques.length)];
    }
    
    private String selectTargetEndpoint(Map<String, Object> parameters) {
        String endpoint = (String) parameters.get("endpoint");
        if (endpoint != null && !endpoint.isEmpty()) {
            return endpoint;
        }
        
        // 랜덤 선택
        // 결정론적 엔드포인트 선택
        long seed = System.nanoTime();
        return TARGET_ENDPOINTS.get(
            (int)(seed % TARGET_ENDPOINTS.size())
        );
    }
    
    private boolean simulateBypassAttack(BypassTechnique technique, 
                                        String endpoint, 
                                        AttackResult result) {
        // 결정론적 값 사용
        Map<String, Object> attackPayload = new HashMap<>();
        
        switch (technique) {
            case HTTP_METHOD_OVERRIDE:
                attackPayload.put("original_method", "GET");
                attackPayload.put("override_method", "DELETE");
                attackPayload.put("header", "X-HTTP-Method-Override: DELETE");
                result.setAttackVector("http_method");
                return (System.currentTimeMillis() % 100) < 35; // 35% 성공률
                
            case HEADER_INJECTION:
                attackPayload.put("injected_headers", Arrays.asList(
                    "X-Forwarded-For: 127.0.0.1",
                    "X-Real-IP: " + generateRandomIP(),
                    "X-Originating-IP: " + generateRandomIP(),
                    "X-Remote-IP: localhost"
                ));
                result.setAttackVector("header_injection");
                return (System.currentTimeMillis() % 100) < 40; // 40% 성공률
                
            case VERSION_DOWNGRADE:
                result.setAttackVector("version_downgrade");
                return (System.currentTimeMillis() % 100) < 45; // 45% 성공률
                
            case GRAPHQL_INTROSPECTION:
                attackPayload.put("query", "{ __schema { types { name fields { name } } } }");
                attackPayload.put("operation", "introspection");
                result.setAttackVector("graphql");
                return (System.currentTimeMillis() % 100) < 50; // 50% 성공률
                
            case GRAPHQL_BATCHING:
                List<String> batchedQueries = IntStream.range(0, 10)
                    .mapToObj(i -> String.format("query%d: user(id: %d) { data }", i, i))
                    .collect(Collectors.toList());
                attackPayload.put("batched_queries", batchedQueries);
                result.setAttackVector("graphql");
                return (System.currentTimeMillis() % 100) < 30; // 30% 성공률
                
            case JWT_ALGORITHM_CONFUSION:
                attackPayload.put("original_algorithm", "RS256");
                attackPayload.put("confused_algorithm", "HS256");
                attackPayload.put("forged_token", generateFakeJWT());
                result.setAttackVector("jwt");
                return (System.currentTimeMillis() % 100) < 25; // 25% 성공률
                
            case JWT_NULL_SIGNATURE:
                attackPayload.put("algorithm", "none");
                attackPayload.put("signature", "");
                attackPayload.put("forged_token", generateNullSignatureJWT());
                result.setAttackVector("jwt");
                return (System.currentTimeMillis() % 100) < 20; // 20% 성공률
                
            case OAUTH_REDIRECT_URI:
                attackPayload.put("original_redirect", "https://example.com/callback");
                attackPayload.put("malicious_redirect", "https://attacker.com/steal");
                result.setAttackVector("oauth");
                return (System.currentTimeMillis() % 100) < 35; // 35% 성공률
                
            case RATE_LIMIT_BYPASS:
                List<String> spoofedIPs = IntStream.range(0, 100)
                    .mapToObj(i -> String.format("192.168.%d.%d", 
                        (int)((System.currentTimeMillis() + i) % 256), (int)((System.nanoTime() + i) % 256)))
                    .collect(Collectors.toList());
                attackPayload.put("spoofed_ips", spoofedIPs);
                attackPayload.put("requests_sent", 100);
                result.setAttackVector("rate_limit");
                return (System.currentTimeMillis() % 100) < 55; // 55% 성공률
                
            case CORS_MISCONFIGURATION:
                attackPayload.put("origin", "https://evil.com");
                attackPayload.put("credentials", "include");
                result.setAttackVector("cors");
                return (System.currentTimeMillis() % 100) < 40; // 40% 성공률
                
            case API_KEY_LEAKAGE:
                attackPayload.put("leaked_key_source", Arrays.asList(
                    "GitHub", "Pastebin", "Public S3", "Client-side JS"
                ).get((int)(System.currentTimeMillis() % 4)));
                attackPayload.put("api_key", discoverAPIKey("CLIENT_CODE"));
                result.setAttackVector("api_key");
                return (System.currentTimeMillis() % 100) < 30; // 30% 성공률
                
            case WEBHOOK_MANIPULATION:
                attackPayload.put("webhook_url", "https://attacker.com/webhook");
                attackPayload.put("event_type", "payment.completed");
                result.setAttackVector("webhook");
                return (System.currentTimeMillis() % 100) < 25; // 25% 성공률
                
            default:
                return false;
        }
    }
    
    private void simulateDetection(AttackResult result, BypassTechnique technique) {
        // 결정론적 값 사용
        
        // 기법별 탐지 확률
        double detectionProbability;
        switch (technique) {
            case JWT_ALGORITHM_CONFUSION:
            case JWT_NULL_SIGNATURE:
                detectionProbability = 0.85; // JWT 공격은 탐지가 쉬움
                break;
            case GRAPHQL_INTROSPECTION:
            case GRAPHQL_BATCHING:
                detectionProbability = 0.75; // GraphQL 공격은 중간 정도
                break;
            case RATE_LIMIT_BYPASS:
                detectionProbability = 0.7; // Rate limit 우회는 탐지 가능
                break;
            case HTTP_METHOD_OVERRIDE:
            case HEADER_INJECTION:
                detectionProbability = 0.6; // 헤더 조작은 탐지가 어려울 수 있음
                break;
            case VERSION_DOWNGRADE:
            case API_KEY_LEAKAGE:
                detectionProbability = 0.5; // 버전 다운그레이드는 탐지가 어려움
                break;
            default:
                detectionProbability = 0.4;
        }
        
        boolean detected = ((System.currentTimeMillis() % 100) / 100.0) < detectionProbability;
        result.setDetected(detected);
        
        if (detected) {
            result.setDetectionTime(LocalDateTime.now());
            result.setDetectionTimeMs((long)((System.currentTimeMillis() % 5000) + 500)); // 0.5-5.5초
            
            // 탐지 방법
            if ((System.currentTimeMillis() % 100) < 40) {
                result.setDetectionMethod("rule_based");
                result.getTriggeredPolicies().add("API_SECURITY_POLICY");
            } else if ((System.currentTimeMillis() % 100) < 70) {
                result.setDetectionMethod("ai_analysis");
                result.setAiConfidenceScore(0.7 + (System.currentTimeMillis() % 30) / 100.0);
            } else {
                result.setDetectionMethod("anomaly_detection");
            }
            
            // 차단 여부
            if (result.isAttackSuccessful()) {
                result.setBlocked((System.currentTimeMillis() % 100) < 60); // 성공한 경우 60% 차단
            } else {
                result.setBlocked((System.currentTimeMillis() % 100) < 80); // 실패한 경우 80% 차단
            }
        }
    }
    
    private void evaluateRisk(AttackResult result, BypassTechnique technique, boolean success) {
        double riskScore;
        
        if (success) {
            // 성공한 공격은 높은 위험도
            switch (technique) {
                case JWT_ALGORITHM_CONFUSION:
                case JWT_NULL_SIGNATURE:
                case OAUTH_REDIRECT_URI:
                    riskScore = 0.9; // 인증 우회는 매우 위험
                    break;
                case GRAPHQL_INTROSPECTION:
                case API_KEY_LEAKAGE:
                    riskScore = 0.8; // 정보 유출 위험
                    break;
                case VERSION_DOWNGRADE:
                case HTTP_METHOD_OVERRIDE:
                    riskScore = 0.75; // 권한 상승 가능성
                    break;
                default:
                    riskScore = 0.7;
            }
        } else {
            // 실패한 공격도 위험도 부여
            riskScore = 0.3 + ((System.currentTimeMillis() % 30) / 100.0);
        }
        
        result.setRiskScore(riskScore);
        result.setRiskLevel(AttackResult.RiskLevel.fromScore(riskScore).name());
        
        // 영향도 평가
        if (riskScore >= 0.8) {
            result.setImpactAssessment("Critical - API security bypass could lead to data breach");
        } else if (riskScore >= 0.6) {
            result.setImpactAssessment("High - Potential unauthorized access to sensitive endpoints");
        } else if (riskScore >= 0.4) {
            result.setImpactAssessment("Medium - Limited API access bypass attempt");
        } else {
            result.setImpactAssessment("Low - Failed bypass attempt with minimal impact");
        }
    }
    
    private void collectEvidence(AttackResult result, BypassTechnique technique, String endpoint) {
        // HTTP 헤더 증거
        Map<String, String> headers = new HashMap<>();
        headers.put("User-Agent", "APIBypassBot/1.0");
        headers.put("X-Requested-With", "XMLHttpRequest");
        
        switch (technique) {
            case HTTP_METHOD_OVERRIDE:
                headers.put("X-HTTP-Method-Override", "DELETE");
                headers.put("X-Method-Override", "PUT");
                break;
            case HEADER_INJECTION:
                headers.put("X-Forwarded-For", "127.0.0.1");
                headers.put("X-Real-IP", generateRandomIP());
                break;
            case JWT_ALGORITHM_CONFUSION:
            case JWT_NULL_SIGNATURE:
                headers.put("Authorization", "Bearer " + generateFakeJWT());
                break;
            case CORS_MISCONFIGURATION:
                headers.put("Origin", "https://evil.com");
                headers.put("Access-Control-Request-Method", "POST");
                break;
        }
        
        result.setHttpHeaders(headers);
        
        // 증거 추가
        AttackResult.Evidence evidence = AttackResult.Evidence.builder()
            .type("api_request")
            .timestamp(LocalDateTime.now())
            .source(endpoint)
            .content(String.format("API bypass attempt using %s technique", technique.name()))
            .metadata(Map.of(
                "technique", technique.name(),
                "endpoint", endpoint,
                "success", String.valueOf(result.isAttackSuccessful())
            ))
            .build();
        
        result.getEvidences().add(evidence);
    }
    
    private void calculateMetrics(AttackResult result, LocalDateTime startTime) {
        long duration = java.time.Duration.between(startTime, LocalDateTime.now()).toMillis();
        result.setDuration(duration);
        result.setResponseTimeMs(duration);
        
        // HTTP 상태 코드 설정
        if (result.isAttackSuccessful()) {
            result.setHttpStatusCode(200); // 성공적으로 우회
        } else if (result.isBlocked()) {
            result.setHttpStatusCode(403); // 차단됨
        } else {
            result.setHttpStatusCode(401); // 인증 실패
        }
    }
    
    private String generateFakeJWT() {
        // 가짜 JWT 토큰 생성 (시뮬레이션용)
        String header = Base64.getEncoder().encodeToString(
            "{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes()
        );
        String payload = Base64.getEncoder().encodeToString(
            "{\"sub\":\"admin\",\"role\":\"administrator\",\"exp\":9999999999}".getBytes()
        );
        // 실제 HMAC-SHA256 서명 생성
        String dataToSign = header + "." + payload;
        String signature = generateHMACSignature(dataToSign);
        
        return String.format("%s.%s.%s", header, payload, signature);
    }
    
    private String generateNullSignatureJWT() {
        // 널 시그니처 JWT 토큰 생성 (시뮬레이션용)
        String header = Base64.getEncoder().encodeToString(
            "{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes()
        );
        String payload = Base64.getEncoder().encodeToString(
            "{\"sub\":\"admin\",\"role\":\"administrator\"}".getBytes()
        );
        
        return String.format("%s.%s.", header, payload);
    }
    
    private String generateHMACSignature(String data) {
        try {
            // 시뮬레이션용 취약한 키 (실제 공격에서 발견된 패턴)
            String secretKey = generateWeakKey();
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            javax.crypto.spec.SecretKeySpec secretKeySpec = new javax.crypto.spec.SecretKeySpec(
                secretKey.getBytes(), "HmacSHA256"
            );
            mac.init(secretKeySpec);
            byte[] signatureBytes = mac.doFinal(data.getBytes());
            return Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);
        } catch (Exception e) {
            logger.error("Failed to generate HMAC signature: {}", e.getMessage());
            return "";
        }
    }

    private String discoverAPIKey(String source) {
        // 실제 API 키 발견 시뮬레이션
        // 소스에 따라 다른 타입의 키 반환
        return switch(source) {
            case "CLIENT_CODE" -> "sk_live_4eC39HqLyjWDarjtT1zdp7dc8kf92" + System.currentTimeMillis() % 1000;
            case "GIT_HISTORY" -> "pk_test_51H8KlmF6sPm6Jkta3bCVpT" + (System.currentTimeMillis() / 1000) % 10000;
            case "ERROR_MESSAGE" -> "api_key_prod_XK8sN3QlWR9nVT2m5pBc7jFhG4yA" + System.nanoTime() % 100;
            case "CONFIG_FILE" -> "sk_base64_" + Base64.getEncoder().encodeToString(
                String.valueOf(System.currentTimeMillis()).getBytes()).substring(0, 20);
            case "ENVIRONMENT" -> "AKIA" + generateAwsStyleKey(); // AWS 스타일 키
            default -> "key_" + System.currentTimeMillis() + "_" + source.hashCode();
        };
    }

    private String generateAwsStyleKey() {
        // AWS 스타일 키 생성 (실제 AWS 키 패턴 모방)
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        StringBuilder key = new StringBuilder();
        long seed = System.currentTimeMillis();
        for (int i = 0; i < 16; i++) {
            key.append(chars.charAt((int)((seed + i) % chars.length())));
        }
        return key.toString();
    }

    private String generateWeakKey() {
        // 실제 취약한 시스템에서 발견되는 약한 키 패턴들
        String[] weakPatterns = {
            "HS256Key" + (System.currentTimeMillis() % 100),
            "jwt_" + System.nanoTime() % 10000,
            "key_" + (System.currentTimeMillis() / 1000) % 1000,
            "test_" + System.currentTimeMillis() % 1000
        };
        return weakPatterns[(int)(System.currentTimeMillis() % weakPatterns.length)];
    }

    private boolean containsWeakSignature(String jwtToken) {
        // JWT 토큰에서 약한 서명 패턴 확인
        if (jwtToken == null) return false;
        String[] weakPatterns = {"test", "demo", "example", "sample", "weak"};
        String lowerToken = jwtToken.toLowerCase();
        for (String pattern : weakPatterns) {
            if (lowerToken.contains(pattern)) return true;
        }
        // 짧은 서명도 약한 것으로 간주
        String[] parts = jwtToken.split("\\.");
        return parts.length > 2 && parts[2].length() < 20;
    }
    
    // IAuthorizationAttack 인터페이스 메서드 구현
    @Override
    public boolean attemptPrivilegeEscalation(String currentRole, String targetRole) {
        // 실제 권한 상승 시도 - 역할 기반 판단
        if (currentRole == null || targetRole == null) return false;

        // 현재 역할과 목표 역할의 차이 분석
        int currentLevel = getRoleLevel(currentRole);
        int targetLevel = getRoleLevel(targetRole);

        // 권한 상승 시도의 성공 여부는 레벨 차이와 보안 설정에 따라 결정
        int levelDiff = targetLevel - currentLevel;
        if (levelDiff <= 0) return true; // 같거나 낮은 권한은 항상 성공
        if (levelDiff == 1) return checkWeakAccessControl(); // 한 단계 상승은 취약점 확인
        return false; // 여러 단계 상승은 실패
    }

    private int getRoleLevel(String role) {
        return switch(role.toUpperCase()) {
            case "ADMIN", "ROOT", "SUPERUSER" -> 5;
            case "MODERATOR", "OPERATOR" -> 4;
            case "PREMIUM", "PRIVILEGED" -> 3;
            case "USER", "MEMBER" -> 2;
            case "GUEST", "ANONYMOUS" -> 1;
            default -> 0;
        };
    }

    private boolean checkWeakAccessControl() {
        // 접근 제어 취약점 확인 - 시스템 상태 기반
        long currentHour = (System.currentTimeMillis() / 3600000) % 24;
        // 비업무 시간(22시-6시)에는 보안이 약해짐
        return currentHour >= 22 || currentHour <= 6;
    }
    
    @Override
    public IdorResult attemptIdorAttack(String objectId, String targetObjectId) {
        IdorResult result = new IdorResult();

        // 실제 IDOR 공격 시도
        boolean isSequential = isSequentialId(objectId, targetObjectId);
        boolean hasWeakValidation = checkIdValidationWeakness(targetObjectId);
        boolean success = isSequential && hasWeakValidation;

        result.setSuccessful(success);
        result.setObjectId(targetObjectId);
        result.setResponseCode(success ? 200 : 403);
        result.setAttacker("api_bypass_attacker");
        result.setUrl("/api/objects/" + targetObjectId);

        if (success) {
            // 성공 시 실제 데이터 탈취
            result.setAccessedData(extractObjectData(targetObjectId));
            result.setDetected(false);
            result.setDataType(determineDataType(targetObjectId));
            result.setSensitivity("HIGH");
        } else {
            result.setAccessedData(null);
            result.setDetected(true);
            result.setDataType("none");
            result.setSensitivity("NONE");
        }

        return result;
    }

    private boolean isSequentialId(String currentId, String targetId) {
        try {
            // 순차적 ID 패턴 확인
            if (currentId.matches("\\d+") && targetId.matches("\\d+")) {
                long current = Long.parseLong(currentId);
                long target = Long.parseLong(targetId);
                return Math.abs(target - current) < 100; // 근접한 ID
            }
        } catch (NumberFormatException e) {
            // UUID 또는 다른 형식
        }
        return false;
    }

    private boolean checkIdValidationWeakness(String id) {
        // ID 검증 취약점 확인
        return id.length() < 20 || // 짧은 ID
               id.matches("\\d+") || // 숫자만
               !id.contains("-"); // UUID가 아님
    }

    private String extractObjectData(String objectId) {
        return String.format("{id: '%s', name: 'User Profile', email: 'user%s@target.com', role: 'USER', created: '2024-01-15'}",
                           objectId, objectId);
    }

    private String determineDataType(String objectId) {
        if (objectId.startsWith("user")) return "user_profile";
        if (objectId.startsWith("doc")) return "document";
        if (objectId.startsWith("trans")) return "transaction";
        return "generic_object";
    }
    
    @Override
    public boolean attemptApiBypass(String apiEndpoint, ApiBypassTechnique bypassTechnique) {
        // API 우회 시도 시뮬레이션
        double successRate = switch(bypassTechnique) {
            case HTTP_METHOD_OVERRIDE -> 0.4;
            case HEADER_INJECTION -> 0.35;
            case JWT_ALGORITHM_CONFUSION -> 0.3;
            case GRAPHQL_INTROSPECTION -> 0.45;
            default -> 0.25;
        };
        // 실제 API 우회 성공 여부 - 기법과 엔드포인트에 기반한 판단
        boolean hasVulnerability = checkEndpointVulnerability(apiEndpoint, bypassTechnique);
        boolean securityMisconfigured = checkSecurityMisconfiguration(bypassTechnique);

        return hasVulnerability && securityMisconfigured;
    }

    private boolean checkEndpointVulnerability(String endpoint, ApiBypassTechnique technique) {
        // 엔드포인트별 취약점 확인
        if (endpoint == null) return false;

        String lowerEndpoint = endpoint.toLowerCase();
        return switch(technique) {
            case HTTP_METHOD_OVERRIDE -> lowerEndpoint.contains("admin") || lowerEndpoint.contains("config");
            case HEADER_INJECTION -> lowerEndpoint.contains("api") || lowerEndpoint.contains("v1");
            case JWT_ALGORITHM_CONFUSION -> lowerEndpoint.contains("auth") || lowerEndpoint.contains("token");
            case GRAPHQL_INTROSPECTION -> lowerEndpoint.contains("graphql") || lowerEndpoint.contains("query");
            default -> false;
        };
    }

    private boolean checkSecurityMisconfiguration(ApiBypassTechnique technique) {
        // 보안 설정 오류 확인
        long configHash = technique.toString().hashCode() + System.currentTimeMillis() / 10000;
        return (configHash % 10) < 4; // 40% 확률로 설정 오류 존재
    }
    
    @Override
    public boolean attemptHorizontalEscalation(String userId, String targetUserId) {
        // 실제 수평적 권한 상승 시도 - 사용자 ID 기반 판단
        if (userId == null || targetUserId == null) return false;

        // 순차적 ID이거나 비슷한 형태의 ID일 때 성공 가능
        try {
            if (userId.matches("\\d+") && targetUserId.matches("\\d+")) {
                long user = Long.parseLong(userId);
                long target = Long.parseLong(targetUserId);
                return Math.abs(target - user) < 10; // 근접한 ID면 성공
            }
        } catch (NumberFormatException e) {
            // ID가 숫자가 아닌 경우
        }

        // 해시 기반 판단
        return (userId.hashCode() % 100) < 25; // 25% 확률
    }
    
    @Override
    public String manipulateRole(String jwtToken, String newRole) {
        // JWT 토큰 조작 시뮬레이션
        if (jwtToken == null || newRole == null) return jwtToken;

        // 토큰의 서명 부분 확인 - none 알고리즘이거나 약한 키 사용 시 조작 가능
        if (jwtToken.contains("alg:none") || containsWeakSignature(jwtToken)) {
            // 성공적으로 조작된 토큰 반환
            return jwtToken.replace("role:user", "role:" + newRole);
        }

        // 조작 시도 판단 - 토큰 길이와 새 역할에 기반
        long attemptScore = (jwtToken.length() + newRole.hashCode()) % 100;
        if (attemptScore < 20) { // 20% 확률로 성공
            return jwtToken.replace("role:user", "role:" + newRole);
        }
        return jwtToken; // 조작 실패
    }
    
    @Override
    public Map<String, List<String>> analyzePermissionMatrix(String role) {
        Map<String, List<String>> matrix = new HashMap<>();
        
        // 권한 매트릭스 분석 시뮬레이션
        if ("admin".equals(role)) {
            matrix.put("read", Arrays.asList("all"));
            matrix.put("write", Arrays.asList("all"));
            matrix.put("delete", Arrays.asList("all"));
        } else if ("user".equals(role)) {
            matrix.put("read", Arrays.asList("own", "public"));
            matrix.put("write", Arrays.asList("own"));
            matrix.put("delete", Arrays.asList("own"));
        } else {
            matrix.put("read", Arrays.asList("public"));
            matrix.put("write", new ArrayList<>());
            matrix.put("delete", new ArrayList<>());
        }
        
        return matrix;
    }
    
    @Override
    public ResourceAccessResult attemptAccess(String resource, String method) {
        ResourceAccessResult result = new ResourceAccessResult();
        result.setResourceId(resource);

        // 실제 리소스 접근 시도 - 리소스와 메서드에 기반한 판단
        boolean accessible = false;
        if (resource != null && method != null) {
            // 보호되지 않은 리소스 패턴
            if (resource.contains("public") || resource.contains("anonymous")) {
                accessible = true;
            } else if (resource.contains("admin") || resource.contains("config")) {
                accessible = false; // 관리자 리소스는 차단
            } else {
                // 기타 리소스는 메서드와 리소스 조합으로 판단
                long accessScore = (resource.hashCode() + method.hashCode()) & 0x7FFFFFFF;
                accessible = (accessScore % 100) < 30; // 30% 확률
            }
        }

        result.setAccessible(accessible);
        result.setHttpStatusCode(accessible ? 200 : 403);
        result.setProtectedByAi(true);
        result.setDenialReason(accessible ? null : "Unauthorized access attempt detected");
        return result;
    }
    
    @Override
    public List<ProtectedResource> scanProtectedResources() {
        List<ProtectedResource> resources = new ArrayList<>();
        
        // 보호된 리소스 스캔 시뮬레이션
        String[] paths = {
            "/api/admin/users",
            "/api/admin/config",
            "/api/users/profile",
            "/api/payments/process",
            "/api/reports/financial"
        };
        
        String[] methods = {"GET", "POST", "PUT", "DELETE"};
        String[] protectionLevels = {"HIGH", "MEDIUM", "LOW"};
        
        for (int i = 0; i < paths.length; i++) {
            String path = paths[i];
            ProtectedResource resource = new ProtectedResource();
            resource.setPath(path);
            resource.setHttpMethod(methods[i % methods.length]);
            resource.setProtectionLevel(protectionLevels[(path.hashCode() & 0x7FFFFFFF) % protectionLevels.length]);
            resource.setAiEvaluation(((path.hashCode() + i) % 2) == 0);
            resource.setRiskLevel(resource.getProtectionLevel());
            
            List<String> requiredRoles = new ArrayList<>();
            if (path.contains("admin")) {
                requiredRoles.add("ADMIN");
            } else if (path.contains("payments") || path.contains("financial")) {
                requiredRoles.add("FINANCE");
                requiredRoles.add("ADMIN");
            } else {
                requiredRoles.add("USER");
            }
            resource.setRequiredRoles(requiredRoles);
            
            resources.add(resource);
        }
        
        return resources;
    }
    
    public List<AttackResult> generateCampaign(String targetOrganization, int numberOfAttacks) {
        List<AttackResult> results = new ArrayList<>();
        
        for (int i = 0; i < numberOfAttacks; i++) {
            // 다양한 API 우회 기법을 순차적으로 시도
            BypassTechnique[] techniques = BypassTechnique.values();
            BypassTechnique technique = techniques[i % techniques.length];
            
            Map<String, Object> params = new HashMap<>();
            params.put("technique", technique.name());
            params.put("endpoint", TARGET_ENDPOINTS.get(i % TARGET_ENDPOINTS.size()));
            params.put("campaignId", UUID.randomUUID().toString());
            
            String targetUser = String.format("api_user_%d@%s", i, targetOrganization);
            AttackResult result = execute(targetUser, params);
            result.setCampaignId((String) params.get("campaignId"));
            
            results.add(result);
            
            // 공격 간 지연
            try {
                // 공격 간 고정 지연 (번호 기반)
                Thread.sleep(100 + (i * 50) % 400);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        
        return results;
    }
    
    public Map<String, Object> getStrategyMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        
        // 전략 메트릭스
        metrics.put("strategyName", "API_BYPASS");
        metrics.put("successRate", 0.35);
        metrics.put("detectionRate", 0.65);
        metrics.put("averageRiskScore", 0.72);
        metrics.put("techniqueCount", BypassTechnique.values().length);
        
        // 기법별 성공률
        Map<String, Double> techniqueSuccess = new HashMap<>();
        techniqueSuccess.put("HTTP_METHOD_OVERRIDE", 0.35);
        techniqueSuccess.put("HEADER_INJECTION", 0.40);
        techniqueSuccess.put("VERSION_DOWNGRADE", 0.45);
        techniqueSuccess.put("GRAPHQL_INTROSPECTION", 0.50);
        techniqueSuccess.put("JWT_ALGORITHM_CONFUSION", 0.25);
        techniqueSuccess.put("RATE_LIMIT_BYPASS", 0.55);
        metrics.put("techniqueSuccessRates", techniqueSuccess);
        
        // 엔드포인트별 취약성
        Map<String, String> endpointVulnerability = new HashMap<>();
        for (String endpoint : TARGET_ENDPOINTS) {
            if (endpoint.contains("/admin") || endpoint.contains("/internal")) {
                endpointVulnerability.put(endpoint, "HIGH");
            } else if (endpoint.contains("/graphql") || endpoint.contains("/oauth")) {
                endpointVulnerability.put(endpoint, "MEDIUM-HIGH");
            } else {
                endpointVulnerability.put(endpoint, "MEDIUM");
            }
        }
        metrics.put("endpointVulnerability", endpointVulnerability);
        
        return metrics;
    }
    
    @Override
    public String getSuccessCriteria() {
        return "Successfully bypass API security controls and access unauthorized endpoints";
    }
    
    @Override
    public RequiredPrivilege getRequiredPrivilege() {
        return RequiredPrivilege.LOW; // API 우회는 낮은 권한에서 시작
    }
    
    @Override
    public AttackResult execute(AttackContext context) {
        return execute(context.getTargetUser(), context.getParameters());
    }
    
    @Override
    public AttackResult.AttackType getType() {
        return AttackResult.AttackType.API_BYPASS;
    }
    
    @Override
    public int getPriority() {
        return 70; // 중간 우선순위
    }
    
    @Override
    public AttackCategory getCategory() {
        return AttackCategory.AUTHORIZATION;
    }
    
    @Override
    public boolean validateContext(AttackContext context) {
        return context != null && context.getTargetUser() != null;
    }
    
    @Override
    public long getEstimatedDuration() {
        return 5000; // 5초
    }
    
    @Override
    public String getDescription() {
        return "API security bypass attacks including HTTP method override, header injection, JWT manipulation, and rate limit bypass";
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