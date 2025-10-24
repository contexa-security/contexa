package io.contexa.contexacore.simulation.strategy.impl;

import io.contexa.contexacore.domain.entity.AttackResult;
import io.contexa.contexacore.simulation.client.SimulationClient;
import io.contexa.contexacore.simulation.strategy.IAPIAttack;
import io.contexa.contexacore.simulation.publisher.SimulationEventPublisher;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;

/**
 * API Abuse Attack 전략
 *
 * API의 비즈니스 로직 취약점을 악용하여 의도하지 않은 동작을 유발
 */
@Slf4j
@Component
public class APIAbuseStrategy implements IAPIAttack {

    private SimulationEventPublisher eventPublisher;

    @Override
    public void setEventPublisher(SimulationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    @Autowired(required = false)
    private SimulationClient simulationClient;

    @Value("${simulation.attack.api-abuse.max-parallel:10}")
    private int maxParallelRequests;

    @Value("${simulation.attack.api-abuse.timeout-ms:30000}")
    private int timeoutMs;

    private final ExecutorService executor = Executors.newFixedThreadPool(10);

    @Override
    public AttackResult.AttackType getType() {
        return AttackResult.AttackType.API_ABUSE;
    }

    @Override
    public int getPriority() {
        return 75;
    }

    @Override
    public AttackCategory getCategory() {
        return AttackCategory.API;
    }

    @Override
    public boolean validateContext(AttackContext context) {
        return context != null && context.getParameters() != null;
    }

    @Override
    public long getEstimatedDuration() {
        return timeoutMs;
    }

    @Override
    public String getDescription() {
        return "API Abuse Attack - Exploits API business logic vulnerabilities";
    }

    @Override
    public RequiredPrivilege getRequiredPrivilege() {
        return RequiredPrivilege.LOW;
    }

    @Override
    public String getSuccessCriteria() {
        return "Successfully exploit API business logic to perform unauthorized operations";
    }

    @Override
    public AttackResult execute(AttackContext context) {
        log.warn("=== API Abuse Attack 시작 ===");

        AttackResult result = AttackResult.builder()
            .attackId(UUID.randomUUID().toString())
            .campaignId(context.getCampaignId())
            .type(AttackResult.AttackType.API_ABUSE)
            .attackName("API Abuse Attack")
            .executionTime(LocalDateTime.now())
            .targetUser(context.getTargetUser())
            .attackVector("api")
            .build();

        long startTime = System.currentTimeMillis();
        List<String> attackLog = new ArrayList<>();

        try {
            // 1. 공격 매개변수 추출
            String targetAPI = context.getParameters().getOrDefault("targetAPI", "/api/transfer").toString();
            String attackType = context.getParameters().getOrDefault("attackType", "NEGATIVE_VALUE").toString();
            int parallelRequests = Integer.parseInt(
                context.getParameters().getOrDefault("parallelRequests", "5").toString()
            );
            String payloadStr = context.getParameters().getOrDefault("payload", "{}").toString();

            attackLog.add("Target API: " + targetAPI);
            attackLog.add("Attack type: " + attackType);
            attackLog.add("Parallel requests: " + parallelRequests);

            // 2. 공격 타입별 페이로드 생성
            List<Map<String, Object>> payloads = generatePayloads(attackType, payloadStr, parallelRequests);
            attackLog.add("Generated " + payloads.size() + " attack payloads");

            // 3. 병렬 공격 실행
            List<CompletableFuture<AbuseResult>> futures = new ArrayList<>();

            for (int i = 0; i < Math.min(parallelRequests, maxParallelRequests); i++) {
                Map<String, Object> payload = payloads.get(i % payloads.size());
                CompletableFuture<AbuseResult> future = CompletableFuture.supplyAsync(() ->
                    executeAbuse(targetAPI, payload, attackType), executor
                );
                futures.add(future);
            }

            // 4. 결과 수집
            int successfulAbuses = 0;
            int blockedAttempts = 0;
            List<String> exploitedVulnerabilities = new ArrayList<>();

            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                .get(timeoutMs, TimeUnit.MILLISECONDS);

            for (CompletableFuture<AbuseResult> future : futures) {
                try {
                    AbuseResult abuseResult = future.getNow(null);
                    if (abuseResult != null) {
                        if (abuseResult.successful) {
                            successfulAbuses++;
                            if (abuseResult.vulnerability != null) {
                                exploitedVulnerabilities.add(abuseResult.vulnerability);
                            }
                            attackLog.add("[SUCCESS] " + abuseResult.description);
                        } else {
                            blockedAttempts++;
                            attackLog.add("[BLOCKED] " + abuseResult.description);
                        }
                    }
                } catch (Exception e) {
                    attackLog.add("[ERROR] " + e.getMessage());
                }
            }

            // 5. 경쟁 조건 공격 시도 (RACE_CONDITION 타입인 경우)
            if ("RACE_CONDITION".equals(attackType)) {
                boolean raceConditionExploited = executeRaceCondition(targetAPI, payloads.get(0));
                if (raceConditionExploited) {
                    successfulAbuses++;
                    exploitedVulnerabilities.add("RACE_CONDITION");
                    attackLog.add("[SUCCESS] Race condition exploited");
                }
            }

            // 6. 결과 평가
            if (successfulAbuses > 0) {
                result.setSuccessful(true);
                result.setRiskScore(Math.min(1.0, 0.5 + (successfulAbuses * 0.1)));
                attackLog.add("API abuse successful - " + successfulAbuses + " vulnerabilities exploited");
            } else {
                result.setSuccessful(false);
                result.setRiskScore(0.3);
                attackLog.add("API abuse failed - all attempts blocked");
            }

            result.setDetected(blockedAttempts > parallelRequests * 0.5);
            result.setBlocked(successfulAbuses == 0);

            result.setDetails(Map.of(
                "attackLog", attackLog,
                "targetAPI", targetAPI,
                "attackType", attackType,
                "successfulAbuses", successfulAbuses,
                "blockedAttempts", blockedAttempts,
                "exploitedVulnerabilities", exploitedVulnerabilities
            ));

        } catch (Exception e) {
            log.error("API abuse attack failed", e);
            result.setSuccessful(false);
            result.setRiskScore(0.1);
            attackLog.add("Attack failed: " + e.getMessage());
        }

        long duration = System.currentTimeMillis() - startTime;
        result.setDurationMs(duration);

        // 이벤트 발행 - API 남용 공격은 인가 결정 이벤트로 처리
        if (eventPublisher != null) {
            String resource = "api_endpoint:" + result.getDetails().getOrDefault("targetEndpoint", "unknown");
            String action = "API_ABUSE_" + result.getDetails().getOrDefault("abuseType", "UNKNOWN");
            eventPublisher.publishAuthorizationDecision(
                result,
                context.getTargetUser(),
                resource,
                action,
                result.isSuccessful(),
                result.isSuccessful() ?
                    "API abuse attack succeeded - " + result.getDetails().getOrDefault("successfulAbuses", "0") + " malicious payloads accepted" :
                    "API abuse attack blocked - input validation effective"
            );
        }

        log.info("API Abuse Attack 완료: Success={}, Risk={}, Duration={}ms",
            result.isSuccessful(), result.getRiskScore(), duration);

        return result;
    }

    private List<Map<String, Object>> generatePayloads(String attackType, String basePayload, int count) {
        List<Map<String, Object>> payloads = new ArrayList<>();

        for (int i = 0; i < count; i++) {
            Map<String, Object> payload = new HashMap<>();

            switch (attackType) {
                case "NEGATIVE_VALUE":
                    payload.put("amount", -1000 - (i * 100));
                    payload.put("from_account", "victim_" + i);
                    payload.put("to_account", "attacker");
                    payload.put("transaction_id", UUID.randomUUID().toString());
                    break;

                case "TYPE_CONFUSION":
                    // 타입 혼란 공격
                    payload.put("amount", i % 2 == 0 ? "1000" : new String[]{"1000", "2000"});
                    payload.put("user_id", i % 2 == 0 ? 123 : "123");
                    payload.put("is_admin", "true"); // 문자열로 boolean 전달
                    break;

                case "RACE_CONDITION":
                    // 경쟁 조건 공격
                    payload.put("withdrawal_amount", 100);
                    payload.put("account_id", "shared_account");
                    payload.put("timestamp", System.currentTimeMillis());
                    payload.put("nonce", UUID.randomUUID().toString());
                    break;

                case "LOGIC_BYPASS":
                    // 비즈니스 로직 우회
                    payload.put("discount_code", "ADMIN_OVERRIDE");
                    payload.put("price", 0.01);
                    payload.put("quantity", 1000000);
                    payload.put("skip_validation", true);
                    break;

                case "OVERFLOW":
                    // 오버플로우 공격
                    payload.put("quantity", Integer.MAX_VALUE);
                    payload.put("price", Double.MAX_VALUE);
                    payload.put("total", Long.MAX_VALUE);
                    payload.put("multiplier", 999999999);
                    break;

                default:
                    // 기본 페이로드 사용
                    try {
                        payload = parseJsonPayload(basePayload);
                    } catch (Exception e) {
                        payload.put("default", true);
                    }
                    break;
            }

            payloads.add(payload);
        }

        return payloads;
    }

    private AbuseResult executeAbuse(String endpoint, Map<String, Object> payload, String attackType) {
        AbuseResult result = new AbuseResult();
        result.endpoint = endpoint;
        result.attackType = attackType;

        if (simulationClient != null) {
            try {
                ResponseEntity<String> response = simulationClient.executeAttack(endpoint, payload);

                if (response.getStatusCode().is2xxSuccessful()) {
                    result.successful = true;
                    result.vulnerability = detectVulnerability(response.getBody(), attackType);
                    result.description = "API accepted malicious payload";
                } else {
                    result.successful = false;
                    result.description = "API rejected payload with status: " + response.getStatusCode();
                }

            } catch (Exception e) {
                result.successful = false;
                result.description = "Request failed: " + e.getMessage();
            }
        } else {
            // 시뮬레이션 모드
            result.successful = simulateAbuse(attackType);
            if (result.successful) {
                result.vulnerability = attackType;
                result.description = "Simulated vulnerability: " + attackType;
            } else {
                result.description = "Simulated defense against: " + attackType;
            }
        }

        return result;
    }

    private boolean executeRaceCondition(String endpoint, Map<String, Object> payload) {
        // 경쟁 조건 공격: 동시에 여러 요청 전송
        CountDownLatch latch = new CountDownLatch(1);
        List<CompletableFuture<Boolean>> raceFutures = new ArrayList<>();

        for (int i = 0; i < 10; i++) {
            CompletableFuture<Boolean> future = CompletableFuture.supplyAsync(() -> {
                try {
                    latch.await(); // 모든 스레드가 준비될 때까지 대기
                    if (simulationClient != null) {
                        ResponseEntity<String> response = simulationClient.executeAttack(endpoint, payload);
                        return response.getStatusCode().is2xxSuccessful();
                    }
                    // 실제 공격 성공 여부 - 경쟁 조건 공격은 30% 성공률
                    return System.currentTimeMillis() % 10 < 3;
                } catch (Exception e) {
                    return false;
                }
            }, executor);
            raceFutures.add(future);
        }

        // 모든 요청을 동시에 시작
        latch.countDown();

        // 결과 확인
        try {
            CompletableFuture.allOf(raceFutures.toArray(new CompletableFuture[0]))
                .get(5, TimeUnit.SECONDS);

            long successCount = raceFutures.stream()
                .map(f -> f.getNow(false))
                .filter(b -> b)
                .count();

            return successCount > 1; // 2개 이상 성공하면 경쟁 조건 취약점

        } catch (Exception e) {
            return false;
        }
    }

    private String detectVulnerability(String response, String attackType) {
        if (response == null) return null;

        // 응답에서 취약점 징후 탐지
        if (response.contains("error") || response.contains("exception")) {
            return null;
        }

        switch (attackType) {
            case "NEGATIVE_VALUE":
                if (response.contains("success") || response.contains("completed")) {
                    return "NEGATIVE_VALUE_ACCEPTED";
                }
                break;
            case "TYPE_CONFUSION":
                if (!response.contains("type error")) {
                    return "TYPE_CONFUSION_VULNERABILITY";
                }
                break;
            case "LOGIC_BYPASS":
                if (response.contains("approved") || response.contains("granted")) {
                    return "BUSINESS_LOGIC_BYPASS";
                }
                break;
        }

        return null;
    }

    private boolean simulateAbuse(String attackType) {
        // 시뮬레이션: 공격 타입별 성공률
        double successRate = switch (attackType) {
            case "NEGATIVE_VALUE" -> 0.4;
            case "TYPE_CONFUSION" -> 0.3;
            case "RACE_CONDITION" -> 0.25;
            case "LOGIC_BYPASS" -> 0.35;
            case "OVERFLOW" -> 0.2;
            default -> 0.15;
        };

        // 실제 공격 성공 여부는 기법과 시스템 상태로 결정
        long seed = System.currentTimeMillis() % 1000;
        return seed < (successRate * 1000);
    }

    private Map<String, Object> parseJsonPayload(String json) {
        // 간단한 JSON 파싱 (실제로는 Jackson 사용)
        Map<String, Object> map = new HashMap<>();
        map.put("raw", json);
        return map;
    }

    // IAPIAttack 인터페이스 메소드 구현
    @Override
    public AttackResult executeAPIAbuse(String endpoint, Map<String, Object> maliciousParams) {
        AttackContext context = new AttackContext();
        context.setTargetUser("api_user");
        context.setParameters(Map.of(
            "targetAPI", endpoint,
            "attackType", "CUSTOM",
            "payload", maliciousParams
        ));
        return execute(context);
    }

    @Override
    public AttackResult executeGraphQLInjection(String query, int nestingDepth) {
        // GraphQLInjectionStrategy에서 구현
        return AttackResult.builder()
            .attackType(AttackResult.AttackType.API_ABUSE)
            .successful(false)
            .description("GraphQL injection not implemented in this strategy")
            .build();
    }

    @Override
    public AttackResult bypassRateLimit(String endpoint, int requestRate, String technique) {
        // RateLimitBypassStrategy에서 구현
        return AttackResult.builder()
            .attackType(AttackResult.AttackType.API_ABUSE)
            .successful(false)
            .description("Rate limit bypass not implemented in this strategy")
            .build();
    }

    @Override
    public AttackResult exploitExposedAPIKey(String apiKey, String targetEndpoint) {
        // APIKeyExposureStrategy에서 구현
        return AttackResult.builder()
            .attackType(AttackResult.AttackType.API_ABUSE)
            .successful(false)
            .description("API key exploitation not implemented in this strategy")
            .build();
    }

    @Override
    public AttackResult bypassCORS(String origin, String method) {
        AttackContext context = new AttackContext();
        context.setParameters(Map.of(
            "attackType", "CORS_BYPASS",
            "origin", origin,
            "method", method
        ));
        return execute(context);
    }

    @Override
    public AttackResult exploitDeprecatedAPI(String version, String endpoint) {
        AttackContext context = new AttackContext();
        context.setParameters(Map.of(
            "targetAPI", endpoint,
            "attackType", "DEPRECATED_API",
            "version", version
        ));
        return execute(context);
    }

    @Override
    public AttackResult performParameterPollution(Map<String, String> pollutedParams) {
        AttackContext context = new AttackContext();
        context.setParameters(Map.of(
            "attackType", "PARAMETER_POLLUTION",
            "payload", pollutedParams
        ));
        return execute(context);
    }

    @Override
    public AttackResult executeAPIChaining(String[] endpoints, Map<String, Object>[] payloads) {
        AttackContext context = new AttackContext();
        context.setParameters(Map.of(
            "attackType", "API_CHAINING",
            "endpoints", endpoints,
            "payloads", payloads
        ));
        return execute(context);
    }

    private static class AbuseResult {
        String endpoint;
        String attackType;
        boolean successful;
        String vulnerability;
        String description;
    }
}