package io.contexa.contexacore.simulation.strategy.impl;

import io.contexa.contexacore.domain.entity.AttackResult;
import io.contexa.contexacore.simulation.domain.UserBehaviorPattern;
import io.contexa.contexacore.simulation.strategy.IBehaviorAttack;
import io.contexa.contexacore.simulation.publisher.SimulationEventPublisher;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Velocity Attack 전략
 *
 * 비정상적인 속도로 대량의 작업을 수행하여 시스템을 공격
 * 최종적으로 @Protectable로 보호된 고객 데이터 엔드포인트를 호출합니다.
 */
@Slf4j
@Component
public class VelocityAttackStrategy extends BaseAttackStrategy implements IBehaviorAttack {

    private SimulationEventPublisher eventPublisher;

    @Override
    public void setEventPublisher(SimulationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    @Value("${simulation.attack.velocity.max-threads:50}")
    private int maxThreads;

    @Value("${simulation.attack.velocity.max-duration-ms:300000}")
    private int maxDurationMs;

    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(10);

    @Override
    public AttackResult.AttackType getType() {
        return AttackResult.AttackType.VELOCITY_ATTACK;
    }

    @Override
    public int getPriority() {
        return 80;
    }

    @Override
    public AttackCategory getCategory() {
        return AttackCategory.BEHAVIORAL;
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
        return "Velocity Attack - Performs high-speed operations to overwhelm systems";
    }

    @Override
    public RequiredPrivilege getRequiredPrivilege() {
        return RequiredPrivilege.NONE;
    }

    @Override
    public String getSuccessCriteria() {
        return "Successfully perform high-velocity operations without detection";
    }

    // IBehaviorAttack interface methods
    @Override
    public BehaviorResult mimicBehavior(UserBehaviorPattern pattern) {
        return new BehaviorResult();
    }

    @Override
    public BehaviorResult performImpossibleTravel(String userId, List<Location> locations, List<Integer> timeIntervals) {
        return new BehaviorResult();
    }

    @Override
    public BehaviorResult performAbnormalTimeAccess(String userId, LocalDateTime accessTime) {
        return new BehaviorResult();
    }

    @Override
    public BehaviorResult violateDeviceTrust(String userId, String deviceFingerprint) {
        return new BehaviorResult();
    }

    @Override
    public BehaviorResult performMassDataAccess(String userId, long dataVolume, int duration) {
        BehaviorResult result = new BehaviorResult();
        result.setAnomalyDetected(true);
        result.setAnomalyType("HIGH_VELOCITY_ACCESS");
        result.setAnomalyScore(0.8);
        return result;
    }

    @Override
    public BehaviorResult generateAnomalousNetworkPattern(String userId, NetworkPattern networkPattern) {
        return new BehaviorResult();
    }

    @Override
    public BehaviorResult simulateAccountTakeover(UserBehaviorPattern legitimatePattern, UserBehaviorPattern attackerPattern) {
        return new BehaviorResult();
    }

    @Override
    public BehaviorResult generateInsiderThreat(String userId, List<ThreatIndicator> threatIndicators) {
        return new BehaviorResult();
    }

    @Override
    public AttackResult execute(AttackContext context) {
        log.warn("=== Velocity Attack 시작: target={} ===", context.getParameters().get("targetService"));

        AttackResult result = AttackResult.builder()
            .attackId(UUID.randomUUID().toString())
            .campaignId(context.getCampaignId())
            .type(AttackResult.AttackType.VELOCITY_ATTACK)
            .attackName("Velocity Attack")
            .executionTime(LocalDateTime.now())
            .targetUser(context.getTargetUser())
            .attackVector("behavior")
            .build();

        long startTime = System.currentTimeMillis();
        List<String> attackLog = new ArrayList<>();

        try {
            // 1. 공격 매개변수 추출
            String targetService = context.getParameters().getOrDefault("targetService", "API").toString();
            int requestRate = Integer.parseInt(
                context.getParameters().getOrDefault("requestRate", "100").toString()
            );
            int duration = Integer.parseInt(
                context.getParameters().getOrDefault("duration", "60").toString()
            );
            String pattern = context.getParameters().getOrDefault("pattern", "CONSTANT").toString();
            String evasion = context.getParameters().getOrDefault("evasion", "NONE").toString();
            int threads = Integer.parseInt(
                context.getParameters().getOrDefault("threads", "10").toString()
            );

            attackLog.add("Target service: " + targetService);
            attackLog.add("Request rate: " + requestRate + " req/s");
            attackLog.add("Duration: " + duration + " seconds");
            attackLog.add("Pattern: " + pattern);
            attackLog.add("Evasion: " + evasion);
            attackLog.add("Threads: " + threads);

            // 2. 스레드 풀 생성
            ExecutorService executor = Executors.newFixedThreadPool(Math.min(threads, maxThreads));

            // 3. 공격 패턴에 따른 실행 계획 수립
            List<RequestBatch> requestPlan = generateRequestPlan(
                requestRate, duration, pattern, threads
            );
            attackLog.add("Generated " + requestPlan.size() + " request batches");

            // 4. 공격 실행
            AtomicInteger totalRequests = new AtomicInteger(0);
            AtomicInteger successfulRequests = new AtomicInteger(0);
            AtomicInteger blockedRequests = new AtomicInteger(0);
            AtomicInteger rateLimitedRequests = new AtomicInteger(0);
            AtomicLong totalResponseTime = new AtomicLong(0);

            List<CompletableFuture<BatchResult>> futures = new ArrayList<>();

            for (RequestBatch batch : requestPlan) {
                CompletableFuture<BatchResult> future = CompletableFuture.supplyAsync(() ->
                    executeBatch(batch, targetService, evasion, context), executor
                );
                futures.add(future);

                // 패턴에 따른 지연
                if (!pattern.equals("BURST")) {
                    Thread.sleep(batch.delayMs);
                }
            }

            // 5. 결과 수집
            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                .get(Math.min(duration * 2, maxDurationMs / 1000), TimeUnit.SECONDS);

            for (CompletableFuture<BatchResult> future : futures) {
                try {
                    BatchResult batchResult = future.getNow(null);
                    if (batchResult != null) {
                        totalRequests.addAndGet(batchResult.totalRequests);
                        successfulRequests.addAndGet(batchResult.successfulRequests);
                        blockedRequests.addAndGet(batchResult.blockedRequests);
                        rateLimitedRequests.addAndGet(batchResult.rateLimitedRequests);
                        totalResponseTime.addAndGet(batchResult.totalResponseTime);
                    }
                } catch (Exception e) {
                    attackLog.add("Batch execution error: " + e.getMessage());
                }
            }

            executor.shutdown();

            // 6. 통계 계산
            double actualRate = (double) totalRequests.get() / duration;
            double successRate = (double) successfulRequests.get() / totalRequests.get();
            double blockRate = (double) blockedRequests.get() / totalRequests.get();
            double rateLimitRate = (double) rateLimitedRequests.get() / totalRequests.get();
            double avgResponseTime = totalRequests.get() > 0 ?
                (double) totalResponseTime.get() / totalRequests.get() : 0;

            attackLog.add(String.format("Total requests: %d (%.1f req/s)",
                totalRequests.get(), actualRate));
            attackLog.add(String.format("Successful: %d (%.1f%%)",
                successfulRequests.get(), successRate * 100));
            attackLog.add(String.format("Blocked: %d (%.1f%%)",
                blockedRequests.get(), blockRate * 100));
            attackLog.add(String.format("Rate limited: %d (%.1f%%)",
                rateLimitedRequests.get(), rateLimitRate * 100));
            attackLog.add(String.format("Average response time: %.2f ms", avgResponseTime));

            // 7. 결과 평가
            if (successRate > 0.7 && actualRate > requestRate * 0.8) {
                result.setSuccessful(true);
                result.setRiskScore(0.8);
                attackLog.add("Velocity attack successful - high-speed requests accepted");
            } else if (rateLimitRate > 0.5) {
                result.setSuccessful(false);
                result.setRiskScore(0.4);
                attackLog.add("Velocity attack partially blocked - rate limiting effective");
            } else {
                result.setSuccessful(false);
                result.setRiskScore(0.2);
                attackLog.add("Velocity attack failed - requests blocked");
            }

            // 탐지 평가
            result.setDetected(blockRate > 0.3 || rateLimitRate > 0.3);
            result.setBlocked(blockRate > 0.7);

            result.setDetails(Map.of(
                "attackLog", attackLog,
                "targetService", targetService,
                "totalRequests", totalRequests.get(),
                "successfulRequests", successfulRequests.get(),
                "blockedRequests", blockedRequests.get(),
                "rateLimitedRequests", rateLimitedRequests.get(),
                "actualRate", String.format("%.2f req/s", actualRate),
                "avgResponseTime", String.format("%.2f ms", avgResponseTime)
            ));

        } catch (Exception e) {
            log.error("Velocity attack failed", e);
            result.setSuccessful(false);
            result.setRiskScore(0.1);
            attackLog.add("Attack failed: " + e.getMessage());
        }

        long duration = System.currentTimeMillis() - startTime;
        result.setDurationMs(duration);

        // 이벤트 발행 - 고속 요청 공격은 인가 결정 이벤트로 처리
        if (eventPublisher != null) {
            String resource = "api_service:" + result.getDetails().getOrDefault("targetService", "unknown");
            String action = "VELOCITY_ATTACK_" + result.getDetails().getOrDefault("actualRate", "0");
            eventPublisher.publishAuthorizationDecision(
                result,
                context.getTargetUser(),
                resource,
                action,
                result.isSuccessful(),
                result.isSuccessful() ?
                    "High velocity attack succeeded - " + result.getDetails().getOrDefault("totalRequests", "0") + " requests processed" :
                    "High velocity attack blocked - rate limiting active"
            );
        }

        log.info("Velocity Attack 완료: Success={}, Risk={}, Duration={}ms",
            result.isSuccessful(), result.getRiskScore(), duration);

        return result;
    }

    private List<RequestBatch> generateRequestPlan(int requestRate, int durationSeconds,
                                                   String pattern, int threads) {
        List<RequestBatch> batches = new ArrayList<>();
        int totalRequests = requestRate * durationSeconds;
        int requestsPerThread = totalRequests / threads;

        switch (pattern) {
            case "CONSTANT":
                // 일정한 속도
                for (int i = 0; i < durationSeconds; i++) {
                    for (int t = 0; t < threads; t++) {
                        RequestBatch batch = new RequestBatch();
                        batch.requestCount = requestRate / threads;
                        batch.delayMs = 1000 / threads;
                        batch.threadId = t;
                        batches.add(batch);
                    }
                }
                break;

            case "BURST":
                // 버스트 패턴
                for (int burst = 0; burst < 5; burst++) {
                    RequestBatch batch = new RequestBatch();
                    batch.requestCount = totalRequests / 5;
                    batch.delayMs = (durationSeconds * 1000) / 5;
                    batch.threadId = burst % threads;
                    batches.add(batch);
                }
                break;

            case "GRADUAL":
                // 점진적 증가
                for (int i = 0; i < durationSeconds; i++) {
                    int rate = (int) (requestRate * (i + 1.0) / durationSeconds);
                    RequestBatch batch = new RequestBatch();
                    batch.requestCount = rate;
                    batch.delayMs = 1000;
                    batch.threadId = i % threads;
                    batches.add(batch);
                }
                break;

            case "RANDOM":
                // 무작위
                Random random = ThreadLocalRandom.current();
                int remainingRequests = totalRequests;
                for (int i = 0; i < durationSeconds && remainingRequests > 0; i++) {
                    int requests = random.nextInt(Math.min(requestRate * 2, remainingRequests)) + 1;
                    RequestBatch batch = new RequestBatch();
                    batch.requestCount = requests;
                    batch.delayMs = random.nextInt(2000);
                    batch.threadId = i % threads;
                    batches.add(batch);
                    remainingRequests -= requests;
                }
                break;

            case "WAVE":
                // 파동형
                for (int i = 0; i < durationSeconds; i++) {
                    double waveMultiplier = Math.sin(i * Math.PI / 10) + 1; // 0-2 multiplier
                    int rate = (int) (requestRate * waveMultiplier / 2);
                    RequestBatch batch = new RequestBatch();
                    batch.requestCount = rate;
                    batch.delayMs = 1000;
                    batch.threadId = i % threads;
                    batches.add(batch);
                }
                break;
        }

        return batches;
    }

    private BatchResult executeBatch(RequestBatch batch, String targetService, String evasion,
                                    AttackContext context) {
        BatchResult result = new BatchResult();
        result.totalRequests = batch.requestCount;

        for (int i = 0; i < batch.requestCount; i++) {
            long requestStart = System.currentTimeMillis();

            try {
                // 회피 기법 적용
                Map<String, String> headers = applyEvasion(evasion, i);

                boolean success = executeRequest(targetService, headers, context);

                if (success) {
                    result.successfulRequests++;
                } else {
                    // 응답 코드에 따른 분류 - 요청 인덱스를 기반으로 판단
                    if (i % 2 == 0 || (i > batch.requestCount / 2)) {
                        result.rateLimitedRequests++;
                    } else {
                        result.blockedRequests++;
                    }
                }

                long responseTime = System.currentTimeMillis() - requestStart;
                result.totalResponseTime += responseTime;

            } catch (Exception e) {
                result.blockedRequests++;
                log.debug("Request failed: {}", e.getMessage());
            }
        }

        return result;
    }

    private boolean executeRequest(String targetService, Map<String, String> headers,
                                  AttackContext context) {
        // 고객 ID 생성 (각 요청마다 다른 고객)
        String customerId = "customer-" + ThreadLocalRandom.current().nextInt(1, 1000);

        // @Protectable로 보호된 엔드포인트 호출
        boolean success = attemptCustomerDataAccess(customerId, "VELOCITY_ATTACK", context);

        return success;
    }

    private boolean executeRequest(String targetService, Map<String, String> headers) {
        // Deprecated - context 있는 버전 사용
        return false;
    }

    private String getEndpointForService(String service) {
        // 모든 서비스가 최종적으로 고객 데이터 엔드포인트로 연결
        return "/api/protected/customer";
    }

    private Map<String, String> applyEvasion(String evasion, int requestIndex) {
        Map<String, String> headers = new HashMap<>();

        switch (evasion) {
            case "USER_AGENT":
                headers.put("User-Agent", generateRandomUserAgent());
                break;

            case "COOKIE":
                headers.put("Cookie", "session=" + UUID.randomUUID().toString());
                break;

            case "DISTRIBUTED":
                headers.put("X-Forwarded-For", generateRandomIP());
                headers.put("X-Real-IP", generateRandomIP());
                break;

            case "NONE":
            default:
                // 기본 헤더
                headers.put("User-Agent", "VelocityAttackBot/1.0");
                break;
        }

        headers.put("X-Request-ID", UUID.randomUUID().toString());
        headers.put("X-Attack-Index", String.valueOf(requestIndex));

        return headers;
    }

    private String generateRandomUserAgent() {
        String[] userAgents = {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
            "Mozilla/5.0 (Android 11; Mobile; rv:89.0) Gecko/89.0"
        };
        return userAgents[ThreadLocalRandom.current().nextInt(userAgents.length)];
    }

    private String generateRandomIP() {
        return String.format("%d.%d.%d.%d",
            ThreadLocalRandom.current().nextInt(1, 255),
            ThreadLocalRandom.current().nextInt(256),
            ThreadLocalRandom.current().nextInt(256),
            ThreadLocalRandom.current().nextInt(256)
        );
    }

    private static class RequestBatch {
        int requestCount;
        int delayMs;
        int threadId;
    }

    private static class BatchResult {
        int totalRequests;
        int successfulRequests;
        int blockedRequests;
        int rateLimitedRequests;
        long totalResponseTime;
    }
}