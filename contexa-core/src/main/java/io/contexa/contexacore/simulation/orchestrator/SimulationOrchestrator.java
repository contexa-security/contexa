package io.contexa.contexacore.simulation.orchestrator;

import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.domain.entity.AttackResult;
import io.contexa.contexacore.simulation.generator.AttackScenarioGenerator;
import io.contexa.contexacore.simulation.generator.AttackScenarioGenerator.AttackType;
import io.contexa.contexacore.simulation.injector.EventInjectionService;
import io.contexa.contexacore.simulation.strategy.IAttackStrategy;
import io.contexa.contexacore.simulation.factory.AttackStrategyFactory;
// import io.contexa.contexaiam.aiam.service.SoarSimulationService;  // 모듈 간 순환 의존성 방지를 위해 주석 처리
// import io.contexa.contexaiam.aiam.web.SoarSimulationController.SimulationStartRequest;
import lombok.Builder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

/**
 * 시뮬레이션 오케스트레이터
 * 
 * 공격 시나리오의 시퀀싱, 타이밍, 병렬 처리를 관리합니다.
 * 3-Tier 에스컬레이션과 SOAR 승인 워크플로우를 테스트합니다.
 * 
 * @author AI3Security
 * @since 1.0.0
 */
@Slf4j
@Service
public class SimulationOrchestrator {
    
    private final AttackScenarioGenerator attackScenarioGenerator;
    private final EventInjectionService eventInjectionService;
    private final AttackStrategyFactory strategyFactory;
    // private final SoarSimulationService soarSimulationService;  // 순환 의존성 방지
    
    public SimulationOrchestrator(AttackScenarioGenerator attackScenarioGenerator,
                                 EventInjectionService eventInjectionService,
                                 AttackStrategyFactory strategyFactory) {
        this.attackScenarioGenerator = attackScenarioGenerator;
        this.eventInjectionService = eventInjectionService;
        this.strategyFactory = strategyFactory;
    }
    
    // 시뮬레이션 세션 관리
    private final Map<String, SimulationSession> activeSessions = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(5);
    private final ExecutorService executor = Executors.newFixedThreadPool(10);
    
    // 시뮬레이션 상태
    private final AtomicBoolean isRunning = new AtomicBoolean(false);
    private final AtomicInteger totalEventsGenerated = new AtomicInteger(0);
    private final AtomicInteger totalEventsProcessed = new AtomicInteger(0);
    
    /**
     * 시뮬레이션 세션
     */
    /**
     * 시뮬레이션 요청 DTO (로컬 사용)
     */
    @Data
    @Builder
    public static class SimulationRequest {
        private String incidentId;
        private String threatType;
        private String description;
        private String severity;
        private String userQuery;
        private String organizationId;
        private Map<String, Object> metadata;
    }
    
    @Data
    @Builder
    public static class SimulationSession {
        private String sessionId;
        private String name;
        private SimulationType type;
        private SimulationStatus status;
        private LocalDateTime startTime;
        private LocalDateTime endTime;
        private int totalEvents;
        private int processedEvents;
        private int successfulEvents;
        private int failedEvents;
        private List<String> eventIds;
        private Map<String, Object> metadata;
        private ScheduledFuture<?> scheduledTask;
    }
    
    public enum SimulationType {
        SINGLE_ATTACK,          // 단일 공격
        COMPLEX_SCENARIO,       // 복합 시나리오
        CONTINUOUS_STREAM,      // 연속 스트림
        TIER_ESCALATION,        // 계층 에스컬레이션 테스트
        SOAR_APPROVAL,          // SOAR 승인 워크플로우 테스트
        APT_CAMPAIGN,           // APT 캠페인 시뮬레이션
        STRESS_TEST,            // 스트레스 테스트
        COMPREHENSIVE,          // 종합 시뮬레이션
        CAMPAIGN                // 캠페인 시뮬레이션
    }
    
    public enum SimulationStatus {
        PREPARING,
        RUNNING,
        PAUSED,
        COMPLETED,
        FAILED,
        CANCELLED,
        STOPPED
    }
    
    /**
     * 종합 시뮬레이션 시작
     */
    public Mono<SimulationSession> startComprehensiveSimulation(String name) {
        log.info("종합 시뮬레이션 시작: {}", name);
        
        String sessionId = UUID.randomUUID().toString();
        SimulationSession session = SimulationSession.builder()
            .sessionId(sessionId)
            .name(name)
            .type(SimulationType.COMPREHENSIVE)
            .status(SimulationStatus.PREPARING)
            .startTime(LocalDateTime.now())
            .totalEvents(0)
            .processedEvents(0)
            .successfulEvents(0)
            .failedEvents(0)
            .eventIds(new ArrayList<>())
            .metadata(new HashMap<>())
            .build();
        
        activeSessions.put(sessionId, session);
        
        return Mono.fromCallable(() -> {
            session.setStatus(SimulationStatus.RUNNING);
            
            // 병렬로 여러 시나리오 실행
            List<CompletableFuture<Void>> scenarios = Arrays.asList(
                // 1. Layer 1 공격들 (낮은 위험도)
                runLayer1Attacks(session),
                
                // 2. Layer 2 공격들 (중간 위험도)  
                runLayer2Attacks(session),
                
                // 3. Layer 3 공격들 (높은 위험도)
                runLayer3Attacks(session),
                
                // 4. 복합 APT 시나리오
                runAPTCampaign(session),
                
                // 5. SOAR 승인 테스트
                runSoarApprovalTest(session)
            );
            
            // 모든 시나리오 완료 대기
            CompletableFuture.allOf(scenarios.toArray(new CompletableFuture[0]))
                .whenComplete((result, error) -> {
                    if (error != null) {
                        log.error("종합 시뮬레이션 실패: {}", sessionId, error);
                        session.setStatus(SimulationStatus.FAILED);
                    } else {
                        log.info("종합 시뮬레이션 완료: {}", sessionId);
                        session.setStatus(SimulationStatus.COMPLETED);
                    }
                    session.setEndTime(LocalDateTime.now());
                });
            
            return session;
        });
    }
    
    /**
     * Layer 1 공격 시뮬레이션 (낮은 위험도)
     */
    private CompletableFuture<Void> runLayer1Attacks(SimulationSession session) {
        return CompletableFuture.runAsync(() -> {
            log.info("Layer 1 공격 시뮬레이션 시작");
            
            List<AttackType> layer1Attacks = Arrays.asList(
                AttackType.BRUTE_FORCE,
                AttackType.PHISHING,
                AttackType.DDOS
            );
            
            for (AttackType type : layer1Attacks) {
                try {
                    for (int i = 0; i < 3; i++) { // 각 타입별 3개씩
                        SecurityEvent event = attackScenarioGenerator.generateAttack(type);
                        injectAndTrack(event, session);
                        Thread.sleep(1000); // 1초 간격
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            
            log.info("Layer 1 공격 시뮬레이션 완료");
        }, executor);
    }
    
    /**
     * Layer 2 공격 시뮬레이션 (중간 위험도)
     */
    private CompletableFuture<Void> runLayer2Attacks(SimulationSession session) {
        return CompletableFuture.runAsync(() -> {
            log.info("Layer 2 공격 시뮬레이션 시작");
            
            List<AttackType> layer2Attacks = Arrays.asList(
                AttackType.SQL_INJECTION,
                AttackType.LATERAL_MOVEMENT,
                AttackType.INSIDER_THREAT
            );
            
            for (AttackType type : layer2Attacks) {
                try {
                    for (int i = 0; i < 2; i++) { // 각 타입별 2개씩
                        SecurityEvent event = attackScenarioGenerator.generateAttack(type);
                        injectAndTrack(event, session);
                        Thread.sleep(2000); // 2초 간격
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            
            log.info("Layer 2 공격 시뮬레이션 완료");
        }, executor);
    }
    
    /**
     * Layer 3 공격 시뮬레이션 (높은 위험도)
     */
    private CompletableFuture<Void> runLayer3Attacks(SimulationSession session) {
        return CompletableFuture.runAsync(() -> {
            log.info("Layer 3 공격 시뮬레이션 시작");
            
            List<AttackType> layer3Attacks = Arrays.asList(
                AttackType.PRIVILEGE_ESCALATION,
                AttackType.DATA_EXFILTRATION,
                AttackType.MALWARE_DEPLOYMENT,
                AttackType.ZERO_DAY,
                AttackType.RANSOMWARE
            );
            
            for (AttackType type : layer3Attacks) {
                try {
                    SecurityEvent event = attackScenarioGenerator.generateAttack(type);
                    injectAndTrack(event, session);
                    
                    // Layer 3는 SOAR 처리 트리거
                    triggerSoarProcessing(event, session);
                    
                    Thread.sleep(3000); // 3초 간격
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            
            log.info("Layer 3 공격 시뮬레이션 완료");
        }, executor);
    }
    
    /**
     * APT 캠페인 시뮬레이션
     */
    private CompletableFuture<Void> runAPTCampaign(SimulationSession session) {
        return CompletableFuture.runAsync(() -> {
            log.info("APT 캠페인 시뮬레이션 시작");
            
            try {
                // 복합 공격 시나리오 생성
                List<SecurityEvent> aptScenario = attackScenarioGenerator.generateComplexAttackScenario();
                
                // 캠페인 ID 부여
                String campaignId = "APT-SIM-" + UUID.randomUUID().toString().substring(0, 8);
                
                for (SecurityEvent event : aptScenario) {
                    event.getDetails().put("simulationCampaignId", campaignId);
                    injectAndTrack(event, session);
                    Thread.sleep(5000); // 5초 간격 (실제 APT는 느리게 진행)
                }
                
                log.info("APT 캠페인 시뮬레이션 완료: {}", campaignId);
                
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }, executor);
    }
    
    /**
     * SOAR 승인 워크플로우 테스트
     */
    private CompletableFuture<Void> runSoarApprovalTest(SimulationSession session) {
        return CompletableFuture.runAsync(() -> {
            log.info("SOAR 승인 워크플로우 테스트 시작");
            
            try {
                // 고위험 이벤트 생성 (SOAR 승인 필요)
                SecurityEvent criticalEvent = attackScenarioGenerator.generateAttack(AttackType.RANSOMWARE);
                criticalEvent.setSeverity(SecurityEvent.Severity.CRITICAL);
                criticalEvent.setRiskScore(9.5);
                
                // SOAR 컨텍스트 생성 (로컬 DTO 사용)
                SimulationRequest soarRequest = SimulationRequest.builder()
                    .incidentId(criticalEvent.getEventId())
                    .threatType(criticalEvent.getEventType().toString())
                    .description(criticalEvent.getDescription())
                    .severity(criticalEvent.getSeverity().toString())
                    .userQuery("긴급: 랜섬웨어 공격 대응 - 자동 격리 및 복구 절차 실행")
                    .organizationId("simulation-org")
                    .build();
                
                // SOAR 시뮬레이션 서비스 호출
                // soarSimulationService.startSimulation(soarRequest)  // 순환 의존성 방지
                log.info("SOAR 시뮬레이션 시작 요청 (실제 서비스는 aiam 모듈에서 처리)");
                /*
                    .subscribe(
                        result -> {
                            log.info("SOAR 처리 완료: SessionId={}, Success={}", 
                                result.getSessionId(), result.isSuccess());
                            session.setSuccessfulEvents(session.getSuccessfulEvents() + 1);
                        },
                        error -> {
                            log.error("SOAR 처리 실패", error);
                            session.setFailedEvents(session.getFailedEvents() + 1);
                        }
                    );
                */
                
                // 이벤트도 주입
                injectAndTrack(criticalEvent, session);
                
            } catch (Exception e) {
                log.error("SOAR 승인 테스트 실패", e);
            }
        }, executor);
    }
    
    /**
     * 3-Tier 에스컬레이션 테스트
     */
    public Mono<SimulationSession> runTierEscalationTest() {
        log.info("3-Tier 에스컬레이션 테스트 시작");
        
        String sessionId = UUID.randomUUID().toString();
        SimulationSession session = createSession(sessionId, "3-Tier Escalation Test", 
            SimulationType.TIER_ESCALATION);
        
        return Mono.fromCallable(() -> {
            // 점진적으로 위험도를 높이는 공격 시퀀스
            List<Double> riskScores = Arrays.asList(3.0, 4.5, 6.0, 7.5, 8.5, 9.5);
            
            for (Double riskScore : riskScores) {
                try {
                    SecurityEvent event = attackScenarioGenerator.generateRandomAttack();
                    event.setRiskScore(riskScore);
                    
                    // 위험도에 따른 설명 추가
                    String tier = riskScore < 4.0 ? "Layer 1" : 
                                 riskScore < 7.0 ? "Layer 2" : "Layer 3";
                    event.setDescription(String.format("[%s] %s (RiskScore: %.1f)", 
                        tier, event.getDescription(), riskScore));
                    
                    injectAndTrack(event, session);
                    
                    // Layer 3 도달 시 SOAR 트리거
                    if (riskScore >= 7.0) {
                        triggerSoarProcessing(event, session);
                    }
                    
                    Thread.sleep(2000);
                    
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            
            session.setStatus(SimulationStatus.COMPLETED);
            session.setEndTime(LocalDateTime.now());
            
            log.info("3-Tier 에스컬레이션 테스트 완료");
            return session;
        });
    }
    
    /**
     * 연속 스트림 시뮬레이션
     */
    public SimulationSession startContinuousStream(int durationMinutes, int eventsPerMinute) {
        log.info("연속 스트림 시뮬레이션 시작: {} 분, 분당 {} 이벤트", 
            durationMinutes, eventsPerMinute);
        
        String sessionId = UUID.randomUUID().toString();
        SimulationSession session = createSession(sessionId, "Continuous Stream", 
            SimulationType.CONTINUOUS_STREAM);
        
        // 스케줄러로 주기적 실행
        ScheduledFuture<?> future = scheduler.scheduleAtFixedRate(() -> {
            try {
                // 무작위 공격 생성 및 주입
                SecurityEvent event = attackScenarioGenerator.generateRandomAttack();
                injectAndTrack(event, session);
                
                // 10% 확률로 복합 시나리오
                if (Math.random() < 0.1) {
                    executor.submit(() -> {
                        List<SecurityEvent> scenario = attackScenarioGenerator.generateComplexAttackScenario();
                        scenario.forEach(e -> injectAndTrack(e, session));
                    });
                }
                
            } catch (Exception e) {
                log.error("연속 스트림 이벤트 생성 실패", e);
            }
        }, 0, 60 / eventsPerMinute, TimeUnit.SECONDS);
        
        session.setScheduledTask(future);
        
        // 종료 스케줄링
        scheduler.schedule(() -> {
            future.cancel(false);
            session.setStatus(SimulationStatus.COMPLETED);
            session.setEndTime(LocalDateTime.now());
            log.info("연속 스트림 시뮬레이션 종료: {}", sessionId);
        }, durationMinutes, TimeUnit.MINUTES);
        
        return session;
    }
    
    /**
     * 스트레스 테스트
     */
    public Mono<SimulationSession> runStressTest(int totalEvents, int parallelThreads) {
        log.info("스트레스 테스트 시작: {} 이벤트, {} 스레드", totalEvents, parallelThreads);
        
        String sessionId = UUID.randomUUID().toString();
        SimulationSession session = createSession(sessionId, "Stress Test", 
            SimulationType.STRESS_TEST);
        
        return Mono.fromCallable(() -> {
            ExecutorService stressExecutor = Executors.newFixedThreadPool(parallelThreads);
            CountDownLatch latch = new CountDownLatch(totalEvents);
            
            for (int i = 0; i < totalEvents; i++) {
                stressExecutor.submit(() -> {
                    try {
                        SecurityEvent event = attackScenarioGenerator.generateRandomAttack();
                        injectAndTrack(event, session);
                    } finally {
                        latch.countDown();
                    }
                });
            }
            
            try {
                latch.await(10, TimeUnit.MINUTES);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            
            stressExecutor.shutdown();
            
            session.setStatus(SimulationStatus.COMPLETED);
            session.setEndTime(LocalDateTime.now());
            
            log.info("스트레스 테스트 완료: 처리된 이벤트 {}/{}", 
                session.getProcessedEvents(), totalEvents);
            
            return session;
        });
    }
    
    /**
     * 이벤트 주입 및 추적
     */
    private void injectAndTrack(SecurityEvent event, SimulationSession session) {
        try {
            session.setTotalEvents(session.getTotalEvents() + 1);
            session.getEventIds().add(event.getEventId());
            
            eventInjectionService.injectEvent(event)
                .whenComplete((success, error) -> {
                    if (success != null && success) {
                        session.setProcessedEvents(session.getProcessedEvents() + 1);
                        session.setSuccessfulEvents(session.getSuccessfulEvents() + 1);
                        totalEventsProcessed.incrementAndGet();
                    } else {
                        session.setFailedEvents(session.getFailedEvents() + 1);
                        log.error("이벤트 주입 실패: {}", event.getEventId(), error);
                    }
                });
            
            totalEventsGenerated.incrementAndGet();
            
        } catch (Exception e) {
            log.error("이벤트 추적 실패: {}", event.getEventId(), e);
        }
    }
    
    /**
     * SOAR 처리 트리거
     */
    private void triggerSoarProcessing(SecurityEvent event, SimulationSession session) {
        try {
            SimulationRequest soarRequest = SimulationRequest.builder()
                .incidentId(event.getEventId())
                .threatType(event.getEventType().toString())
                .description(event.getDescription())
                .severity(event.getSeverity().toString())
                .userQuery(String.format("자동 대응: %s (위험도: %.1f)", 
                    event.getEventType(), event.getRiskScore()))
                .organizationId("simulation-org")
                .metadata(event.getDetails())
                .build();
            
            // soarSimulationService.startSimulation(soarRequest)  // 순환 의존성 방지
            //     .subscribe(
            //         result -> log.debug("SOAR 처리 트리거 성공: {}", event.getEventId()),
            //         error -> log.error("SOAR 처리 트리거 실패: {}", event.getEventId(), error)
            //     );
            log.info("SOAR 처리 트리거 - ID: {}, Type: {}", event.getEventId(), event.getEventType());
            
        } catch (Exception e) {
            log.error("SOAR 트리거 예외: {}", event.getEventId(), e);
        }
    }
    
    /**
     * 시뮬레이션 세션 생성
     */
    private SimulationSession createSession(String sessionId, String name, SimulationType type) {
        SimulationSession session = SimulationSession.builder()
            .sessionId(sessionId)
            .name(name)
            .type(type)
            .status(SimulationStatus.RUNNING)
            .startTime(LocalDateTime.now())
            .totalEvents(0)
            .processedEvents(0)
            .successfulEvents(0)
            .failedEvents(0)
            .eventIds(new ArrayList<>())
            .metadata(new HashMap<>())
            .build();
        
        activeSessions.put(sessionId, session);
        return session;
    }
    
    /**
     * 시뮬레이션 중지
     */
    public void stopSimulation(String sessionId) {
        SimulationSession session = activeSessions.get(sessionId);
        if (session != null) {
            if (session.getScheduledTask() != null) {
                session.getScheduledTask().cancel(true);
            }
            session.setStatus(SimulationStatus.CANCELLED);
            session.setEndTime(LocalDateTime.now());
            log.info("시뮬레이션 중지: {}", sessionId);
        }
    }
    
    /**
     * 모든 시뮬레이션 중지
     */
    public void stopAllSimulations() {
        log.info("모든 시뮬레이션 중지");
        activeSessions.values().forEach(session -> stopSimulation(session.getSessionId()));
        isRunning.set(false);
    }
    
    /**
     * 활성 세션 조회
     */
    public List<SimulationSession> getActiveSessions() {
        return activeSessions.values().stream()
            .filter(s -> s.getStatus() == SimulationStatus.RUNNING)
            .collect(Collectors.toList());
    }
    
    /**
     * 세션 상태 조회
     */
    public SimulationSession getSession(String sessionId) {
        return activeSessions.get(sessionId);
    }
    
    /**
     * 통계 조회
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalSessions", activeSessions.size());
        stats.put("activeSessions", getActiveSessions().size());
        stats.put("totalEventsGenerated", totalEventsGenerated.get());
        stats.put("totalEventsProcessed", totalEventsProcessed.get());
        stats.put("isRunning", isRunning.get());
        
        // 이벤트 주입 서비스 통계 포함
        stats.putAll(eventInjectionService.getStatistics());
        
        return stats;
    }
    
    /**
     * 추가 메트릭 메서드들
     */
    public double getDetectionRate() {
        long total = totalEventsGenerated.get();
        long detected = totalEventsProcessed.get();
        return total > 0 ? (double) detected / total * 100 : 0;
    }
    
    public long getAverageResponseTime() {
        // 평균 응답 시간 (밀리초)
        return Math.round(activeSessions.values().stream()
            .filter(s -> s.getEndTime() != null && s.getStartTime() != null)
            .mapToLong(s -> java.time.Duration.between(s.getStartTime(), s.getEndTime()).toMillis())
            .average()
            .orElse(0.0));
    }
    
    public long getTotalAttacks() {
        return totalEventsGenerated.get();
    }
    
    public long getDetectedAttacks() {
        return totalEventsProcessed.get();
    }
    
    public long getActiveAttacks() {
        return activeSessions.values().stream()
            .filter(s -> s.getStatus() == SimulationStatus.RUNNING)
            .count();
    }
    
    public List<Map<String, Object>> getActiveCampaigns() {
        return activeSessions.values().stream()
            .filter(s -> s.getStatus() == SimulationStatus.RUNNING)
            .map(s -> {
                Map<String, Object> campaign = new HashMap<>();
                campaign.put("id", s.getSessionId());
                campaign.put("name", s.getName());
                campaign.put("type", s.getType());
                campaign.put("startTime", s.getStartTime());
                return campaign;
            })
            .collect(Collectors.toList());
    }
    
    public String getStatus() {
        return isRunning.get() ? "RUNNING" : "STOPPED";
    }
    
    public int getQueuedAttacks() {
        // 큐에 대기 중인 공격 수
        return ((ThreadPoolExecutor) executor).getQueue().size();
    }
    
    public double getProcessingCapacity() {
        // 처리 용량 (0-100%)
        ThreadPoolExecutor pool = (ThreadPoolExecutor) executor;
        int active = pool.getActiveCount();
        int max = pool.getMaximumPoolSize();
        return max > 0 ? (double) active / max * 100 : 0;
    }
    
    public double getSystemLoad() {
        // 시스템 부하 (0-100%)
        return getProcessingCapacity();
    }
    
    /**
     * 정리 작업
     */
//    @Scheduled(fixedDelay = 3600000) // 1시간마다
    public void cleanupCompletedSessions() {
        LocalDateTime cutoff = LocalDateTime.now().minusHours(24);
        
        activeSessions.entrySet().removeIf(entry -> {
            SimulationSession session = entry.getValue();
            return (session.getStatus() == SimulationStatus.COMPLETED || 
                   session.getStatus() == SimulationStatus.FAILED) &&
                   session.getEndTime() != null &&
                   session.getEndTime().isBefore(cutoff);
        });
        
        log.debug("완료된 세션 정리: 남은 세션 {}", activeSessions.size());
    }
    
    /**
     * 단일 공격 실행
     */
    public AttackResult executeAttack(String strategyName, IAttackStrategy.AttackContext context) {
        log.info("Executing attack: {} for user: {}", strategyName, context.getTargetUser());
        
        try {
            IAttackStrategy strategy = strategyFactory.createStrategy(strategyName);
            if (strategy == null) {
                log.error("Unknown strategy: {}", strategyName);
                return createFailedResult("Unknown strategy: " + strategyName);
            }
            
            AttackResult result = strategy.execute(context);
            log.info("Attack executed - Success: {}, Detected: {}, Risk: {}", 
                    result.isSuccessful(), result.isDetected(), result.getRiskScore());
            
            return result;
            
        } catch (Exception e) {
            log.error("Error executing attack: {}", e.getMessage(), e);
            return createFailedResult("Error executing attack: " + e.getMessage());
        }
    }
    
    /**
     * 캠페인 실행
     */
    public CampaignResult executeCampaign(String campaignId, List<AttackScenario> scenarios) {
        log.info("Executing campaign: {} with {} scenarios", campaignId, scenarios.size());
        
        CampaignResult campaignResult = new CampaignResult();
        campaignResult.setCampaignId(campaignId);
        campaignResult.setStartTime(LocalDateTime.now());
        
        List<AttackResult> results = new ArrayList<>();
        
        for (AttackScenario scenario : scenarios) {
            try {
                AttackResult result = executeAttack(scenario.getStrategyName(), scenario.getContext());
                results.add(result);
            } catch (Exception e) {
                log.error("Error executing scenario: {}", e.getMessage());
                AttackResult failedResult = createFailedResult("Scenario failed: " + e.getMessage());
                results.add(failedResult);
            }
        }
        
        campaignResult.setResults(results);
        campaignResult.setEndTime(LocalDateTime.now());
        campaignResult.calculateStatistics();
        
        return campaignResult;
    }
    
    /**
     * 병렬 공격 실행
     */
    public CompletableFuture<List<AttackResult>> executeParallelAttacks(List<AttackScenario> scenarios) {
        log.info("Executing parallel attacks: {} scenarios", scenarios.size());
        
        return CompletableFuture.supplyAsync(() -> {
            List<CompletableFuture<AttackResult>> futures = scenarios.stream()
                .map(scenario -> CompletableFuture.supplyAsync(() -> 
                    executeAttack(scenario.getStrategyName(), scenario.getContext())))
                .collect(Collectors.toList());
            
            return futures.stream()
                .map(CompletableFuture::join)
                .collect(Collectors.toList());
        });
    }
    
    /**
     * 적응형 공격 실행
     */
    public List<AttackResult> executeAdaptiveAttack(String targetUser, int iterations) {
        log.info("Executing adaptive attack for user: {} with {} iterations", targetUser, iterations);
        
        List<AttackResult> results = new ArrayList<>();
        String[] strategies = {"BruteForceStrategy", "CredentialStuffingStrategy", "SessionHijackingStrategy"};
        
        for (int i = 0; i < iterations; i++) {
            String strategy = strategies[i % strategies.length];
            
            IAttackStrategy.AttackContext context = new IAttackStrategy.AttackContext();
            context.setTargetUser(targetUser);
            context.setStartTime(LocalDateTime.now());
            context.setParameters(Map.of("iteration", i + 1, "adaptive", true));
            
            AttackResult result = executeAttack(strategy, context);
            results.add(result);
            
            // 이전 결과를 바탕으로 다음 공격 조정
            if (result.isDetected() && i < iterations - 1) {
                // 탐지되었으면 전략 변경
                log.info("Attack detected, switching strategy for next iteration");
            }
        }
        
        return results;
    }
    
    /**
     * 실패 결과 생성
     */
    private AttackResult createFailedResult(String reason) {
        AttackResult result = new AttackResult();
        result.setSuccessful(false);
        result.setDetected(false);
        result.setBlocked(true);
        result.setRiskScore(0.0);
        result.setRiskLevel("LOW");
        result.setTimestamp(LocalDateTime.now());
        result.setDescription(reason);
        return result;
    }
    
    /**
     * 캠페인 시작
     */
    public void startCampaign(String campaignId, String campaignName, 
                              int eventCount, int delayMs, int durationMinutes) {
        log.info("Starting campaign: {} ({}) - {} events over {} minutes", 
                campaignName, campaignId, eventCount, durationMinutes);
        
        SimulationSession session = createSession(campaignId, campaignName, SimulationType.CAMPAIGN);
        activeSessions.put(campaignId, session);
        
        // 캠페인 실행 스케줄링
        executor.execute(() -> {
            try {
                LocalDateTime endTime = LocalDateTime.now().plusMinutes(durationMinutes);
                int eventsGenerated = 0;
                
                while (LocalDateTime.now().isBefore(endTime) && eventsGenerated < eventCount) {
                    // 랜덤 공격 타입 선택
                    AttackType[] types = AttackType.values();
                    AttackType type = types[ThreadLocalRandom.current().nextInt(types.length)];
                    
                    // 이벤트 생성 및 전송
                    SecurityEvent event = attackScenarioGenerator.generateAttack(type);
                    eventInjectionService.injectSecurityEvent(event).subscribe();
                    
                    eventsGenerated++;
                    session.setTotalEvents(eventsGenerated);
                    
                    // 딜레이 적용
                    if (delayMs > 0) {
                        Thread.sleep(delayMs);
                    }
                }
                
                session.setStatus(SimulationStatus.COMPLETED);
                session.setEndTime(LocalDateTime.now());
                log.info("Campaign {} completed: {} events generated", campaignId, eventsGenerated);
                
            } catch (Exception e) {
                log.error("Campaign {} failed", campaignId, e);
                session.setStatus(SimulationStatus.FAILED);
                session.setEndTime(LocalDateTime.now());
            }
        });
    }
    
    /**
     * 모든 캠페인 중지
     */
    public void stopAllCampaigns() {
        log.info("Stopping all campaigns");
        
        activeSessions.values().stream()
            .filter(s -> s.getStatus() == SimulationStatus.RUNNING)
            .forEach(s -> {
                s.setStatus(SimulationStatus.STOPPED);
                s.setEndTime(LocalDateTime.now());
            });
        
        // 실행 중인 태스크 중단
        executor.shutdownNow();
        
        // Note: executor will be recreated when needed
        
        log.info("All campaigns stopped");
    }
    
    // 내부 클래스들
    
    public static class AttackScenario {
        private String strategyName;
        private IAttackStrategy.AttackContext context;
        private String targetUser;
        private String targetResource;
        private String sourceIp;
        private Integer maxAttempts;
        private Long delayMs;
        private boolean stealthMode;
        private Map<String, Object> parameters;

        // Getters and Setters
        public String getStrategyName() { return strategyName; }
        public void setStrategyName(String strategyName) { this.strategyName = strategyName; }

        public IAttackStrategy.AttackContext getContext() { return context; }
        public void setContext(IAttackStrategy.AttackContext context) { this.context = context; }

        public String getTargetUser() { return targetUser; }
        public void setTargetUser(String targetUser) { this.targetUser = targetUser; }

        public String getTargetResource() { return targetResource; }
        public void setTargetResource(String targetResource) { this.targetResource = targetResource; }

        public String getSourceIp() { return sourceIp; }
        public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }

        public Integer getMaxAttempts() { return maxAttempts; }
        public void setMaxAttempts(Integer maxAttempts) { this.maxAttempts = maxAttempts; }

        public Long getDelayMs() { return delayMs; }
        public void setDelayMs(Long delayMs) { this.delayMs = delayMs; }

        public boolean isStealthMode() { return stealthMode; }
        public void setStealthMode(boolean stealthMode) { this.stealthMode = stealthMode; }

        public Map<String, Object> getParameters() { return parameters; }
        public void setParameters(Map<String, Object> parameters) { this.parameters = parameters; }
    }
    
    public static class CampaignResult {
        private String campaignId;
        private LocalDateTime startTime;
        private LocalDateTime endTime;
        private List<AttackResult> results;
        private int totalAttacks;
        private int successfulAttacks;
        private int detectedAttacks;
        private int blockedAttacks;
        private double averageDetectionTime;
        
        public void calculateStatistics() {
            if (results == null) return;
            
            totalAttacks = results.size();
            successfulAttacks = (int) results.stream().filter(AttackResult::isSuccessful).count();
            detectedAttacks = (int) results.stream().filter(AttackResult::isDetected).count();
            blockedAttacks = (int) results.stream().filter(AttackResult::isBlocked).count();
            
            averageDetectionTime = results.stream()
                .filter(r -> r.getDetectionTimeMs() != null)
                .mapToLong(AttackResult::getDetectionTimeMs)
                .average()
                .orElse(0);
        }
        
        // Getters and Setters
        public String getCampaignId() { return campaignId; }
        public void setCampaignId(String campaignId) { this.campaignId = campaignId; }
        
        public LocalDateTime getStartTime() { return startTime; }
        public void setStartTime(LocalDateTime startTime) { this.startTime = startTime; }
        
        public LocalDateTime getEndTime() { return endTime; }
        public void setEndTime(LocalDateTime endTime) { this.endTime = endTime; }
        
        public List<AttackResult> getResults() { return results; }
        public void setResults(List<AttackResult> results) { this.results = results; }
        
        public int getTotalAttacks() { return totalAttacks; }
        public int getSuccessfulAttacks() { return successfulAttacks; }
        public int getDetectedAttacks() { return detectedAttacks; }
        public int getBlockedAttacks() { return blockedAttacks; }
        public double getAverageDetectionTime() { return averageDetectionTime; }
    }
}