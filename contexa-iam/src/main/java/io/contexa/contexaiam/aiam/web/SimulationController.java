package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacore.domain.entity.AttackResult;
import io.contexa.contexacore.simulation.orchestrator.SimulationOrchestrator;
import io.contexa.contexacore.simulation.orchestrator.SimulationOrchestrator.*;
import io.contexa.contexacore.simulation.factory.AttackStrategyFactory;
import io.contexa.contexacore.simulation.service.SimulationStatisticsService;
import io.contexa.contexacore.simulation.strategy.IAttackStrategy;
import io.contexa.contexacore.simulation.strategy.IAttackStrategy.AttackContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 시뮬레이션 REST API 컨트롤러
 * 
 * 웹 UI에서 공격 시뮬레이션을 실행하고 모니터링할 수 있는 API를 제공합니다.
 */
@RequestMapping("/api/simulation")
@CrossOrigin(origins = "*")
public class SimulationController {
    private static final Logger logger = LoggerFactory.getLogger(SimulationController.class);
    
    @Autowired
    private SimulationOrchestrator orchestrator;

    @Autowired
    private AttackStrategyFactory strategyFactory;

    @Autowired(required = false)
    private SimpMessagingTemplate messagingTemplate;

    @Autowired
    private SimulationStatisticsService statisticsService;
    
    // 실행 중인 캠페인 관리
    private final Map<String, CampaignStatus> runningCampaigns = new ConcurrentHashMap<>();
    
    /**
     * 사용 가능한 공격 전략 목록 조회
     */
    @GetMapping("/strategies")
    public ResponseEntity<List<StrategyInfo>> getAvailableStrategies() {
        List<StrategyInfo> strategies = new ArrayList<>();
        
        if (strategyFactory != null) {
            for (String name : strategyFactory.getAllStrategyNames()) {
                AttackStrategyFactory.StrategyMetadata metadata = strategyFactory.getStrategyMetadata(name);
                strategies.add(new StrategyInfo(
                    name,
                    metadata.getType().name(),
                    metadata.getCategory().name(),
                    metadata.getDescription()
                ));
            }
        } else {
            // 팩토리가 없을 때 기본 전략 목록
            strategies.add(new StrategyInfo("BRUTE_FORCE", "BRUTE_FORCE", "AUTHENTICATION", "Brute force password attack"));
            strategies.add(new StrategyInfo("CREDENTIAL_STUFFING", "CREDENTIAL_STUFFING", "AUTHENTICATION", "Credential stuffing attack"));
            strategies.add(new StrategyInfo("SESSION_HIJACKING", "SESSION_HIJACKING", "SESSION", "Session hijacking attack"));
            strategies.add(new StrategyInfo("PRIVILEGE_ESCALATION", "PRIVILEGE_ESCALATION", "AUTHORIZATION", "Privilege escalation attack"));
            strategies.add(new StrategyInfo("IDOR", "IDOR", "AUTHORIZATION", "IDOR attack"));
            strategies.add(new StrategyInfo("API_BYPASS", "API_BYPASS", "AUTHORIZATION", "API bypass attack"));
            strategies.add(new StrategyInfo("IMPOSSIBLE_TRAVEL", "IMPOSSIBLE_TRAVEL", "BEHAVIORAL", "Impossible travel attack"));
        }
        
        return ResponseEntity.ok(strategies);
    }
    
    /**
     * 단일 공격 실행
     */
    @PostMapping("/attack/single")
    public ResponseEntity<AttackResponse> executeSingleAttack(@RequestBody AttackRequest request) {
        logger.info("Executing single attack: {} against {}", request.getStrategyName(), request.getTargetUser());
        
        try {
            AttackContext context = createAttackContext(request);
            
            AttackResult result;
            if (orchestrator != null) {
                result = orchestrator.executeAttack(request.getStrategyName(), context);
            } else {
                // 오케스트레이터가 없을 때 실제 공격 실행
                result = executeRealAttack(request);
            }
            
            // 통계 기록
            if (statisticsService != null) {
                statisticsService.recordAttackAttempt(result);
            }

            // WebSocket으로 실시간 알림
            if (messagingTemplate != null) {
                messagingTemplate.convertAndSend("/topic/attacks", result);
            }

            return ResponseEntity.ok(new AttackResponse(
                result.isSuccessful() ? "SUCCESS" : "FAILED",
                result.isDetected(),
                result.isBlocked(),
                result.getRiskScore(),
                result.getRiskLevel(),
                result.getDetectionTimeMs(),
                result.generateSummary()
            ));
            
        } catch (Exception e) {
            logger.error("Error executing attack: {}", e.getMessage());
            return ResponseEntity.internalServerError()
                .body(new AttackResponse("ERROR", false, false, 0.0, "LOW", 0L, e.getMessage()));
        }
    }
    
    /**
     * 캠페인 시작
     */
    @PostMapping("/campaign/start")
    public ResponseEntity<CampaignResponse> startCampaign(@RequestBody CampaignRequest request) {
        String campaignId = "campaign-" + UUID.randomUUID().toString().substring(0, 8);
        logger.info("Starting campaign: {} with {} scenarios", campaignId, request.getScenarios().size());
        
        CampaignStatus status = new CampaignStatus();
        status.setCampaignId(campaignId);
        status.setStatus("RUNNING");
        status.setTotalScenarios(request.getScenarios().size());
        status.setStartTime(LocalDateTime.now());
        
        runningCampaigns.put(campaignId, status);
        
        // 비동기로 캠페인 실행
        CompletableFuture.runAsync(() -> {
            try {
                List<AttackScenario> scenarios = convertToScenarios(request.getScenarios());
                
                CampaignResult result;
                if (orchestrator != null) {
                    result = orchestrator.executeCampaign(campaignId, scenarios);
                } else {
                    result = executeRealCampaign(campaignId, scenarios);
                }
                
                status.setCompletedScenarios(result.getTotalAttacks());
                status.setSuccessfulAttacks(result.getSuccessfulAttacks());
                status.setDetectedAttacks(result.getDetectedAttacks());
                status.setBlockedAttacks(result.getBlockedAttacks());
                status.setStatus("COMPLETED");
                status.setEndTime(LocalDateTime.now());
                
                // WebSocket으로 완료 알림
                if (messagingTemplate != null) {
                    messagingTemplate.convertAndSend("/topic/campaigns", status);
                }
                
            } catch (Exception e) {
                logger.error("Error running campaign {}: {}", campaignId, e.getMessage());
                status.setStatus("ERROR");
                status.setErrorMessage(e.getMessage());
            }
        });
        
        return ResponseEntity.ok(new CampaignResponse(campaignId, "STARTED", 
            "Campaign started successfully"));
    }
    
    /**
     * 캠페인 상태 조회
     */
    @GetMapping("/campaign/{campaignId}/status")
    public ResponseEntity<CampaignStatus> getCampaignStatus(@PathVariable String campaignId) {
        CampaignStatus status = runningCampaigns.get(campaignId);
        if (status == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(status);
    }
    
    /**
     * 실행 중인 모든 캠페인 조회
     */
    @GetMapping("/campaigns")
    public ResponseEntity<List<CampaignStatus>> getAllCampaigns() {
        return ResponseEntity.ok(new ArrayList<>(runningCampaigns.values()));
    }
    
    /**
     * 캠페인 중지
     */
    @PostMapping("/campaign/{campaignId}/stop")
    public ResponseEntity<CampaignResponse> stopCampaign(@PathVariable String campaignId) {
        CampaignStatus status = runningCampaigns.get(campaignId);
        if (status == null) {
            return ResponseEntity.notFound().build();
        }
        
        status.setStatus("STOPPED");
        status.setEndTime(LocalDateTime.now());
        
        return ResponseEntity.ok(new CampaignResponse(campaignId, "STOPPED", 
            "Campaign stopped successfully"));
    }
    
    /**
     * 병렬 공격 실행
     */
    @PostMapping("/attack/parallel")
    public ResponseEntity<ParallelAttackResponse> executeParallelAttacks(@RequestBody ParallelAttackRequest request) {
        logger.info("Executing {} attacks in parallel", request.getAttacks().size());
        
        try {
            List<AttackScenario> scenarios = new ArrayList<>();
            for (AttackRequest attackReq : request.getAttacks()) {
                AttackScenario scenario = new AttackScenario();
                scenario.setStrategyName(attackReq.getStrategyName());
                scenario.setContext(createAttackContext(attackReq));
                scenarios.add(scenario);
            }
            
            if (orchestrator != null) {
                CompletableFuture<List<AttackResult>> future = orchestrator.executeParallelAttacks(scenarios);
                List<AttackResult> results = future.get();
                
                int successful = (int) results.stream().filter(AttackResult::isSuccessful).count();
                int detected = (int) results.stream().filter(AttackResult::isDetected).count();
                int blocked = (int) results.stream().filter(AttackResult::isBlocked).count();
                
                return ResponseEntity.ok(new ParallelAttackResponse(
                    results.size(), successful, detected, blocked,
                    "Parallel attacks completed"
                ));
            } else {
                // 모의 결과
                return ResponseEntity.ok(new ParallelAttackResponse(
                    request.getAttacks().size(), 2, 3, 1,
                    "Mock parallel attacks completed"
                ));
            }
            
        } catch (Exception e) {
            logger.error("Error executing parallel attacks: {}", e.getMessage());
            return ResponseEntity.internalServerError()
                .body(new ParallelAttackResponse(0, 0, 0, 0, "Error: " + e.getMessage()));
        }
    }
    
    /**
     * 적응형 공격 실행
     */
    @PostMapping("/attack/adaptive")
    public ResponseEntity<AdaptiveAttackResponse> executeAdaptiveAttack(@RequestBody AdaptiveAttackRequest request) {
        logger.info("Starting adaptive attack against {} for {} iterations", 
            request.getTargetUser(), request.getIterations());
        
        try {
            List<AttackResult> results;
            if (orchestrator != null) {
                results = orchestrator.executeAdaptiveAttack(request.getTargetUser(), request.getIterations());
            } else {
                results = new ArrayList<>();
                // 모의 결과 생성
                for (int i = 0; i < request.getIterations(); i++) {
                    AttackRequest attackReq = new AttackRequest();
                    attackReq.setStrategyName(request.getStrategyName());
                    attackReq.setTargetUser(request.getTargetUser());
                    attackReq.setTargetResource(request.getTargetResource());
                    attackReq.setSourceIp(request.getSourceIp() != null ? request.getSourceIp() : generateRandomIP());
                    results.add(executeRealAttack(attackReq));
                }
            }
            
            List<String> strategies = new ArrayList<>();
            for (AttackResult result : results) {
                if (result.getAttackType() != null) {
                    strategies.add(result.getAttackType().name());
                }
            }
            
            return ResponseEntity.ok(new AdaptiveAttackResponse(
                request.getIterations(),
                (int) results.stream().filter(AttackResult::isSuccessful).count(),
                strategies,
                "Adaptive attack completed"
            ));
            
        } catch (Exception e) {
            logger.error("Error executing adaptive attack: {}", e.getMessage());
            return ResponseEntity.internalServerError()
                .body(new AdaptiveAttackResponse(0, 0, new ArrayList<>(), "Error: " + e.getMessage()));
        }
    }
    
    /**
     * 시뮬레이션 통계 조회
     */
    @GetMapping("/statistics")
    public ResponseEntity<SimulationStatistics> getStatistics() {
        SimulationStatistics stats = new SimulationStatistics();
        
        // 캠페인 통계
        int totalCampaigns = runningCampaigns.size();
        int runningCampaigns = (int) this.runningCampaigns.values().stream()
            .filter(s -> "RUNNING".equals(s.getStatus())).count();
        int completedCampaigns = (int) this.runningCampaigns.values().stream()
            .filter(s -> "COMPLETED".equals(s.getStatus())).count();
        
        stats.setTotalCampaigns(totalCampaigns);
        stats.setRunningCampaigns(runningCampaigns);
        stats.setCompletedCampaigns(completedCampaigns);
        
        // 전략 통계
        if (strategyFactory != null) {
            AttackStrategyFactory.StrategyStatistics strategyStats = strategyFactory.getStatistics();
            stats.setTotalStrategies(strategyStats.getTotalStrategies());
            stats.setStrategiesByCategory(strategyStats.getStrategiesByCategory());
        } else {
            stats.setTotalStrategies(7);
            Map<IAttackStrategy.AttackCategory, Integer> categoryMap = new HashMap<>();
            categoryMap.put(IAttackStrategy.AttackCategory.AUTHENTICATION, 3);
            categoryMap.put(IAttackStrategy.AttackCategory.AUTHORIZATION, 3);
            categoryMap.put(IAttackStrategy.AttackCategory.BEHAVIORAL, 1);
            stats.setStrategiesByCategory(categoryMap);
        }
        
        return ResponseEntity.ok(stats);
    }

    /**
     * 상세 시뮬레이션 통계 조회 (Redis 기반)
     */
    @GetMapping("/statistics/detailed")
    public ResponseEntity<DetailedStatistics> getDetailedStatistics() {
        DetailedStatistics stats = new DetailedStatistics();

        if (statisticsService != null) {
            // Redis에서 통계 조회
            stats.setTotalAttacks(statisticsService.getTotalAttacks());
            stats.setSuccessfulAttacks(statisticsService.getSuccessfulAttacks());
            stats.setDetectedAttacks(statisticsService.getDetectedAttacks());
            stats.setBlockedAttacks(statisticsService.getBlockedAttacks());
            stats.setAverageRiskScore(statisticsService.getAverageRiskScore());
            stats.setAttacksByType(statisticsService.getAttackCountByType());
            stats.setAttacksByCategory(statisticsService.getAttackCountByCategory());
            stats.setSuccessRateByType(statisticsService.getSuccessRateByType());
            stats.setDetectionRateByType(statisticsService.getDetectionRateByType());
            stats.setThreatDistribution(statisticsService.getThreatDistribution());

            // 최근 공격 트렌드
            Map<String, Long> recentTrends = new HashMap<>();
            recentTrends.put("lastHour", statisticsService.getAttacksInLastHour());
            recentTrends.put("lastDay", statisticsService.getAttacksInLastDay());
            recentTrends.put("lastWeek", statisticsService.getAttacksInLastWeek());
            stats.setRecentTrends(recentTrends);
        } else {
            // 기본 통계값
            stats.setTotalAttacks(0L);
            stats.setSuccessfulAttacks(0L);
            stats.setDetectedAttacks(0L);
            stats.setBlockedAttacks(0L);
            stats.setAverageRiskScore(0.0);
        }

        // 캠페인 통계 추가
        stats.setTotalCampaigns(runningCampaigns.size());
        stats.setRunningCampaigns((int) runningCampaigns.values().stream()
            .filter(s -> "RUNNING".equals(s.getStatus())).count());
        stats.setCompletedCampaigns((int) runningCampaigns.values().stream()
            .filter(s -> "COMPLETED".equals(s.getStatus())).count());

        return ResponseEntity.ok(stats);
    }

    /**
     * 통계 초기화
     */
    @PostMapping("/statistics/reset")
    public ResponseEntity<Map<String, String>> resetStatistics() {
        if (statisticsService != null) {
            statisticsService.resetAllStatistics();
            return ResponseEntity.ok(Map.of("status", "SUCCESS", "message", "Statistics reset successfully"));
        }
        return ResponseEntity.ok(Map.of("status", "SKIPPED", "message", "Statistics service not available"));
    }

    /**
     * 특정 공격 타입의 통계 조회
     */
    @GetMapping("/statistics/attack-type/{type}")
    public ResponseEntity<AttackTypeStatistics> getAttackTypeStatistics(@PathVariable String type) {
        AttackTypeStatistics stats = new AttackTypeStatistics();
        stats.setAttackType(type);

        if (statisticsService != null) {
            stats.setTotalCount(statisticsService.getAttackCountByType().getOrDefault(type, 0L));
            stats.setSuccessRate(statisticsService.getSuccessRateByType().getOrDefault(type, 0.0));
            stats.setDetectionRate(statisticsService.getDetectionRateByType().getOrDefault(type, 0.0));
            stats.setAverageRiskScore(statisticsService.getAverageRiskScore());

            // 시간대별 트렌드
            Map<String, Long> timeTrends = new HashMap<>();
            timeTrends.put("lastHour", statisticsService.getAttacksInLastHour());
            timeTrends.put("lastDay", statisticsService.getAttacksInLastDay());
            stats.setTimeTrends(timeTrends);
        } else {
            stats.setTotalCount(0L);
            stats.setSuccessRate(0.0);
            stats.setDetectionRate(0.0);
            stats.setAverageRiskScore(0.0);
        }

        return ResponseEntity.ok(stats);
    }

    // Helper methods
    
    private AttackContext createAttackContext(AttackRequest request) {
        AttackContext context = new AttackContext();
        context.setTargetUser(request.getTargetUser());
        context.setTargetResource(request.getTargetResource());
        context.setSourceIp(request.getSourceIp() != null ? request.getSourceIp() : generateRandomIP());
        context.setMaxAttempts(request.getMaxAttempts() != null ? request.getMaxAttempts() : 10);
        context.setDelayBetweenAttempts(request.getDelayMs() != null ? request.getDelayMs() : 1000L);
        context.setStealthMode(request.isStealthMode());
        
        if (request.getParameters() != null) {
            context.setParameters(request.getParameters());
        }
        
        return context;
    }
    
    private List<AttackScenario> convertToScenarios(List<ScenarioRequest> requests) {
        List<AttackScenario> scenarios = new ArrayList<>();
        for (ScenarioRequest req : requests) {
            AttackScenario scenario = new AttackScenario();
            scenario.setStrategyName(req.getStrategyName());
            
            AttackRequest attackReq = new AttackRequest();
            attackReq.setStrategyName(req.getStrategyName());
            attackReq.setTargetUser(req.getTargetUser());
            attackReq.setTargetResource(req.getTargetResource());
            scenario.setContext(createAttackContext(attackReq));
            
            scenarios.add(scenario);
        }
        return scenarios;
    }
    
    private AttackResult executeRealAttack(AttackRequest request) {
        AttackResult result = new AttackResult();
        result.setAttackType(determineAttackType(request.getStrategyName()));
        result.setUsername(request.getTargetUser());
        result.setTargetResource(request.getTargetResource());
        result.setTimestamp(LocalDateTime.now());

        // 실제 공격 실행
        try {
            IAttackStrategy strategy = strategyFactory.getStrategy(request.getStrategyName());
            if (strategy != null) {
                AttackContext context = new AttackContext();
                context.setTargetUser(request.getTargetUser());
                context.setTargetResource(request.getTargetResource());
                context.setSourceIp(request.getSourceIp());

                AttackResult strategyResult = strategy.execute(context);
                result.setSuccessful(strategyResult.isSuccessful());
                result.setDetected(strategyResult.isDetected());
                result.setBlocked(strategyResult.isBlocked());
                result.setRiskScore(strategyResult.getRiskScore());
                result.setRiskLevel(calculateRiskLevel(strategyResult.getRiskScore()));
                result.setDetectionTimeMs(System.currentTimeMillis() - result.getTimestamp().toInstant(java.time.ZoneOffset.UTC).toEpochMilli());
            } else {
                // 전략이 없는 경우 실패 처리
                result.setSuccessful(false);
                result.setDetected(true);
                result.setBlocked(true);
                result.setRiskScore(0.0);
                result.setRiskLevel("LOW");
                result.setDetectionTimeMs(100L);
            }
        } catch (Exception e) {
            logger.error("Attack execution failed", e);
            result.setSuccessful(false);
            result.setDetected(true);
            result.setBlocked(true);
            result.setRiskScore(1.0);
            result.setRiskLevel("CRITICAL");
            result.setDetectionTimeMs(50L);
        }

        return result;
    }

    private AttackResult.AttackType determineAttackType(String strategyName) {
        if (strategyName == null) return AttackResult.AttackType.UNKNOWN;

        String upperName = strategyName.toUpperCase();
        if (upperName.contains("BRUTE") || upperName.contains("PASSWORD")) {
            return AttackResult.AttackType.BRUTE_FORCE;
        } else if (upperName.contains("INJECTION") || upperName.contains("SQL") || upperName.contains("XSS")) {
            return AttackResult.AttackType.INJECTION;
        } else if (upperName.contains("PRIVILEGE") || upperName.contains("ESCALATION")) {
            return AttackResult.AttackType.PRIVILEGE_ESCALATION;
        } else if (upperName.contains("SESSION") || upperName.contains("HIJACK")) {
            return AttackResult.AttackType.SESSION_HIJACKING;
        } else if (upperName.contains("DOS") || upperName.contains("DDOS") || upperName.contains("FLOOD")) {
            return AttackResult.AttackType.DOS;
        } else if (upperName.contains("BYPASS") || upperName.contains("EVASION")) {
            return AttackResult.AttackType.AUTHORIZATION_BYPASS;
        } else if (upperName.contains("PHISHING") || upperName.contains("SOCIAL")) {
            return AttackResult.AttackType.PHISHING;
        } else if (upperName.contains("DATA") || upperName.contains("EXFILTRATION")) {
            return AttackResult.AttackType.DATA_EXFILTRATION;
        } else {
            return AttackResult.AttackType.UNKNOWN;
        }
    }

    private String calculateRiskLevel(double riskScore) {
        if (riskScore >= 0.8) return "CRITICAL";
        else if (riskScore >= 0.6) return "HIGH";
        else if (riskScore >= 0.4) return "MEDIUM";
        else if (riskScore >= 0.2) return "LOW";
        else return "INFO";
    }
    
    private CampaignResult executeRealCampaign(String campaignId, List<AttackScenario> scenarios) {
        CampaignResult result = new CampaignResult();
        result.setCampaignId(campaignId);
        result.setStartTime(LocalDateTime.now());

        List<AttackResult> results = new ArrayList<>();

        // 각 시나리오를 실제로 실행
        for (AttackScenario scenario : scenarios) {
            AttackRequest request = new AttackRequest();
            request.setStrategyName(scenario.getStrategyName());
            request.setTargetUser(scenario.getTargetUser());
            request.setTargetResource(scenario.getTargetResource());
            request.setSourceIp(scenario.getSourceIp() != null ? scenario.getSourceIp() : generateRandomIP());
            request.setMaxAttempts(scenario.getMaxAttempts() != null ? scenario.getMaxAttempts() : 10);
            request.setDelayMs(scenario.getDelayMs() != null ? scenario.getDelayMs() : 1000L);
            request.setStealthMode(scenario.isStealthMode());
            request.setParameters(scenario.getParameters());

            AttackResult attackResult = executeRealAttack(request);
            results.add(attackResult);

            // 시나리오 간 지연 시간 적용
            if (scenario.getDelayMs() != null && scenario.getDelayMs() > 0) {
                try {
                    Thread.sleep(scenario.getDelayMs());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    logger.warn("Campaign execution interrupted");
                    break;
                }
            }
        }

        result.setResults(results);
        result.setEndTime(LocalDateTime.now());
        result.calculateStatistics();

        return result;
    }
    
    // Request/Response DTOs
    
    public static class AttackRequest {
        private String strategyName;
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
    
    public static class AttackResponse {
        private String status;
        private boolean detected;
        private boolean blocked;
        private Double riskScore;
        private String riskLevel;
        private Long detectionTimeMs;
        private String summary;
        
        public AttackResponse(String status, boolean detected, boolean blocked, 
                            Double riskScore, String riskLevel, Long detectionTimeMs, String summary) {
            this.status = status;
            this.detected = detected;
            this.blocked = blocked;
            this.riskScore = riskScore;
            this.riskLevel = riskLevel;
            this.detectionTimeMs = detectionTimeMs;
            this.summary = summary;
        }
        
        // Getters
        public String getStatus() { return status; }
        public boolean isDetected() { return detected; }
        public boolean isBlocked() { return blocked; }
        public Double getRiskScore() { return riskScore; }
        public String getRiskLevel() { return riskLevel; }
        public Long getDetectionTimeMs() { return detectionTimeMs; }
        public String getSummary() { return summary; }
    }
    
    public static class StrategyInfo {
        private String name;
        private String type;
        private String category;
        private String description;
        
        public StrategyInfo(String name, String type, String category, String description) {
            this.name = name;
            this.type = type;
            this.category = category;
            this.description = description;
        }
        
        // Getters
        public String getName() { return name; }
        public String getType() { return type; }
        public String getCategory() { return category; }
        public String getDescription() { return description; }
    }
    
    public static class CampaignRequest {
        private List<ScenarioRequest> scenarios;
        
        public List<ScenarioRequest> getScenarios() { return scenarios; }
        public void setScenarios(List<ScenarioRequest> scenarios) { this.scenarios = scenarios; }
    }
    
    public static class ScenarioRequest {
        private String strategyName;
        private String targetUser;
        private String targetResource;
        
        // Getters and Setters
        public String getStrategyName() { return strategyName; }
        public void setStrategyName(String strategyName) { this.strategyName = strategyName; }
        
        public String getTargetUser() { return targetUser; }
        public void setTargetUser(String targetUser) { this.targetUser = targetUser; }
        
        public String getTargetResource() { return targetResource; }
        public void setTargetResource(String targetResource) { this.targetResource = targetResource; }
    }
    
    public static class CampaignResponse {
        private String campaignId;
        private String status;
        private String message;
        
        public CampaignResponse(String campaignId, String status, String message) {
            this.campaignId = campaignId;
            this.status = status;
            this.message = message;
        }
        
        // Getters
        public String getCampaignId() { return campaignId; }
        public String getStatus() { return status; }
        public String getMessage() { return message; }
    }
    
    public static class CampaignStatus {
        private String campaignId;
        private String status;
        private int totalScenarios;
        private int completedScenarios;
        private int successfulAttacks;
        private int detectedAttacks;
        private int blockedAttacks;
        private LocalDateTime startTime;
        private LocalDateTime endTime;
        private String errorMessage;
        
        // Getters and Setters
        public String getCampaignId() { return campaignId; }
        public void setCampaignId(String campaignId) { this.campaignId = campaignId; }
        
        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }
        
        public int getTotalScenarios() { return totalScenarios; }
        public void setTotalScenarios(int totalScenarios) { this.totalScenarios = totalScenarios; }
        
        public int getCompletedScenarios() { return completedScenarios; }
        public void setCompletedScenarios(int completedScenarios) { 
            this.completedScenarios = completedScenarios; 
        }
        
        public int getSuccessfulAttacks() { return successfulAttacks; }
        public void setSuccessfulAttacks(int successfulAttacks) { 
            this.successfulAttacks = successfulAttacks; 
        }
        
        public int getDetectedAttacks() { return detectedAttacks; }
        public void setDetectedAttacks(int detectedAttacks) { this.detectedAttacks = detectedAttacks; }
        
        public int getBlockedAttacks() { return blockedAttacks; }
        public void setBlockedAttacks(int blockedAttacks) { this.blockedAttacks = blockedAttacks; }
        
        public LocalDateTime getStartTime() { return startTime; }
        public void setStartTime(LocalDateTime startTime) { this.startTime = startTime; }
        
        public LocalDateTime getEndTime() { return endTime; }
        public void setEndTime(LocalDateTime endTime) { this.endTime = endTime; }
        
        public String getErrorMessage() { return errorMessage; }
        public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
    }
    
    public static class ParallelAttackRequest {
        private List<AttackRequest> attacks;
        
        public List<AttackRequest> getAttacks() { return attacks; }
        public void setAttacks(List<AttackRequest> attacks) { this.attacks = attacks; }
    }
    
    public static class ParallelAttackResponse {
        private int totalAttacks;
        private int successfulAttacks;
        private int detectedAttacks;
        private int blockedAttacks;
        private String message;
        
        public ParallelAttackResponse(int totalAttacks, int successfulAttacks, 
                                     int detectedAttacks, int blockedAttacks, String message) {
            this.totalAttacks = totalAttacks;
            this.successfulAttacks = successfulAttacks;
            this.detectedAttacks = detectedAttacks;
            this.blockedAttacks = blockedAttacks;
            this.message = message;
        }
        
        // Getters
        public int getTotalAttacks() { return totalAttacks; }
        public int getSuccessfulAttacks() { return successfulAttacks; }
        public int getDetectedAttacks() { return detectedAttacks; }
        public int getBlockedAttacks() { return blockedAttacks; }
        public String getMessage() { return message; }
    }
    
    public static class AdaptiveAttackRequest {
        private String targetUser;
        private int iterations;
        private String strategyName;
        private String targetResource;
        private String sourceIp;
        private Integer maxAttempts;
        private Long delayMs;
        private boolean stealthMode;
        private Map<String, Object> parameters;

        // Getters and Setters
        public String getTargetUser() { return targetUser; }
        public void setTargetUser(String targetUser) { this.targetUser = targetUser; }

        public int getIterations() { return iterations; }
        public void setIterations(int iterations) { this.iterations = iterations; }

        public String getStrategyName() { return strategyName; }
        public void setStrategyName(String strategyName) { this.strategyName = strategyName; }

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
    
    public static class AdaptiveAttackResponse {
        private int iterations;
        private int successfulIterations;
        private List<String> strategiesUsed;
        private String message;
        
        public AdaptiveAttackResponse(int iterations, int successfulIterations, 
                                     List<String> strategiesUsed, String message) {
            this.iterations = iterations;
            this.successfulIterations = successfulIterations;
            this.strategiesUsed = strategiesUsed;
            this.message = message;
        }
        
        // Getters
        public int getIterations() { return iterations; }
        public int getSuccessfulIterations() { return successfulIterations; }
        public List<String> getStrategiesUsed() { return strategiesUsed; }
        public String getMessage() { return message; }
    }
    
    public static class SimulationStatistics {
        private int totalCampaigns;
        private int runningCampaigns;
        private int completedCampaigns;
        private int totalStrategies;
        private Map<IAttackStrategy.AttackCategory, Integer> strategiesByCategory;
        
        // Getters and Setters
        public int getTotalCampaigns() { return totalCampaigns; }
        public void setTotalCampaigns(int totalCampaigns) { this.totalCampaigns = totalCampaigns; }
        
        public int getRunningCampaigns() { return runningCampaigns; }
        public void setRunningCampaigns(int runningCampaigns) { this.runningCampaigns = runningCampaigns; }
        
        public int getCompletedCampaigns() { return completedCampaigns; }
        public void setCompletedCampaigns(int completedCampaigns) { 
            this.completedCampaigns = completedCampaigns; 
        }
        
        public int getTotalStrategies() { return totalStrategies; }
        public void setTotalStrategies(int totalStrategies) { this.totalStrategies = totalStrategies; }
        
        public Map<IAttackStrategy.AttackCategory, Integer> getStrategiesByCategory() { 
            return strategiesByCategory; 
        }
        public void setStrategiesByCategory(Map<IAttackStrategy.AttackCategory, Integer> strategiesByCategory) {
            this.strategiesByCategory = strategiesByCategory;
        }
    }

    public static class DetailedStatistics {
        private Long totalAttacks;
        private Long successfulAttacks;
        private Long detectedAttacks;
        private Long blockedAttacks;
        private Double averageRiskScore;
        private Map<String, Long> attacksByType;
        private Map<String, Long> attacksByCategory;
        private Map<String, Double> successRateByType;
        private Map<String, Double> detectionRateByType;
        private Map<String, Long> threatDistribution;
        private Map<String, Long> recentTrends;
        private int totalCampaigns;
        private int runningCampaigns;
        private int completedCampaigns;

        // Getters and Setters
        public Long getTotalAttacks() { return totalAttacks; }
        public void setTotalAttacks(Long totalAttacks) { this.totalAttacks = totalAttacks; }

        public Long getSuccessfulAttacks() { return successfulAttacks; }
        public void setSuccessfulAttacks(Long successfulAttacks) { this.successfulAttacks = successfulAttacks; }

        public Long getDetectedAttacks() { return detectedAttacks; }
        public void setDetectedAttacks(Long detectedAttacks) { this.detectedAttacks = detectedAttacks; }

        public Long getBlockedAttacks() { return blockedAttacks; }
        public void setBlockedAttacks(Long blockedAttacks) { this.blockedAttacks = blockedAttacks; }

        public Double getAverageRiskScore() { return averageRiskScore; }
        public void setAverageRiskScore(Double averageRiskScore) { this.averageRiskScore = averageRiskScore; }

        public Map<String, Long> getAttacksByType() { return attacksByType; }
        public void setAttacksByType(Map<String, Long> attacksByType) { this.attacksByType = attacksByType; }

        public Map<String, Long> getAttacksByCategory() { return attacksByCategory; }
        public void setAttacksByCategory(Map<String, Long> attacksByCategory) { this.attacksByCategory = attacksByCategory; }

        public Map<String, Double> getSuccessRateByType() { return successRateByType; }
        public void setSuccessRateByType(Map<String, Double> successRateByType) { this.successRateByType = successRateByType; }

        public Map<String, Double> getDetectionRateByType() { return detectionRateByType; }
        public void setDetectionRateByType(Map<String, Double> detectionRateByType) { this.detectionRateByType = detectionRateByType; }

        public Map<String, Long> getThreatDistribution() { return threatDistribution; }
        public void setThreatDistribution(Map<String, Long> threatDistribution) { this.threatDistribution = threatDistribution; }

        public Map<String, Long> getRecentTrends() { return recentTrends; }
        public void setRecentTrends(Map<String, Long> recentTrends) { this.recentTrends = recentTrends; }

        public int getTotalCampaigns() { return totalCampaigns; }
        public void setTotalCampaigns(int totalCampaigns) { this.totalCampaigns = totalCampaigns; }

        public int getRunningCampaigns() { return runningCampaigns; }
        public void setRunningCampaigns(int runningCampaigns) { this.runningCampaigns = runningCampaigns; }

        public int getCompletedCampaigns() { return completedCampaigns; }
        public void setCompletedCampaigns(int completedCampaigns) { this.completedCampaigns = completedCampaigns; }
    }

    public static class AttackTypeStatistics {
        private String attackType;
        private Long totalCount;
        private Double successRate;
        private Double detectionRate;
        private Double averageRiskScore;
        private Map<String, Long> timeTrends;

        // Getters and Setters
        public String getAttackType() { return attackType; }
        public void setAttackType(String attackType) { this.attackType = attackType; }

        public Long getTotalCount() { return totalCount; }
        public void setTotalCount(Long totalCount) { this.totalCount = totalCount; }

        public Double getSuccessRate() { return successRate; }
        public void setSuccessRate(Double successRate) { this.successRate = successRate; }

        public Double getDetectionRate() { return detectionRate; }
        public void setDetectionRate(Double detectionRate) { this.detectionRate = detectionRate; }

        public Double getAverageRiskScore() { return averageRiskScore; }
        public void setAverageRiskScore(Double averageRiskScore) { this.averageRiskScore = averageRiskScore; }

        public Map<String, Long> getTimeTrends() { return timeTrends; }
        public void setTimeTrends(Map<String, Long> timeTrends) { this.timeTrends = timeTrends; }
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