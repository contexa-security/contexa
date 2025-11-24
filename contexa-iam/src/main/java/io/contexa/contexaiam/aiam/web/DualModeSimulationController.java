package io.contexa.contexaiam.aiam.web;

import io.contexa.contexacore.domain.entity.AttackResult;
import io.contexa.contexacore.simulation.event.SimulationProcessingCompleteEvent;
import io.contexa.contexacore.simulation.orchestrator.SimulationOrchestrator;
import io.contexa.contexacore.simulation.factory.AttackStrategyFactory;
import io.contexa.contexacore.repository.SimulationResultRepository;
import io.contexa.contexacore.domain.entity.SimulationResult;
import io.contexa.contexacore.simulation.strategy.IAttackStrategy;
import io.contexa.contexacore.simulation.strategy.IAttackStrategy.AttackContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 무방비 vs 방어 모드 시뮬레이션 컨트롤러
 *
 * 동일한 공격에 대해 무방비 모드와 방어 모드를 실행하여
 * 보안 시스템의 효과를 비교 분석할 수 있는 API를 제공합니다.
 *
 * @author contexa
 * @since 1.0.0
 */
@RequestMapping("/api/simulation/dual-mode")
@CrossOrigin(origins = "*")
@RequiredArgsConstructor
@Slf4j
public class DualModeSimulationController {

    private final SimulationOrchestrator orchestrator;
    private final AttackStrategyFactory strategyFactory;
    private final SimulationResultRepository simulationResultRepository;

    // 실행 중인 비교 시뮬레이션 관리
    private final Map<String, ComparisonStatus> runningComparisons = new ConcurrentHashMap<>();

    /**
     * 무방비 vs 방어 모드 비교 시뮬레이션 실행
     *
     * @param request 비교 시뮬레이션 요청
     * @return 시뮬레이션 실행 결과
     */
    @PostMapping("/execute")
    public ResponseEntity<Map<String, Object>> executeComparison(@RequestBody ComparisonRequest request) {
        try {
            String comparisonId = "comparison-" + UUID.randomUUID().toString();

            log.info("Starting dual-mode simulation comparison - comparisonId: {}, attackType: {}, targetCount: {}",
                    comparisonId, request.getAttackType(), request.getTargetUserCount());

            // 비교 상태 초기화
            ComparisonStatus status = new ComparisonStatus();
            status.setComparisonId(comparisonId);
            status.setAttackType(request.getAttackType());
            status.setTargetUserCount(request.getTargetUserCount());
            status.setStartedAt(LocalDateTime.now());
            status.setStatus("RUNNING");
            runningComparisons.put(comparisonId, status);

            // 비동기로 무방비/방어 모드 시뮬레이션 실행
            CompletableFuture.runAsync(() -> {
                executeUnprotectedMode(comparisonId, request);
                executeProtectedMode(comparisonId, request);
                completeComparison(comparisonId);
            });

            Map<String, Object> response = new HashMap<>();
            response.put("comparisonId", comparisonId);
            response.put("status", "STARTED");
            response.put("message", "Dual-mode simulation started");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Failed to start dual-mode simulation", e);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "Failed to start simulation: " + e.getMessage());
            return ResponseEntity.internalServerError().body(errorResponse);
        }
    }

    /**
     * 비교 시뮬레이션 상태 조회
     *
     * @param comparisonId 비교 시뮬레이션 ID
     * @return 시뮬레이션 상태 및 진행률
     */
    @GetMapping("/status/{comparisonId}")
    public ResponseEntity<Map<String, Object>> getComparisonStatus(@PathVariable String comparisonId) {
        ComparisonStatus status = runningComparisons.get(comparisonId);

        if (status == null) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "Comparison not found");
            return ResponseEntity.notFound().build();
        }

        Map<String, Object> response = new HashMap<>();
        response.put("comparisonId", comparisonId);
        response.put("status", status.getStatus());
        response.put("attackType", status.getAttackType());
        response.put("startedAt", status.getStartedAt());
        response.put("unprotectedProgress", status.getUnprotectedProgress());
        response.put("protectedProgress", status.getProtectedProgress());
        response.put("completedAt", status.getCompletedAt());

        return ResponseEntity.ok(response);
    }

    /**
     * 비교 시뮬레이션 결과 조회
     *
     * @param comparisonId 비교 시뮬레이션 ID
     * @return 무방비 vs 방어 모드 비교 결과
     */
    @GetMapping("/results/{comparisonId}")
    public ResponseEntity<Map<String, Object>> getComparisonResults(@PathVariable String comparisonId) {
        try {
            // comparisonId에 해당하는 시뮬레이션 결과들 조회
            List<SimulationResult> unprotectedResults = simulationResultRepository
                    .findByAttackIdAndSimulationMode(comparisonId,
                            SimulationProcessingCompleteEvent.SimulationMode.UNPROTECTED)
                    .map(List::of)
                    .orElse(new ArrayList<>());

            List<SimulationResult> protectedResults = simulationResultRepository
                    .findByAttackIdAndSimulationMode(comparisonId,
                            SimulationProcessingCompleteEvent.SimulationMode.PROTECTED)
                    .map(List::of)
                    .orElse(new ArrayList<>());

            // 결과 분석 및 통계 계산
            Map<String, Object> comparison = analyzeComparisonResults(unprotectedResults, protectedResults);
            comparison.put("comparisonId", comparisonId);

            return ResponseEntity.ok(comparison);

        } catch (Exception e) {
            log.error("Failed to get comparison results for: {}", comparisonId, e);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "Failed to get results: " + e.getMessage());
            return ResponseEntity.internalServerError().body(errorResponse);
        }
    }

    /**
     * 공격 타입별 비교 통계 조회
     *
     * @param attackType 공격 타입 (선택사항)
     * @return 공격 타입별 통계
     */
    @GetMapping("/statistics")
    public ResponseEntity<Map<String, Object>> getComparisonStatistics(
            @RequestParam(required = false) String attackType) {
        try {
            Map<String, Object> statistics = new HashMap<>();

            if (attackType != null) {
                // 특정 공격 타입 통계
                double unprotectedDetectionRate = simulationResultRepository
                        .getDetectionRateByAttackType(attackType,
                                SimulationProcessingCompleteEvent.SimulationMode.UNPROTECTED);
                double protectedDetectionRate = simulationResultRepository
                        .getDetectionRateByAttackType(attackType,
                                SimulationProcessingCompleteEvent.SimulationMode.PROTECTED);

                double unprotectedBlockingRate = simulationResultRepository
                        .getBlockingRateByAttackType(attackType,
                                SimulationProcessingCompleteEvent.SimulationMode.UNPROTECTED);
                double protectedBlockingRate = simulationResultRepository
                        .getBlockingRateByAttackType(attackType,
                                SimulationProcessingCompleteEvent.SimulationMode.PROTECTED);

                statistics.put("attackType", attackType);
                statistics.put("unprotected", Map.of(
                        "detectionRate", unprotectedDetectionRate,
                        "blockingRate", unprotectedBlockingRate
                ));
                statistics.put("protected", Map.of(
                        "detectionRate", protectedDetectionRate,
                        "blockingRate", protectedBlockingRate
                ));
                statistics.put("improvement", Map.of(
                        "detectionImprovement", protectedDetectionRate - unprotectedDetectionRate,
                        "blockingImprovement", protectedBlockingRate - unprotectedBlockingRate
                ));
            } else {
                // 전체 통계 (구현 필요시 추가)
                statistics.put("message", "Overall statistics not yet implemented");
            }

            return ResponseEntity.ok(statistics);

        } catch (Exception e) {
            log.error("Failed to get comparison statistics", e);
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "Failed to get statistics: " + e.getMessage());
            return ResponseEntity.internalServerError().body(errorResponse);
        }
    }

    /**
     * 무방비 모드 시뮬레이션 실행
     */
    private void executeUnprotectedMode(String comparisonId, ComparisonRequest request) {
        try {
            log.info("Executing unprotected mode simulation - comparisonId: {}", comparisonId);

            ComparisonStatus status = runningComparisons.get(comparisonId);
            status.setUnprotectedProgress("RUNNING");

            // 무방비 모드에서 공격 실행
            IAttackStrategy strategy = strategyFactory.createStrategy(request.getAttackType());

            for (int i = 0; i < request.getTargetUserCount(); i++) {
                String attackId = comparisonId + "-unprotected-" + i;
                String targetUser = "user-" + i;

                // SimulationModeHolder에 무방비 모드 설정
                io.contexa.contexacore.simulation.context.SimulationModeHolder.setContext(
                    new io.contexa.contexacore.simulation.context.SimulationModeHolder.SimulationContext(
                        io.contexa.contexacore.simulation.context.SimulationModeHolder.Mode.UNPROTECTED,
                        comparisonId,
                        attackId
                    )
                );

                AttackContext context = new AttackContext();
                context.setAttackId(attackId);
                context.setTargetUser(targetUser);
                context.setSourceIp("192.168.1." + (100 + i));
                context.setUserAgent("SimulationAgent/1.0");
                context.setSessionId("session-" + UUID.randomUUID());
                context.setCampaignId(comparisonId);

                // metadata를 parameters로 설정
                Map<String, Object> parameters = new HashMap<>();
                parameters.put("simulationMode", "UNPROTECTED");
                parameters.put("comparisonId", comparisonId);
                parameters.put("attackType", request.getAttackType());
                context.setParameters(parameters);

                // 무방비 모드로 공격 실행 (보안 시스템 비활성화)
                AttackResult result = strategy.execute(context);

                // 결과 로깅
                log.debug("Unprotected attack completed - attackId: {}, detected: {}, blocked: {}",
                        attackId, result.isDetected(), result.isBlocked());
            }

            status.setUnprotectedProgress("COMPLETED");
            log.info("Unprotected mode simulation completed - comparisonId: {}", comparisonId);

        } catch (Exception e) {
            log.error("Failed to execute unprotected mode simulation", e);
            ComparisonStatus status = runningComparisons.get(comparisonId);
            if (status != null) {
                status.setUnprotectedProgress("FAILED");
            }
        } finally {
            // SimulationModeHolder 정리
            io.contexa.contexacore.simulation.context.SimulationModeHolder.clear();
        }
    }

    /**
     * 방어 모드 시뮬레이션 실행
     */
    private void executeProtectedMode(String comparisonId, ComparisonRequest request) {
        try {
            log.info("Executing protected mode simulation - comparisonId: {}", comparisonId);

            ComparisonStatus status = runningComparisons.get(comparisonId);
            status.setProtectedProgress("RUNNING");

            // 방어 모드에서 공격 실행
            IAttackStrategy strategy = strategyFactory.createStrategy(request.getAttackType());

            for (int i = 0; i < request.getTargetUserCount(); i++) {
                String attackId = comparisonId + "-protected-" + i;
                String targetUser = "user-" + i;

                // SimulationModeHolder에 방어 모드 설정
                io.contexa.contexacore.simulation.context.SimulationModeHolder.setContext(
                    new io.contexa.contexacore.simulation.context.SimulationModeHolder.SimulationContext(
                        io.contexa.contexacore.simulation.context.SimulationModeHolder.Mode.PROTECTED,
                        comparisonId,
                        attackId
                    )
                );

                AttackContext context = new AttackContext();
                context.setAttackId(attackId);
                context.setTargetUser(targetUser);
                context.setSourceIp("192.168.1." + (100 + i));
                context.setUserAgent("SimulationAgent/1.0");
                context.setSessionId("session-" + UUID.randomUUID());
                context.setCampaignId(comparisonId);

                // metadata를 parameters로 설정
                Map<String, Object> parameters = new HashMap<>();
                parameters.put("simulationMode", "PROTECTED");
                parameters.put("comparisonId", comparisonId);
                parameters.put("attackType", request.getAttackType());
                context.setParameters(parameters);

                // 방어 모드로 공격 실행 (보안 시스템 활성화)
                AttackResult result = strategy.execute(context);

                // 결과 로깅
                log.debug("Protected attack completed - attackId: {}, detected: {}, blocked: {}",
                        attackId, result.isDetected(), result.isBlocked());
            }

            status.setProtectedProgress("COMPLETED");
            log.info("Protected mode simulation completed - comparisonId: {}", comparisonId);

        } catch (Exception e) {
            log.error("Failed to execute protected mode simulation", e);
            ComparisonStatus status = runningComparisons.get(comparisonId);
            if (status != null) {
                status.setProtectedProgress("FAILED");
            }
        } finally {
            // SimulationModeHolder 정리
            io.contexa.contexacore.simulation.context.SimulationModeHolder.clear();
        }
    }

    /**
     * 비교 시뮬레이션 완료 처리
     */
    private void completeComparison(String comparisonId) {
        try {
            ComparisonStatus status = runningComparisons.get(comparisonId);
            if (status != null &&
                "COMPLETED".equals(status.getUnprotectedProgress()) &&
                "COMPLETED".equals(status.getProtectedProgress())) {

                status.setStatus("COMPLETED");
                status.setCompletedAt(LocalDateTime.now());

                log.info("Dual-mode simulation comparison completed - comparisonId: {}", comparisonId);
            }
        } catch (Exception e) {
            log.error("Failed to complete comparison: {}", comparisonId, e);
        }
    }

    /**
     * 비교 결과 분석
     */
    private Map<String, Object> analyzeComparisonResults(
            List<SimulationResult> unprotectedResults,
            List<SimulationResult> protectedResults) {

        Map<String, Object> analysis = new HashMap<>();

        // 무방비 모드 통계
        Map<String, Object> unprotectedStats = calculateStats(unprotectedResults);
        analysis.put("unprotected", unprotectedStats);

        // 방어 모드 통계
        Map<String, Object> protectedStats = calculateStats(protectedResults);
        analysis.put("protected", protectedStats);

        // 개선 효과 계산
        double detectionImprovement = (Double) protectedStats.get("detectionRate") -
                                    (Double) unprotectedStats.get("detectionRate");
        double blockingImprovement = (Double) protectedStats.get("blockingRate") -
                                   (Double) unprotectedStats.get("blockingRate");

        Map<String, Object> improvement = new HashMap<>();
        improvement.put("detectionImprovement", detectionImprovement);
        improvement.put("blockingImprovement", blockingImprovement);
        improvement.put("overallImprovement", (detectionImprovement + blockingImprovement) / 2);

        analysis.put("improvement", improvement);
        analysis.put("summary", createSummary(unprotectedStats, protectedStats, improvement));

        return analysis;
    }

    /**
     * 시뮬레이션 결과 통계 계산
     */
    private Map<String, Object> calculateStats(List<SimulationResult> results) {
        Map<String, Object> stats = new HashMap<>();

        if (results.isEmpty()) {
            stats.put("totalCount", 0);
            stats.put("detectionRate", 0.0);
            stats.put("blockingRate", 0.0);
            stats.put("averageProcessingTime", 0.0);
            return stats;
        }

        int totalCount = results.size();
        long detectedCount = results.stream().mapToLong(r -> r.isDetected() ? 1 : 0).sum();
        long blockedCount = results.stream().mapToLong(r -> r.isBlocked() ? 1 : 0).sum();
        double avgProcessingTime = results.stream()
                .mapToDouble(r -> r.getProcessingTimeMs())
                .average()
                .orElse(0.0);

        stats.put("totalCount", totalCount);
        stats.put("detectedCount", detectedCount);
        stats.put("blockedCount", blockedCount);
        stats.put("detectionRate", (double) detectedCount / totalCount);
        stats.put("blockingRate", (double) blockedCount / totalCount);
        stats.put("averageProcessingTime", avgProcessingTime);

        return stats;
    }

    /**
     * 비교 요약 생성
     */
    private String createSummary(Map<String, Object> unprotectedStats,
                                Map<String, Object> protectedStats,
                                Map<String, Object> improvement) {
        double detectionImprovement = (Double) improvement.get("detectionImprovement");
        double blockingImprovement = (Double) improvement.get("blockingImprovement");

        StringBuilder summary = new StringBuilder();
        summary.append("보안 시스템 적용 결과: ");

        if (detectionImprovement > 0) {
            summary.append(String.format("탐지율 %.1f%% 향상, ", detectionImprovement * 100));
        }

        if (blockingImprovement > 0) {
            summary.append(String.format("차단율 %.1f%% 향상", blockingImprovement * 100));
        }

        if (detectionImprovement <= 0 && blockingImprovement <= 0) {
            summary.append("개선 효과가 미미함");
        }

        return summary.toString();
    }

    /**
     * 비교 시뮬레이션 요청 DTO
     */
    public static class ComparisonRequest {
        private String attackType;
        private int targetUserCount = 10;
        private Map<String, Object> attackParams;

        // Getters and Setters
        public String getAttackType() { return attackType; }
        public void setAttackType(String attackType) { this.attackType = attackType; }

        public int getTargetUserCount() { return targetUserCount; }
        public void setTargetUserCount(int targetUserCount) { this.targetUserCount = targetUserCount; }

        public Map<String, Object> getAttackParams() { return attackParams; }
        public void setAttackParams(Map<String, Object> attackParams) { this.attackParams = attackParams; }
    }

    /**
     * 비교 시뮬레이션 상태 관리
     */
    private static class ComparisonStatus {
        private String comparisonId;
        private String attackType;
        private int targetUserCount;
        private LocalDateTime startedAt;
        private LocalDateTime completedAt;
        private String status = "INITIALIZING";
        private String unprotectedProgress = "PENDING";
        private String protectedProgress = "PENDING";

        // Getters and Setters
        public String getComparisonId() { return comparisonId; }
        public void setComparisonId(String comparisonId) { this.comparisonId = comparisonId; }

        public String getAttackType() { return attackType; }
        public void setAttackType(String attackType) { this.attackType = attackType; }

        public int getTargetUserCount() { return targetUserCount; }
        public void setTargetUserCount(int targetUserCount) { this.targetUserCount = targetUserCount; }

        public LocalDateTime getStartedAt() { return startedAt; }
        public void setStartedAt(LocalDateTime startedAt) { this.startedAt = startedAt; }

        public LocalDateTime getCompletedAt() { return completedAt; }
        public void setCompletedAt(LocalDateTime completedAt) { this.completedAt = completedAt; }

        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }

        public String getUnprotectedProgress() { return unprotectedProgress; }
        public void setUnprotectedProgress(String unprotectedProgress) { this.unprotectedProgress = unprotectedProgress; }

        public String getProtectedProgress() { return protectedProgress; }
        public void setProtectedProgress(String protectedProgress) { this.protectedProgress = protectedProgress; }
    }
}
