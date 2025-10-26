package io.contexa.contexacore.dashboard.metrics.vectorstore;

import io.contexa.contexacore.dashboard.api.DomainMetrics;
import io.contexa.contexacore.dashboard.api.EventRecorder;
import io.contexa.contexacore.std.rag.service.AbstractVectorLabService;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 벡터 저장소 메트릭 수집 및 모니터링 시스템
 *
 * Lab별 벡터 저장소 사용 통계, 성능 메트릭, 에러 추적을 제공합니다.
 * 실시간 모니터링과 대시보드 데이터를 지원합니다.
 *
 * @since 1.0.0
 * @implNote VectorStoreMetrics는 특수 구조(ConcurrentHashMap, 내부 클래스)로 인해
 *           현재 패키지에 유지됩니다. 향후 리팩토링 시 metrics 패키지로 이동 예정.
 */
@Slf4j
@Component
public class VectorStoreMetrics implements DomainMetrics, EventRecorder {
    
    private final Map<String, LabMetrics> labMetrics = new ConcurrentHashMap<>();
    private final Map<String, List<ErrorRecord>> errorHistory = new ConcurrentHashMap<>();
    private final Map<String, List<PerformanceRecord>> performanceHistory = new ConcurrentHashMap<>();
    
    private static final int MAX_HISTORY_SIZE = 1000;
    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
    
    /**
     * Lab 작업 기록
     * 
     * @param labName Lab 이름
     * @param operationType 작업 타입
     * @param documentCount 처리된 문서 수
     * @param durationMs 소요 시간 (밀리초)
     */
    public void recordOperation(String labName, AbstractVectorLabService.OperationType operationType, 
                               int documentCount, long durationMs) {
        try {
            LabMetrics metrics = labMetrics.computeIfAbsent(labName, k -> new LabMetrics(labName));
            
            synchronized (metrics) {
                // 작업 통계 업데이트
                switch (operationType) {
                    case STORE:
                        metrics.getStoreOperations().incrementAndGet();
                        metrics.getStoredDocuments().addAndGet(documentCount);
                        metrics.getTotalStoreDuration().addAndGet(durationMs);
                        break;
                    case SEARCH:
                        metrics.getSearchOperations().incrementAndGet();
                        metrics.getSearchedDocuments().addAndGet(documentCount);
                        metrics.getTotalSearchDuration().addAndGet(durationMs);
                        break;
                    case UPDATE:
                        metrics.getUpdateOperations().incrementAndGet();
                        metrics.getUpdatedDocuments().addAndGet(documentCount);
                        metrics.getTotalUpdateDuration().addAndGet(durationMs);
                        break;
                    case DELETE:
                        metrics.getDeleteOperations().incrementAndGet();
                        metrics.getDeletedDocuments().addAndGet(documentCount);
                        metrics.getTotalDeleteDuration().addAndGet(durationMs);
                        break;
                }
                
                metrics.getTotalOperations().incrementAndGet();
                metrics.setLastOperationTime(LocalDateTime.now());
                
                // 평균 성능 업데이트
                updateAveragePerformance(metrics, operationType, durationMs);
            }
            
            // 성능 히스토리 기록
            recordPerformanceHistory(labName, operationType, documentCount, durationMs);
            
            log.debug("[{}] 작업 기록: {} - 문서 {}개, {}ms", 
                     labName, operationType, documentCount, durationMs);
            
        } catch (Exception e) {
            log.error("메트릭 기록 실패: Lab={}, 작업={}", labName, operationType, e);
        }
    }
    
    /**
     * 에러 기록
     * 
     * @param labName Lab 이름
     * @param operationType 작업 타입
     * @param error 발생한 에러
     */
    public void recordError(String labName, AbstractVectorLabService.OperationType operationType, 
                           Throwable error) {
        try {
            LabMetrics metrics = labMetrics.computeIfAbsent(labName, k -> new LabMetrics(labName));
            
            synchronized (metrics) {
                metrics.getErrorCount().incrementAndGet();
                metrics.setLastErrorTime(LocalDateTime.now());
            }
            
            // 에러 히스토리 기록
            ErrorRecord errorRecord = new ErrorRecord(
                LocalDateTime.now(),
                operationType,
                error.getClass().getSimpleName(),
                error.getMessage()
            );
            
            List<ErrorRecord> labErrors = errorHistory.computeIfAbsent(labName, k -> new CopyOnWriteArrayList<>());
            labErrors.add(errorRecord);

            // 히스토리 크기 제한 (lock-free)
            if (labErrors.size() > MAX_HISTORY_SIZE) {
                labErrors.remove(0);
            }
            
            log.error("[{}] 에러 기록: {} - {}", labName, operationType, error.getMessage());
            
        } catch (Exception e) {
            log.error("에러 메트릭 기록 실패: Lab={}, 작업={}", labName, operationType, e);
        }
    }
    
    /**
     * Lab별 통계 조회
     * 
     * @param labName Lab 이름
     * @return Lab 통계 정보
     */
    public Map<String, Object> getLabStatistics(String labName) {
        LabMetrics metrics = labMetrics.get(labName);
        if (metrics == null) {
            return Collections.emptyMap();
        }
        
        Map<String, Object> stats = new HashMap<>();
        
        synchronized (metrics) {
            // 기본 통계
            stats.put("labName", metrics.getLabName());
            stats.put("totalOperations", metrics.getTotalOperations().get());
            stats.put("errorCount", metrics.getErrorCount().get());
            stats.put("lastOperationTime", metrics.getLastOperationTime());
            stats.put("lastErrorTime", metrics.getLastErrorTime());
            
            // 작업별 통계
            stats.put("storeOperations", metrics.getStoreOperations().get());
            stats.put("searchOperations", metrics.getSearchOperations().get());
            stats.put("updateOperations", metrics.getUpdateOperations().get());
            stats.put("deleteOperations", metrics.getDeleteOperations().get());
            
            // 문서 수 통계
            stats.put("storedDocuments", metrics.getStoredDocuments().get());
            stats.put("searchedDocuments", metrics.getSearchedDocuments().get());
            stats.put("updatedDocuments", metrics.getUpdatedDocuments().get());
            stats.put("deletedDocuments", metrics.getDeletedDocuments().get());
            
            // 성능 통계
            stats.put("averageStoreTime", metrics.getAverageStoreTime());
            stats.put("averageSearchTime", metrics.getAverageSearchTime());
            stats.put("averageUpdateTime", metrics.getAverageUpdateTime());
            stats.put("averageDeleteTime", metrics.getAverageDeleteTime());
            
            // 에러율 계산
            long totalOps = metrics.getTotalOperations().get();
            double errorRate = totalOps > 0 ? (metrics.getErrorCount().get() * 100.0 / totalOps) : 0.0;
            stats.put("errorRate", String.format("%.2f%%", errorRate));
        }
        
        return stats;
    }
    
    /**
     * 전체 시스템 통계 조회
     * 
     * @return 전체 시스템 통계
     */
    public Map<String, Object> getSystemStatistics() {
        Map<String, Object> systemStats = new HashMap<>();
        
        long totalOperations = 0;
        long totalErrors = 0;
        long totalStoredDocuments = 0;
        long totalSearchedDocuments = 0;
        
        Map<String, Map<String, Object>> labStatsMap = new HashMap<>();
        
        for (Map.Entry<String, LabMetrics> entry : labMetrics.entrySet()) {
            String labName = entry.getKey();
            LabMetrics metrics = entry.getValue();
            
            synchronized (metrics) {
                totalOperations += metrics.getTotalOperations().get();
                totalErrors += metrics.getErrorCount().get();
                totalStoredDocuments += metrics.getStoredDocuments().get();
                totalSearchedDocuments += metrics.getSearchedDocuments().get();
            }
            
            labStatsMap.put(labName, getLabStatistics(labName));
        }
        
        systemStats.put("totalOperations", totalOperations);
        systemStats.put("totalErrors", totalErrors);
        systemStats.put("totalStoredDocuments", totalStoredDocuments);
        systemStats.put("totalSearchedDocuments", totalSearchedDocuments);
        systemStats.put("activeLabs", labMetrics.size());
        systemStats.put("systemErrorRate", 
                       totalOperations > 0 ? String.format("%.2f%%", totalErrors * 100.0 / totalOperations) : "0.00%");
        
        systemStats.put("labStatistics", labStatsMap);
        
        return systemStats;
    }
    
    /**
     * Lab 에러 히스토리 조회
     * 
     * @param labName Lab 이름
     * @param limit 조회할 최대 개수
     * @return 에러 히스토리
     */
    public List<ErrorRecord> getErrorHistory(String labName, int limit) {
        List<ErrorRecord> labErrors = errorHistory.get(labName);
        if (labErrors == null || labErrors.isEmpty()) {
            return Collections.emptyList();
        }

        // CopyOnWriteArrayList는 이미 thread-safe하므로 synchronized 불필요
        List<ErrorRecord> result = new ArrayList<>(labErrors);
        result.sort((a, b) -> b.getTimestamp().compareTo(a.getTimestamp())); // 최신순

        return limit > 0 && result.size() > limit ?
               result.subList(0, limit) : result;
    }
    
    /**
     * Lab 성능 히스토리 조회
     * 
     * @param labName Lab 이름
     * @param operationType 작업 타입 (선택적)
     * @param limit 조회할 최대 개수
     * @return 성능 히스토리
     */
    public List<PerformanceRecord> getPerformanceHistory(String labName, 
                                                        AbstractVectorLabService.OperationType operationType, 
                                                        int limit) {
        List<PerformanceRecord> labPerformance = performanceHistory.get(labName);
        if (labPerformance == null || labPerformance.isEmpty()) {
            return Collections.emptyList();
        }

        // CopyOnWriteArrayList는 이미 thread-safe하므로 synchronized 불필요
        List<PerformanceRecord> filtered = labPerformance.stream()
            .filter(record -> operationType == null || record.getOperationType() == operationType)
            .sorted((a, b) -> b.getTimestamp().compareTo(a.getTimestamp())) // 최신순
            .limit(limit > 0 ? limit : labPerformance.size())
            .toList();

        return new ArrayList<>(filtered);
    }
    
    /**
     * 대시보드용 요약 통계
     * 
     * @return 대시보드 데이터
     */
    public VectorStoreDashboard getDashboard() {
        Map<String, Object> systemStats = getSystemStatistics();
        List<LabSummary> labSummaries = new ArrayList<>();
        
        for (String labName : labMetrics.keySet()) {
            Map<String, Object> labStats = getLabStatistics(labName);
            
            LabSummary summary = new LabSummary();
            summary.setLabName(labName);
            summary.setTotalOperations((Long) labStats.get("totalOperations"));
            summary.setErrorCount((Long) labStats.get("errorCount"));
            summary.setStoredDocuments((Long) labStats.get("storedDocuments"));
            summary.setErrorRate((String) labStats.get("errorRate"));
            summary.setLastOperationTime((LocalDateTime) labStats.get("lastOperationTime"));
            
            labSummaries.add(summary);
        }
        
        // 활동량 기준 정렬
        labSummaries.sort((a, b) -> Long.compare(b.getTotalOperations(), a.getTotalOperations()));
        
        VectorStoreDashboard dashboard = new VectorStoreDashboard();
        dashboard.setSystemStatistics(systemStats);
        dashboard.setLabSummaries(labSummaries);
        dashboard.setGeneratedAt(LocalDateTime.now());
        
        return dashboard;
    }
    
    /**
     * 메트릭 초기화
     * 
     * @param labName Lab 이름 (null이면 전체 초기화)
     */
    public void resetMetrics(String labName) {
        if (labName == null) {
            labMetrics.clear();
            errorHistory.clear();
            performanceHistory.clear();
            log.info("전체 메트릭 초기화 완료");
        } else {
            labMetrics.remove(labName);
            errorHistory.remove(labName);
            performanceHistory.remove(labName);
            log.info("[{}] 메트릭 초기화 완료", labName);
        }
    }
    
    /**
     * 평균 성능 업데이트
     */
    private void updateAveragePerformance(LabMetrics metrics, 
                                        AbstractVectorLabService.OperationType operationType, 
                                        long durationMs) {
        switch (operationType) {
            case STORE:
                long storeOps = metrics.getStoreOperations().get();
                long totalStoreDuration = metrics.getTotalStoreDuration().get();
                metrics.setAverageStoreTime(storeOps > 0 ? totalStoreDuration / (double) storeOps : 0.0);
                break;
            case SEARCH:
                long searchOps = metrics.getSearchOperations().get();
                long totalSearchDuration = metrics.getTotalSearchDuration().get();
                metrics.setAverageSearchTime(searchOps > 0 ? totalSearchDuration / (double) searchOps : 0.0);
                break;
            case UPDATE:
                long updateOps = metrics.getUpdateOperations().get();
                long totalUpdateDuration = metrics.getTotalUpdateDuration().get();
                metrics.setAverageUpdateTime(updateOps > 0 ? totalUpdateDuration / (double) updateOps : 0.0);
                break;
            case DELETE:
                long deleteOps = metrics.getDeleteOperations().get();
                long totalDeleteDuration = metrics.getTotalDeleteDuration().get();
                metrics.setAverageDeleteTime(deleteOps > 0 ? totalDeleteDuration / (double) deleteOps : 0.0);
                break;
        }
    }
    
    /**
     * 성능 히스토리 기록
     */
    private void recordPerformanceHistory(String labName, 
                                        AbstractVectorLabService.OperationType operationType,
                                        int documentCount, long durationMs) {
        PerformanceRecord record = new PerformanceRecord(
            LocalDateTime.now(),
            operationType,
            documentCount,
            durationMs
        );
        
        List<PerformanceRecord> labPerformance = performanceHistory.computeIfAbsent(labName, k -> new CopyOnWriteArrayList<>());
        labPerformance.add(record);

        // 히스토리 크기 제한 (lock-free)
        if (labPerformance.size() > MAX_HISTORY_SIZE) {
            labPerformance.remove(0);
        }
    }
    
    /**
     * Lab별 메트릭 정보
     */
    @Data
    public static class LabMetrics {
        private final String labName;
        
        // 작업 통계
        private final AtomicLong totalOperations = new AtomicLong(0);
        private final AtomicLong storeOperations = new AtomicLong(0);
        private final AtomicLong searchOperations = new AtomicLong(0);
        private final AtomicLong updateOperations = new AtomicLong(0);
        private final AtomicLong deleteOperations = new AtomicLong(0);
        
        // 문서 수 통계
        private final AtomicLong storedDocuments = new AtomicLong(0);
        private final AtomicLong searchedDocuments = new AtomicLong(0);
        private final AtomicLong updatedDocuments = new AtomicLong(0);
        private final AtomicLong deletedDocuments = new AtomicLong(0);
        
        // 성능 통계
        private final AtomicLong totalStoreDuration = new AtomicLong(0);
        private final AtomicLong totalSearchDuration = new AtomicLong(0);
        private final AtomicLong totalUpdateDuration = new AtomicLong(0);
        private final AtomicLong totalDeleteDuration = new AtomicLong(0);
        
        private double averageStoreTime = 0.0;
        private double averageSearchTime = 0.0;
        private double averageUpdateTime = 0.0;
        private double averageDeleteTime = 0.0;
        
        // 에러 통계
        private final AtomicLong errorCount = new AtomicLong(0);
        
        // 시간 정보
        private LocalDateTime lastOperationTime;
        private LocalDateTime lastErrorTime;
        
        public LabMetrics(String labName) {
            this.labName = labName;
        }
    }
    
    /**
     * 에러 기록
     */
    @Data
    public static class ErrorRecord {
        private final LocalDateTime timestamp;
        private final AbstractVectorLabService.OperationType operationType;
        private final String errorType;
        private final String errorMessage;
    }
    
    /**
     * 성능 기록
     */
    @Data
    public static class PerformanceRecord {
        private final LocalDateTime timestamp;
        private final AbstractVectorLabService.OperationType operationType;
        private final int documentCount;
        private final long durationMs;
    }
    
    /**
     * Lab 요약 정보
     */
    @Data
    public static class LabSummary {
        private String labName;
        private Long totalOperations;
        private Long errorCount;
        private Long storedDocuments;
        private String errorRate;
        private LocalDateTime lastOperationTime;
    }
    
    /**
     * 대시보드 데이터
     */
    @Data
    public static class VectorStoreDashboard {
        private Map<String, Object> systemStatistics;
        private List<LabSummary> labSummaries;
        private LocalDateTime generatedAt;
    }

    // ===== MetricsCollector 인터페이스 구현 =====

    @Override
    public String getDomain() {
        return "vectorstore";
    }

    @Override
    public void initialize() {
        log.info("VectorStoreMetrics 초기화 완료");
    }

    @Override
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("total_labs", labMetrics.size());
        stats.put("total_operations", labMetrics.values().stream()
            .mapToLong(lm -> lm.getTotalOperations().get()).sum());
        stats.put("total_errors", errorHistory.values().stream()
            .mapToInt(List::size).sum());
        stats.put("health_score", getHealthScore());
        return stats;
    }

    @Override
    public void reset() {
        labMetrics.clear();
        errorHistory.clear();
        performanceHistory.clear();
        log.info("VectorStoreMetrics 리셋 완료");
    }

    // ===== DomainMetrics 인터페이스 구현 =====

    @Override
    public double getHealthScore() {
        if (labMetrics.isEmpty()) return 1.0;

        double avgSuccessRate = labMetrics.values().stream()
            .mapToDouble(lm -> {
                long total = lm.getTotalOperations().get();
                long errors = lm.getErrorCount().get();
                return total > 0 ? (total - errors) / (double) total : 1.0;
            })
            .average()
            .orElse(1.0);

        return avgSuccessRate;
    }

    @Override
    public Map<String, Double> getKeyMetrics() {
        Map<String, Double> metrics = new HashMap<>();
        metrics.put("total_labs", (double) labMetrics.size());
        metrics.put("total_operations", (double) labMetrics.values().stream()
            .mapToLong(lm -> lm.getTotalOperations().get()).sum());
        metrics.put("success_rate", getHealthScore());
        return metrics;
    }

    // ===== EventRecorder 인터페이스 구현 =====

    @Override
    public void recordEvent(String eventType, Map<String, Object> metadata) {
        String labName = metadata.containsKey("labName") ?
            (String) metadata.get("labName") : "unknown";
        AbstractVectorLabService.OperationType opType = metadata.containsKey("operationType") ?
            (AbstractVectorLabService.OperationType) metadata.get("operationType") :
            AbstractVectorLabService.OperationType.SEARCH;

        switch (eventType) {
            case "operation":
                int documentCount = metadata.containsKey("documentCount") ?
                    ((Number) metadata.get("documentCount")).intValue() : 0;
                long durationMs = metadata.containsKey("durationMs") ?
                    ((Number) metadata.get("durationMs")).longValue() : 0L;
                recordOperation(labName, opType, documentCount, durationMs);
                break;
            case "error":
                Throwable error = metadata.containsKey("error") ?
                    (Throwable) metadata.get("error") : new RuntimeException("Unknown error");
                recordError(labName, opType, error);
                break;
            default:
                log.warn("Unknown event type: {}", eventType);
        }
    }

    @Override
    public void recordDuration(String operationName, long durationNanos) {
        // VectorStoreMetrics는 자체 recordOperation 메서드 사용
        log.debug("Duration recorded: {} ns", durationNanos);
    }
}