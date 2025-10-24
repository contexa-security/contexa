package io.contexa.contexaiam.aiam.web;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * VectorStore 메트릭 모니터링 컨트롤러
 *
 * aicore 모듈의 SecurityVectorStoreObservationConvention이 수집한
 * VectorStore 메트릭을 관리자 UI에서 볼 수 있도록 제공합니다.
 *
 * 기능:
 * - 실시간 VectorStore 작업 모니터링
 * - 문서 타입별 사용량 통계
 * - 성능 메트릭 (응답 시간, 처리량)
 * - 에러율 추적
 *
 * @since 1.0.0
 */
@Slf4j
@Controller
@RequestMapping("/admin/vectorstore-metrics")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
public class VectorStoreMetricsController {

    private final MeterRegistry meterRegistry;

    /**
     * VectorStore 메트릭 모니터링 페이지
     *
     * @param model Spring MVC Model
     * @return vectorstore-metrics.html 뷰
     */
    @GetMapping
    public String metricsPage(Model model) {
        model.addAttribute("pageTitle", "VectorStore 모니터링");
        return "admin/vectorstore-metrics";
    }

    /**
     * 현재 메트릭 조회 API
     *
     * Chart.js에서 5초마다 폴링하여 실시간 업데이트
     *
     * @return 현재 메트릭 데이터
     */
    @GetMapping("/api/current")
    @ResponseBody
    public VectorStoreMetricsDto getCurrentMetrics() {
        VectorStoreMetricsDto dto = new VectorStoreMetricsDto();
        dto.setTimestamp(Instant.now());

        // 작업 타입별 통계
        dto.setOperationStats(getOperationStats());

        // 문서 타입별 통계
        dto.setDocumentTypeStats(getDocumentTypeStats());

        // 성능 메트릭
        dto.setPerformanceMetrics(getPerformanceMetrics());

        // 에러율
        dto.setErrorRate(getErrorRate());

        return dto;
    }

    /**
     * 시계열 데이터 조회 API
     *
     * @param range 조회 범위 (1h, 6h, 24h, 7d)
     * @return 시계열 메트릭 데이터
     */
    @GetMapping("/api/history")
    @ResponseBody
    public List<VectorStoreHistoryDto> getHistory(
            @RequestParam(defaultValue = "1h") String range) {

        // TODO: Redis나 InfluxDB에 시계열 데이터 저장 후 조회
        // 현재는 Micrometer의 현재 상태만 반환
        log.warn("History API not yet implemented. Returning current snapshot only.");

        VectorStoreHistoryDto snapshot = new VectorStoreHistoryDto();
        snapshot.setTimestamp(Instant.now());
        snapshot.setTotalOperations(getTotalOperations());
        snapshot.setAverageResponseTime(getAverageResponseTime());
        snapshot.setErrorCount(getErrorCount());

        return Collections.singletonList(snapshot);
    }

    /**
     * 최근 에러 조회 API
     *
     * @return 최근 에러 목록
     */
    @GetMapping("/api/errors")
    @ResponseBody
    public List<VectorStoreErrorDto> getRecentErrors() {
        // TODO: 에러 로그를 별도 저장하여 조회
        // 현재는 에러 카운트만 반환
        log.warn("Error details API not yet implemented. Returning error counts only.");

        List<VectorStoreErrorDto> errors = new ArrayList<>();

        meterRegistry.getMeters().stream()
            .filter(meter -> meter.getId().getName().contains("vector.store"))
            .filter(meter -> "failure".equals(meter.getId().getTag("status")))
            .forEach(meter -> {
                VectorStoreErrorDto error = new VectorStoreErrorDto();
                error.setTimestamp(Instant.now());
                error.setOperation(meter.getId().getTag("operation"));
                error.setDocumentType(meter.getId().getTag("document.type"));
                error.setErrorType("Unknown"); // 실제로는 메타데이터에서 가져와야 함
                error.setCount(getCounterValue(meter.getId().getName(), meter.getId().getTags()));
                errors.add(error);
            });

        return errors;
    }

    // ========== 내부 메서드 ==========

    /**
     * 작업 타입별 통계
     */
    private Map<String, Long> getOperationStats() {
        Map<String, Long> stats = new HashMap<>();

        stats.put("QUERY", getCounterValue("vector.store.operation", "operation", "QUERY"));
        stats.put("ADD", getCounterValue("vector.store.operation", "operation", "ADD"));
        stats.put("DELETE", getCounterValue("vector.store.operation", "operation", "DELETE"));

        return stats;
    }

    /**
     * 문서 타입별 통계
     */
    private Map<String, Long> getDocumentTypeStats() {
        Map<String, Long> stats = new HashMap<>();

        stats.put("threat", getCounterValue("vector.store.operation", "document.type", "threat"));
        stats.put("behavior", getCounterValue("vector.store.operation", "document.type", "behavior"));
        stats.put("risk_assessment", getCounterValue("vector.store.operation", "document.type", "risk_assessment"));
        stats.put("policy", getCounterValue("vector.store.operation", "document.type", "policy"));
        stats.put("unknown", getCounterValue("vector.store.operation", "document.type", "unknown"));

        return stats;
    }

    /**
     * 성능 메트릭
     */
    private PerformanceMetricsDto getPerformanceMetrics() {
        PerformanceMetricsDto metrics = new PerformanceMetricsDto();

        // VectorStore 작업 Timer 조회
        Timer timer = meterRegistry.find("vector.store.operation").timer();

        if (timer != null) {
            metrics.setAverageResponseTime(timer.mean(TimeUnit.MILLISECONDS));
            metrics.setMaxResponseTime(timer.max(TimeUnit.MILLISECONDS));
            metrics.setTotalOperations(timer.count());

            // P95, P99는 histogram이 활성화되어 있어야 함
            // 현재는 평균값만 제공
            metrics.setP95ResponseTime(timer.mean(TimeUnit.MILLISECONDS) * 1.5); // 추정값
            metrics.setP99ResponseTime(timer.max(TimeUnit.MILLISECONDS) * 0.8); // 추정값
        }

        return metrics;
    }

    /**
     * 에러율 계산
     */
    private double getErrorRate() {
        long totalOps = getTotalOperations();
        long errorOps = getErrorCount();

        if (totalOps == 0) {
            return 0.0;
        }

        return (double) errorOps / totalOps * 100;
    }

    /**
     * Counter 값 조회 (태그 없음)
     */
    private long getCounterValue(String name, String tagKey, String tagValue) {
        Counter counter = meterRegistry.find(name)
            .tag(tagKey, tagValue)
            .counter();

        return counter != null ? (long) counter.count() : 0L;
    }

    /**
     * Counter 값 조회 (다중 태그)
     */
    private long getCounterValue(String name, List<io.micrometer.core.instrument.Tag> tags) {
        Counter counter = meterRegistry.find(name)
            .tags(tags)
            .counter();

        return counter != null ? (long) counter.count() : 0L;
    }

    /**
     * 전체 작업 수
     */
    private long getTotalOperations() {
        Timer timer = meterRegistry.find("vector.store.operation").timer();
        return timer != null ? timer.count() : 0L;
    }

    /**
     * 평균 응답 시간
     */
    private double getAverageResponseTime() {
        Timer timer = meterRegistry.find("vector.store.operation").timer();
        return timer != null ? timer.mean(TimeUnit.MILLISECONDS) : 0.0;
    }

    /**
     * 에러 개수
     */
    private long getErrorCount() {
        return getCounterValue("vector.store.operation", "status", "failure");
    }

    // ========== DTO 클래스 ==========

    @Data
    public static class VectorStoreMetricsDto {
        private Instant timestamp;
        private Map<String, Long> operationStats;
        private Map<String, Long> documentTypeStats;
        private PerformanceMetricsDto performanceMetrics;
        private double errorRate;
    }

    @Data
    public static class PerformanceMetricsDto {
        private double averageResponseTime;
        private double p95ResponseTime;
        private double p99ResponseTime;
        private double maxResponseTime;
        private long totalOperations;
    }

    @Data
    public static class VectorStoreHistoryDto {
        private Instant timestamp;
        private long totalOperations;
        private double averageResponseTime;
        private long errorCount;
    }

    @Data
    public static class VectorStoreErrorDto {
        private Instant timestamp;
        private String operation;
        private String documentType;
        private String errorType;
        private String errorMessage;
        private long count;
    }
}
