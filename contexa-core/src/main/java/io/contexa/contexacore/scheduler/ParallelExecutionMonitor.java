package io.contexa.contexacore.scheduler;

// ParallelExecutionMonitor.java - 병렬 실행 모니터링

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;

@Component
@Slf4j
public class ParallelExecutionMonitor {

    private final ConcurrentHashMap<String, Long> labStartTimes = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> labThreads = new ConcurrentHashMap<>();

    public void recordLabStart(String labName) {
        long startTime = System.currentTimeMillis();
        String threadName = Thread.currentThread().getName();

        labStartTimes.put(labName, startTime);
        labThreads.put(labName, threadName);

        log.info("🏁 [PARALLEL-MONITOR] {} 시작 - 스레드: {} - 시간: {}",
                labName, threadName, startTime);

        // 다른 Lab들 과의 시간 차이 계산
        labStartTimes.forEach((otherLab, otherStartTime) -> {
            if (!otherLab.equals(labName)) {
                long diff = Math.abs(startTime - otherStartTime);
                if (diff < 1000) { // 1초 이내 차이
                    log.info("[PARALLEL-MONITOR] {} 와 {} 병렬 실행 중 ({}ms 차이)",
                            labName, otherLab, diff);
                } else {
                    log.warn("[PARALLEL-MONITOR] {} 와 {} 순차 실행 의심 ({}ms 차이)",
                            labName, otherLab, diff);
                }
            }
        });
    }

    public void recordLabComplete(String labName) {
        Long startTime = labStartTimes.get(labName);
        if (startTime != null) {
            long duration = System.currentTimeMillis() - startTime;
            log.info("🏁 [PARALLEL-MONITOR] {} 완료 - 소요시간: {}ms", labName, duration);
        }
    }

    public void printExecutionSummary() {
        log.info("[PARALLEL-MONITOR] 실행 요약:");
        labThreads.forEach((lab, thread) -> {
            Long startTime = labStartTimes.get(lab);
            log.info("  - {}: {} (시작: {})", lab, thread, startTime);
        });
    }

    public void recordLabError(String labName, Throwable error) {
        Long startTime = labStartTimes.get(labName);
        if (startTime != null) {
            long duration = System.currentTimeMillis() - startTime;
            log.info("🏁 [PARALLEL-MONITOR] {} 오류 - 소요시간: {}ms", labName, duration);
        }
    }
}