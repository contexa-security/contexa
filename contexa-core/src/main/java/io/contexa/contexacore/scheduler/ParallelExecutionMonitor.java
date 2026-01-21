package io.contexa.contexacore.scheduler;

import lombok.extern.slf4j.Slf4j;

import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class ParallelExecutionMonitor {

    private final ConcurrentHashMap<String, Long> labStartTimes = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> labThreads = new ConcurrentHashMap<>();

    public void recordLabStart(String labName) {
        long startTime = System.currentTimeMillis();
        String threadName = Thread.currentThread().getName();

        labStartTimes.put(labName, startTime);
        labThreads.put(labName, threadName);

        labStartTimes.forEach((otherLab, otherStartTime) -> {
            if (!otherLab.equals(labName)) {
                long diff = Math.abs(startTime - otherStartTime);
                if (diff < 1000) { 
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
                    }
    }

    public void printExecutionSummary() {
                labThreads.forEach((lab, thread) -> {
            Long startTime = labStartTimes.get(lab);
                    });
    }

    public void recordLabError(String labName, Throwable error) {
        Long startTime = labStartTimes.get(labName);
        if (startTime != null) {
            long duration = System.currentTimeMillis() - startTime;
                    }
    }
}