package io.contexa.contexacore.autonomous.monitor;

import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.repository.PolicyProposalRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;


@Slf4j
@RequiredArgsConstructor
public class PolicyEffectivenessMonitor {
    
    private final PolicyProposalRepository proposalRepository;
    
    
    private final Map<Long, PolicyMetrics> metricsStore = new ConcurrentHashMap<>();
    
    
    private final Map<Long, PerformanceData> performanceData = new ConcurrentHashMap<>();
    
    
    public void startMonitoring(Long proposalId) {
        log.info("Starting effectiveness monitoring for proposal: {}", proposalId);
        
        PolicyMetrics metrics = PolicyMetrics.builder()
            .proposalId(proposalId)
            .startTime(LocalDateTime.now())
            .status(MonitoringStatus.ACTIVE)
            .measurements(new ArrayList<>())
            .build();
        
        metricsStore.put(proposalId, metrics);
        
        
        establishBaseline(proposalId);
    }
    
    
    public void stopMonitoring(Long proposalId) {
        log.info("Stopping effectiveness monitoring for proposal: {}", proposalId);
        
        PolicyMetrics metrics = metricsStore.get(proposalId);
        if (metrics != null) {
            metrics.setEndTime(LocalDateTime.now());
            metrics.setStatus(MonitoringStatus.COMPLETED);
            
            
            calculateFinalImpact(proposalId);
        }
    }
    
    
    public void recordMetric(Long proposalId, MetricType metricType, double value) {
        PolicyMetrics metrics = metricsStore.get(proposalId);
        if (metrics == null) {
            log.warn("No monitoring session found for proposal: {}", proposalId);
            return;
        }
        
        Measurement measurement = Measurement.builder()
            .timestamp(LocalDateTime.now())
            .metricType(metricType)
            .value(value)
            .build();
        
        metrics.getMeasurements().add(measurement);
        
        
        updatePerformanceData(proposalId, metricType, value);
    }
    
    
    public void recordSecurityEvent(Long proposalId, String eventType, boolean blocked) {
        PolicyMetrics metrics = metricsStore.get(proposalId);
        if (metrics == null) {
            return;
        }
        
        if (blocked) {
            metrics.incrementBlockedThreats();
            recordMetric(proposalId, MetricType.THREATS_BLOCKED, 1);
        } else {
            metrics.incrementDetectedThreats();
            recordMetric(proposalId, MetricType.THREATS_DETECTED, 1);
        }
        
        
        double blockRate = calculateBlockRate(metrics);
        recordMetric(proposalId, MetricType.BLOCK_RATE, blockRate);
    }
    
    
    @Transactional
    public double calculateActualImpact(Long proposalId) {
        log.debug("Calculating actual impact for proposal: {}", proposalId);
        
        PolicyMetrics metrics = metricsStore.get(proposalId);
        if (metrics == null || metrics.getMeasurements().isEmpty()) {
            return 0.0;
        }
        
        double impact = 0.0;
        double weight = 0.0;
        
        
        double securityImprovement = calculateSecurityImprovement(metrics);
        impact += securityImprovement * 0.4;
        weight += 0.4;
        
        
        double performanceImpact = calculatePerformanceImpact(metrics);
        impact += performanceImpact * 0.2;
        weight += 0.2;
        
        
        double falsePositiveReduction = calculateFalsePositiveReduction(metrics);
        impact += falsePositiveReduction * 0.2;
        weight += 0.2;
        
        
        double userImpact = calculateUserImpact(metrics);
        impact += userImpact * 0.1;
        weight += 0.1;
        
        
        double costEfficiency = calculateCostEfficiency(metrics);
        impact += costEfficiency * 0.1;
        weight += 0.1;
        
        
        double actualImpact = weight > 0 ? impact / weight : 0.0;
        
        
        updateProposalActualImpact(proposalId, actualImpact);
        
        log.info("Actual impact calculated for proposal {}: {}", proposalId, actualImpact);
        return actualImpact;
    }
    
    
    public EffectivenessReport getEffectivenessReport(Long proposalId) {
        PolicyMetrics metrics = metricsStore.get(proposalId);
        if (metrics == null) {
            return EffectivenessReport.builder()
                .proposalId(proposalId)
                .status(MonitoringStatus.NOT_MONITORED)
                .build();
        }
        
        PerformanceData perfData = performanceData.get(proposalId);
        
        return EffectivenessReport.builder()
            .proposalId(proposalId)
            .status(metrics.getStatus())
            .startTime(metrics.getStartTime())
            .endTime(metrics.getEndTime())
            .actualImpact(calculateActualImpact(proposalId))
            .threatsBlocked(metrics.getBlockedThreats())
            .threatsDetected(metrics.getDetectedThreats())
            .blockRate(calculateBlockRate(metrics))
            .averageResponseTime(perfData != null ? perfData.getAverageResponseTime() : 0.0)
            .cpuUsage(perfData != null ? perfData.getCpuUsage() : 0.0)
            .memoryUsage(perfData != null ? perfData.getMemoryUsage() : 0.0)
            .improvementRate(calculateImprovementRate(metrics))
            .measurements(metrics.getMeasurements())
            .build();
    }
    
    

    @Transactional
    public void evaluateActivePolices() {
        log.info("Starting periodic effectiveness evaluation");
        
        try {
            
            List<PolicyEvolutionProposal> activeProposals = 
                proposalRepository.findActiveProposals();
            
            for (PolicyEvolutionProposal proposal : activeProposals) {
                Long proposalId = proposal.getId();
                
                
                if (!metricsStore.containsKey(proposalId)) {
                    startMonitoring(proposalId);
                }
                
                
                double actualImpact = calculateActualImpact(proposalId);
                
                
                Double expectedImpact = proposal.getExpectedImpact();
                if (expectedImpact != null) {
                    double deviation = Math.abs(actualImpact - expectedImpact);
                    
                    if (deviation > 0.3) {
                        log.warn("Significant deviation detected for proposal {}: " +
                            "expected={}, actual={}", proposalId, expectedImpact, actualImpact);
                        
                        
                        triggerReEvaluation(proposal, actualImpact, expectedImpact);
                    }
                }
                
                
                if (actualImpact < 0.3) {
                    log.warn("Low performing policy detected: {}", proposalId);
                    markAsLowPerforming(proposal);
                }
            }
            
            
            cleanupOldMetrics();
            
            log.info("Periodic effectiveness evaluation completed");
            
        } catch (Exception e) {
            log.error("Error during effectiveness evaluation", e);
        }
    }
    
    
    
    private void establishBaseline(Long proposalId) {
        
        recordMetric(proposalId, MetricType.BASELINE_THREATS, 0);
        recordMetric(proposalId, MetricType.BASELINE_RESPONSE_TIME, 100);
        recordMetric(proposalId, MetricType.BASELINE_FALSE_POSITIVES, 0);
    }
    
    private void updatePerformanceData(Long proposalId, MetricType metricType, double value) {
        PerformanceData data = performanceData.computeIfAbsent(proposalId, 
            k -> new PerformanceData());
        
        switch (metricType) {
            case RESPONSE_TIME:
                data.updateResponseTime(value);
                break;
            case CPU_USAGE:
                data.setCpuUsage(value);
                break;
            case MEMORY_USAGE:
                data.setMemoryUsage(value);
                break;
        }
    }
    
    private double calculateBlockRate(PolicyMetrics metrics) {
        int total = metrics.getDetectedThreats() + metrics.getBlockedThreats();
        if (total == 0) return 0.0;
        return (double) metrics.getBlockedThreats() / total;
    }
    
    private double calculateSecurityImprovement(PolicyMetrics metrics) {
        
        double blockRate = calculateBlockRate(metrics);
        
        
        double baselineThreats = getBaselineMetric(metrics, MetricType.BASELINE_THREATS);
        double currentThreats = metrics.getDetectedThreats();
        
        if (baselineThreats > 0) {
            double reduction = (baselineThreats - currentThreats) / baselineThreats;
            return (blockRate + reduction) / 2;
        }
        
        return blockRate;
    }
    
    private double calculatePerformanceImpact(PolicyMetrics metrics) {
        
        double baselineResponseTime = getBaselineMetric(metrics, MetricType.BASELINE_RESPONSE_TIME);
        double currentResponseTime = getAverageMetric(metrics, MetricType.RESPONSE_TIME);
        
        if (baselineResponseTime > 0) {
            
            double degradation = (currentResponseTime - baselineResponseTime) / baselineResponseTime;
            return Math.max(0, 1 - degradation);
        }
        
        return 0.5; 
    }
    
    private double calculateFalsePositiveReduction(PolicyMetrics metrics) {
        double baselineFP = getBaselineMetric(metrics, MetricType.BASELINE_FALSE_POSITIVES);
        double currentFP = getAverageMetric(metrics, MetricType.FALSE_POSITIVES);
        
        if (baselineFP > 0) {
            return Math.max(0, (baselineFP - currentFP) / baselineFP);
        }
        
        return currentFP == 0 ? 1.0 : 0.5;
    }
    
    private double calculateUserImpact(PolicyMetrics metrics) {
        
        double userComplaints = getAverageMetric(metrics, MetricType.USER_COMPLAINTS);
        return Math.max(0, 1 - (userComplaints / 100)); 
    }
    
    private double calculateCostEfficiency(PolicyMetrics metrics) {
        
        double cpuUsage = getAverageMetric(metrics, MetricType.CPU_USAGE);
        double memoryUsage = getAverageMetric(metrics, MetricType.MEMORY_USAGE);
        double effectiveness = calculateBlockRate(metrics);
        
        double resourceUsage = (cpuUsage + memoryUsage) / 2;
        if (resourceUsage > 0) {
            return effectiveness / resourceUsage;
        }
        
        return effectiveness;
    }
    
    private double calculateImprovementRate(PolicyMetrics metrics) {
        if (metrics.getMeasurements().size() < 2) {
            return 0.0;
        }
        
        
        List<Measurement> measurements = metrics.getMeasurements().stream()
            .filter(m -> m.getMetricType() == MetricType.THREATS_BLOCKED)
            .collect(Collectors.toList());
        
        if (measurements.size() >= 2) {
            double first = measurements.get(0).getValue();
            double last = measurements.get(measurements.size() - 1).getValue();
            
            if (first > 0) {
                return (last - first) / first;
            }
        }
        
        return 0.0;
    }
    
    private double getBaselineMetric(PolicyMetrics metrics, MetricType type) {
        return metrics.getMeasurements().stream()
            .filter(m -> m.getMetricType() == type)
            .findFirst()
            .map(Measurement::getValue)
            .orElse(0.0);
    }
    
    private double getAverageMetric(PolicyMetrics metrics, MetricType type) {
        return metrics.getMeasurements().stream()
            .filter(m -> m.getMetricType() == type)
            .mapToDouble(Measurement::getValue)
            .average()
            .orElse(0.0);
    }
    
    private void calculateFinalImpact(Long proposalId) {
        double finalImpact = calculateActualImpact(proposalId);
        
        PolicyMetrics metrics = metricsStore.get(proposalId);
        if (metrics != null) {
            metrics.setFinalImpact(finalImpact);
        }
    }
    
    @Transactional
    private void updateProposalActualImpact(Long proposalId, double actualImpact) {
        try {
            PolicyEvolutionProposal proposal = proposalRepository.findById(proposalId)
                .orElse(null);
            
            if (proposal != null) {
                proposal.setActualImpact(actualImpact);
                proposalRepository.save(proposal);
            }
        } catch (Exception e) {
            log.error("Failed to update actual impact for proposal: {}", proposalId, e);
        }
    }
    
    private void triggerReEvaluation(PolicyEvolutionProposal proposal, 
                                    double actualImpact, double expectedImpact) {
        log.info("Triggering re-evaluation for proposal {}: actual={}, expected={}", 
            proposal.getId(), actualImpact, expectedImpact);
        
        
        
    }
    
    private void markAsLowPerforming(PolicyEvolutionProposal proposal) {
        proposal.addMetadata("low_performing", true);
        proposal.addMetadata("marked_at", LocalDateTime.now().toString());
        proposalRepository.save(proposal);
    }
    
    private void cleanupOldMetrics() {
        LocalDateTime cutoff = LocalDateTime.now().minus(30, ChronoUnit.DAYS);
        
        metricsStore.entrySet().removeIf(entry -> {
            PolicyMetrics metrics = entry.getValue();
            return metrics.getEndTime() != null && metrics.getEndTime().isBefore(cutoff);
        });
    }
    
    
    
    
    @lombok.Builder
    @lombok.Data
    private static class PolicyMetrics {
        private Long proposalId;
        private LocalDateTime startTime;
        private LocalDateTime endTime;
        private MonitoringStatus status;
        private List<Measurement> measurements;
        private int blockedThreats;
        private int detectedThreats;
        private double finalImpact;
        
        public void incrementBlockedThreats() {
            this.blockedThreats++;
        }
        
        public void incrementDetectedThreats() {
            this.detectedThreats++;
        }
    }
    
    
    @lombok.Builder
    @lombok.Data
    public static class Measurement {
        private LocalDateTime timestamp;
        private MetricType metricType;
        private double value;
    }
    
    
    @lombok.Data
    private static class PerformanceData {
        private double averageResponseTime;
        private double cpuUsage;
        private double memoryUsage;
        private List<Double> responseTimes = new ArrayList<>();
        
        public void updateResponseTime(double time) {
            responseTimes.add(time);
            if (responseTimes.size() > 100) {
                responseTimes.remove(0);
            }
            averageResponseTime = responseTimes.stream()
                .mapToDouble(Double::doubleValue)
                .average()
                .orElse(0.0);
        }
    }
    
    
    @lombok.Builder
    @lombok.Data
    public static class EffectivenessReport {
        private Long proposalId;
        private MonitoringStatus status;
        private LocalDateTime startTime;
        private LocalDateTime endTime;
        private double actualImpact;
        private int threatsBlocked;
        private int threatsDetected;
        private double blockRate;
        private double averageResponseTime;
        private double cpuUsage;
        private double memoryUsage;
        private double improvementRate;
        private List<Measurement> measurements;
    }
    
    
    public enum MetricType {
        THREATS_DETECTED,
        THREATS_BLOCKED,
        FALSE_POSITIVES,
        RESPONSE_TIME,
        CPU_USAGE,
        MEMORY_USAGE,
        BLOCK_RATE,
        USER_COMPLAINTS,
        BASELINE_THREATS,
        BASELINE_RESPONSE_TIME,
        BASELINE_FALSE_POSITIVES
    }
    
    
    public enum MonitoringStatus {
        NOT_MONITORED,
        ACTIVE,
        PAUSED,
        COMPLETED
    }
}