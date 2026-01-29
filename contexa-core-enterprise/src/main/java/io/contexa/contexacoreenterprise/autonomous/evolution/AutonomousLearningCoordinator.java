package io.contexa.contexacoreenterprise.autonomous.evolution;

import io.contexa.contexacore.autonomous.ISecurityPlaneAgent;
import io.contexa.contexacore.autonomous.domain.LearningMetadata;
import io.contexa.contexacore.autonomous.event.IncidentResolvedEvent;
import io.contexa.contexacore.autonomous.event.PolicyApprovedEvent;
import io.contexa.contexacore.autonomous.event.ProcessingCompletedEvent;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal.ProposalStatus;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacoreenterprise.autonomous.intelligence.AITuningService;
import io.contexa.contexacoreenterprise.dashboard.metrics.unified.SystemMetricsCollector;
import io.contexa.contexacoreenterprise.autonomous.metrics.PolicyUsageMetricsService;
import io.contexa.contexacoreenterprise.dashboard.metrics.evolution.EvolutionMetricsCollector;
import io.contexa.contexacore.repository.PolicyProposalRepository;
import io.contexa.contexacore.domain.SoarIncidentStatus;
import io.contexa.contexacore.domain.entity.SoarIncident;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
public class AutonomousLearningCoordinator {

    private final ISecurityPlaneAgent securityPlaneAgent;
    private final PolicyEvolutionEngine evolutionEngine;
    private final AITuningService tuningService;
    private final PolicyProposalRepository proposalRepository;
    private final ApplicationEventPublisher eventPublisher;
    private SystemMetricsCollector metricsCollector;
    private EvolutionMetricsCollector evolutionMetricsCollector;
    private AccessGovernanceLabConnector accessGovernanceConnector;
    private PolicyUsageMetricsService policyUsageMetrics;

    public AutonomousLearningCoordinator(ISecurityPlaneAgent securityPlaneAgent,
                                         PolicyEvolutionEngine evolutionEngine,
                                         AITuningService tuningService,
                                         PolicyProposalRepository proposalRepository,
                                         ApplicationEventPublisher eventPublisher) {
        this.securityPlaneAgent = securityPlaneAgent;
        this.evolutionEngine = evolutionEngine;
        this.tuningService = tuningService;
        this.proposalRepository = proposalRepository;
        this.eventPublisher = eventPublisher;
    }

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setMetricsCollector(SystemMetricsCollector metricsCollector) {
        this.metricsCollector = metricsCollector;
    }

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setEvolutionMetricsCollector(EvolutionMetricsCollector evolutionMetricsCollector) {
        this.evolutionMetricsCollector = evolutionMetricsCollector;
    }

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setAccessGovernanceConnector(AccessGovernanceLabConnector connector) {
        this.accessGovernanceConnector = connector;
    }

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setPolicyUsageMetrics(PolicyUsageMetricsService service) {
        this.policyUsageMetrics = service;
    }
    
    @Value("${security.autonomous.learning.enabled:true}")
    private boolean enabled;

    @Value("${security.autonomous.learning.evolution.confidence-threshold:0.8}")
    private double confidenceThreshold;

    @Value("${learning.coordinator.batch.size:10}")
    private int batchSize;

    @Value("${security.autonomous.learning.evolution.max-proposals:100}")
    private int maxProposalsPerDay;

    @Value("${learning.coordinator.threat.level.threshold:0.8}")
    private double threatLevelThreshold;

    @Value("${learning.coordinator.max.active.incidents:10}")
    private long maxActiveIncidents;

    @Value("${security.autonomous.learning.evolution.slow-policy-threshold-ms:1000}")
    private long slowPolicyThresholdMs;

    private final AtomicLong totalEventsProcessed = new AtomicLong(0);
    private final AtomicLong totalProposalsGenerated = new AtomicLong(0);
    private final AtomicLong totalLearningCycles = new AtomicLong(0);
    private final AtomicLong totalIncidentsProcessed = new AtomicLong(0);
    private final AtomicLong successfulLearnings = new AtomicLong(0);
    private final AtomicLong proposalsGenerated = new AtomicLong(0);

    private final Map<String, Integer> dailyProposalCount = new ConcurrentHashMap<>();

    @EventListener
    @Async
    public void onIncidentResolved(IncidentResolvedEvent event) {
        if (!enabled) {
                        return;
        }

                long startTime = System.currentTimeMillis();

        try {
            
            SecurityEvent securityEvent = event.getSecurityEvent();
            if (securityEvent == null) {
                log.warn("Security event is null: {}", event.getIncidentId());
                return;
            }

            LearningMetadata metadata = extractLearningMetadata(event);

            if (!canLearn(metadata)) {

                if (evolutionMetricsCollector != null) {
                    evolutionMetricsCollector.recordIncidentProcessed(
                        securityEvent.getSeverity().name(),
                        false,
                        "low_confidence"
                    );
                }
                return;
            }

            if (!checkDailyLimit()) {
                log.warn("Daily proposal limit exceeded");

                if (evolutionMetricsCollector != null) {
                    evolutionMetricsCollector.recordIncidentProcessed(
                        securityEvent.getSeverity().name(),
                        false,
                        "daily_limit_exceeded"
                    );
                }
                return;
            }

            triggerPolicyEvolution(securityEvent, metadata);

            AITuningService.UserFeedback feedback = AITuningService.UserFeedback.builder()
                .feedbackType("FALSE_POSITIVE")
                .comment("Automatic learning feedback")
                .timestamp(LocalDateTime.now())
                .build();
            tuningService.learnFalsePositive(securityEvent, feedback).subscribe();

            totalEventsProcessed.incrementAndGet();

            if (evolutionMetricsCollector != null) {
                evolutionMetricsCollector.recordIncidentProcessed(
                    securityEvent.getSeverity().name(),
                    true,
                    metadata.getLearningType().name()
                );
            }

        } catch (Exception e) {
            log.error("Incident learning processing failed", e);

            if (evolutionMetricsCollector != null) {
                String severity = event.getSecurityEvent() != null ?
                    event.getSecurityEvent().getSeverity().name() : "UNKNOWN";
                evolutionMetricsCollector.recordIncidentProcessed(
                    severity,
                    false,
                    "error"
                );
            }
        }
    }

    @Transactional
    public void performProactiveOptimization() {
        if (!enabled) {
            return;
        }

        try {
            totalLearningCycles.incrementAndGet();

            analyzeSystemState();

            detectExcessivePermissions();

            identifyUnusedPolicies();

            suggestPerformanceOptimizations();

            cleanupExpiredProposals();

        } catch (Exception e) {
            log.error("Periodic optimization failed", e);
        }
    }

    private LearningMetadata extractLearningMetadata(IncidentResolvedEvent event) {
        LearningMetadata.LearningMetadataBuilder builder = LearningMetadata.builder()
            .isLearnable(true)
            .incidentId(event.getIncidentId())
            .createdAt(LocalDateTime.now())
            .status(LearningMetadata.LearningStatus.PENDING);

        SoarIncident incident = event.getIncident();
        if (incident != null) {
            
            String severity = incident.getSeverity();
            if ("CRITICAL".equals(severity)) {
                builder.priority(10);
                builder.learningType(LearningMetadata.LearningType.THREAT_RESPONSE);
            } else if ("HIGH".equals(severity)) {
                builder.priority(8);
                builder.learningType(LearningMetadata.LearningType.THREAT_RESPONSE);
            } else if ("MEDIUM".equals(severity)) {
                builder.priority(5);
                builder.learningType(LearningMetadata.LearningType.ACCESS_PATTERN);
            } else {
                builder.priority(3);
                builder.learningType(LearningMetadata.LearningType.POLICY_FEEDBACK);
            }

            double confidence = calculateConfidence(incident);
            builder.confidenceScore(confidence);

            Map<String, Object> context = new HashMap<>();
            context.put("incidentId", incident.getId());
            context.put("severity", incident.getSeverity());
            context.put("status", incident.getStatus());
            context.put("createdAt", incident.getCreatedAt());
            context.put("updatedAt", incident.getUpdatedAt());
            builder.learningContext(context);
        } else {
            
            builder.learningType(LearningMetadata.LearningType.POLICY_FEEDBACK)
                   .priority(5)
                   .confidenceScore(0.5);
        }
        
        return builder.build();
    }

    private double calculateConfidence(SoarIncident incident) {
        double confidence = 0.5; 

        SoarIncidentStatus status = incident.getStatus();
        if (status != null && status.name().equals("RESOLVED")) {
            confidence += 0.2;
        } else if (status != null && status.name().equals("MITIGATED")) {
            confidence += 0.1;
        }

        if (incident.getHistory() != null) {
            int historyCount = incident.getHistory().size();
            if (historyCount >= 3) {
                confidence += 0.2;
            } else if (historyCount >= 1) {
                confidence += 0.1;
            }
        }

        if (incident.getUpdatedAt() != null && incident.getCreatedAt() != null) {
            long updateMinutes = java.time.Duration.between(
                incident.getCreatedAt(), 
                incident.getUpdatedAt()
            ).toMinutes();
            
            if (updateMinutes < 30) {
                confidence += 0.1; 
            }
        }
        
        return Math.min(confidence, 1.0);
    }

    private boolean canLearn(LearningMetadata metadata) {
        return metadata.isLearnable() &&
               metadata.getConfidenceScore() >= confidenceThreshold &&
               metadata.getStatus() == LearningMetadata.LearningStatus.PENDING;
    }

    private void processLearning(LearningMetadata metadata, SoarIncident incident, SecurityEvent securityEvent) {

        if (tuningService != null) {
            Map<String, Object> tuningMetadata = new HashMap<>();
            tuningMetadata.put("incidentId", metadata.getIncidentId());
            tuningMetadata.put("successful", metadata.getStatus() == LearningMetadata.LearningStatus.COMPLETED);
            tuningMetadata.put("resolution", metadata.getStatus().toString());
            tuningMetadata.put("timestamp", LocalDateTime.now());

            tuningService.tuneFromIncident(incident, tuningMetadata)
                    .subscribe(
                            result -> log.debug("Incident learning completed: {}", result.getMessage()),
                            error -> log.warn("Incident learning failed", error)
                    );
        }

        metadata.setStatus(LearningMetadata.LearningStatus.COMPLETED);
        metadata.setCompletedAt(LocalDateTime.now());
    }

    private io.contexa.contexacore.domain.SoarIncidentDto convertEntityToDomain(
            SoarIncident entity) {

        io.contexa.contexacore.domain.SoarIncidentDto dto = new io.contexa.contexacore.domain.SoarIncidentDto();

        dto.setIncidentId(entity.getIncidentId());
        dto.setTitle(entity.getTitle());
        dto.setDescription(entity.getDescription());
        dto.setCreatedAt(entity.getCreatedAt());

        if (entity.getType() != null && !entity.getType().isEmpty()) {
            try {
                dto.setType(io.contexa.contexacore.domain.SoarIncidentDto.IncidentType.valueOf(
                    entity.getType().toUpperCase()));
            } catch (IllegalArgumentException e) {
                log.warn("Unknown IncidentType: {}, defaulting to OTHER", entity.getType());
                dto.setType(io.contexa.contexacore.domain.SoarIncidentDto.IncidentType.OTHER);
            }
        } else {
            dto.setType(io.contexa.contexacore.domain.SoarIncidentDto.IncidentType.OTHER);
        }

        if (entity.getSeverity() != null && !entity.getSeverity().isEmpty()) {
            try {
                dto.setSeverity(io.contexa.contexacore.domain.SoarIncidentDto.IncidentSeverity.valueOf(
                    entity.getSeverity().toUpperCase()));
            } catch (IllegalArgumentException e) {
                log.warn("Unknown Severity: {}, defaulting to MEDIUM", entity.getSeverity());
                dto.setSeverity(io.contexa.contexacore.domain.SoarIncidentDto.IncidentSeverity.MEDIUM);
            }
        } else {
            dto.setSeverity(io.contexa.contexacore.domain.SoarIncidentDto.IncidentSeverity.MEDIUM);
        }

        if (entity.getStatus() != null) {
            try {
                dto.setStatus(io.contexa.contexacore.domain.SoarIncidentDto.IncidentStatus.valueOf(
                    entity.getStatus().name()));
            } catch (IllegalArgumentException e) {
                log.warn("Unknown Status: {}, defaulting to NEW", entity.getStatus());
                dto.setStatus(io.contexa.contexacore.domain.SoarIncidentDto.IncidentStatus.NEW);
            }
        } else {
            dto.setStatus(io.contexa.contexacore.domain.SoarIncidentDto.IncidentStatus.NEW);
        }

        return dto;
    }

    private boolean checkDailyLimit() {
        String today = LocalDateTime.now().toLocalDate().toString();
        int count = dailyProposalCount.getOrDefault(today, 0);
        
        if (count >= maxProposalsPerDay) {
            return false;
        }
        
        dailyProposalCount.put(today, count + 1);

        dailyProposalCount.entrySet().removeIf(entry -> !entry.getKey().equals(today));
        
        return true;
    }

    private void triggerPolicyEvolution(SecurityEvent securityEvent, LearningMetadata metadata) {
        try {

            PolicyEvolutionProposal proposal = evolutionEngine.evolvePolicy(securityEvent, metadata);

            proposal = proposalRepository.save(proposal);

            totalProposalsGenerated.incrementAndGet();

            metadata.markAsCompleted("Policy proposal generated: " + proposal.getId());

        } catch (Exception e) {
            log.error("Policy evolution failed", e);
            metadata.markAsFailed(e.getMessage());
        }
    }

    private void analyzeSystemState() {
                
        try {
            
            Map<String, Object> systemState = metricsCollector != null ?
                metricsCollector.getSystemMetrics() : new HashMap<>();

            if (metricsCollector != null && systemState != null && !systemState.isEmpty()) {
                Map<String, Object> eventMetadata = new HashMap<>();
                eventMetadata.put("threat_level", systemState.get("threatLevel"));
                eventMetadata.put("active_incidents", systemState.get("activeIncidents"));
                eventMetadata.put("event_rate", systemState.get("eventRatePerMinute"));
                metricsCollector.recordEvent("system_state_analyzed", eventMetadata);
            }

            if (systemState != null && !systemState.isEmpty()) {
                Double threatLevel = (Double) systemState.get("threatLevel");
                if (threatLevel != null && threatLevel > threatLevelThreshold) {
                    log.warn("High threat level detected: {}", threatLevel);
                    createSystemStateProposal("HIGH_THREAT", systemState);
                }

                Long activeIncidents = (Long) systemState.get("activeIncidents");
                if (activeIncidents != null && activeIncidents > maxActiveIncidents) {
                    log.warn("Many active incidents detected: {}", activeIncidents);
                    createSystemStateProposal("MANY_INCIDENTS", systemState);
                }

                Double eventRate = (Double) systemState.get("eventRatePerMinute");
                if (eventRate != null && eventRate > 100) {
                    log.warn("High event rate detected: {} events/min", eventRate);
                    createSystemStateProposal("HIGH_EVENT_RATE", systemState);
                }
            }
            
        } catch (Exception e) {
            log.error("System state analysis failed", e);
        }
    }

    private void detectExcessivePermissions() {
                
        try {
            
            if (accessGovernanceConnector != null && accessGovernanceConnector.shouldRunAnalysis()) {
                List<SecurityEvent> events = accessGovernanceConnector.analyzeExcessivePermissions();

                for (SecurityEvent event : events) {
                    LearningMetadata metadata = LearningMetadata.builder()
                        .isLearnable(true)
                        .learningType(LearningMetadata.LearningType.ACCESS_PATTERN)
                        .confidenceScore(0.85)
                        .priority(6)
                        .sourceLabId("AccessGovernanceLab")
                        .build();

                    if (canLearn(metadata) && checkDailyLimit()) {
                        triggerPolicyEvolution(event, metadata);
                    }
                }

            } else {
                            }
            
        } catch (Exception e) {
            log.error("Excessive privilege detection failed", e);
        }
    }

    private void identifyUnusedPolicies() {
                
        try {
            
            LocalDateTime threshold = LocalDateTime.now().minusDays(30);
            List<PolicyEvolutionProposal> oldActiveProposals = 
                proposalRepository.findByStatusAndActivatedAtBefore(
                    ProposalStatus.ACTIVATED, 
                    threshold
                );
            
            for (PolicyEvolutionProposal proposal : oldActiveProposals) {
                
                double actualImpact = 0.0;
                if (policyUsageMetrics != null && proposal.getPolicyId() != null) {
                    PolicyUsageMetricsService.PolicyMetrics metrics =
                        policyUsageMetrics.getPolicyMetrics(String.valueOf(proposal.getPolicyId()));
                    actualImpact = metrics.getAverageImpact();
                } else {
                    actualImpact = proposal.getActualImpact() != null ? proposal.getActualImpact() : 0.0;
                }

                if (actualImpact < 0.1) {

                    PolicyEvolutionProposal deactivationProposal = PolicyEvolutionProposal.builder()
                        .title("Unused policy deactivation proposal")
                        .description("Ineffective policy for 30+ days: " + proposal.getTitle())
                        .proposalType(PolicyEvolutionProposal.ProposalType.DELETE_POLICY)
                        .parentProposalId(proposal.getId())
                        .confidenceScore(0.9)
                        .riskLevel(PolicyEvolutionProposal.RiskLevel.LOW)
                        .aiReasoning("Long-term unused policies only increase system complexity")
                        .createdAt(LocalDateTime.now())
                        .build();
                    
                    proposalRepository.save(deactivationProposal);
                }
            }
            
        } catch (Exception e) {
            log.error("Unused policy identification failed", e);
        }
    }

    private void suggestPerformanceOptimizations() {
                
        try {
            
            List<PolicyEvolutionProposal> activeProposals = proposalRepository.findActiveProposals();
            
            for (PolicyEvolutionProposal proposal : activeProposals) {
                
                double avgExecutionTime = 0;
                if (policyUsageMetrics != null && proposal.getPolicyId() != null) {
                    PolicyUsageMetricsService.PolicyMetrics metrics =
                        policyUsageMetrics.getPolicyMetrics(String.valueOf(proposal.getPolicyId()));
                    avgExecutionTime = metrics.getAverageExecutionTime();
                } else {
                    
                    Map<String, Object> metadata = proposal.getMetadata();
                    if (metadata != null) {
                        Integer time = (Integer) metadata.get("avgExecutionTime");
                        avgExecutionTime = time != null ? time : 0;
                    }
                }

                if (avgExecutionTime > slowPolicyThresholdMs) {

                    PolicyEvolutionProposal optimizationProposal = PolicyEvolutionProposal.builder()
                        .title("Policy performance optimization proposal")
                        .description("Slow policy needs optimization: " + proposal.getTitle())
                        .proposalType(PolicyEvolutionProposal.ProposalType.OPTIMIZE_RULE)
                        .parentProposalId(proposal.getId())
                        .confidenceScore(0.7)
                        .riskLevel(PolicyEvolutionProposal.RiskLevel.MEDIUM)
                        .aiReasoning("Current average execution time is " + avgExecutionTime + "ms, optimization needed")
                        .createdAt(LocalDateTime.now())
                        .build();

                    proposalRepository.save(optimizationProposal);
                }
            }
            
        } catch (Exception e) {
            log.error("Performance optimization proposal failed", e);
        }
    }

    private void cleanupExpiredProposals() {
                
        try {
            int expiredCount = proposalRepository.expireOldProposals(LocalDateTime.now());
            if (expiredCount > 0) {
                            }

            LocalDateTime deleteThreshold = LocalDateTime.now().minusDays(90);
            int deletedCount = proposalRepository.deleteOldRejectedProposals(deleteThreshold);
            if (deletedCount > 0) {
                            }
            
        } catch (Exception e) {
            log.error("Expired proposal cleanup failed", e);
        }
    }

    private void createSystemStateProposal(String type, Map<String, Object> systemState) {
        try {
            
            SecurityEvent event = SecurityEvent.builder()
                .eventId(UUID.randomUUID().toString())
                .source(SecurityEvent.EventSource.ENDPOINT)
                .severity(SecurityEvent.Severity.HIGH)
                .description("System state anomaly: " + type)
                .timestamp(LocalDateTime.now())
                .build();
            event.addMetadata("incidentType", "SYSTEM_ALERT");
            
            LearningMetadata metadata = LearningMetadata.builder()
                .isLearnable(true)
                .learningType(LearningMetadata.LearningType.PERFORMANCE_OPTIMIZATION)
                .confidenceScore(0.9)
                .priority(8)
                .learningContext(systemState)
                .build();
            
            if (checkDailyLimit()) {
                triggerPolicyEvolution(event, metadata);
            }
            
        } catch (Exception e) {
            log.error("System state proposal generation failed", e);
        }
    }

    @Transactional
    public void approvePolicyProposal(Long proposalId, String approvedBy) {
        try {
            Optional<PolicyEvolutionProposal> proposalOpt = proposalRepository.findById(proposalId);
            if (!proposalOpt.isPresent()) {
                log.warn("Policy proposal not found: {}", proposalId);
                return;
            }

            PolicyEvolutionProposal proposal = proposalOpt.get();

            proposal.setStatus(ProposalStatus.APPROVED);
            proposal.setApprovedAt(LocalDateTime.now());
            proposal.setApprovedBy(approvedBy);
            proposalRepository.save(proposal);

            PolicyApprovedEvent approvedEvent = new PolicyApprovedEvent(
                this,
                String.valueOf(proposal.getId()),
                proposal.getTitle(),
                proposal.getDescription(),
                proposal.getPolicyContent(),
                approvedBy,
                "AIAM", 
                proposal.getConfidenceScore()
            );

            eventPublisher.publishEvent(approvedEvent);

        } catch (Exception e) {
            log.error("Failed to approve policy proposal: {}", proposalId, e);
        }
    }

    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalEventsProcessed", totalEventsProcessed.get());
        stats.put("totalProposalsGenerated", totalProposalsGenerated.get());
        stats.put("totalLearningCycles", totalLearningCycles.get());
        stats.put("dailyProposalCount", dailyProposalCount.getOrDefault(
            LocalDateTime.now().toLocalDate().toString(), 0
        ));
        stats.put("enabled", enabled);
        stats.put("confidenceThreshold", confidenceThreshold);
        return stats;
    }

    @EventListener
    @Async
    public void onProcessingCompleted(ProcessingCompletedEvent event) {
        if (!enabled) {
                        return;
        }

        try {
            SecurityEvent originalEvent = event.getOriginalEvent();

            LearningMetadata metadata = LearningMetadata.builder()
                .isLearnable(true)
                .learningType(LearningMetadata.LearningType.THREAT_RESPONSE)
                .confidenceScore(event.getResult() != null ? 0.8 : 0.5)
                .sourceLabId(event.isHotPath() ? "HOT_PATH" : "COLD_PATH")
                .eventType(originalEvent.getSeverity() != null ?
                    originalEvent.getSeverity().toString() : "UNKNOWN")
                .status(LearningMetadata.LearningStatus.PENDING)
                .priority(event.isHighValueForLearning() ? 8 : 5)
                .build();

            metadata.addContext("processingMode", event.getMode().toString());
            metadata.addContext("processingLayer", event.getLayer().toString());
            metadata.addContext("processingTimeMs", event.getProcessingTimeMs());
            metadata.addContext("accuracy", event.getAccuracy());

            if (event.getResult() != null) {
                metadata.addContext("riskLevel", event.getResult().getCurrentRiskLevel());
                
                metadata.addContext("riskScore", event.getResult().getRiskScore());
                metadata.addContext("aiAnalysisPerformed", event.getResult().isAiAnalysisPerformed());

                if (event.getResult().getThreatIndicators() != null) {
                    metadata.addContext("threatIndicatorsCount", event.getResult().getThreatIndicators().size());
                }
            }

            boolean shouldEvolvePolicy = event.isHighValueForLearning() ||
                (event.getResult() != null && event.getResult().getCurrentRiskLevel() >= threatLevelThreshold);

            if (shouldEvolvePolicy) {
                PolicyEvolutionProposal proposal = evolutionEngine.evolvePolicy(originalEvent, metadata);

                if (proposal != null) {
                    proposalRepository.save(proposal);
                    proposalsGenerated.incrementAndGet();

                                    } else {
                                    }
            } else {
                            }

            totalEventsProcessed.incrementAndGet();

        } catch (Exception e) {
            log.error("[AutonomousLearning] ProcessingCompletedEvent processing failed - eventId: {}",
                event.getOriginalEvent() != null ? event.getOriginalEvent().getEventId() : "unknown", e);
        }
    }

}