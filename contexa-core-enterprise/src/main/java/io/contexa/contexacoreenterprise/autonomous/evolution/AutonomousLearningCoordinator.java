package io.contexa.contexacoreenterprise.autonomous.evolution;

import io.contexa.contexacore.autonomous.domain.LearningMetadata;
import io.contexa.contexacore.autonomous.domain.SecurityEvent;
import io.contexa.contexacore.autonomous.event.IncidentResolvedEvent;
import io.contexa.contexacore.autonomous.event.ThreatPolicyTriggerEvent;
import io.contexa.contexacore.domain.SoarIncidentStatus;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.domain.entity.SoarIncident;
import io.contexa.contexacore.repository.PolicyProposalRepository;
import io.contexa.contexacoreenterprise.autonomous.governance.PolicyEvolutionGovernance;
import io.contexa.contexacoreenterprise.dashboard.metrics.evolution.EvolutionMetricsCollector;
import io.contexa.contexacoreenterprise.properties.SecurityAutonomousProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
public class AutonomousLearningCoordinator {

    private final PolicyEvolutionEngine evolutionEngine;
    private final PolicyProposalRepository proposalRepository;
    private final PolicyEvolutionGovernance governanceService;
    private final EvolutionMetricsCollector evolutionMetricsCollector;
    private final SecurityAutonomousProperties securityAutonomousProperties;

    public AutonomousLearningCoordinator(PolicyEvolutionEngine evolutionEngine,
                                         PolicyProposalRepository proposalRepository,
                                         PolicyEvolutionGovernance governanceService,
                                         EvolutionMetricsCollector evolutionMetricsCollector,
                                         SecurityAutonomousProperties securityAutonomousProperties) {
        this.evolutionEngine = evolutionEngine;
        this.proposalRepository = proposalRepository;
        this.governanceService = governanceService;
        this.evolutionMetricsCollector = evolutionMetricsCollector;
        this.securityAutonomousProperties = securityAutonomousProperties;
    }

    private final AtomicLong totalEventsProcessed = new AtomicLong(0);
    private final AtomicLong totalProposalsGenerated = new AtomicLong(0);

    private final Map<String, Integer> dailyProposalCount = new ConcurrentHashMap<>();

    // TODO: IncidentResolvedEvent is not published anywhere in the codebase yet.
    //  This listener will be activated when the incident management module is integrated
    //  and publishes IncidentResolvedEvent upon incident resolution.
    //  Currently, only ThreatPolicyTriggerEvent path is active (see onThreatPolicyTrigger).
    @EventListener
    @Async
    public void onIncidentResolved(IncidentResolvedEvent event) {
        if (!securityAutonomousProperties.getLearning().isEnabled()) {
            return;
        }
        try {

            SecurityEvent securityEvent = event.getSecurityEvent();
            if (securityEvent == null) {
                log.error("Security event is null: {}", event.getIncidentId());
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
                log.error("Daily proposal limit exceeded");

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

    @EventListener
    @Async
    public void onThreatPolicyTrigger(ThreatPolicyTriggerEvent event) {
        if (!securityAutonomousProperties.getLearning().isEnabled()) {
            return;
        }
        try {
            SecurityEvent securityEvent = event.getSecurityEvent();
            if (securityEvent == null) {
                log.error("Security event is null in ThreatPolicyTriggerEvent");
                return;
            }

            LearningMetadata metadata = buildThreatMetadata(event);

            if (!canLearn(metadata)) {
                if (evolutionMetricsCollector != null) {
                    evolutionMetricsCollector.recordIncidentProcessed(
                            securityEvent.getSeverity().name(), false, "low_confidence");
                }
                return;
            }

            if (!checkDailyLimit()) {
                log.error("Daily proposal limit exceeded for threat policy trigger");
                if (evolutionMetricsCollector != null) {
                    evolutionMetricsCollector.recordIncidentProcessed(
                            securityEvent.getSeverity().name(), false, "daily_limit_exceeded");
                }
                return;
            }

            triggerPolicyEvolution(securityEvent, metadata);
            totalEventsProcessed.incrementAndGet();

            if (evolutionMetricsCollector != null) {
                evolutionMetricsCollector.recordIncidentProcessed(
                        securityEvent.getSeverity().name(), true, metadata.getLearningType().name());
            }

        } catch (Exception e) {
            log.error("Threat policy trigger processing failed", e);
            if (evolutionMetricsCollector != null) {
                String severity = event.getSecurityEvent() != null ?
                        event.getSecurityEvent().getSeverity().name() : "UNKNOWN";
                evolutionMetricsCollector.recordIncidentProcessed(severity, false, "error");
            }
        }
    }

    private LearningMetadata buildThreatMetadata(ThreatPolicyTriggerEvent event) {
        int priority = "BLOCK".equals(event.getAction()) ? 10 : 8;

        Map<String, Object> learningContext = new HashMap<>();
        learningContext.put("action", event.getAction());
        learningContext.put("riskScore", event.getRiskScore());
        learningContext.put("confidence", event.getConfidence());
        learningContext.put("reasoning", event.getReasoning());
        learningContext.put("mitre", event.getMitre());
        learningContext.put("layerName", event.getLayerName());

        SecurityEvent securityEvent = event.getSecurityEvent();
        if (securityEvent != null && securityEvent.getMetadata() != null) {
            Map<String, Object> eventMeta = securityEvent.getMetadata();
            if (eventMeta.containsKey("targetResource")) {
                learningContext.put("targetResource", eventMeta.get("targetResource"));
            }
            if (eventMeta.containsKey("requestMethod")) {
                learningContext.put("requestMethod", eventMeta.get("requestMethod"));
            }
        }

        if (event.getAnalysisContext() != null) {
            learningContext.put("analysisContext", event.getAnalysisContext());
        }

        return LearningMetadata.builder()
                .isLearnable(true)
                .learningType(LearningMetadata.LearningType.THREAT_RESPONSE)
                .priority(priority)
                .confidenceScore(event.getConfidence())
                .status(LearningMetadata.LearningStatus.PENDING)
                .createdAt(LocalDateTime.now())
                .learningContext(learningContext)
                .build();
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
                metadata.getConfidenceScore() >= securityAutonomousProperties.getLearning().getEvolution().getConfidenceThreshold() &&
                metadata.getStatus() == LearningMetadata.LearningStatus.PENDING;
    }

    private boolean checkDailyLimit() {
        String today = LocalDateTime.now().toLocalDate().toString();
        int maxProposals = securityAutonomousProperties.getLearning().getEvolution().getMaxProposals();

        dailyProposalCount.entrySet().removeIf(entry -> !entry.getKey().equals(today));

        int currentCount = dailyProposalCount.getOrDefault(today, 0);
        if (currentCount >= maxProposals) {
            if (evolutionMetricsCollector != null) {
                evolutionMetricsCollector.recordDailyLimitReached();
            }
            return false;
        }

        dailyProposalCount.merge(today, 1, Integer::sum);
        return true;
    }

    private void triggerPolicyEvolution(SecurityEvent securityEvent, LearningMetadata metadata) {
        try {

            PolicyEvolutionProposal proposal = evolutionEngine.evolvePolicy(securityEvent, metadata);

            proposal = proposalRepository.save(proposal);

            totalProposalsGenerated.incrementAndGet();

            metadata.markAsCompleted("Policy proposal generated: " + proposal.getId());

            try {
                governanceService.evaluateProposal(proposal.getId());
            } catch (Exception ge) {
                log.error("Governance evaluation failed for proposal: {}", proposal.getId(), ge);
            }

        } catch (Exception e) {
            log.error("Policy evolution failed", e);
            metadata.markAsFailed(e.getMessage());
        }
    }

    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalEventsProcessed", totalEventsProcessed.get());
        stats.put("totalProposalsGenerated", totalProposalsGenerated.get());
        stats.put("dailyProposalCount", dailyProposalCount.getOrDefault(
                LocalDateTime.now().toLocalDate().toString(), 0
        ));
        stats.put("enabled", securityAutonomousProperties.getLearning().isEnabled());
        stats.put("confidenceThreshold", securityAutonomousProperties.getLearning().getEvolution().getConfidenceThreshold());
        return stats;
    }
}