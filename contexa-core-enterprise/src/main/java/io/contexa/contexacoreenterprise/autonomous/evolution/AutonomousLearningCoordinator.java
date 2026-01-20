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
    private final PolicyEvolutionEngine policyEvolutionEngine; 
    private final AITuningService tuningService;
    private final AITuningService aiTuningService; 
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
        this.policyEvolutionEngine = evolutionEngine; 
        this.tuningService = tuningService;
        this.aiTuningService = tuningService; 
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
            log.debug("학습 코디네이터가 비활성화되어 있습니다");
            return;
        }

        log.info("인시던트 해결 이벤트 수신 - IncidentId: {}", event.getIncidentId());
        long startTime = System.currentTimeMillis();

        try {
            
            SecurityEvent securityEvent = event.getSecurityEvent();
            if (securityEvent == null) {
                log.warn("보안 이벤트가 없습니다: {}", event.getIncidentId());
                return;
            }

            
            LearningMetadata metadata = extractLearningMetadata(event);

            
            if (!canLearn(metadata)) {
                log.info("학습 조건을 만족하지 않습니다. Confidence: {}", metadata.getConfidenceScore());

                
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
                log.warn("일일 제안 생성 한도 초과");

                
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
                .comment("자동 학습 피드백")
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
            log.error("인시던트 학습 처리 실패", e);

            
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
        
        log.info("주기적 최적화 시작");
        
        try {
            totalLearningCycles.incrementAndGet();
            
            
            analyzeSystemState();
            
            
            detectExcessivePermissions();
            
            
            identifyUnusedPolicies();
            
            
            suggestPerformanceOptimizations();
            
            
            cleanupExpiredProposals();
            
            log.info("주기적 최적화 완료");
            
        } catch (Exception e) {
            log.error("주기적 최적화 실패", e);
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
        log.info("[자율 학습] 사건 {}에서 학습 시작", metadata.getIncidentId());

        
        if (aiTuningService != null) {
            Map<String, Object> tuningMetadata = new HashMap<>();
            tuningMetadata.put("incidentId", metadata.getIncidentId());
            tuningMetadata.put("successful", metadata.getStatus() == LearningMetadata.LearningStatus.COMPLETED);
            tuningMetadata.put("resolution", metadata.getStatus().toString());
            tuningMetadata.put("timestamp", LocalDateTime.now());

            aiTuningService.tuneFromIncident(incident, tuningMetadata)
                .subscribe(
                    result -> log.debug("인시던트 학습 완료: {}", result.getMessage()),
                    error -> log.warn("인시던트 학습 실패", error)
                );
        }

        
        metadata.setStatus(LearningMetadata.LearningStatus.COMPLETED);
        metadata.setCompletedAt(LocalDateTime.now());
    }

    
    private void requestPolicyEvolution(LearningMetadata metadata, SoarIncident incident, SecurityEvent securityEvent) {
        if (policyEvolutionEngine == null) {
            log.warn("[자율 학습] PolicyEvolutionEngine을 사용할 수 없습니다");
            return;
        }

        try {
            PolicyEvolutionProposal proposal = null;

            
            if (incident != null) {
                io.contexa.contexacore.domain.SoarIncidentDto incidentDto = convertEntityToDomain(incident);
                proposal = policyEvolutionEngine.evolvePolicy(incidentDto, metadata);
            } else if (securityEvent != null) {
                proposal = policyEvolutionEngine.evolvePolicy(securityEvent, metadata);
            }

            if (proposal != null) {
                proposalRepository.save(proposal);
                proposalsGenerated.incrementAndGet();
                log.info("[자율 학습] 정책 진화 제안 생성: {}", proposal.getId());
            }
        } catch (Exception e) {
            log.error("[자율 학습] 정책 진화 요청 실패", e);
        }
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
                log.warn("알 수 없는 IncidentType: {}, OTHER로 대체", entity.getType());
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
                log.warn("알 수 없는 Severity: {}, MEDIUM으로 대체", entity.getSeverity());
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
                log.warn("알 수 없는 Status: {}, NEW로 대체", entity.getStatus());
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
            log.info("정책 진화 트리거 - EventId: {}, LearningType: {}", 
                     securityEvent.getEventId(), metadata.getLearningType());
            
            
            PolicyEvolutionProposal proposal = evolutionEngine.evolvePolicy(securityEvent, metadata);
            
            
            proposal = proposalRepository.save(proposal);
            
            
            totalProposalsGenerated.incrementAndGet();
            
            
            metadata.markAsCompleted("정책 제안 생성 완료: " + proposal.getId());
            
            log.info("정책 제안 생성 완료 - ProposalId: {}, Type: {}, Risk: {}", 
                     proposal.getId(), proposal.getProposalType(), proposal.getRiskLevel());
            
        } catch (Exception e) {
            log.error("정책 진화 실패", e);
            metadata.markAsFailed(e.getMessage());
        }
    }
    
    
    private void analyzeSystemState() {
        log.debug("시스템 상태 분석 시작");
        
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
                    log.warn("높은 위협 수준 감지: {}", threatLevel);
                    createSystemStateProposal("HIGH_THREAT", systemState);
                }

                Long activeIncidents = (Long) systemState.get("activeIncidents");
                if (activeIncidents != null && activeIncidents > maxActiveIncidents) {
                    log.warn("많은 활성 인시던트 감지: {}", activeIncidents);
                    createSystemStateProposal("MANY_INCIDENTS", systemState);
                }

                
                Double eventRate = (Double) systemState.get("eventRatePerMinute");
                if (eventRate != null && eventRate > 100) {
                    log.warn("높은 이벤트 발생률 감지: {} events/min", eventRate);
                    createSystemStateProposal("HIGH_EVENT_RATE", systemState);
                }
            }
            
        } catch (Exception e) {
            log.error("시스템 상태 분석 실패", e);
        }
    }
    
    
    private void detectExcessivePermissions() {
        log.debug("과도한 권한 탐지 시작");
        
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

                log.info("AccessGovernanceLab 분석 완료: {} 개의 권한 이벤트 처리", events.size());

            } else {
                log.debug("AccessGovernanceLab 커넥터를 사용할 수 없거나 분석이 필요하지 않음");
            }
            
        } catch (Exception e) {
            log.error("과도한 권한 탐지 실패", e);
        }
    }
    
    
    private void identifyUnusedPolicies() {
        log.debug("미사용 정책 식별 시작");
        
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
                    log.info("미사용 정책 감지: {} (impact: {})", proposal.getId(), actualImpact);
                    
                    
                    PolicyEvolutionProposal deactivationProposal = PolicyEvolutionProposal.builder()
                        .title("미사용 정책 비활성화 제안")
                        .description("30일 이상 효과가 없는 정책: " + proposal.getTitle())
                        .proposalType(PolicyEvolutionProposal.ProposalType.DELETE_POLICY)
                        .parentProposalId(proposal.getId())
                        .confidenceScore(0.9)
                        .riskLevel(PolicyEvolutionProposal.RiskLevel.LOW)
                        .aiReasoning("장기간 미사용 정책은 시스템 복잡도만 증가시킵니다")
                        .createdAt(LocalDateTime.now())
                        .build();
                    
                    proposalRepository.save(deactivationProposal);
                }
            }
            
        } catch (Exception e) {
            log.error("미사용 정책 식별 실패", e);
        }
    }
    
    
    private void suggestPerformanceOptimizations() {
        log.debug("성능 최적화 제안 생성");
        
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
                    log.info("느린 정책 감지: {} ({}ms)", proposal.getId(), avgExecutionTime);

                    
                    PolicyEvolutionProposal optimizationProposal = PolicyEvolutionProposal.builder()
                        .title("정책 성능 최적화 제안")
                        .description("느린 정책 최적화 필요: " + proposal.getTitle())
                        .proposalType(PolicyEvolutionProposal.ProposalType.OPTIMIZE_RULE)
                        .parentProposalId(proposal.getId())
                        .confidenceScore(0.7)
                        .riskLevel(PolicyEvolutionProposal.RiskLevel.MEDIUM)
                        .aiReasoning("현재 평균 실행 시간이 " + avgExecutionTime + "ms로 최적화가 필요합니다")
                        .createdAt(LocalDateTime.now())
                        .build();

                    proposalRepository.save(optimizationProposal);
                }
            }
            
        } catch (Exception e) {
            log.error("성능 최적화 제안 실패", e);
        }
    }
    
    
    private void cleanupExpiredProposals() {
        log.debug("만료된 제안 정리 시작");
        
        try {
            int expiredCount = proposalRepository.expireOldProposals(LocalDateTime.now());
            if (expiredCount > 0) {
                log.info("{}개의 만료된 제안을 정리했습니다", expiredCount);
            }
            
            
            LocalDateTime deleteThreshold = LocalDateTime.now().minusDays(90);
            int deletedCount = proposalRepository.deleteOldRejectedProposals(deleteThreshold);
            if (deletedCount > 0) {
                log.info("{}개의 오래된 거부 제안을 삭제했습니다", deletedCount);
            }
            
        } catch (Exception e) {
            log.error("만료된 제안 정리 실패", e);
        }
    }
    
    
    private void createSystemStateProposal(String type, Map<String, Object> systemState) {
        try {
            
            SecurityEvent event = SecurityEvent.builder()
                .eventId(UUID.randomUUID().toString())
                .source(SecurityEvent.EventSource.ENDPOINT)
                .severity(SecurityEvent.Severity.HIGH)
                .description("시스템 상태 이상: " + type)
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
            log.error("시스템 상태 제안 생성 실패", e);
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

            log.info("PolicyApprovedEvent published: policy {} approved by {} with confidence {}",
                proposal.getId(), approvedBy, proposal.getConfidenceScore());

        } catch (Exception e) {
            log.error("Failed to approve policy proposal: {}", proposalId, e);
        }
    }

    

    public void processAutoApprovalCandidates() {
        if (!enabled) {
            return;
        }

        try {
            log.debug("Processing auto-approval candidates");

            
            List<PolicyEvolutionProposal> candidates = proposalRepository
                .findByStatus(ProposalStatus.PENDING)
                .stream()
                .filter(p -> p.getConfidenceScore() != null && p.getConfidenceScore() > confidenceThreshold)
                .toList();

            for (PolicyEvolutionProposal proposal : candidates) {
                
                if (proposal.getRiskLevel() == PolicyEvolutionProposal.RiskLevel.LOW ||
                    proposal.getRiskLevel() == PolicyEvolutionProposal.RiskLevel.MEDIUM) {

                    approvePolicyProposal(proposal.getId(), "system-auto-approval");

                    log.info("Auto-approved policy proposal: {} (confidence: {}, risk: {})",
                        proposal.getId(), proposal.getConfidenceScore(), proposal.getRiskLevel());
                }
            }

        } catch (Exception e) {
            log.error("Failed to process auto-approval candidates", e);
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
            log.debug("[자율 학습] 학습 코디네이터가 비활성화되어 있습니다");
            return;
        }

        try {
            SecurityEvent originalEvent = event.getOriginalEvent();

            log.info("[자율 학습] 처리 완료 이벤트 수신 - eventId: {}, mode: {}, layer: {}, highValue: {}",
                originalEvent.getEventId(), event.getMode(), event.getLayer(), event.isHighValueForLearning());

            
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
                PolicyEvolutionProposal proposal = policyEvolutionEngine.evolvePolicy(originalEvent, metadata);

                if (proposal != null) {
                    proposalRepository.save(proposal);
                    proposalsGenerated.incrementAndGet();

                    log.info("[자율 학습] 정책 진화 제안 생성 - proposalId: {}, eventId: {}, confidence: {}",
                        proposal.getId(), originalEvent.getEventId(), proposal.getConfidenceScore());
                } else {
                    log.debug("[자율 학습] 정책 진화 제안 생성 실패 - eventId: {}", originalEvent.getEventId());
                }
            } else {
                log.debug("[자율 학습] 정책 진화 임계값 미달 - eventId: {}, riskLevel: {}, highValue: {}",
                    originalEvent.getEventId(),
                    event.getResult() != null ? event.getResult().getCurrentRiskLevel() : "N/A",
                    event.isHighValueForLearning());
            }

            totalEventsProcessed.incrementAndGet();

        } catch (Exception e) {
            log.error("[자율 학습] ProcessingCompletedEvent 처리 실패 - eventId: {}",
                event.getOriginalEvent() != null ? event.getOriginalEvent().getEventId() : "unknown", e);
        }
    }

}