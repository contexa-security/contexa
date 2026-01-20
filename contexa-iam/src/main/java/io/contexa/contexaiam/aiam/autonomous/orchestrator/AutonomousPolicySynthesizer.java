package io.contexa.contexaiam.aiam.autonomous.orchestrator;

import io.contexa.contexacore.autonomous.IPolicyProposalManagementService;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.autonomous.event.DynamicThreatResponseEvent;
import io.contexa.contexacore.autonomous.event.LearnableEvent;
import io.contexa.contexacore.autonomous.event.StaticAccessAnalysisEvent;
import io.contexa.contexacoreenterprise.autonomous.evolution.PolicyEvolutionLabIntegration;
import io.contexa.contexacore.std.labs.AILabFactory;
import io.contexa.contexaiam.aiam.labs.synthesis.DynamicThreatResponseSynthesisLab;
import io.contexa.contexaiam.aiam.service.StaticAccessOptimizationService;
import io.contexa.contexaiam.aiam.protocol.request.StaticAccessOptimizationRequest;
import io.contexa.contexaiam.aiam.protocol.response.StaticAccessOptimizationResponse;
import io.contexa.contexaiam.aiam.protocol.request.DynamicThreatResponseRequest;
import io.contexa.contexaiam.aiam.protocol.response.DynamicThreatResponseResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;


@Slf4j
@RequiredArgsConstructor
public class AutonomousPolicySynthesizer {

    private final IPolicyProposalManagementService proposalManagementService;
    private final PolicyEvolutionLabIntegration labIntegration;
    private final DynamicThreatResponseSynthesisLab dynamicThreatLab;
    private final StaticAccessOptimizationService staticAccessService;
    private final ApplicationEventPublisher eventPublisher;
    private final AILabFactory labFactory;
    
    
    private final AtomicInteger totalEventsProcessed = new AtomicInteger(0);
    private final AtomicInteger proposalsGenerated = new AtomicInteger(0);
    private final AtomicInteger proposalsSubmitted = new AtomicInteger(0);
    private final Map<LearnableEvent.EventType, Integer> eventTypeCount = new ConcurrentHashMap<>();
    private final Map<String, LocalDateTime> lastProcessedTime = new ConcurrentHashMap<>();
    
    
    @EventListener
    @Async
    public void handleLearnableEvent(LearnableEvent event) {
        log.info("[자율 정책 합성] 학습 가능한 이벤트 수신: {} (ID: {})", 
                event.getEventType(), event.getEventId());
        
        try {
            
            totalEventsProcessed.incrementAndGet();
            eventTypeCount.merge(event.getEventType(), 1, Integer::sum);
            lastProcessedTime.put(event.getEventType().toString(), LocalDateTime.now());
            
            
            if (!event.requiresPolicyGeneration()) {
                log.info("[자율 정책 합성] 이벤트 {}는 정책 생성이 필요하지 않음", event.getEventId());
                return;
            }
            
            
            switch (event.getEventType()) {
                case DYNAMIC_THREAT_RESPONSE:
                    handleDynamicThreatResponse((DynamicThreatResponseEvent) event);
                    break;
                    
                case STATIC_ACCESS_ANALYSIS:
                    handleStaticAccessAnalysis((StaticAccessAnalysisEvent) event);
                    break;
                    
                case PERFORMANCE_ANOMALY:
                    handlePerformanceAnomaly(event);
                    break;
                    
                case COMPLIANCE_VIOLATION:
                    handleComplianceViolation(event);
                    break;
                    
                case USER_BEHAVIOR_ANOMALY:
                    handleUserBehaviorAnomaly(event);
                    break;
                    
                default:
                    log.warn("[자율 정책 합성] 처리되지 않은 이벤트 타입: {}", event.getEventType());
            }
            
        } catch (Exception e) {
            log.error("[자율 정책 합성] 이벤트 처리 실패: {}", event.getEventId(), e);
            publishProcessingError(event, e);
        }
    }
    
    
    private void handleDynamicThreatResponse(DynamicThreatResponseEvent event) {
        log.info("[자율 정책 합성] 동적 위협 대응 처리 시작: {}", event.getEventId());
        
        CompletableFuture.runAsync(() -> {
            try {
                
                DynamicThreatResponseRequest request = DynamicThreatResponseRequest.fromEvent(event);
                
                
                DynamicThreatResponseResponse response = dynamicThreatLab.process(request);
                
                if (response != null && response.isValidProposal()) {
                    
                    PolicyEvolutionProposal proposal = convertToEvolutionProposal(response);
                    
                    
                    Long proposalId = proposalManagementService.submitProposal(proposal);
                    
                    log.info("[자율 정책 합성] 정책 제안 제출 완료: ID = {}", proposalId);
                    proposalsGenerated.incrementAndGet();
                    proposalsSubmitted.incrementAndGet();
                    
                    
                    publishProposalGeneratedEvent(proposalId, event, response);
                } else {
                    log.warn("[자율 정책 합성] 유효하지 않은 제안: {}", event.getEventId());
                }
                
            } catch (Exception e) {
                log.error("[자율 정책 합성] 동적 위협 대응 처리 실패", e);
            }
        });
    }
    
    
    private void handleStaticAccessAnalysis(StaticAccessAnalysisEvent event) {
        log.info("[자율 정책 합성] 정적 접근 분석 처리 시작: {}", event.getEventId());
        
        CompletableFuture.runAsync(() -> {
            try {
                
                StaticAccessOptimizationRequest request = StaticAccessOptimizationRequest.fromEvent(event);
                
                
                StaticAccessOptimizationResponse response = staticAccessService.process(request);
                
                if (response != null && response.getStatus().equals("COMPLETED")) {
                    
                    PolicyEvolutionProposal proposal = convertStaticAccessResponseToProposal(response);
                    
                    
                    Long proposalId = proposalManagementService.submitProposal(proposal);
                    
                    log.info("[자율 정책 합성] 정적 접근 최적화 정책 제안 제출 완료: ID = {}", proposalId);
                    proposalsGenerated.incrementAndGet();
                    proposalsSubmitted.incrementAndGet();
                    
                    
                    publishProposalGeneratedEvent(proposalId, event, response);
                } else {
                    log.warn("[자율 정책 합성] 정적 접근 최적화 실패: {}", event.getEventId());
                }
                
            } catch (Exception e) {
                log.error("[자율 정책 합성] 정적 접근 분석 처리 실패", e);
            }
        });
    }
    
    
    private void handlePerformanceAnomaly(LearnableEvent event) {
        log.info("[자율 정책 합성] 성능 이상 처리: {}", event.getEventId());
        
    }
    
    
    private void handleComplianceViolation(LearnableEvent event) {
        log.info("[자율 정책 합성] 컴플라이언스 위반 처리: {}", event.getEventId());
        
    }
    
    
    private void handleUserBehaviorAnomaly(LearnableEvent event) {
        log.info("[자율 정책 합성] 사용자 행동 이상 처리: {}", event.getEventId());
        
    }
    
    
    private PolicyEvolutionProposal convertStaticAccessResponseToProposal(StaticAccessOptimizationResponse response) {
        PolicyEvolutionProposal proposal = new PolicyEvolutionProposal();
        
        StaticAccessOptimizationResponse.PolicyProposal policyProposal = response.getPolicyProposal();
        
        if (policyProposal != null) {
            proposal.setTitle(policyProposal.getTitle());
            proposal.setDescription(policyProposal.getDescription());
            proposal.setProposalType(mapProposalType(policyProposal.getActionType()));
            proposal.setRiskLevel(mapRiskLevel(policyProposal.getRiskLevel()));
            
            proposal.setSpelExpression(response.getSpelExpression());
            proposal.setRationale(policyProposal.getAiRationale());
            proposal.setExpectedImpact(response.getAiConfidenceScore());
            proposal.setCreatedBy("AutonomousPolicySynthesizer");
            proposal.setCreatedAt(LocalDateTime.now());

            
            Map<String, Object> metadata = new HashMap<>();
            metadata.put("proposalId", policyProposal.getProposalId());
            metadata.put("optimizationStrategy", response.getOptimizationStrategy());
            metadata.put("confidenceScore", response.getAiConfidenceScore());
            if (response.getEffectPrediction() != null) {
                metadata.put("accessReductionRate", response.getEffectPrediction().getAccessReductionRate());
                metadata.put("securityImprovement", response.getEffectPrediction().getSecurityImprovement());
                metadata.put("complianceScore", response.getEffectPrediction().getComplianceScore());
            }
            proposal.setMetadata(metadata);
        }
        
        return proposal;
    }
    
    
    private PolicyEvolutionProposal convertToEvolutionProposal(DynamicThreatResponseResponse response) {
        PolicyEvolutionProposal proposal = new PolicyEvolutionProposal();
        
        DynamicThreatResponseResponse.PolicyProposal policyProposal = response.getPolicyProposal();
        
        proposal.setTitle(policyProposal.getTitle());
        proposal.setDescription(policyProposal.getDescription());
        proposal.setProposalType(mapProposalType(policyProposal.getActionType()));
        proposal.setRiskLevel(mapRiskLevel(policyProposal.getRiskLevel()));
        
        proposal.setSpelExpression(response.getSpelExpression());
        proposal.setRationale(policyProposal.getAiRationale());
        proposal.setExpectedImpact(response.getAiConfidenceScore());
        proposal.setCreatedBy("AutonomousPolicySynthesizer");
        proposal.setCreatedAt(LocalDateTime.now());

        
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("proposalId", policyProposal.getProposalId());
        metadata.put("strategicPrinciple", response.getStrategicPrinciple());
        metadata.put("confidenceScore", response.getAiConfidenceScore());
        if (response.getEffectPrediction() != null) {
            metadata.put("threatReductionRate", response.getEffectPrediction().getThreatReductionRate());
            metadata.put("falsePositiveRate", response.getEffectPrediction().getFalsePositiveRate());
        }
        proposal.setMetadata(metadata);
        
        return proposal;
    }
    
    
    private PolicyEvolutionProposal.ProposalType mapProposalType(String actionType) {
        if (actionType == null) return PolicyEvolutionProposal.ProposalType.CREATE_POLICY;
        
        switch (actionType.toUpperCase()) {
            case "CREATE":
                return PolicyEvolutionProposal.ProposalType.CREATE_POLICY;
            case "MODIFY":
                return PolicyEvolutionProposal.ProposalType.UPDATE_POLICY;
            case "REVOKE":
            case "DELETE":
                return PolicyEvolutionProposal.ProposalType.DELETE_POLICY;
            default:
                return PolicyEvolutionProposal.ProposalType.CREATE_POLICY;
        }
    }
    
    
    private PolicyEvolutionProposal.RiskLevel mapRiskLevel(String riskLevel) {
        if (riskLevel == null) return PolicyEvolutionProposal.RiskLevel.MEDIUM;
        
        try {
            return PolicyEvolutionProposal.RiskLevel.valueOf(riskLevel.toUpperCase());
        } catch (IllegalArgumentException e) {
            return PolicyEvolutionProposal.RiskLevel.MEDIUM;
        }
    }
    
    
    private void publishProposalGeneratedEvent(Long proposalId, LearnableEvent sourceEvent, Object response) {
        Map<String, Object> eventData = new HashMap<>();
        eventData.put("proposalId", proposalId);
        eventData.put("sourceEventId", sourceEvent.getEventId());
        eventData.put("sourceEventType", sourceEvent.getEventType());
        eventData.put("timestamp", LocalDateTime.now());
        
        log.info("[자율 정책 합성] 제안 생성 이벤트 발행: {}", proposalId);
        
    }
    
    
    private void publishProcessingError(LearnableEvent event, Exception error) {
        log.error("[자율 정책 합성] 처리 오류 이벤트 발행: {}", event.getEventId());
        
    }
    
    

    public void reportMetrics() {
        log.info("[자율 정책 합성 메트릭]");
        log.info("- 총 처리 이벤트: {}", totalEventsProcessed.get());
        log.info("- 생성된 제안: {}", proposalsGenerated.get());
        log.info("- 제출된 제안: {}", proposalsSubmitted.get());
        log.info("- 이벤트 타입별 카운트: {}", eventTypeCount);
        log.info("- 마지막 처리 시간: {}", lastProcessedTime);
    }
    
    
    public Map<String, Object> getSystemStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("totalEventsProcessed", totalEventsProcessed.get());
        status.put("proposalsGenerated", proposalsGenerated.get());
        status.put("proposalsSubmitted", proposalsSubmitted.get());
        status.put("eventTypeDistribution", new HashMap<>(eventTypeCount));
        status.put("lastProcessedTimes", new HashMap<>(lastProcessedTime));
        status.put("isActive", true);
        return status;
    }
}