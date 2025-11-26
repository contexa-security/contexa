package io.contexa.contexacoreenterprise.autonomous.evolution;

import io.contexa.contexacore.autonomous.IPolicyProposalManagementService;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal.ProposalType;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal.RiskLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import reactor.core.publisher.Flux;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;

/**
 * 정책 진화 시스템과 AI Lab 통합 서비스
 * Lab의 분석 결과를 정책 진화 제안으로 변환하고 제출
 * 
 * @author contexa
 * @since 1.0.0
 */
@Slf4j
@RequiredArgsConstructor
public class PolicyEvolutionLabIntegration {

    private final IPolicyProposalManagementService proposalManagementService;
    private final ApplicationEventPublisher eventPublisher;
    
    /**
     * Lab 분석 결과를 정책 제안으로 변환
     */
    public PolicyEvolutionProposal convertLabAnalysisToProposal(
            String labName, 
            Map<String, Object> analysisResult) {
        
        log.info("Converting lab analysis from {} to policy proposal", labName);
        
        PolicyEvolutionProposal proposal = new PolicyEvolutionProposal();
        
        // 기본 정보 설정
        proposal.setTitle(generateTitle(labName, analysisResult));
        proposal.setDescription(generateDescription(labName, analysisResult));
        proposal.setCreatedBy(labName);
        proposal.setCreatedAt(LocalDateTime.now());
        
        // Lab별 특화 설정
        configureProposalByLab(proposal, labName, analysisResult);
        
        // 위험 수준 평가
        RiskLevel riskLevel = assessRiskLevel(labName, analysisResult);
        proposal.setRiskLevel(riskLevel);
        
        // 제안 타입 결정
        ProposalType proposalType = determineProposalType(labName, analysisResult);
        proposal.setProposalType(proposalType);
        
        // 정책 내용 생성
        String policyContent = generatePolicyContent(labName, analysisResult);
        proposal.setPolicyContent(policyContent);
        
        // 예상 영향도 계산
        double expectedImpact = calculateExpectedImpact(labName, analysisResult);
        proposal.setExpectedImpact(expectedImpact);
        
        // 근거 생성
        String rationale = generateRationale(labName, analysisResult);
        proposal.setRationale(rationale);
        
        return proposal;
    }
    
    /**
     * Lab 분석 결과를 비동기로 제출
     */
    public CompletableFuture<Long> submitLabAnalysisAsync(
            String labName, 
            Map<String, Object> analysisResult) {
        
        return CompletableFuture.supplyAsync(() -> {
            try {
                PolicyEvolutionProposal proposal = convertLabAnalysisToProposal(labName, analysisResult);
                Long proposalId = proposalManagementService.submitProposal(proposal);

                log.info("Lab analysis from {} submitted as proposal {}", labName, proposalId);

                // 이벤트 발행
                publishLabProposalEvent(labName, proposalId, proposal);

                return proposalId;

            } catch (Exception e) {
                log.error("Failed to submit lab analysis from {}", labName, e);
                throw new RuntimeException("Lab analysis submission failed", e);
            }
        });
    }
    
    /**
     * 다중 Lab 분석 결과 병합 및 제출
     */
    public CompletableFuture<List<Long>> submitMultipleLabAnalyses(
            Map<String, Map<String, Object>> labAnalyses) {
        
        List<CompletableFuture<Long>> futures = new ArrayList<>();
        
        for (Map.Entry<String, Map<String, Object>> entry : labAnalyses.entrySet()) {
            String labName = entry.getKey();
            Map<String, Object> analysisResult = entry.getValue();
            
            CompletableFuture<Long> future = submitLabAnalysisAsync(labName, analysisResult);
            futures.add(future);
        }
        
        return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
            .thenApply(v -> futures.stream()
                .map(CompletableFuture::join)
                .collect(java.util.stream.Collectors.toList()));
    }
    
    /**
     * 스트리밍 분석 결과 처리
     */
    public Flux<PolicyEvolutionProposal> processStreamingAnalysis(
            String labName,
            Flux<Map<String, Object>> analysisStream) {
        
        return analysisStream
            .buffer(10) // 10개씩 배치 처리
            .flatMap(batch -> {
                List<PolicyEvolutionProposal> proposals = new ArrayList<>();
                
                for (Map<String, Object> analysis : batch) {
                    try {
                        PolicyEvolutionProposal proposal = convertLabAnalysisToProposal(labName, analysis);
                        proposals.add(proposal);
                    } catch (Exception e) {
                        log.error("Error processing streaming analysis from {}", labName, e);
                    }
                }
                
                return Flux.fromIterable(proposals);
            })
            .doOnNext(proposal -> {
                try {
                    proposalManagementService.submitProposal(proposal);
                    log.debug("Streaming proposal submitted: {}", proposal.getTitle());
                } catch (Exception e) {
                    log.error("Failed to submit streaming proposal", e);
                }
            });
    }
    
    /**
     * Lab별 특화 처리기 등록
     */
    public static class LabHandlerRegistry {
        private final Map<String, LabHandler> handlers = new HashMap<>();
        
        public void registerHandler(String labName, LabHandler handler) {
            handlers.put(labName, handler);
        }
        
        public LabHandler getHandler(String labName) {
            return handlers.getOrDefault(labName, new DefaultLabHandler());
        }
    }
    
    /**
     * Lab 처리기 인터페이스
     */
    public interface LabHandler {
        ProposalType determineProposalType(Map<String, Object> analysisResult);
        RiskLevel assessRiskLevel(Map<String, Object> analysisResult);
        String generatePolicyContent(Map<String, Object> analysisResult);
        double calculateExpectedImpact(Map<String, Object> analysisResult);
    }
    
    /**
     * 기본 Lab 처리기
     */
    public static class DefaultLabHandler implements LabHandler {
        @Override
        public ProposalType determineProposalType(Map<String, Object> analysisResult) {
            return ProposalType.OPTIMIZATION;
        }
        
        @Override
        public RiskLevel assessRiskLevel(Map<String, Object> analysisResult) {
            return RiskLevel.MEDIUM;
        }
        
        @Override
        public String generatePolicyContent(Map<String, Object> analysisResult) {
            return "Policy content generated from lab analysis";
        }
        
        @Override
        public double calculateExpectedImpact(Map<String, Object> analysisResult) {
            return 50.0;
        }
    }
    
    /**
     * 특화 Lab 처리기들
     */
    public static class ThreatDetectionLabHandler implements LabHandler {
        @Override
        public ProposalType determineProposalType(Map<String, Object> analysisResult) {
            Integer threatLevel = (Integer) analysisResult.getOrDefault("threatLevel", 5);
            if (threatLevel >= 8) {
                return ProposalType.THREAT_RESPONSE;
            } else if (threatLevel >= 5) {
                return ProposalType.INCIDENT_RESPONSE;
            }
            return ProposalType.OPTIMIZATION;
        }
        
        @Override
        public RiskLevel assessRiskLevel(Map<String, Object> analysisResult) {
            Integer threatLevel = (Integer) analysisResult.getOrDefault("threatLevel", 5);
            if (threatLevel >= 9) return RiskLevel.CRITICAL;
            if (threatLevel >= 7) return RiskLevel.HIGH;
            if (threatLevel >= 5) return RiskLevel.MEDIUM;
            return RiskLevel.LOW;
        }
        
        @Override
        public String generatePolicyContent(Map<String, Object> analysisResult) {
            String threatType = (String) analysisResult.getOrDefault("threatType", "unknown");
            String mitigation = (String) analysisResult.getOrDefault("mitigation", "standard");
            
            return String.format(
                "Threat Response Policy:\n" +
                "- Threat Type: %s\n" +
                "- Mitigation Strategy: %s\n" +
                "- Auto-response enabled for immediate threat containment",
                threatType, mitigation
            );
        }
        
        @Override
        public double calculateExpectedImpact(Map<String, Object> analysisResult) {
            Integer threatLevel = (Integer) analysisResult.getOrDefault("threatLevel", 5);
            return Math.min(100, threatLevel * 12.5);
        }
    }
    
    public static class ComplianceLabHandler implements LabHandler {
        @Override
        public ProposalType determineProposalType(Map<String, Object> analysisResult) {
            return ProposalType.COMPLIANCE;
        }
        
        @Override
        public RiskLevel assessRiskLevel(Map<String, Object> analysisResult) {
            Boolean isRegulatory = (Boolean) analysisResult.getOrDefault("isRegulatory", false);
            return isRegulatory ? RiskLevel.HIGH : RiskLevel.MEDIUM;
        }
        
        @Override
        public String generatePolicyContent(Map<String, Object> analysisResult) {
            String regulation = (String) analysisResult.getOrDefault("regulation", "general");
            List<String> requirements = (List<String>) analysisResult.getOrDefault("requirements", new ArrayList<>());
            
            StringBuilder content = new StringBuilder();
            content.append("Compliance Policy for ").append(regulation).append(":\n");
            for (String req : requirements) {
                content.append("- ").append(req).append("\n");
            }
            
            return content.toString();
        }
        
        @Override
        public double calculateExpectedImpact(Map<String, Object> analysisResult) {
            Boolean isRegulatory = (Boolean) analysisResult.getOrDefault("isRegulatory", false);
            return isRegulatory ? 85.0 : 60.0;
        }
    }
    
    public static class BehaviorAnalysisLabHandler implements LabHandler {
        @Override
        public ProposalType determineProposalType(Map<String, Object> analysisResult) {
            Boolean isAnomaly = (Boolean) analysisResult.getOrDefault("isAnomaly", false);
            return isAnomaly ? ProposalType.ANOMALY_RESPONSE : ProposalType.USER_BEHAVIOR;
        }
        
        @Override
        public RiskLevel assessRiskLevel(Map<String, Object> analysisResult) {
            Double anomalyScore = (Double) analysisResult.getOrDefault("anomalyScore", 0.5);
            if (anomalyScore > 0.8) return RiskLevel.HIGH;
            if (anomalyScore > 0.6) return RiskLevel.MEDIUM;
            return RiskLevel.LOW;
        }
        
        @Override
        public String generatePolicyContent(Map<String, Object> analysisResult) {
            String behaviorPattern = (String) analysisResult.getOrDefault("pattern", "normal");
            Double anomalyScore = (Double) analysisResult.getOrDefault("anomalyScore", 0.5);
            
            return String.format(
                "Behavior Analysis Policy:\n" +
                "- Pattern: %s\n" +
                "- Anomaly Score: %.2f\n" +
                "- Adaptive response based on user behavior patterns",
                behaviorPattern, anomalyScore
            );
        }
        
        @Override
        public double calculateExpectedImpact(Map<String, Object> analysisResult) {
            Double anomalyScore = (Double) analysisResult.getOrDefault("anomalyScore", 0.5);
            return anomalyScore * 100;
        }
    }
    
    /**
     * Helper 메서드들
     */
    private String generateTitle(String labName, Map<String, Object> analysisResult) {
        String baseTitle = labName.replace("Lab", "") + " Policy Proposal";
        String context = (String) analysisResult.getOrDefault("context", "");
        
        if (!context.isEmpty()) {
            return baseTitle + ": " + context;
        }
        return baseTitle;
    }
    
    private String generateDescription(String labName, Map<String, Object> analysisResult) {
        return String.format(
            "Automated policy proposal generated by %s based on analysis results. " +
            "Analysis timestamp: %s",
            labName, LocalDateTime.now()
        );
    }
    
    private void configureProposalByLab(PolicyEvolutionProposal proposal, 
                                       String labName, 
                                       Map<String, Object> analysisResult) {
        // Lab별 특화 설정
        switch (labName) {
            case "ThreatDetectionLab":
                proposal.getMetadata().put("threatIndicators", 
                    analysisResult.getOrDefault("indicators", new ArrayList<>()));
                break;
                
            case "ComplianceLab":
                proposal.getMetadata().put("complianceFramework", 
                    analysisResult.getOrDefault("framework", ""));
                break;
                
            case "BehaviorAnalysisLab":
                proposal.getMetadata().put("behaviorProfile", 
                    analysisResult.getOrDefault("profile", new HashMap<>()));
                break;
                
            default:
                proposal.getMetadata().put("labAnalysis", analysisResult);
        }
    }
    
    private RiskLevel assessRiskLevel(String labName, Map<String, Object> analysisResult) {
        // Lab별 위험 수준 평가 로직
        Object severityObj = analysisResult.get("severity");
        if (severityObj instanceof Number) {
            int severity = ((Number) severityObj).intValue();
            if (severity >= 9) return RiskLevel.CRITICAL;
            if (severity >= 7) return RiskLevel.HIGH;
            if (severity >= 5) return RiskLevel.MEDIUM;
            return RiskLevel.LOW;
        }
        
        // 기본값
        return RiskLevel.MEDIUM;
    }
    
    private ProposalType determineProposalType(String labName, Map<String, Object> analysisResult) {
        // Lab 이름 기반 타입 결정
        if (labName.contains("Threat")) return ProposalType.THREAT_RESPONSE;
        if (labName.contains("Compliance")) return ProposalType.COMPLIANCE;
        if (labName.contains("Behavior")) return ProposalType.USER_BEHAVIOR;
        if (labName.contains("Access")) return ProposalType.ACCESS_CONTROL;
        if (labName.contains("Data")) return ProposalType.DATA_PROTECTION;
        if (labName.contains("Incident")) return ProposalType.INCIDENT_RESPONSE;
        
        return ProposalType.OPTIMIZATION;
    }
    
    private String generatePolicyContent(String labName, Map<String, Object> analysisResult) {
        StringBuilder content = new StringBuilder();
        content.append("Policy generated by ").append(labName).append("\n\n");
        
        // 분석 결과 주요 항목 포함
        content.append("Key Findings:\n");
        for (Map.Entry<String, Object> entry : analysisResult.entrySet()) {
            if (isKeyFinding(entry.getKey())) {
                content.append("- ").append(entry.getKey()).append(": ")
                      .append(entry.getValue()).append("\n");
            }
        }
        
        // SpEL 표현식 예시
        content.append("\nPolicy Rules:\n");
        content.append("- hasRole('ADMIN') or hasAuthority('POLICY_OVERRIDE')\n");
        content.append("- @securityService.validateAccess(#request)\n");
        
        return content.toString();
    }
    
    private boolean isKeyFinding(String key) {
        List<String> keyFindings = Arrays.asList(
            "threat", "risk", "severity", "impact", "compliance", 
            "anomaly", "violation", "recommendation"
        );
        
        return keyFindings.stream().anyMatch(key.toLowerCase()::contains);
    }
    
    private double calculateExpectedImpact(String labName, Map<String, Object> analysisResult) {
        // 기본 영향도 계산
        double baseImpact = 50.0;
        
        // 심각도 기반 조정
        Object severityObj = analysisResult.get("severity");
        if (severityObj instanceof Number) {
            baseImpact += ((Number) severityObj).doubleValue() * 5;
        }
        
        // 영향 범위 기반 조정
        Object scopeObj = analysisResult.get("affectedScope");
        if (scopeObj instanceof Number) {
            baseImpact += ((Number) scopeObj).doubleValue() * 3;
        }
        
        return Math.min(100, baseImpact);
    }
    
    private String generateRationale(String labName, Map<String, Object> analysisResult) {
        StringBuilder rationale = new StringBuilder();
        rationale.append("This policy proposal is based on automated analysis by ")
                .append(labName).append(". ");
        
        // 주요 근거 추가
        Object mainReason = analysisResult.get("primaryReason");
        if (mainReason != null) {
            rationale.append("Primary reason: ").append(mainReason).append(". ");
        }
        
        // 증거 기반 근거
        Object evidence = analysisResult.get("evidence");
        if (evidence instanceof List) {
            List<?> evidenceList = (List<?>) evidence;
            if (!evidenceList.isEmpty()) {
                rationale.append("Supporting evidence: ")
                        .append(evidenceList.size()).append(" data points analyzed.");
            }
        }
        
        return rationale.toString();
    }
    
    private void publishLabProposalEvent(String labName, Long proposalId, PolicyEvolutionProposal proposal) {
        LabProposalEvent event = new LabProposalEvent(this, labName, proposalId, proposal);
        eventPublisher.publishEvent(event);
    }
    
    /**
     * Lab 제안 이벤트
     */
    public static class LabProposalEvent {
        private final Object source;
        private final String labName;
        private final Long proposalId;
        private final PolicyEvolutionProposal proposal;
        private final LocalDateTime timestamp;
        
        public LabProposalEvent(Object source, String labName, Long proposalId, PolicyEvolutionProposal proposal) {
            this.source = source;
            this.labName = labName;
            this.proposalId = proposalId;
            this.proposal = proposal;
            this.timestamp = LocalDateTime.now();
        }
        
        // Getters
        public Object getSource() { return source; }
        public String getLabName() { return labName; }
        public Long getProposalId() { return proposalId; }
        public PolicyEvolutionProposal getProposal() { return proposal; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
}