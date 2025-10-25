package io.contexa.contexacore.autonomous.scheduler;

import io.contexa.contexacore.autonomous.PolicyEvolutionService;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal.ProposalType;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal.RiskLevel;
import io.contexa.contexacore.autonomous.monitor.PolicyEffectivenessMonitor;
import io.contexa.contexacore.autonomous.monitor.PolicyProposalAnalytics;
import io.contexa.contexacore.autonomous.repository.PolicyEvolutionProposalRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

/**
 * 정책 진화 스케줄러
 * 실시간 위협 대응과 주기적 정책 최적화를 자동으로 수행
 * 
 * @author contexa
 * @since 1.0.0
 */
@Slf4j
//@Component
@RequiredArgsConstructor
public class PolicyEvolutionScheduler {
    
    private final PolicyEvolutionService evolutionService;
    private final PolicyEvolutionProposalRepository proposalRepository;
    private final PolicyEffectivenessMonitor effectivenessMonitor;
    private final PolicyProposalAnalytics proposalAnalytics;
    
    // 스케줄러 상태
    private boolean realTimeMonitoringEnabled = true;
    private boolean staticAnalysisEnabled = true;
    private LocalDateTime lastRealTimeRun = LocalDateTime.now();
    private LocalDateTime lastStaticAnalysisRun = LocalDateTime.now();
    
    /**
     * 실시간 위협 대응 (5분마다)
     * 24/7 자율 운영, 즉각적인 위협 대응
     */
//    @Scheduled(fixedDelay = 300000) // 5분
    public void performRealTimeThreatResponse() {
        if (!realTimeMonitoringEnabled) {
            log.debug("Real-time monitoring is disabled");
            return;
        }
        
        log.info("Starting real-time threat response cycle...");
        lastRealTimeRun = LocalDateTime.now();
        
        try {
            // 1. 현재 위협 상황 분석
            ThreatContext threatContext = analyzeCurrrentThreats();
            
            // 2. 긴급 대응이 필요한 경우 정책 생성
            if (threatContext.requiresImmediateResponse()) {
                generateEmergencyPolicies(threatContext);
            }
            
            // 3. 기존 정책 효과성 모니터링
            monitorPolicyEffectiveness();
            
            // 4. 비효과적인 정책 자동 개선
            improveIneffectivePolicies();
            
            // 5. 학습 및 적응
            learnFromRecentEvents();
            
            log.info("Real-time threat response cycle completed successfully");
            
        } catch (Exception e) {
            log.error("Error during real-time threat response", e);
        }
    }
    
    /**
     * 정적 분석 기반 최적화 (매일 새벽 2시)
     * 전체 정책 검토 및 최적화
     */
//    @Scheduled(cron = "0 0 2 * * *")
    public void performStaticAnalysis() {
        if (!staticAnalysisEnabled) {
            log.debug("Static analysis is disabled");
            return;
        }
        
        log.info("Starting static analysis optimization cycle...");
        lastStaticAnalysisRun = LocalDateTime.now();
        
        try {
            // 1. 전체 정책 효과성 분석
            PolicyAnalysisReport report = analyzeAllPolicies();
            
            // 2. 중복/충돌 정책 식별
            identifyAndResolvePolicyConflicts(report);
            
            // 3. 정책 통합 기회 식별
            consolidateSimilarPolicies(report);
            
            // 4. 성능 최적화 기회 식별
            optimizePolicyPerformance(report);
            
            // 5. 정책 커버리지 갭 분석
            analyzePolicyCoverageGaps(report);
            
            // 6. 최적화 제안 생성
            generateOptimizationProposals(report);
            
            log.info("Static analysis optimization cycle completed successfully");
            
        } catch (Exception e) {
            log.error("Error during static analysis", e);
        }
    }
    
    /**
     * 현재 위협 상황 분석
     */
    private ThreatContext analyzeCurrrentThreats() {
        ThreatContext context = new ThreatContext();
        
        // 최근 보안 이벤트 분석
        context.setRecentSecurityEvents(getRecentSecurityEvents());
        
        // 위협 레벨 평가
        context.setThreatLevel(evaluateThreatLevel(context.getRecentSecurityEvents()));
        
        // 영향받는 시스템 식별
        context.setAffectedSystems(identifyAffectedSystems(context.getRecentSecurityEvents()));
        
        // 대응 우선순위 설정
        context.setPriority(determinePriority(context));
        
        log.debug("Threat context analyzed: level={}, priority={}, affected systems={}",
            context.getThreatLevel(), context.getPriority(), context.getAffectedSystems().size());
        
        return context;
    }
    
    /**
     * 긴급 정책 생성
     */
    private void generateEmergencyPolicies(ThreatContext threatContext) {
        log.info("Generating emergency policies for threat level: {}", threatContext.getThreatLevel());
        
        List<PolicyEvolutionProposal> emergencyProposals = new ArrayList<>();
        
        // 위협 유형별 정책 생성
        for (SecurityEvent event : threatContext.getRecentSecurityEvents()) {
            if (event.getSeverity() >= 8) { // 높은 심각도
                PolicyEvolutionProposal proposal = createEmergencyProposal(event);
                emergencyProposals.add(proposal);
            }
        }
        
        // 비동기로 정책 제안 처리
        emergencyProposals.forEach(proposal -> {
            CompletableFuture.runAsync(() -> {
                try {
                    evolutionService.submitProposal(proposal);
                    log.info("Emergency policy submitted: {}", proposal.getTitle());
                } catch (Exception e) {
                    log.error("Failed to submit emergency policy", e);
                }
            });
        });
    }
    
    /**
     * 긴급 제안 생성
     */
    private PolicyEvolutionProposal createEmergencyProposal(SecurityEvent event) {
        PolicyEvolutionProposal proposal = new PolicyEvolutionProposal();
        
        proposal.setTitle("Emergency Response: " + event.getEventType());
        proposal.setDescription("Automated emergency policy for " + event.getDescription());
        proposal.setProposalType(determineProposalType(event));
        proposal.setRiskLevel(RiskLevel.HIGH);
        proposal.setCreatedBy("PolicyEvolutionScheduler");
        proposal.setCreatedAt(LocalDateTime.now());
        proposal.setRationale("Immediate threat detected: " + event.getThreatIndicator());
        proposal.setPolicyContent(generateEmergencyPolicyContent(event));
        proposal.setExpectedImpact(event.getSeverity() * 10.0); // 예상 영향도
        
        return proposal;
    }
    
    /**
     * 정책 효과성 모니터링
     */
    private void monitorPolicyEffectiveness() {
        List<PolicyEvolutionProposal> activeProposals = proposalRepository.findAll().stream()
            .filter(p -> p.getStatus() == PolicyEvolutionProposal.ProposalStatus.APPROVED)
            .filter(p -> p.getPolicyId() != null)
            .collect(Collectors.toList());
        
        for (PolicyEvolutionProposal proposal : activeProposals) {
            double effectiveness = effectivenessMonitor.calculateActualImpact(proposal.getId());
            
            if (effectiveness < 30.0) { // 효과성이 30% 미만
                log.warn("Policy {} has low effectiveness: {:.2f}%", 
                    proposal.getTitle(), effectiveness);
                markForImprovement(proposal);
            }
        }
    }
    
    /**
     * 비효과적인 정책 개선
     */
    private void improveIneffectivePolicies() {
        List<PolicyEvolutionProposal> ineffectiveProposals = proposalRepository.findAll().stream()
            .filter(p -> p.getStatus() == PolicyEvolutionProposal.ProposalStatus.APPROVED)
            .filter(p -> effectivenessMonitor.calculateActualImpact(p.getId()) < 40.0)
            .collect(Collectors.toList());
        
        for (PolicyEvolutionProposal original : ineffectiveProposals) {
            PolicyEvolutionProposal improvement = createImprovementProposal(original);
            
            try {
                evolutionService.submitProposal(improvement);
                log.info("Improvement proposal submitted for policy: {}", original.getTitle());
            } catch (Exception e) {
                log.error("Failed to submit improvement proposal", e);
            }
        }
    }
    
    /**
     * 개선 제안 생성
     */
    private PolicyEvolutionProposal createImprovementProposal(PolicyEvolutionProposal original) {
        PolicyEvolutionProposal improvement = new PolicyEvolutionProposal();
        
        improvement.setTitle("Improvement: " + original.getTitle());
        improvement.setDescription("Automated improvement for underperforming policy");
        improvement.setProposalType(original.getProposalType());
        improvement.setRiskLevel(RiskLevel.MEDIUM);
        improvement.setCreatedBy("PolicyEvolutionScheduler");
        improvement.setCreatedAt(LocalDateTime.now());
        improvement.setRationale("Policy effectiveness below threshold: " + 
            effectivenessMonitor.calculateActualImpact(original.getId()) + "%");
        improvement.setPolicyContent(enhancePolicyContent(original.getPolicyContent()));
        improvement.setExpectedImpact(original.getExpectedImpact() * 1.5);
        
        return improvement;
    }
    
    /**
     * 최근 이벤트로부터 학습
     */
    private void learnFromRecentEvents() {
        // 최근 승인된 정책들의 효과성 분석
        List<PolicyEvolutionProposal> recentApproved = proposalRepository.findAll().stream()
            .filter(p -> p.getStatus() == PolicyEvolutionProposal.ProposalStatus.APPROVED)
            .filter(p -> p.getApprovedAt() != null)
            .filter(p -> p.getApprovedAt().isAfter(LocalDateTime.now().minusDays(7)))
            .collect(Collectors.toList());
        
        // 패턴 학습
        Map<ProposalType, Double> typeEffectiveness = recentApproved.stream()
            .collect(Collectors.groupingBy(
                PolicyEvolutionProposal::getProposalType,
                Collectors.averagingDouble(p -> effectivenessMonitor.calculateActualImpact(p.getId()))
            ));
        
        // 학습 결과 저장 (추후 정책 생성시 활용)
        typeEffectiveness.forEach((type, effectiveness) -> {
            log.info("Learning: {} policies have average effectiveness of {:.2f}%", 
                type, effectiveness);
        });
    }
    
    /**
     * 전체 정책 분석
     */
    private PolicyAnalysisReport analyzeAllPolicies() {
        PolicyAnalysisReport report = new PolicyAnalysisReport();
        
        List<PolicyEvolutionProposal> allProposals = proposalRepository.findAll();
        
        // 전체 정책 수
        report.setTotalPolicies(allProposals.size());
        
        // 활성 정책 수
        long activePolicies = allProposals.stream()
            .filter(p -> p.getStatus() == PolicyEvolutionProposal.ProposalStatus.APPROVED)
            .count();
        report.setActivePolicies(activePolicies);
        
        // 평균 효과성
        double avgEffectiveness = allProposals.stream()
            .filter(p -> p.getStatus() == PolicyEvolutionProposal.ProposalStatus.APPROVED)
            .mapToDouble(p -> effectivenessMonitor.calculateActualImpact(p.getId()))
            .average()
            .orElse(0.0);
        report.setAverageEffectiveness(avgEffectiveness);
        
        // 정책 유형별 분포
        Map<ProposalType, Long> typeDistribution = allProposals.stream()
            .collect(Collectors.groupingBy(
                PolicyEvolutionProposal::getProposalType,
                Collectors.counting()
            ));
        report.setTypeDistribution(typeDistribution);
        
        // 중복 의심 정책
        List<PolicyPair> duplicates = findDuplicatePolicies(allProposals);
        report.setDuplicatePolicies(duplicates);
        
        // 충돌 의심 정책
        List<PolicyPair> conflicts = findConflictingPolicies(allProposals);
        report.setConflictingPolicies(conflicts);
        
        log.info("Policy analysis completed: {} total, {} active, {:.2f}% avg effectiveness",
            report.getTotalPolicies(), report.getActivePolicies(), report.getAverageEffectiveness());
        
        return report;
    }
    
    /**
     * 정책 충돌 식별 및 해결
     */
    private void identifyAndResolvePolicyConflicts(PolicyAnalysisReport report) {
        for (PolicyPair conflict : report.getConflictingPolicies()) {
            log.warn("Policy conflict detected between {} and {}", 
                conflict.getPolicy1().getTitle(), conflict.getPolicy2().getTitle());
            
            // 충돌 해결 제안 생성
            PolicyEvolutionProposal resolution = createConflictResolution(conflict);
            
            try {
                evolutionService.submitProposal(resolution);
                log.info("Conflict resolution proposal submitted");
            } catch (Exception e) {
                log.error("Failed to submit conflict resolution", e);
            }
        }
    }
    
    /**
     * 유사 정책 통합
     */
    private void consolidateSimilarPolicies(PolicyAnalysisReport report) {
        for (PolicyPair duplicate : report.getDuplicatePolicies()) {
            log.info("Similar policies found: {} and {}", 
                duplicate.getPolicy1().getTitle(), duplicate.getPolicy2().getTitle());
            
            // 통합 제안 생성
            PolicyEvolutionProposal consolidation = createConsolidationProposal(duplicate);
            
            try {
                evolutionService.submitProposal(consolidation);
                log.info("Consolidation proposal submitted");
            } catch (Exception e) {
                log.error("Failed to submit consolidation proposal", e);
            }
        }
    }
    
    /**
     * 정책 성능 최적화
     */
    private void optimizePolicyPerformance(PolicyAnalysisReport report) {
        List<PolicyEvolutionProposal> slowPolicies = proposalRepository.findAll().stream()
            .filter(p -> p.getStatus() == PolicyEvolutionProposal.ProposalStatus.APPROVED)
            .filter(p -> evaluatePerformance(p) < 50.0) // 성능 점수가 50 미만
            .collect(Collectors.toList());
        
        for (PolicyEvolutionProposal slowPolicy : slowPolicies) {
            PolicyEvolutionProposal optimization = createPerformanceOptimization(slowPolicy);
            
            try {
                evolutionService.submitProposal(optimization);
                log.info("Performance optimization proposal submitted for: {}", slowPolicy.getTitle());
            } catch (Exception e) {
                log.error("Failed to submit optimization proposal", e);
            }
        }
    }
    
    /**
     * 정책 커버리지 갭 분석
     */
    private void analyzePolicyCoverageGaps(PolicyAnalysisReport report) {
        Set<String> coveredAreas = new HashSet<>();
        Set<String> requiredAreas = getRequiredSecurityAreas();
        
        // 현재 커버되는 영역 확인
        proposalRepository.findAll().stream()
            .filter(p -> p.getStatus() == PolicyEvolutionProposal.ProposalStatus.APPROVED)
            .forEach(p -> coveredAreas.add(extractCoverageArea(p)));
        
        // 갭 식별
        Set<String> gaps = new HashSet<>(requiredAreas);
        gaps.removeAll(coveredAreas);
        
        report.setCoverageGaps(gaps);
        
        if (!gaps.isEmpty()) {
            log.warn("Policy coverage gaps detected: {}", gaps);
        }
    }
    
    /**
     * 최적화 제안 생성
     */
    private void generateOptimizationProposals(PolicyAnalysisReport report) {
        List<PolicyEvolutionProposal> proposals = new ArrayList<>();
        
        // 커버리지 갭에 대한 제안
        for (String gap : report.getCoverageGaps()) {
            PolicyEvolutionProposal proposal = createCoverageProposal(gap);
            proposals.add(proposal);
        }
        
        // 효과성 개선 제안
        if (report.getAverageEffectiveness() < 60.0) {
            PolicyEvolutionProposal proposal = createEffectivenessImprovementProposal(report);
            proposals.add(proposal);
        }
        
        // 제안 제출
        proposals.forEach(proposal -> {
            try {
                evolutionService.submitProposal(proposal);
                log.info("Optimization proposal submitted: {}", proposal.getTitle());
            } catch (Exception e) {
                log.error("Failed to submit optimization proposal", e);
            }
        });
    }
    
    /**
     * Helper 클래스들
     */
    private static class ThreatContext {
        private List<SecurityEvent> recentSecurityEvents = new ArrayList<>();
        private ThreatLevel threatLevel;
        private List<String> affectedSystems = new ArrayList<>();
        private Priority priority;
        
        public boolean requiresImmediateResponse() {
            return threatLevel == ThreatLevel.CRITICAL || 
                   threatLevel == ThreatLevel.HIGH;
        }
        
        // Getters and Setters
        public List<SecurityEvent> getRecentSecurityEvents() { return recentSecurityEvents; }
        public void setRecentSecurityEvents(List<SecurityEvent> events) { this.recentSecurityEvents = events; }
        
        public ThreatLevel getThreatLevel() { return threatLevel; }
        public void setThreatLevel(ThreatLevel threatLevel) { this.threatLevel = threatLevel; }
        
        public List<String> getAffectedSystems() { return affectedSystems; }
        public void setAffectedSystems(List<String> systems) { this.affectedSystems = systems; }
        
        public Priority getPriority() { return priority; }
        public void setPriority(Priority priority) { this.priority = priority; }
    }
    
    private static class SecurityEvent {
        private String eventType;
        private String description;
        private int severity;
        private String threatIndicator;
        private LocalDateTime timestamp;
        
        // Getters
        public String getEventType() { return eventType; }
        public String getDescription() { return description; }
        public int getSeverity() { return severity; }
        public String getThreatIndicator() { return threatIndicator; }
        public LocalDateTime getTimestamp() { return timestamp; }
    }
    
    private static class PolicyAnalysisReport {
        private long totalPolicies;
        private long activePolicies;
        private double averageEffectiveness;
        private Map<ProposalType, Long> typeDistribution;
        private List<PolicyPair> duplicatePolicies = new ArrayList<>();
        private List<PolicyPair> conflictingPolicies = new ArrayList<>();
        private Set<String> coverageGaps = new HashSet<>();
        
        // Getters and Setters
        public long getTotalPolicies() { return totalPolicies; }
        public void setTotalPolicies(long totalPolicies) { this.totalPolicies = totalPolicies; }
        
        public long getActivePolicies() { return activePolicies; }
        public void setActivePolicies(long activePolicies) { this.activePolicies = activePolicies; }
        
        public double getAverageEffectiveness() { return averageEffectiveness; }
        public void setAverageEffectiveness(double effectiveness) { this.averageEffectiveness = effectiveness; }
        
        public Map<ProposalType, Long> getTypeDistribution() { return typeDistribution; }
        public void setTypeDistribution(Map<ProposalType, Long> distribution) { this.typeDistribution = distribution; }
        
        public List<PolicyPair> getDuplicatePolicies() { return duplicatePolicies; }
        public void setDuplicatePolicies(List<PolicyPair> duplicates) { this.duplicatePolicies = duplicates; }
        
        public List<PolicyPair> getConflictingPolicies() { return conflictingPolicies; }
        public void setConflictingPolicies(List<PolicyPair> conflicts) { this.conflictingPolicies = conflicts; }
        
        public Set<String> getCoverageGaps() { return coverageGaps; }
        public void setCoverageGaps(Set<String> gaps) { this.coverageGaps = gaps; }
    }
    
    private static class PolicyPair {
        private PolicyEvolutionProposal policy1;
        private PolicyEvolutionProposal policy2;
        
        public PolicyPair(PolicyEvolutionProposal p1, PolicyEvolutionProposal p2) {
            this.policy1 = p1;
            this.policy2 = p2;
        }
        
        public PolicyEvolutionProposal getPolicy1() { return policy1; }
        public PolicyEvolutionProposal getPolicy2() { return policy2; }
    }
    
    private enum ThreatLevel {
        LOW, MEDIUM, HIGH, CRITICAL
    }
    
    private enum Priority {
        LOW, NORMAL, HIGH, URGENT
    }
    
    /**
     * Helper 메서드들
     */
    private List<SecurityEvent> getRecentSecurityEvents() {
        // 실제 구현: 보안 이벤트 로그에서 최근 이벤트 조회
        return new ArrayList<>();
    }
    
    private ThreatLevel evaluateThreatLevel(List<SecurityEvent> events) {
        if (events.isEmpty()) return ThreatLevel.LOW;
        
        int maxSeverity = events.stream()
            .mapToInt(SecurityEvent::getSeverity)
            .max()
            .orElse(0);
        
        if (maxSeverity >= 9) return ThreatLevel.CRITICAL;
        if (maxSeverity >= 7) return ThreatLevel.HIGH;
        if (maxSeverity >= 5) return ThreatLevel.MEDIUM;
        return ThreatLevel.LOW;
    }
    
    private List<String> identifyAffectedSystems(List<SecurityEvent> events) {
        // 실제 구현: 이벤트에서 영향받는 시스템 추출
        return new ArrayList<>();
    }
    
    private Priority determinePriority(ThreatContext context) {
        if (context.getThreatLevel() == ThreatLevel.CRITICAL) return Priority.URGENT;
        if (context.getThreatLevel() == ThreatLevel.HIGH) return Priority.HIGH;
        if (context.getAffectedSystems().size() > 5) return Priority.HIGH;
        return Priority.NORMAL;
    }
    
    private ProposalType determineProposalType(SecurityEvent event) {
        // 이벤트 유형에 따라 적절한 제안 타입 결정
        return ProposalType.THREAT_RESPONSE;
    }
    
    private String generateEmergencyPolicyContent(SecurityEvent event) {
        // 긴급 정책 내용 생성
        return "Emergency policy for " + event.getEventType();
    }
    
    private void markForImprovement(PolicyEvolutionProposal proposal) {
        // 개선 대상으로 표시
        log.info("Marking policy {} for improvement", proposal.getTitle());
    }
    
    private String enhancePolicyContent(String original) {
        // 정책 내용 개선
        return original + " [Enhanced]";
    }
    
    private List<PolicyPair> findDuplicatePolicies(List<PolicyEvolutionProposal> policies) {
        List<PolicyPair> duplicates = new ArrayList<>();
        
        for (int i = 0; i < policies.size(); i++) {
            for (int j = i + 1; j < policies.size(); j++) {
                if (areSimilar(policies.get(i), policies.get(j))) {
                    duplicates.add(new PolicyPair(policies.get(i), policies.get(j)));
                }
            }
        }
        
        return duplicates;
    }
    
    private List<PolicyPair> findConflictingPolicies(List<PolicyEvolutionProposal> policies) {
        List<PolicyPair> conflicts = new ArrayList<>();
        
        for (int i = 0; i < policies.size(); i++) {
            for (int j = i + 1; j < policies.size(); j++) {
                if (areConflicting(policies.get(i), policies.get(j))) {
                    conflicts.add(new PolicyPair(policies.get(i), policies.get(j)));
                }
            }
        }
        
        return conflicts;
    }
    
    private boolean areSimilar(PolicyEvolutionProposal p1, PolicyEvolutionProposal p2) {
        // 유사성 판단 로직
        return p1.getProposalType() == p2.getProposalType() &&
               p1.getTitle().contains(p2.getTitle()) || p2.getTitle().contains(p1.getTitle());
    }
    
    private boolean areConflicting(PolicyEvolutionProposal p1, PolicyEvolutionProposal p2) {
        // 충돌 판단 로직
        return false; // 간단한 구현
    }
    
    private PolicyEvolutionProposal createConflictResolution(PolicyPair conflict) {
        PolicyEvolutionProposal resolution = new PolicyEvolutionProposal();
        resolution.setTitle("Conflict Resolution: " + conflict.getPolicy1().getTitle());
        resolution.setDescription("Resolves conflict between policies");
        resolution.setProposalType(ProposalType.COMPLIANCE);
        resolution.setRiskLevel(RiskLevel.MEDIUM);
        resolution.setCreatedBy("PolicyEvolutionScheduler");
        resolution.setCreatedAt(LocalDateTime.now());
        return resolution;
    }
    
    private PolicyEvolutionProposal createConsolidationProposal(PolicyPair duplicate) {
        PolicyEvolutionProposal consolidation = new PolicyEvolutionProposal();
        consolidation.setTitle("Consolidation: " + duplicate.getPolicy1().getTitle());
        consolidation.setDescription("Consolidates similar policies");
        consolidation.setProposalType(ProposalType.OPTIMIZATION);
        consolidation.setRiskLevel(RiskLevel.LOW);
        consolidation.setCreatedBy("PolicyEvolutionScheduler");
        consolidation.setCreatedAt(LocalDateTime.now());
        return consolidation;
    }
    
    private double evaluatePerformance(PolicyEvolutionProposal proposal) {
        // 성능 평가 로직
        return 75.0; // 간단한 구현
    }
    
    private PolicyEvolutionProposal createPerformanceOptimization(PolicyEvolutionProposal original) {
        PolicyEvolutionProposal optimization = new PolicyEvolutionProposal();
        optimization.setTitle("Performance Optimization: " + original.getTitle());
        optimization.setDescription("Optimizes policy performance");
        optimization.setProposalType(ProposalType.OPTIMIZATION);
        optimization.setRiskLevel(RiskLevel.LOW);
        optimization.setCreatedBy("PolicyEvolutionScheduler");
        optimization.setCreatedAt(LocalDateTime.now());
        return optimization;
    }
    
    private Set<String> getRequiredSecurityAreas() {
        Set<String> areas = new HashSet<>();
        areas.add("authentication");
        areas.add("authorization");
        areas.add("data_protection");
        areas.add("network_security");
        areas.add("application_security");
        areas.add("incident_response");
        return areas;
    }
    
    private String extractCoverageArea(PolicyEvolutionProposal proposal) {
        // 정책이 커버하는 보안 영역 추출
        if (proposal.getProposalType() == ProposalType.ACCESS_CONTROL) return "authorization";
        if (proposal.getProposalType() == ProposalType.DATA_PROTECTION) return "data_protection";
        return "general";
    }
    
    private PolicyEvolutionProposal createCoverageProposal(String gap) {
        PolicyEvolutionProposal proposal = new PolicyEvolutionProposal();
        proposal.setTitle("Coverage Gap: " + gap);
        proposal.setDescription("Fills security coverage gap in " + gap);
        proposal.setProposalType(ProposalType.COMPLIANCE);
        proposal.setRiskLevel(RiskLevel.MEDIUM);
        proposal.setCreatedBy("PolicyEvolutionScheduler");
        proposal.setCreatedAt(LocalDateTime.now());
        return proposal;
    }
    
    private PolicyEvolutionProposal createEffectivenessImprovementProposal(PolicyAnalysisReport report) {
        PolicyEvolutionProposal proposal = new PolicyEvolutionProposal();
        proposal.setTitle("System-wide Effectiveness Improvement");
        proposal.setDescription("Improves overall policy effectiveness from " + 
            report.getAverageEffectiveness() + "%");
        proposal.setProposalType(ProposalType.OPTIMIZATION);
        proposal.setRiskLevel(RiskLevel.MEDIUM);
        proposal.setCreatedBy("PolicyEvolutionScheduler");
        proposal.setCreatedAt(LocalDateTime.now());
        return proposal;
    }
    
    /**
     * 스케줄러 상태 조회
     */
    public SchedulerStatus getStatus() {
        SchedulerStatus status = new SchedulerStatus();
        status.setRealTimeMonitoringEnabled(realTimeMonitoringEnabled);
        status.setStaticAnalysisEnabled(staticAnalysisEnabled);
        status.setLastRealTimeRun(lastRealTimeRun);
        status.setLastStaticAnalysisRun(lastStaticAnalysisRun);
        return status;
    }
    
    /**
     * 스케줄러 상태 클래스
     */
    public static class SchedulerStatus {
        private boolean realTimeMonitoringEnabled;
        private boolean staticAnalysisEnabled;
        private LocalDateTime lastRealTimeRun;
        private LocalDateTime lastStaticAnalysisRun;
        
        // Getters and Setters
        public boolean isRealTimeMonitoringEnabled() { return realTimeMonitoringEnabled; }
        public void setRealTimeMonitoringEnabled(boolean enabled) { this.realTimeMonitoringEnabled = enabled; }
        
        public boolean isStaticAnalysisEnabled() { return staticAnalysisEnabled; }
        public void setStaticAnalysisEnabled(boolean enabled) { this.staticAnalysisEnabled = enabled; }
        
        public LocalDateTime getLastRealTimeRun() { return lastRealTimeRun; }
        public void setLastRealTimeRun(LocalDateTime lastRun) { this.lastRealTimeRun = lastRun; }
        
        public LocalDateTime getLastStaticAnalysisRun() { return lastStaticAnalysisRun; }
        public void setLastStaticAnalysisRun(LocalDateTime lastRun) { this.lastStaticAnalysisRun = lastRun; }
    }
    
    /**
     * 실시간 모니터링 활성화/비활성화
     */
    public void setRealTimeMonitoringEnabled(boolean enabled) {
        this.realTimeMonitoringEnabled = enabled;
        log.info("Real-time monitoring {}", enabled ? "enabled" : "disabled");
    }
    
    /**
     * 정적 분석 활성화/비활성화
     */
    public void setStaticAnalysisEnabled(boolean enabled) {
        this.staticAnalysisEnabled = enabled;
        log.info("Static analysis {}", enabled ? "enabled" : "disabled");
    }
}