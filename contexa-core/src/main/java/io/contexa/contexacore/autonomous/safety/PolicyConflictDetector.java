package io.contexa.contexacore.autonomous.safety;

import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.repository.PolicyProposalRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 정책 충돌 감지기
 * 
 * 정책 간 충돌을 감지하고 해결 방안을 제시합니다.
 * 실시간으로 정책 호환성을 검증하고 위험을 평가합니다.
 * 
 * @author contexa
 * @since 1.0.0
 */
@Component
public class PolicyConflictDetector {
    
    private static final Logger logger = LoggerFactory.getLogger(PolicyConflictDetector.class);
    
    @Autowired
    private PolicyProposalRepository proposalRepository;
    
    @Autowired
    private PolicyVersionManager versionManager;
    
    // 충돌 규칙 저장소
    private final Map<String, ConflictRule> conflictRules = new ConcurrentHashMap<>();
    
    // 충돌 이력
    private final List<ConflictRecord> conflictHistory = Collections.synchronizedList(new ArrayList<>());
    
    // 정책 의존성 그래프
    private final PolicyDependencyGraph dependencyGraph = new PolicyDependencyGraph();
    
    /**
     * 정책 충돌 검사
     * 
     * @param proposal 검사할 제안
     * @return 충돌 검사 결과
     */
    public ConflictCheckResult checkConflicts(PolicyEvolutionProposal proposal) {
        logger.info("Checking conflicts for proposal: {}", proposal.getId());
        
        List<PolicyConflict> conflicts = new ArrayList<>();
        
        try {
            // 1. 활성 정책과의 충돌 검사
            conflicts.addAll(checkActiveConflicts(proposal));
            
            // 2. 의존성 충돌 검사
            conflicts.addAll(checkDependencyConflicts(proposal));
            
            // 3. 리소스 충돌 검사
            conflicts.addAll(checkResourceConflicts(proposal));
            
            // 4. 규칙 기반 충돌 검사
            conflicts.addAll(checkRuleBasedConflicts(proposal));
            
            // 충돌 심각도 평가
            ConflictSeverity overallSeverity = evaluateSeverity(conflicts);
            
            // 해결 방안 생성
            List<ConflictResolution> resolutions = generateResolutions(conflicts);
            
            ConflictCheckResult result = ConflictCheckResult.builder()
                .proposalId(proposal.getId())
                .conflicts(conflicts)
                .severity(overallSeverity)
                .resolutions(resolutions)
                .canProceed(overallSeverity != ConflictSeverity.CRITICAL)
                .build();
            
            // 충돌 이력 기록
            if (!conflicts.isEmpty()) {
                recordConflicts(proposal, conflicts);
            }
            
            logger.info("Conflict check completed. Found {} conflicts with severity: {}", 
                conflicts.size(), overallSeverity);
            
            return result;
            
        } catch (Exception e) {
            logger.error("Error during conflict detection for proposal: {}", proposal.getId(), e);
            throw new ConflictDetectionException("Conflict detection failed", e);
        }
    }
    
    /**
     * 정책 호환성 검증
     * 
     * @param proposal1 첫 번째 제안
     * @param proposal2 두 번째 제안
     * @return 호환성 여부
     */
    public boolean areCompatible(PolicyEvolutionProposal proposal1, PolicyEvolutionProposal proposal2) {
        logger.debug("Checking compatibility between proposals {} and {}", 
            proposal1.getId(), proposal2.getId());
        
        // 정책 유형 호환성 검사
        if (!areTypesCompatible(proposal1.getProposalType(), proposal2.getProposalType())) {
            return false;
        }
        
        // 타겟 리소스 충돌 검사
        if (hasResourceOverlap(proposal1, proposal2)) {
            return false;
        }
        
        // 의존성 순환 검사
        if (createsCyclicDependency(proposal1, proposal2)) {
            return false;
        }
        
        return true;
    }
    
    /**
     * 충돌 해결
     * 
     * @param conflict 충돌
     * @param resolution 해결 방안
     * @return 해결 성공 여부
     */
    public boolean resolveConflict(PolicyConflict conflict, ConflictResolution resolution) {
        logger.info("Attempting to resolve conflict: {} with resolution: {}", 
            conflict.getConflictId(), resolution.getType());
        
        try {
            switch (resolution.getType()) {
                case MERGE:
                    return mergeConflictingPolicies(conflict);
                    
                case PRIORITIZE:
                    return prioritizePolicy(conflict, resolution);
                    
                case DEFER:
                    return deferPolicy(conflict);
                    
                case SPLIT:
                    return splitPolicy(conflict);
                    
                case REJECT:
                    return rejectPolicy(conflict);
                    
                default:
                    logger.warn("Unknown resolution type: {}", resolution.getType());
                    return false;
            }
        } catch (Exception e) {
            logger.error("Failed to resolve conflict: {}", conflict.getConflictId(), e);
            return false;
        }
    }
    
    /**
     * 충돌 규칙 추가
     * 
     * @param rule 충돌 규칙
     */
    public void addConflictRule(ConflictRule rule) {
        logger.info("Adding conflict rule: {}", rule.getRuleId());
        conflictRules.put(rule.getRuleId(), rule);
    }
    
    /**
     * 의존성 추가
     * 
     * @param proposalId 제안 ID
     * @param dependsOn 의존하는 제안 ID
     */
    public void addDependency(Long proposalId, Long dependsOn) {
        logger.debug("Adding dependency: {} depends on {}", proposalId, dependsOn);
        dependencyGraph.addDependency(proposalId, dependsOn);
    }
    
    // ==================== Private Methods ====================
    
    private List<PolicyConflict> checkActiveConflicts(PolicyEvolutionProposal proposal) {
        List<PolicyConflict> conflicts = new ArrayList<>();
        
        // 활성 정책 조회
        List<PolicyEvolutionProposal> activeProposals = proposalRepository.findActiveProposals();
        
        for (PolicyEvolutionProposal active : activeProposals) {
            if (!areCompatible(proposal, active)) {
                conflicts.add(PolicyConflict.builder()
                    .conflictId(generateConflictId())
                    .proposalId(proposal.getId())
                    .conflictingProposalId(active.getId())
                    .type(ConflictType.ACTIVE_POLICY)
                    .severity(ConflictSeverity.HIGH)
                    .description(String.format("Conflicts with active policy: %s", active.getTitle()))
                    .build());
            }
        }
        
        return conflicts;
    }
    
    private List<PolicyConflict> checkDependencyConflicts(PolicyEvolutionProposal proposal) {
        List<PolicyConflict> conflicts = new ArrayList<>();
        
        // 의존성 체인 검사
        Set<Long> dependencies = dependencyGraph.getDependencies(proposal.getId());
        Set<Long> dependents = dependencyGraph.getDependents(proposal.getId());
        
        // 순환 의존성 검사
        if (!Collections.disjoint(dependencies, dependents)) {
            conflicts.add(PolicyConflict.builder()
                .conflictId(generateConflictId())
                .proposalId(proposal.getId())
                .type(ConflictType.CYCLIC_DEPENDENCY)
                .severity(ConflictSeverity.CRITICAL)
                .description("Cyclic dependency detected")
                .build());
        }
        
        return conflicts;
    }
    
    private List<PolicyConflict> checkResourceConflicts(PolicyEvolutionProposal proposal) {
        List<PolicyConflict> conflicts = new ArrayList<>();
        
        // 리소스 사용량 검사
        if (proposal.getExpectedImpact() > 0.8) {
            conflicts.add(PolicyConflict.builder()
                .conflictId(generateConflictId())
                .proposalId(proposal.getId())
                .type(ConflictType.RESOURCE_CONTENTION)
                .severity(ConflictSeverity.MEDIUM)
                .description("High resource impact expected")
                .build());
        }
        
        return conflicts;
    }
    
    private List<PolicyConflict> checkRuleBasedConflicts(PolicyEvolutionProposal proposal) {
        List<PolicyConflict> conflicts = new ArrayList<>();
        
        for (ConflictRule rule : conflictRules.values()) {
            if (rule.applies(proposal)) {
                conflicts.add(PolicyConflict.builder()
                    .conflictId(generateConflictId())
                    .proposalId(proposal.getId())
                    .type(ConflictType.RULE_VIOLATION)
                    .severity(rule.getSeverity())
                    .description(rule.getDescription())
                    .ruleId(rule.getRuleId())
                    .build());
            }
        }
        
        return conflicts;
    }
    
    private ConflictSeverity evaluateSeverity(List<PolicyConflict> conflicts) {
        if (conflicts.isEmpty()) {
            return ConflictSeverity.NONE;
        }
        
        return conflicts.stream()
            .map(PolicyConflict::getSeverity)
            .max(Comparator.naturalOrder())
            .orElse(ConflictSeverity.LOW);
    }
    
    private List<ConflictResolution> generateResolutions(List<PolicyConflict> conflicts) {
        List<ConflictResolution> resolutions = new ArrayList<>();
        
        for (PolicyConflict conflict : conflicts) {
            resolutions.addAll(generateResolutionForConflict(conflict));
        }
        
        return resolutions;
    }
    
    private List<ConflictResolution> generateResolutionForConflict(PolicyConflict conflict) {
        List<ConflictResolution> resolutions = new ArrayList<>();
        
        switch (conflict.getType()) {
            case ACTIVE_POLICY:
                resolutions.add(ConflictResolution.builder()
                    .type(ResolutionType.DEFER)
                    .description("Defer activation until conflicting policy is deactivated")
                    .estimatedEffort(EffortLevel.LOW)
                    .build());
                resolutions.add(ConflictResolution.builder()
                    .type(ResolutionType.MERGE)
                    .description("Merge with existing policy")
                    .estimatedEffort(EffortLevel.MEDIUM)
                    .build());
                break;
                
            case CYCLIC_DEPENDENCY:
                resolutions.add(ConflictResolution.builder()
                    .type(ResolutionType.SPLIT)
                    .description("Split policy to break dependency cycle")
                    .estimatedEffort(EffortLevel.HIGH)
                    .build());
                break;
                
            case RESOURCE_CONTENTION:
                resolutions.add(ConflictResolution.builder()
                    .type(ResolutionType.PRIORITIZE)
                    .description("Adjust resource allocation priorities")
                    .estimatedEffort(EffortLevel.MEDIUM)
                    .build());
                break;
                
            default:
                resolutions.add(ConflictResolution.builder()
                    .type(ResolutionType.REJECT)
                    .description("Reject proposal due to unresolvable conflicts")
                    .estimatedEffort(EffortLevel.LOW)
                    .build());
        }
        
        return resolutions;
    }
    
    private boolean areTypesCompatible(PolicyEvolutionProposal.ProposalType type1, 
                                      PolicyEvolutionProposal.ProposalType type2) {
        // 같은 타입의 정책은 충돌 가능성이 높음
        if (type1 == type2) {
            return false;
        }
        
        // 특정 타입 조합의 비호환성 검사
        if (type1 == PolicyEvolutionProposal.ProposalType.ACCESS_CONTROL && 
            type2 == PolicyEvolutionProposal.ProposalType.ACCESS_CONTROL) {
            return false;
        }
        
        return true;
    }
    
    private boolean hasResourceOverlap(PolicyEvolutionProposal p1, PolicyEvolutionProposal p2) {
        // 메타데이터에서 타겟 리소스 추출
        Map<String, Object> meta1 = p1.getMetadata();
        Map<String, Object> meta2 = p2.getMetadata();
        
        if (meta1 == null || meta2 == null) {
            return false;
        }
        
        // 타겟 리소스 비교
        Object target1 = meta1.get("targetResource");
        Object target2 = meta2.get("targetResource");
        
        return target1 != null && target1.equals(target2);
    }
    
    private boolean createsCyclicDependency(PolicyEvolutionProposal p1, PolicyEvolutionProposal p2) {
        return dependencyGraph.wouldCreateCycle(p1.getId(), p2.getId());
    }
    
    private boolean mergeConflictingPolicies(PolicyConflict conflict) {
        logger.info("Merging conflicting policies for conflict: {}", conflict.getConflictId());
        // 실제 병합 로직 구현
        return true;
    }
    
    private boolean prioritizePolicy(PolicyConflict conflict, ConflictResolution resolution) {
        logger.info("Prioritizing policy for conflict: {}", conflict.getConflictId());
        // 우선순위 조정 로직 구현
        return true;
    }
    
    private boolean deferPolicy(PolicyConflict conflict) {
        logger.info("Deferring policy for conflict: {}", conflict.getConflictId());
        // 정책 연기 로직 구현
        return true;
    }
    
    private boolean splitPolicy(PolicyConflict conflict) {
        logger.info("Splitting policy for conflict: {}", conflict.getConflictId());
        // 정책 분할 로직 구현
        return true;
    }
    
    private boolean rejectPolicy(PolicyConflict conflict) {
        logger.info("Rejecting policy for conflict: {}", conflict.getConflictId());
        // 정책 거부 로직 구현
        return true;
    }
    
    private void recordConflicts(PolicyEvolutionProposal proposal, List<PolicyConflict> conflicts) {
        ConflictRecord record = ConflictRecord.builder()
            .proposalId(proposal.getId())
            .conflicts(conflicts)
            .timestamp(new Date())
            .build();
        
        conflictHistory.add(record);
    }
    
    private String generateConflictId() {
        return "CONF_" + System.currentTimeMillis() + "_" + UUID.randomUUID().toString().substring(0, 8);
    }
    
    // ==================== Inner Classes ====================
    
    /**
     * 충돌 검사 결과
     */
    @lombok.Builder
    @lombok.Data
    public static class ConflictCheckResult {
        private Long proposalId;
        private List<PolicyConflict> conflicts;
        private ConflictSeverity severity;
        private List<ConflictResolution> resolutions;
        private boolean canProceed;
    }
    
    /**
     * 정책 충돌
     */
    @lombok.Builder
    @lombok.Data
    public static class PolicyConflict {
        private String conflictId;
        private Long proposalId;
        private Long conflictingProposalId;
        private ConflictType type;
        private ConflictSeverity severity;
        private String description;
        private String ruleId;
    }
    
    /**
     * 충돌 해결 방안
     */
    @lombok.Builder
    @lombok.Data
    public static class ConflictResolution {
        private ResolutionType type;
        private String description;
        private EffortLevel estimatedEffort;
    }
    
    /**
     * 충돌 규칙
     */
    @lombok.Data
    public static class ConflictRule {
        private String ruleId;
        private String description;
        private ConflictSeverity severity;
        private java.util.function.Predicate<PolicyEvolutionProposal> condition;
        
        public boolean applies(PolicyEvolutionProposal proposal) {
            return condition != null && condition.test(proposal);
        }
    }
    
    /**
     * 충돌 기록
     */
    @lombok.Builder
    @lombok.Data
    private static class ConflictRecord {
        private Long proposalId;
        private List<PolicyConflict> conflicts;
        private Date timestamp;
    }
    
    /**
     * 정책 의존성 그래프
     */
    private static class PolicyDependencyGraph {
        private final Map<Long, Set<Long>> dependencies = new ConcurrentHashMap<>();
        private final Map<Long, Set<Long>> dependents = new ConcurrentHashMap<>();
        
        public void addDependency(Long from, Long to) {
            dependencies.computeIfAbsent(from, k -> new HashSet<>()).add(to);
            dependents.computeIfAbsent(to, k -> new HashSet<>()).add(from);
        }
        
        public Set<Long> getDependencies(Long proposalId) {
            return dependencies.getOrDefault(proposalId, Collections.emptySet());
        }
        
        public Set<Long> getDependents(Long proposalId) {
            return dependents.getOrDefault(proposalId, Collections.emptySet());
        }
        
        public boolean wouldCreateCycle(Long from, Long to) {
            // DFS를 사용한 순환 감지
            Set<Long> visited = new HashSet<>();
            return hasCycle(from, to, visited);
        }
        
        private boolean hasCycle(Long current, Long target, Set<Long> visited) {
            if (current.equals(target)) {
                return true;
            }
            
            if (visited.contains(current)) {
                return false;
            }
            
            visited.add(current);
            
            for (Long dependency : getDependencies(current)) {
                if (hasCycle(dependency, target, visited)) {
                    return true;
                }
            }
            
            return false;
        }
    }
    
    /**
     * 충돌 유형
     */
    public enum ConflictType {
        ACTIVE_POLICY,
        CYCLIC_DEPENDENCY,
        RESOURCE_CONTENTION,
        RULE_VIOLATION,
        VERSION_MISMATCH
    }
    
    /**
     * 충돌 심각도
     */
    public enum ConflictSeverity {
        NONE,
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }
    
    /**
     * 해결 유형
     */
    public enum ResolutionType {
        MERGE,
        PRIORITIZE,
        DEFER,
        SPLIT,
        REJECT
    }
    
    /**
     * 노력 수준
     */
    public enum EffortLevel {
        LOW,
        MEDIUM,
        HIGH
    }
    
    /**
     * 충돌 감지 예외
     */
    public static class ConflictDetectionException extends RuntimeException {
        public ConflictDetectionException(String message) {
            super(message);
        }
        
        public ConflictDetectionException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}