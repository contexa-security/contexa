package io.contexa.contexacore.autonomous.safety;

import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.repository.PolicyProposalRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;


public class PolicyConflictDetector {
    
    private static final Logger logger = LoggerFactory.getLogger(PolicyConflictDetector.class);
    
    @Autowired
    private PolicyProposalRepository proposalRepository;
    
    @Autowired
    private PolicyVersionManager versionManager;
    
    
    private final Map<String, ConflictRule> conflictRules = new ConcurrentHashMap<>();
    
    
    private final List<ConflictRecord> conflictHistory = Collections.synchronizedList(new ArrayList<>());
    
    
    private final PolicyDependencyGraph dependencyGraph = new PolicyDependencyGraph();
    
    
    public ConflictCheckResult checkConflicts(PolicyEvolutionProposal proposal) {
        logger.info("Checking conflicts for proposal: {}", proposal.getId());
        
        List<PolicyConflict> conflicts = new ArrayList<>();
        
        try {
            
            conflicts.addAll(checkActiveConflicts(proposal));
            
            
            conflicts.addAll(checkDependencyConflicts(proposal));
            
            
            conflicts.addAll(checkResourceConflicts(proposal));
            
            
            conflicts.addAll(checkRuleBasedConflicts(proposal));
            
            
            ConflictSeverity overallSeverity = evaluateSeverity(conflicts);
            
            
            List<ConflictResolution> resolutions = generateResolutions(conflicts);
            
            ConflictCheckResult result = ConflictCheckResult.builder()
                .proposalId(proposal.getId())
                .conflicts(conflicts)
                .severity(overallSeverity)
                .resolutions(resolutions)
                .canProceed(overallSeverity != ConflictSeverity.CRITICAL)
                .build();
            
            
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
    
    
    public boolean areCompatible(PolicyEvolutionProposal proposal1, PolicyEvolutionProposal proposal2) {
        logger.debug("Checking compatibility between proposals {} and {}", 
            proposal1.getId(), proposal2.getId());
        
        
        if (!areTypesCompatible(proposal1.getProposalType(), proposal2.getProposalType())) {
            return false;
        }
        
        
        if (hasResourceOverlap(proposal1, proposal2)) {
            return false;
        }
        
        
        if (createsCyclicDependency(proposal1, proposal2)) {
            return false;
        }
        
        return true;
    }
    
    
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
    
    
    public void addConflictRule(ConflictRule rule) {
        logger.info("Adding conflict rule: {}", rule.getRuleId());
        conflictRules.put(rule.getRuleId(), rule);
    }
    
    
    public void addDependency(Long proposalId, Long dependsOn) {
        logger.debug("Adding dependency: {} depends on {}", proposalId, dependsOn);
        dependencyGraph.addDependency(proposalId, dependsOn);
    }
    
    
    
    private List<PolicyConflict> checkActiveConflicts(PolicyEvolutionProposal proposal) {
        List<PolicyConflict> conflicts = new ArrayList<>();
        
        
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
        
        
        Set<Long> dependencies = dependencyGraph.getDependencies(proposal.getId());
        Set<Long> dependents = dependencyGraph.getDependents(proposal.getId());
        
        
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
        
        if (type1 == type2) {
            return false;
        }
        
        
        if (type1 == PolicyEvolutionProposal.ProposalType.ACCESS_CONTROL && 
            type2 == PolicyEvolutionProposal.ProposalType.ACCESS_CONTROL) {
            return false;
        }
        
        return true;
    }
    
    private boolean hasResourceOverlap(PolicyEvolutionProposal p1, PolicyEvolutionProposal p2) {
        
        Map<String, Object> meta1 = p1.getMetadata();
        Map<String, Object> meta2 = p2.getMetadata();
        
        if (meta1 == null || meta2 == null) {
            return false;
        }
        
        
        Object target1 = meta1.get("targetResource");
        Object target2 = meta2.get("targetResource");
        
        return target1 != null && target1.equals(target2);
    }
    
    private boolean createsCyclicDependency(PolicyEvolutionProposal p1, PolicyEvolutionProposal p2) {
        return dependencyGraph.wouldCreateCycle(p1.getId(), p2.getId());
    }
    
    private boolean mergeConflictingPolicies(PolicyConflict conflict) {
        logger.info("Merging conflicting policies for conflict: {}", conflict.getConflictId());
        
        return true;
    }
    
    private boolean prioritizePolicy(PolicyConflict conflict, ConflictResolution resolution) {
        logger.info("Prioritizing policy for conflict: {}", conflict.getConflictId());
        
        return true;
    }
    
    private boolean deferPolicy(PolicyConflict conflict) {
        logger.info("Deferring policy for conflict: {}", conflict.getConflictId());
        
        return true;
    }
    
    private boolean splitPolicy(PolicyConflict conflict) {
        logger.info("Splitting policy for conflict: {}", conflict.getConflictId());
        
        return true;
    }
    
    private boolean rejectPolicy(PolicyConflict conflict) {
        logger.info("Rejecting policy for conflict: {}", conflict.getConflictId());
        
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
    
    
    
    
    @lombok.Builder
    @lombok.Data
    public static class ConflictCheckResult {
        private Long proposalId;
        private List<PolicyConflict> conflicts;
        private ConflictSeverity severity;
        private List<ConflictResolution> resolutions;
        private boolean canProceed;
    }
    
    
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
    
    
    @lombok.Builder
    @lombok.Data
    public static class ConflictResolution {
        private ResolutionType type;
        private String description;
        private EffortLevel estimatedEffort;
    }
    
    
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
    
    
    @lombok.Builder
    @lombok.Data
    private static class ConflictRecord {
        private Long proposalId;
        private List<PolicyConflict> conflicts;
        private Date timestamp;
    }
    
    
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
    
    
    public enum ConflictType {
        ACTIVE_POLICY,
        CYCLIC_DEPENDENCY,
        RESOURCE_CONTENTION,
        RULE_VIOLATION,
        VERSION_MISMATCH
    }
    
    
    public enum ConflictSeverity {
        NONE,
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }
    
    
    public enum ResolutionType {
        MERGE,
        PRIORITIZE,
        DEFER,
        SPLIT,
        REJECT
    }
    
    
    public enum EffortLevel {
        LOW,
        MEDIUM,
        HIGH
    }
    
    
    public static class ConflictDetectionException extends RuntimeException {
        public ConflictDetectionException(String message) {
            super(message);
        }
        
        public ConflictDetectionException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}