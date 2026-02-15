package io.contexa.contexacoreenterprise.repository;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * In-memory policy cache backed by ConcurrentHashMap.
 * Primary persistence is handled by IAM PolicyService via PolicyActivationEventListener.
 * This repository serves as a read-optimized query cache for the Policy Workbench UI.
 * Data is volatile and will be lost on server restart - rebuild from IAM PolicyService if needed.
 */
@Slf4j
@Repository
public class SynthesisPolicyRepository {

    private final Map<Long, Policy> policies = new ConcurrentHashMap<>();

    private final Map<String, Set<Long>> policyByType = new ConcurrentHashMap<>();
    private final Map<PolicyStatus, Set<Long>> policyByStatus = new ConcurrentHashMap<>();

    private long nextPolicyId = 1000L;

    public Policy save(Policy policy) {
        if (policy.getPolicyId() == null) {
            policy.setPolicyId(generatePolicyId());
            policy.setCreatedAt(LocalDateTime.now());
        }
        policy.setUpdatedAt(LocalDateTime.now());

        policies.put(policy.getPolicyId(), policy);

        updateIndexes(policy);
        
                return policy;
    }

    public Optional<Policy> findById(Long policyId) {
        return Optional.ofNullable(policies.get(policyId));
    }

    public List<Policy> findByProposalId(Long proposalId) {
        return policies.values().stream()
            .filter(p -> proposalId.equals(p.getProposalId()))
            .collect(Collectors.toList());
    }

    public List<Policy> findActivePolices() {
        Set<Long> activePolicyIds = policyByStatus.getOrDefault(PolicyStatus.ACTIVE, Collections.emptySet());
        return activePolicyIds.stream()
            .map(policies::get)
            .filter(Objects::nonNull)
            .collect(Collectors.toList());
    }

    public List<Policy> findByType(String policyType) {
        Set<Long> policyIds = policyByType.getOrDefault(policyType, Collections.emptySet());
        return policyIds.stream()
            .map(policies::get)
            .filter(Objects::nonNull)
            .collect(Collectors.toList());
    }

    public List<Policy> findByStatus(PolicyStatus status) {
        Set<Long> policyIds = policyByStatus.getOrDefault(status, Collections.emptySet());
        return policyIds.stream()
            .map(policies::get)
            .filter(Objects::nonNull)
            .collect(Collectors.toList());
    }

    public List<Policy> findBySpelExpression(String spelExpression) {
        return policies.values().stream()
            .filter(p -> spelExpression.equals(p.getSpelExpression()))
            .collect(Collectors.toList());
    }

    public List<Policy> findAllActive() {
        return findByStatus(PolicyStatus.ACTIVE);
    }

    public List<Policy> findAll() {
        return new ArrayList<>(policies.values());
    }

    public Policy activate(Long policyId) {
        Policy policy = policies.get(policyId);
        if (policy == null) {
            throw new IllegalArgumentException("Policy not found: " + policyId);
        }

        PolicyStatus previousStatus = policy.getStatus();

        policy.setStatus(PolicyStatus.ACTIVE);
        policy.setActivatedAt(LocalDateTime.now());
        policy.setUpdatedAt(LocalDateTime.now());

        policy.incrementVersion();

        updateStatusIndex(policy, previousStatus);
        
                return policy;
    }

    public Policy deactivate(Long policyId, String reason) {
        Policy policy = policies.get(policyId);
        if (policy == null) {
            throw new IllegalArgumentException("Policy not found: " + policyId);
        }

        PolicyStatus previousStatus = policy.getStatus();

        policy.setStatus(PolicyStatus.INACTIVE);
        policy.setDeactivatedAt(LocalDateTime.now());
        policy.setUpdatedAt(LocalDateTime.now());
        policy.addMetadata("deactivation_reason", reason);

        policy.incrementVersion();

        updateStatusIndex(policy, previousStatus);
        
                return policy;
    }

    public boolean delete(Long policyId) {
        Policy policy = policies.remove(policyId);
        if (policy != null) {
            
            removeFromIndexes(policy);
                        return true;
        }
        return false;
    }

    public Optional<PolicyVersion> findVersion(Long policyId, int version) {
        Policy policy = policies.get(policyId);
        if (policy == null) {
            return Optional.empty();
        }
        
        return policy.getVersionHistory().stream()
            .filter(v -> v.getVersion() == version)
            .findFirst();
    }

    public List<PolicyVersion> getVersionHistory(Long policyId) {
        Policy policy = policies.get(policyId);
        if (policy == null) {
            return Collections.emptyList();
        }
        
        return new ArrayList<>(policy.getVersionHistory());
    }

    public Policy rollback(Long policyId, int targetVersion) {
        Policy policy = policies.get(policyId);
        if (policy == null) {
            throw new IllegalArgumentException("Policy not found: " + policyId);
        }
        
        PolicyVersion version = policy.getVersionHistory().stream()
            .filter(v -> v.getVersion() == targetVersion)
            .findFirst()
            .orElseThrow(() -> new IllegalArgumentException("Version not found: " + targetVersion));

        policy.saveCurrentVersion();

        policy.setSpelExpression(version.getSpelExpression());
        policy.setPolicyContent(version.getPolicyContent());
        policy.setMetadata(new HashMap<>(version.getMetadata()));
        policy.setUpdatedAt(LocalDateTime.now());
        policy.incrementVersion();
        policy.addMetadata("rolled_back_from", policy.getVersion() - 1);
        policy.addMetadata("rolled_back_to", targetVersion);
        
                return policy;
    }

    public PolicyStatistics getStatistics() {
        PolicyStatistics stats = new PolicyStatistics();
        
        stats.setTotalPolicies(policies.size());
        stats.setActivePolicies(policyByStatus.getOrDefault(PolicyStatus.ACTIVE, Collections.emptySet()).size());
        stats.setInactivePolicies(policyByStatus.getOrDefault(PolicyStatus.INACTIVE, Collections.emptySet()).size());

        Map<String, Integer> typeStats = new HashMap<>();
        for (Map.Entry<String, Set<Long>> entry : policyByType.entrySet()) {
            typeStats.put(entry.getKey(), entry.getValue().size());
        }
        stats.setPoliciesByType(typeStats);

        double avgVersion = policies.values().stream()
            .mapToInt(Policy::getVersion)
            .average()
            .orElse(0.0);
        stats.setAverageVersion(avgVersion);
        
        return stats;
    }

    private synchronized Long generatePolicyId() {
        return nextPolicyId++;
    }
    
    private void updateIndexes(Policy policy) {
        
        policyByType.computeIfAbsent(policy.getPolicyType(), k -> ConcurrentHashMap.newKeySet())
            .add(policy.getPolicyId());

        policyByStatus.computeIfAbsent(policy.getStatus(), k -> ConcurrentHashMap.newKeySet())
            .add(policy.getPolicyId());
    }
    
    private void updateStatusIndex(Policy policy, PolicyStatus previousStatus) {
        
        if (previousStatus != null) {
            Set<Long> previousSet = policyByStatus.get(previousStatus);
            if (previousSet != null) {
                previousSet.remove(policy.getPolicyId());
            }
        }

        policyByStatus.computeIfAbsent(policy.getStatus(), k -> ConcurrentHashMap.newKeySet())
            .add(policy.getPolicyId());
    }
    
    private void removeFromIndexes(Policy policy) {
        
        Set<Long> typeSet = policyByType.get(policy.getPolicyType());
        if (typeSet != null) {
            typeSet.remove(policy.getPolicyId());
        }

        Set<Long> statusSet = policyByStatus.get(policy.getStatus());
        if (statusSet != null) {
            statusSet.remove(policy.getPolicyId());
        }
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Policy {
        private Long policyId;
        private Long proposalId;
        private String policyName;
        private String policyType;
        private String spelExpression;
        private String policyContent;
        private PolicyStatus status;
        private int version;
        @Builder.Default
        private List<PolicyVersion> versionHistory = new ArrayList<>();
        @Builder.Default
        private Map<String, Object> metadata = new HashMap<>();
        private LocalDateTime createdAt;
        private LocalDateTime updatedAt;
        private LocalDateTime activatedAt;
        private LocalDateTime deactivatedAt;
        private String createdBy;

        public void incrementVersion() {
            this.version++;
        }
        
        public void addMetadata(String key, Object value) {
            this.metadata.put(key, value);
        }
        
        public void saveCurrentVersion() {
            PolicyVersion currentVersion = PolicyVersion.builder()
                .version(this.version)
                .spelExpression(this.spelExpression)
                .policyContent(this.policyContent)
                .metadata(new HashMap<>(this.metadata))
                .createdAt(LocalDateTime.now())
                .build();
            
            this.versionHistory.add(currentVersion);
        }
        
        public LocalDateTime getLastModified() {
            return updatedAt != null ? updatedAt : createdAt;
        }
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class PolicyVersion {
        private int version;
        private String spelExpression;
        private String policyContent;
        private Map<String, Object> metadata;
        private LocalDateTime createdAt;
    }

    public enum PolicyStatus {
        DRAFT,
        PENDING,
        ACTIVE,
        INACTIVE,
        DEPRECATED
    }

    @Data
    public static class PolicyStatistics {
        private int totalPolicies;
        private int activePolicies;
        private int inactivePolicies;
        private Map<String, Integer> policiesByType;
        private double averageVersion;
    }
}