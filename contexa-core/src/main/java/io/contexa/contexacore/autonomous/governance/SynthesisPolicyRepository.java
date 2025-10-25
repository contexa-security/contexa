package io.contexa.contexacore.autonomous.governance;

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
 * 정책 저장소
 * 
 * 활성화된 정책을 저장하고 관리합니다.
 * SpEL 표현식, 정책 버전, 정책 메타데이터를 관리합니다.
 * 
 * @author contexa
 * @since 1.0.0
 */
@Slf4j
@Repository
public class SynthesisPolicyRepository {
    
    // 정책 저장소 (실제 환경에서는 DB 사용)
    private final Map<Long, Policy> policies = new ConcurrentHashMap<>();
    
    // 정책 인덱스
    private final Map<String, Set<Long>> policyByType = new ConcurrentHashMap<>();
    private final Map<PolicyStatus, Set<Long>> policyByStatus = new ConcurrentHashMap<>();
    
    // ID 생성기
    private long nextPolicyId = 1000L;
    
    /**
     * 정책 저장
     * 
     * @param policy 정책
     * @return 저장된 정책
     */
    public Policy save(Policy policy) {
        if (policy.getPolicyId() == null) {
            policy.setPolicyId(generatePolicyId());
            policy.setCreatedAt(LocalDateTime.now());
        }
        policy.setUpdatedAt(LocalDateTime.now());
        
        // 저장
        policies.put(policy.getPolicyId(), policy);
        
        // 인덱스 업데이트
        updateIndexes(policy);
        
        log.info("Policy {} saved with status {}", policy.getPolicyId(), policy.getStatus());
        return policy;
    }
    
    /**
     * 정책 조회
     * 
     * @param policyId 정책 ID
     * @return 정책
     */
    public Optional<Policy> findById(Long policyId) {
        return Optional.ofNullable(policies.get(policyId));
    }
    
    /**
     * 제안 ID로 정책 조회
     * 
     * @param proposalId 제안 ID
     * @return 정책 목록
     */
    public List<Policy> findByProposalId(Long proposalId) {
        return policies.values().stream()
            .filter(p -> proposalId.equals(p.getProposalId()))
            .collect(Collectors.toList());
    }
    
    /**
     * 활성 정책 조회
     * 
     * @return 활성 정책 목록
     */
    public List<Policy> findActivePolices() {
        Set<Long> activePolicyIds = policyByStatus.getOrDefault(PolicyStatus.ACTIVE, Collections.emptySet());
        return activePolicyIds.stream()
            .map(policies::get)
            .filter(Objects::nonNull)
            .collect(Collectors.toList());
    }
    
    /**
     * 타입별 정책 조회
     * 
     * @param policyType 정책 타입
     * @return 정책 목록
     */
    public List<Policy> findByType(String policyType) {
        Set<Long> policyIds = policyByType.getOrDefault(policyType, Collections.emptySet());
        return policyIds.stream()
            .map(policies::get)
            .filter(Objects::nonNull)
            .collect(Collectors.toList());
    }
    
    /**
     * 상태별 정책 조회
     * 
     * @param status 정책 상태
     * @return 정책 목록
     */
    public List<Policy> findByStatus(PolicyStatus status) {
        Set<Long> policyIds = policyByStatus.getOrDefault(status, Collections.emptySet());
        return policyIds.stream()
            .map(policies::get)
            .filter(Objects::nonNull)
            .collect(Collectors.toList());
    }
    
    /**
     * SpEL 표현식으로 정책 검색
     * 
     * @param spelExpression SpEL 표현식
     * @return 정책 목록
     */
    public List<Policy> findBySpelExpression(String spelExpression) {
        return policies.values().stream()
            .filter(p -> spelExpression.equals(p.getSpelExpression()))
            .collect(Collectors.toList());
    }
    
    /**
     * 모든 활성 정책 조회
     * 
     * @return 활성 정책 목록
     */
    public List<Policy> findAllActive() {
        return findByStatus(PolicyStatus.ACTIVE);
    }
    
    /**
     * 모든 정책 조회
     * 
     * @return 전체 정책 목록
     */
    public List<Policy> findAll() {
        return new ArrayList<>(policies.values());
    }
    
    /**
     * 정책 활성화
     * 
     * @param policyId 정책 ID
     * @return 활성화된 정책
     */
    public Policy activate(Long policyId) {
        Policy policy = policies.get(policyId);
        if (policy == null) {
            throw new IllegalArgumentException("Policy not found: " + policyId);
        }
        
        // 이전 상태 저장
        PolicyStatus previousStatus = policy.getStatus();
        
        // 상태 변경
        policy.setStatus(PolicyStatus.ACTIVE);
        policy.setActivatedAt(LocalDateTime.now());
        policy.setUpdatedAt(LocalDateTime.now());
        
        // 버전 증가
        policy.incrementVersion();
        
        // 인덱스 업데이트
        updateStatusIndex(policy, previousStatus);
        
        log.info("Policy {} activated. Version: {}", policyId, policy.getVersion());
        return policy;
    }
    
    /**
     * 정책 비활성화
     * 
     * @param policyId 정책 ID
     * @param reason 비활성화 사유
     * @return 비활성화된 정책
     */
    public Policy deactivate(Long policyId, String reason) {
        Policy policy = policies.get(policyId);
        if (policy == null) {
            throw new IllegalArgumentException("Policy not found: " + policyId);
        }
        
        // 이전 상태 저장
        PolicyStatus previousStatus = policy.getStatus();
        
        // 상태 변경
        policy.setStatus(PolicyStatus.INACTIVE);
        policy.setDeactivatedAt(LocalDateTime.now());
        policy.setUpdatedAt(LocalDateTime.now());
        policy.addMetadata("deactivation_reason", reason);
        
        // 버전 증가
        policy.incrementVersion();
        
        // 인덱스 업데이트
        updateStatusIndex(policy, previousStatus);
        
        log.info("Policy {} deactivated. Reason: {}", policyId, reason);
        return policy;
    }
    
    /**
     * 정책 삭제
     * 
     * @param policyId 정책 ID
     * @return 삭제 성공 여부
     */
    public boolean delete(Long policyId) {
        Policy policy = policies.remove(policyId);
        if (policy != null) {
            // 인덱스에서 제거
            removeFromIndexes(policy);
            log.info("Policy {} deleted", policyId);
            return true;
        }
        return false;
    }
    
    /**
     * 정책 버전 조회
     * 
     * @param policyId 정책 ID
     * @param version 버전
     * @return 정책 버전
     */
    public Optional<PolicyVersion> findVersion(Long policyId, int version) {
        Policy policy = policies.get(policyId);
        if (policy == null) {
            return Optional.empty();
        }
        
        return policy.getVersionHistory().stream()
            .filter(v -> v.getVersion() == version)
            .findFirst();
    }
    
    /**
     * 정책 버전 이력 조회
     * 
     * @param policyId 정책 ID
     * @return 버전 이력
     */
    public List<PolicyVersion> getVersionHistory(Long policyId) {
        Policy policy = policies.get(policyId);
        if (policy == null) {
            return Collections.emptyList();
        }
        
        return new ArrayList<>(policy.getVersionHistory());
    }
    
    /**
     * 정책 롤백
     * 
     * @param policyId 정책 ID
     * @param targetVersion 대상 버전
     * @return 롤백된 정책
     */
    public Policy rollback(Long policyId, int targetVersion) {
        Policy policy = policies.get(policyId);
        if (policy == null) {
            throw new IllegalArgumentException("Policy not found: " + policyId);
        }
        
        PolicyVersion version = policy.getVersionHistory().stream()
            .filter(v -> v.getVersion() == targetVersion)
            .findFirst()
            .orElseThrow(() -> new IllegalArgumentException("Version not found: " + targetVersion));
        
        // 현재 상태를 버전 이력에 저장
        policy.saveCurrentVersion();
        
        // 버전 복원
        policy.setSpelExpression(version.getSpelExpression());
        policy.setPolicyContent(version.getPolicyContent());
        policy.setMetadata(new HashMap<>(version.getMetadata()));
        policy.setUpdatedAt(LocalDateTime.now());
        policy.incrementVersion();
        policy.addMetadata("rolled_back_from", policy.getVersion() - 1);
        policy.addMetadata("rolled_back_to", targetVersion);
        
        log.info("Policy {} rolled back to version {}", policyId, targetVersion);
        return policy;
    }
    
    /**
     * 정책 통계 조회
     * 
     * @return 정책 통계
     */
    public PolicyStatistics getStatistics() {
        PolicyStatistics stats = new PolicyStatistics();
        
        stats.setTotalPolicies(policies.size());
        stats.setActivePolicies(policyByStatus.getOrDefault(PolicyStatus.ACTIVE, Collections.emptySet()).size());
        stats.setInactivePolicies(policyByStatus.getOrDefault(PolicyStatus.INACTIVE, Collections.emptySet()).size());
        
        // 타입별 통계
        Map<String, Integer> typeStats = new HashMap<>();
        for (Map.Entry<String, Set<Long>> entry : policyByType.entrySet()) {
            typeStats.put(entry.getKey(), entry.getValue().size());
        }
        stats.setPoliciesByType(typeStats);
        
        // 평균 버전
        double avgVersion = policies.values().stream()
            .mapToInt(Policy::getVersion)
            .average()
            .orElse(0.0);
        stats.setAverageVersion(avgVersion);
        
        return stats;
    }
    
    // ==================== Private Methods ====================
    
    private synchronized Long generatePolicyId() {
        return nextPolicyId++;
    }
    
    private void updateIndexes(Policy policy) {
        // 타입 인덱스
        policyByType.computeIfAbsent(policy.getPolicyType(), k -> ConcurrentHashMap.newKeySet())
            .add(policy.getPolicyId());
        
        // 상태 인덱스
        policyByStatus.computeIfAbsent(policy.getStatus(), k -> ConcurrentHashMap.newKeySet())
            .add(policy.getPolicyId());
    }
    
    private void updateStatusIndex(Policy policy, PolicyStatus previousStatus) {
        // 이전 상태에서 제거
        if (previousStatus != null) {
            Set<Long> previousSet = policyByStatus.get(previousStatus);
            if (previousSet != null) {
                previousSet.remove(policy.getPolicyId());
            }
        }
        
        // 새 상태에 추가
        policyByStatus.computeIfAbsent(policy.getStatus(), k -> ConcurrentHashMap.newKeySet())
            .add(policy.getPolicyId());
    }
    
    private void removeFromIndexes(Policy policy) {
        // 타입 인덱스에서 제거
        Set<Long> typeSet = policyByType.get(policy.getPolicyType());
        if (typeSet != null) {
            typeSet.remove(policy.getPolicyId());
        }
        
        // 상태 인덱스에서 제거
        Set<Long> statusSet = policyByStatus.get(policy.getStatus());
        if (statusSet != null) {
            statusSet.remove(policy.getPolicyId());
        }
    }
    
    // ==================== Inner Classes ====================
    
    /**
     * 정책 엔티티
     */
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
    
    /**
     * 정책 버전
     */
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
    
    /**
     * 정책 상태
     */
    public enum PolicyStatus {
        DRAFT,
        PENDING,
        ACTIVE,
        INACTIVE,
        DEPRECATED
    }
    
    /**
     * 정책 통계
     */
    @Data
    public static class PolicyStatistics {
        private int totalPolicies;
        private int activePolicies;
        private int inactivePolicies;
        private Map<String, Integer> policiesByType;
        private double averageVersion;
    }
}