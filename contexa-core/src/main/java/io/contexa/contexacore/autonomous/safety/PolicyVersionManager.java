package io.contexa.contexacore.autonomous.safety;

import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.repository.PolicyProposalRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 정책 버전 관리자
 * 
 * 정책의 버전 이력을 관리하고 롤백 기능을 제공합니다.
 * 버전 충돌을 방지하고 정책 변경 추적을 가능하게 합니다.
 * 
 * @author contexa
 * @since 1.0.0
 */
@Component
public class PolicyVersionManager {
    
    private static final Logger logger = LoggerFactory.getLogger(PolicyVersionManager.class);
    
    @Autowired
    private PolicyProposalRepository proposalRepository;
    
    // 버전 체인 저장소
    private final Map<Long, PolicyVersionChain> versionChains = new ConcurrentHashMap<>();
    
    // 활성 버전 추적
    private final Map<String, Long> activePolicies = new ConcurrentHashMap<>();
    
    // 롤백 이력
    private final List<RollbackHistory> rollbackHistories = Collections.synchronizedList(new ArrayList<>());
    
    /**
     * 새로운 정책 버전 생성
     * 
     * @param proposal 정책 제안
     * @return 버전 ID
     */
    @Transactional
    public Long createVersion(PolicyEvolutionProposal proposal) {
        logger.info("Creating new policy version for proposal: {}", proposal.getId());
        
        try {
            // 버전 체인 생성 또는 가져오기
            PolicyVersionChain chain = getOrCreateChain(proposal);
            
            // 새 버전 추가
            PolicyVersion version = PolicyVersion.builder()
                .versionId(generateVersionId())
                .proposalId(proposal.getId())
                .createdAt(LocalDateTime.now())
                .parentVersionId(chain.getCurrentVersion())
                .metadata(extractMetadata(proposal))
                .build();
            
            chain.addVersion(version);
            
            // 버전 체인 저장
            versionChains.put(proposal.getId(), chain);
            
            logger.info("Created version {} for proposal {}", version.getVersionId(), proposal.getId());
            return version.getVersionId();
            
        } catch (Exception e) {
            logger.error("Failed to create version for proposal: {}", proposal.getId(), e);
            throw new PolicyVersionException("Version creation failed", e);
        }
    }
    
    /**
     * 정책 활성화
     * 
     * @param proposalId 제안 ID
     * @param versionId 버전 ID
     */
    @Transactional
    public void activateVersion(Long proposalId, Long versionId) {
        logger.info("Activating version {} for proposal {}", versionId, proposalId);
        
        PolicyVersionChain chain = versionChains.get(proposalId);
        if (chain == null) {
            throw new PolicyVersionException("Version chain not found for proposal: " + proposalId);
        }
        
        // 기존 활성 버전 비활성화
        deactivateCurrentVersion(proposalId);
        
        // 새 버전 활성화
        chain.setCurrentVersion(versionId);
        activePolicies.put(getPolicyKey(proposalId), versionId);
        
        logger.info("Activated version {} for proposal {}", versionId, proposalId);
    }
    
    /**
     * 정책 롤백
     * 
     * @param proposalId 제안 ID
     * @param targetVersionId 대상 버전 ID (null이면 이전 버전)
     * @return 롤백된 버전 ID
     */
    @Transactional
    public Long rollback(Long proposalId, Long targetVersionId) {
        logger.warn("Rolling back proposal {} to version {}", proposalId, targetVersionId);
        
        PolicyVersionChain chain = versionChains.get(proposalId);
        if (chain == null) {
            throw new PolicyVersionException("Cannot rollback: version chain not found");
        }
        
        Long currentVersion = chain.getCurrentVersion();
        Long rollbackTarget = targetVersionId != null ? targetVersionId : chain.getPreviousVersion(currentVersion);
        
        if (rollbackTarget == null) {
            throw new PolicyVersionException("No previous version available for rollback");
        }
        
        // 롤백 실행
        activateVersion(proposalId, rollbackTarget);
        
        // 롤백 이력 기록
        recordRollback(proposalId, currentVersion, rollbackTarget);
        
        logger.info("Rolled back proposal {} from version {} to {}", 
            proposalId, currentVersion, rollbackTarget);
        
        return rollbackTarget;
    }
    
    /**
     * 버전 이력 조회
     * 
     * @param proposalId 제안 ID
     * @return 버전 이력 목록
     */
    public List<PolicyVersion> getVersionHistory(Long proposalId) {
        PolicyVersionChain chain = versionChains.get(proposalId);
        if (chain == null) {
            return Collections.emptyList();
        }
        
        return chain.getVersionHistory();
    }
    
    /**
     * 버전 비교
     * 
     * @param proposalId 제안 ID
     * @param versionId1 첫 번째 버전
     * @param versionId2 두 번째 버전
     * @return 버전 차이점
     */
    public VersionDiff compareVersions(Long proposalId, Long versionId1, Long versionId2) {
        PolicyVersionChain chain = versionChains.get(proposalId);
        if (chain == null) {
            throw new PolicyVersionException("Version chain not found");
        }
        
        PolicyVersion v1 = chain.getVersion(versionId1);
        PolicyVersion v2 = chain.getVersion(versionId2);
        
        if (v1 == null || v2 == null) {
            throw new PolicyVersionException("One or both versions not found");
        }
        
        return VersionDiff.builder()
            .proposalId(proposalId)
            .fromVersion(versionId1)
            .toVersion(versionId2)
            .changes(calculateChanges(v1, v2))
            .timestamp(LocalDateTime.now())
            .build();
    }
    
    /**
     * 버전 정리 (오래된 버전 제거)
     * 
     * @param retainCount 유지할 버전 수
     */
    @Transactional
    public void pruneOldVersions(int retainCount) {
        logger.info("Pruning old versions, retaining {} versions per chain", retainCount);
        
        int totalPruned = 0;
        for (PolicyVersionChain chain : versionChains.values()) {
            int pruned = chain.pruneOldVersions(retainCount);
            totalPruned += pruned;
        }
        
        logger.info("Pruned {} old versions across all chains", totalPruned);
    }
    
    /**
     * 활성 정책 확인
     * 
     * @param proposalId 제안 ID
     * @return 활성 상태 여부
     */
    public boolean isActive(Long proposalId) {
        String key = getPolicyKey(proposalId);
        return activePolicies.containsKey(key);
    }
    
    /**
     * 버전 충돌 검사
     * 
     * @param proposalId 제안 ID
     * @param versionId 버전 ID
     * @return 충돌 여부
     */
    public boolean hasConflict(Long proposalId, Long versionId) {
        // 다른 활성 정책과의 충돌 검사
        for (Map.Entry<String, Long> entry : activePolicies.entrySet()) {
            if (!entry.getKey().equals(getPolicyKey(proposalId))) {
                // 실제 충돌 검사 로직 (PolicyConflictDetector에서 수행)
                if (checkVersionConflict(versionId, entry.getValue())) {
                    return true;
                }
            }
        }
        return false;
    }
    
    // ==================== Private Methods ====================
    
    private PolicyVersionChain getOrCreateChain(PolicyEvolutionProposal proposal) {
        return versionChains.computeIfAbsent(proposal.getId(), 
            id -> new PolicyVersionChain(id));
    }
    
    private Long generateVersionId() {
        return System.currentTimeMillis() + new Random().nextInt(1000);
    }
    
    private Map<String, Object> extractMetadata(PolicyEvolutionProposal proposal) {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("title", proposal.getTitle());
        metadata.put("type", proposal.getProposalType());
        metadata.put("riskLevel", proposal.getRiskLevel());
        metadata.put("confidenceScore", proposal.getConfidenceScore());
        metadata.put("createdAt", proposal.getCreatedAt());
        return metadata;
    }
    
    private void deactivateCurrentVersion(Long proposalId) {
        String key = getPolicyKey(proposalId);
        Long currentActive = activePolicies.get(key);
        if (currentActive != null) {
            logger.info("Deactivating current version {} for proposal {}", currentActive, proposalId);
            activePolicies.remove(key);
        }
    }
    
    private String getPolicyKey(Long proposalId) {
        return "policy_" + proposalId;
    }
    
    private void recordRollback(Long proposalId, Long fromVersion, Long toVersion) {
        RollbackHistory history = RollbackHistory.builder()
            .proposalId(proposalId)
            .fromVersion(fromVersion)
            .toVersion(toVersion)
            .timestamp(LocalDateTime.now())
            .reason("Manual rollback")
            .build();
        
        rollbackHistories.add(history);
    }
    
    private Map<String, Object> calculateChanges(PolicyVersion v1, PolicyVersion v2) {
        Map<String, Object> changes = new HashMap<>();
        
        // 메타데이터 비교
        Map<String, Object> meta1 = v1.getMetadata();
        Map<String, Object> meta2 = v2.getMetadata();
        
        for (String key : meta2.keySet()) {
            if (!meta1.containsKey(key) || !Objects.equals(meta1.get(key), meta2.get(key))) {
                changes.put(key, Map.of(
                    "old", meta1.get(key),
                    "new", meta2.get(key)
                ));
            }
        }
        
        return changes;
    }
    
    private boolean checkVersionConflict(Long versionId1, Long versionId2) {
        // 간단한 충돌 검사 (실제로는 PolicyConflictDetector에서 상세 검사)
        return false;
    }
    
    // ==================== Inner Classes ====================
    
    /**
     * 정책 버전 체인
     */
    private static class PolicyVersionChain {
        private final Long proposalId;
        private final List<PolicyVersion> versions;
        private Long currentVersion;
        
        public PolicyVersionChain(Long proposalId) {
            this.proposalId = proposalId;
            this.versions = new ArrayList<>();
        }
        
        public void addVersion(PolicyVersion version) {
            versions.add(version);
            currentVersion = version.getVersionId();
        }
        
        public PolicyVersion getVersion(Long versionId) {
            return versions.stream()
                .filter(v -> v.getVersionId().equals(versionId))
                .findFirst()
                .orElse(null);
        }
        
        public List<PolicyVersion> getVersionHistory() {
            return new ArrayList<>(versions);
        }
        
        public Long getCurrentVersion() {
            return currentVersion;
        }
        
        public void setCurrentVersion(Long versionId) {
            this.currentVersion = versionId;
        }
        
        public Long getPreviousVersion(Long versionId) {
            for (int i = versions.size() - 1; i >= 0; i--) {
                if (versions.get(i).getVersionId().equals(versionId) && i > 0) {
                    return versions.get(i - 1).getVersionId();
                }
            }
            return null;
        }
        
        public int pruneOldVersions(int retainCount) {
            if (versions.size() <= retainCount) {
                return 0;
            }
            
            int toRemove = versions.size() - retainCount;
            versions.subList(0, toRemove).clear();
            return toRemove;
        }
    }
    
    /**
     * 정책 버전
     */
    @lombok.Builder
    @lombok.Data
    private static class PolicyVersion {
        private Long versionId;
        private Long proposalId;
        private Long parentVersionId;
        private LocalDateTime createdAt;
        private Map<String, Object> metadata;
    }
    
    /**
     * 버전 차이점
     */
    @lombok.Builder
    @lombok.Data
    public static class VersionDiff {
        private Long proposalId;
        private Long fromVersion;
        private Long toVersion;
        private Map<String, Object> changes;
        private LocalDateTime timestamp;
    }
    
    /**
     * 롤백 이력
     */
    @lombok.Builder
    @lombok.Data
    private static class RollbackHistory {
        private Long proposalId;
        private Long fromVersion;
        private Long toVersion;
        private LocalDateTime timestamp;
        private String reason;
    }
    
    /**
     * 정책 버전 예외
     */
    public static class PolicyVersionException extends RuntimeException {
        public PolicyVersionException(String message) {
            super(message);
        }
        
        public PolicyVersionException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}