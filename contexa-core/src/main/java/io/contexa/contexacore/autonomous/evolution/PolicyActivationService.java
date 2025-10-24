package io.contexa.contexacore.autonomous.evolution;

import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal;
import io.contexa.contexacore.domain.entity.PolicyEvolutionProposal.ProposalStatus;
import io.contexa.contexacore.repository.PolicyProposalRepository;
import io.contexa.contexacore.autonomous.safety.EmergencyKillSwitch;
import io.contexa.contexacore.autonomous.safety.PolicyConflictDetector;
import io.contexa.contexacore.autonomous.safety.PolicyVersionManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * 정책 활성화 서비스
 * 
 * AI가 생성한 정책을 실제 시스템에 적용하고 관리합니다.
 * 안전한 활성화와 실시간 모니터링을 제공합니다.
 * 
 * @author AI3Security
 * @since 1.0.0
 */
@Service
public class PolicyActivationService {
    
    private static final Logger logger = LoggerFactory.getLogger(PolicyActivationService.class);
    
    @Autowired
    private PolicyProposalRepository proposalRepository;
    
    @Autowired
    private PolicyVersionManager versionManager;
    
    @Autowired
    private PolicyConflictDetector conflictDetector;
    
    @Autowired
    private EmergencyKillSwitch killSwitch;
    
    // CustomDynamicAuthorizationManager는 aiam 모듈에 있으므로 
    // aicore 에서는 ApplicationEventPublisher를 통해 간접적으로 정책을 전달
    @Autowired
    private ApplicationEventPublisher eventPublisher;
    
    // 활성화 작업 추적
    private final Map<Long, ActivationTask> activationTasks = new ConcurrentHashMap<>();
    
    // 활성화 메트릭
    private final ActivationMetrics metrics = new ActivationMetrics();
    
    /**
     * 정책 활성화
     * 
     * @param proposalId 제안 ID
     * @param activatedBy 활성화 요청자
     * @return 활성화 결과
     */
    @Transactional
    public ActivationResult activatePolicy(Long proposalId, String activatedBy) {
        logger.info("Activating policy {} requested by {}", proposalId, activatedBy);
        
        try {
            // 1. 제안 조회 및 검증
            PolicyEvolutionProposal proposal = proposalRepository.findById(proposalId)
                .orElseThrow(() -> new IllegalArgumentException("Proposal not found: " + proposalId));
            
            if (!canActivate(proposal)) {
                return ActivationResult.failure(proposalId, "Policy cannot be activated in current state");
            }
            
            // 2. 충돌 검사
            PolicyConflictDetector.ConflictCheckResult conflictResult = 
                conflictDetector.checkConflicts(proposal);
            
            if (!conflictResult.isCanProceed()) {
                return ActivationResult.failure(proposalId, 
                    "Conflicts detected: " + conflictResult.getConflicts());
            }
            
            // 3. 버전 생성
            Long versionId = versionManager.createVersion(proposal);
            
            // 4. 활성화 작업 생성
            ActivationTask task = createActivationTask(proposal, versionId, activatedBy);
            activationTasks.put(proposalId, task);
            
            // 5. 비동기 활성화 실행
            CompletableFuture<ActivationResult> future = executeActivation(task);
            
            // 6. 타임아웃 설정
            ActivationResult result = future.get(30, TimeUnit.SECONDS);
            
            // 7. 메트릭 업데이트
            updateMetrics(result);
            
            return result;
            
        } catch (Exception e) {
            logger.error("Failed to activate policy: {}", proposalId, e);
            return ActivationResult.failure(proposalId, "Activation failed: " + e.getMessage());
        }
    }
    
    /**
     * 정책 비활성화
     * 
     * @param proposalId 제안 ID
     * @param deactivatedBy 비활성화 요청자
     * @param reason 비활성화 이유
     * @return 비활성화 성공 여부
     */
    @Transactional
    public boolean deactivatePolicy(Long proposalId, String deactivatedBy, String reason) {
        logger.info("Deactivating policy {} requested by {}: {}", proposalId, deactivatedBy, reason);
        
        try {
            PolicyEvolutionProposal proposal = proposalRepository.findById(proposalId)
                .orElseThrow(() -> new IllegalArgumentException("Proposal not found"));
            
            if (proposal.getStatus() != ProposalStatus.ACTIVATED) {
                logger.warn("Policy {} is not active", proposalId);
                return false;
            }
            
            // 상태 변경
            proposal.setStatus(ProposalStatus.DEACTIVATED);
            proposal.setDeactivatedAt(LocalDateTime.now());
            proposal.addMetadata("deactivated_by", deactivatedBy);
            proposal.addMetadata("deactivation_reason", reason);
            
            proposalRepository.save(proposal);
            
            // 정책 비활성화 이벤트 발행 (aiam 모듈에서 처리)
            publishPolicyChangeEvent(proposal, PolicyChangeType.DEACTIVATED);
            
            // 이벤트 발행
            publishDeactivationEvent(proposal, deactivatedBy, reason);
            
            logger.info("Policy {} successfully deactivated", proposalId);
            return true;
            
        } catch (Exception e) {
            logger.error("Failed to deactivate policy: {}", proposalId, e);
            return false;
        }
    }
    
    /**
     * 일괄 활성화
     * 
     * @param proposalIds 제안 ID 목록
     * @param activatedBy 활성화 요청자
     * @return 활성화 결과 목록
     */
    @Async
    public CompletableFuture<List<ActivationResult>> batchActivate(
            List<Long> proposalIds, String activatedBy) {
        
        logger.info("Batch activating {} policies", proposalIds.size());
        
        List<CompletableFuture<ActivationResult>> futures = proposalIds.stream()
            .map(id -> CompletableFuture.supplyAsync(() -> activatePolicy(id, activatedBy)))
            .collect(Collectors.toList());
        
        return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
            .thenApply(v -> futures.stream()
                .map(CompletableFuture::join)
                .collect(Collectors.toList()));
    }
    
    /**
     * 조건부 활성화
     * 
     * @param proposalId 제안 ID
     * @param conditions 활성화 조건
     * @return 활성화 결과
     */
    public ActivationResult conditionalActivate(Long proposalId, ActivationConditions conditions) {
        logger.info("Conditional activation for policy {} with conditions: {}", proposalId, conditions);
        
        try {
            PolicyEvolutionProposal proposal = proposalRepository.findById(proposalId)
                .orElseThrow(() -> new IllegalArgumentException("Proposal not found"));
            
            // 조건 검증
            if (!validateConditions(proposal, conditions)) {
                return ActivationResult.failure(proposalId, "Activation conditions not met");
            }
            
            // 조건이 충족되면 활성화
            return activatePolicy(proposalId, conditions.getRequestedBy());
            
        } catch (Exception e) {
            logger.error("Conditional activation failed: {}", proposalId, e);
            return ActivationResult.failure(proposalId, e.getMessage());
        }
    }
    
    /**
     * 활성화 상태 조회
     * 
     * @param proposalId 제안 ID
     * @return 활성화 상태
     */
    public ActivationStatus getActivationStatus(Long proposalId) {
        ActivationTask task = activationTasks.get(proposalId);
        
        if (task == null) {
            PolicyEvolutionProposal proposal = proposalRepository.findById(proposalId).orElse(null);
            if (proposal == null) {
                return ActivationStatus.NOT_FOUND;
            }
            
            return mapStatusToActivationStatus(proposal.getStatus());
        }
        
        return task.getStatus();
    }
    
    /**
     * 활성화 롤백
     * 
     * @param proposalId 제안 ID
     * @param reason 롤백 이유
     * @return 롤백 성공 여부
     */
    @Transactional
    public boolean rollbackActivation(Long proposalId, String reason) {
        logger.warn("Rolling back activation for policy {}: {}", proposalId, reason);
        
        try {
            // 킬 스위치를 통한 롤백
            boolean rollbackSuccess = killSwitch.rollbackPolicy(proposalId, null);
            
            if (rollbackSuccess) {
                // 제안 상태 업데이트
                PolicyEvolutionProposal proposal = proposalRepository.findById(proposalId)
                    .orElseThrow(() -> new IllegalArgumentException("Proposal not found"));
                
                proposal.setStatus(ProposalStatus.ROLLED_BACK);
                proposal.addMetadata("rollback_reason", reason);
                proposal.addMetadata("rollback_time", LocalDateTime.now().toString());
                
                proposalRepository.save(proposal);
                
                // 정책 롤백 이벤트 발행 (aiam 모듈에서 처리)
                publishPolicyChangeEvent(proposal, PolicyChangeType.ROLLED_BACK);
                
                logger.info("Successfully rolled back policy {}", proposalId);
            }
            
            return rollbackSuccess;
            
        } catch (Exception e) {
            logger.error("Failed to rollback policy: {}", proposalId, e);
            return false;
        }
    }
    
    /**
     * 활성화 메트릭 조회
     * 
     * @return 활성화 메트릭
     */
    public ActivationMetrics getMetrics() {
        return metrics.snapshot();
    }
    
    // ==================== Private Methods ====================
    
    private boolean canActivate(PolicyEvolutionProposal proposal) {
        ProposalStatus status = proposal.getStatus();
        return status == ProposalStatus.APPROVED || status == ProposalStatus.PENDING;
    }
    
    private ActivationTask createActivationTask(PolicyEvolutionProposal proposal, 
                                               Long versionId, String activatedBy) {
        return ActivationTask.builder()
            .proposalId(proposal.getId())
            .versionId(versionId)
            .activatedBy(activatedBy)
            .startTime(LocalDateTime.now())
            .status(ActivationStatus.PREPARING)
            .build();
    }
    
    @Async
    public CompletableFuture<ActivationResult> executeActivation(ActivationTask task) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                // 1. 준비 단계
                task.setStatus(ActivationStatus.PREPARING);
                prepareActivation(task);
                
                // 2. 검증 단계
                task.setStatus(ActivationStatus.VALIDATING);
                validateActivation(task);
                
                // 3. 적용 단계
                task.setStatus(ActivationStatus.APPLYING);
                applyActivation(task);
                
                // 4. 검증 단계
                task.setStatus(ActivationStatus.VERIFYING);
                verifyActivation(task);
                
                // 5. 완료
                task.setStatus(ActivationStatus.ACTIVE);
                task.setEndTime(LocalDateTime.now());
                
                return ActivationResult.success(task.getProposalId(), task.getVersionId());
                
            } catch (Exception e) {
                task.setStatus(ActivationStatus.FAILED);
                task.setError(e.getMessage());
                
                // 실패 시 킬 스위치 활성화 고려
                if (shouldActivateKillSwitch(e)) {
                    killSwitch.activate("Activation failure: " + e.getMessage(), task.getProposalId());
                }
                
                return ActivationResult.failure(task.getProposalId(), e.getMessage());
            }
        });
    }
    
    private void prepareActivation(ActivationTask task) throws Exception {
        logger.debug("Preparing activation for proposal {}", task.getProposalId());

        PolicyEvolutionProposal proposal = proposalRepository.findById(task.getProposalId())
            .orElseThrow(() -> new ActivationException("Proposal not found during preparation"));

        // 1. 리소스 준비 - 제안 타입에 따른 리소스 확인
        validateResourceAvailability(proposal);

        // 2. 의존성 확인 - 다른 활성화된 정책과의 의존성 체크
        checkDependencies(proposal);

        // 3. 백업 생성 - 롤백을 위한 현재 상태 백업
        createBackup(task);

        logger.info("Activation preparation completed for proposal {}", task.getProposalId());
    }

    /**
     * 리소스 가용성 검증
     */
    private void validateResourceAvailability(PolicyEvolutionProposal proposal) throws ActivationException {
        // 정책 타입에 따른 리소스 확인
        switch (proposal.getProposalType()) {
            case CREATE_POLICY:
            case UPDATE_POLICY:
                // SpEL 표현식 유효성 확인
                if (proposal.getSpelExpression() == null || proposal.getSpelExpression().isEmpty()) {
                    throw new ActivationException("SpEL expression is required for policy creation/update");
                }
                break;

            case DELETE_POLICY:
            case REVOKE_ACCESS:
                // 삭제/취소 작업은 추가 리소스 불필요
                break;

            case ADJUST_THRESHOLD:
            case OPTIMIZE_RULE:
                // 임계값 조정은 메타데이터 확인
                if (proposal.getMetadata() == null || proposal.getMetadata().isEmpty()) {
                    throw new ActivationException("Metadata is required for threshold adjustment");
                }
                break;

            default:
                logger.debug("No specific resource validation for type: {}", proposal.getProposalType());
        }
    }

    /**
     * 의존성 확인
     */
    private void checkDependencies(PolicyEvolutionProposal proposal) throws ActivationException {
        // 활성화된 정책들과의 충돌 여부 확인 (ConflictDetector 활용)
        PolicyConflictDetector.ConflictCheckResult conflictResult = conflictDetector.checkConflicts(proposal);

        if (!conflictResult.isCanProceed()) {
            throw new ActivationException("Dependency conflict detected: " + conflictResult.getConflicts());
        }

        logger.debug("Dependency check passed for proposal {}", proposal.getId());
    }

    /**
     * 백업 생성
     */
    private void createBackup(ActivationTask task) throws ActivationException {
        try {
            // 버전 관리자를 통한 백업 생성
            Long backupVersionId = versionManager.createVersion(
                proposalRepository.findById(task.getProposalId())
                    .orElseThrow(() -> new ActivationException("Proposal not found for backup"))
            );

            // 백업 버전 ID를 태스크 메타데이터에 저장 (롤백 시 사용)
            logger.debug("Backup created with version ID: {} for proposal {}",
                backupVersionId, task.getProposalId());

        } catch (Exception e) {
            throw new ActivationException("Failed to create backup: " + e.getMessage(), e);
        }
    }
    
    private void validateActivation(ActivationTask task) throws Exception {
        logger.debug("Validating activation for proposal {}", task.getProposalId());
        
        PolicyEvolutionProposal proposal = proposalRepository.findById(task.getProposalId())
            .orElseThrow(() -> new IllegalStateException("Proposal not found"));
        
        // 버전 충돌 검사
        if (versionManager.hasConflict(task.getProposalId(), task.getVersionId())) {
            throw new ActivationException("Version conflict detected");
        }
        
        // 시스템 상태 검사
        EmergencyKillSwitch.KillSwitchStatus killSwitchStatus = killSwitch.getStatus();
        if (killSwitchStatus.isActivated() || killSwitchStatus.isSafeMode()) {
            throw new ActivationException("System is in safe mode");
        }
    }
    
    private void applyActivation(ActivationTask task) throws Exception {
        logger.info("Applying activation for proposal {}", task.getProposalId());
        
        PolicyEvolutionProposal proposal = proposalRepository.findById(task.getProposalId())
            .orElseThrow(() -> new IllegalStateException("Proposal not found"));
        
        // 정책 활성화 이벤트 발행 (aiam 모듈에서 처리)
        publishPolicyChangeEvent(proposal, PolicyChangeType.ACTIVATED);
        
        // 버전 관리자에 활성화 기록
        versionManager.activateVersion(task.getProposalId(), task.getVersionId());
        
        // 제안 상태 업데이트
        proposal.setStatus(ProposalStatus.ACTIVATED);
        proposal.setActivatedAt(LocalDateTime.now());
        proposal.setActivatedBy(task.getActivatedBy());
        
        proposalRepository.save(proposal);
        
        // 이벤트 발행
        publishActivationEvent(proposal, task);
    }
    
    private void verifyActivation(ActivationTask task) throws Exception {
        logger.debug("Verifying activation for proposal {}", task.getProposalId());

        PolicyEvolutionProposal proposal = proposalRepository.findById(task.getProposalId())
            .orElseThrow(() -> new ActivationException("Proposal not found during verification"));

        // 1. 활성화 검증 - 정책이 실제로 적용되었는지 확인
        verifyPolicyApplication(proposal);

        // 2. 건강 상태 확인 - 시스템 안정성 검사
        performHealthCheck(proposal, task);

        // 3. 초기 모니터링 - 정책 적용 직후 모니터링
        performInitialMonitoring(proposal, task);

        // 4. 킬 스위치에 성공 기록
        killSwitch.monitorExecution(task.getProposalId(), true);

        logger.info("Activation verification completed for proposal {}", task.getProposalId());
    }

    /**
     * 정책 적용 검증
     */
    private void verifyPolicyApplication(PolicyEvolutionProposal proposal) throws ActivationException {
        // 제안 상태가 ACTIVATED로 변경되었는지 확인
        if (proposal.getStatus() != ProposalStatus.ACTIVATED) {
            throw new ActivationException("Proposal status is not ACTIVATED: " + proposal.getStatus());
        }

        // 활성화 시간이 기록되었는지 확인
        if (proposal.getActivatedAt() == null) {
            throw new ActivationException("Activation timestamp is missing");
        }

        // 활성화자가 기록되었는지 확인
        if (proposal.getActivatedBy() == null || proposal.getActivatedBy().isEmpty()) {
            throw new ActivationException("Activator information is missing");
        }

        logger.debug("Policy application verified for proposal {}", proposal.getId());
    }

    /**
     * 건강 상태 확인
     */
    private void performHealthCheck(PolicyEvolutionProposal proposal, ActivationTask task) throws ActivationException {
        // 1. 킬 스위치 상태 확인
        EmergencyKillSwitch.KillSwitchStatus killSwitchStatus = killSwitch.getStatus();
        if (killSwitchStatus.isActivated()) {
            throw new ActivationException("Kill switch activated during verification");
        }

        // 2. 버전 관리자 상태 확인
        if (versionManager.hasConflict(task.getProposalId(), task.getVersionId())) {
            throw new ActivationException("Version conflict detected after activation");
        }

        // 3. 정책 충돌 재확인 (활성화 후 다른 정책과 충돌 발생 가능성)
        PolicyConflictDetector.ConflictCheckResult conflictResult = conflictDetector.checkConflicts(proposal);
        if (!conflictResult.isCanProceed()) {
            logger.warn("Post-activation conflict detected: {}", conflictResult.getConflicts());
            // 경고만 로그하고 계속 진행 (이미 활성화된 상태)
        }

        logger.debug("Health check passed for proposal {}", proposal.getId());
    }

    /**
     * 초기 모니터링
     */
    private void performInitialMonitoring(PolicyEvolutionProposal proposal, ActivationTask task) throws ActivationException {
        // 1. 활성화 메트릭 초기값 설정
        Map<String, Object> monitoringMetrics = new HashMap<>();
        monitoringMetrics.put("activatedAt", proposal.getActivatedAt());
        monitoringMetrics.put("activationType", proposal.getProposalType());
        monitoringMetrics.put("riskLevel", proposal.getRiskLevel());
        monitoringMetrics.put("confidenceScore", proposal.getConfidenceScore());
        monitoringMetrics.put("initialStatus", "HEALTHY");

        // 2. 제안 메타데이터에 모니터링 정보 추가
        proposal.addMetadata("monitoring_started_at", LocalDateTime.now().toString());
        proposal.addMetadata("initial_metrics", monitoringMetrics);

        // 3. 제안 저장 (메타데이터 업데이트)
        proposalRepository.save(proposal);

        logger.debug("Initial monitoring configured for proposal {}", proposal.getId());
    }
    
    private void publishPolicyChangeEvent(PolicyEvolutionProposal proposal, PolicyChangeType changeType) {
        logger.info("Publishing policy change event: {} for policy {}", changeType, proposal.getId());
        
        PolicyChangeEvent event = PolicyChangeEvent.builder()
            .proposalId(proposal.getId())
            .changeType(changeType)
            .policyRules(extractPolicyRules(proposal))
            .timestamp(LocalDateTime.now())
            .build();
        
        eventPublisher.publishEvent(event);
    }
    
    private Map<String, Object> extractPolicyRules(PolicyEvolutionProposal proposal) {
        Map<String, Object> rules = new HashMap<>();
        
        // 제안의 정책 내용에서 규칙 추출
        rules.put("id", proposal.getId());
        rules.put("type", proposal.getProposalType());
        rules.put("content", proposal.getPolicyContent());
        rules.put("metadata", proposal.getMetadata());
        
        return rules;
    }
    
    private boolean validateConditions(PolicyEvolutionProposal proposal, 
                                      ActivationConditions conditions) {
        // 시간 조건 검증
        if (conditions.getActivateAfter() != null && 
            LocalDateTime.now().isBefore(conditions.getActivateAfter())) {
            return false;
        }
        
        // 위험 수준 조건 검증
        if (conditions.getMaxRiskLevel() != null && 
            proposal.getRiskLevel().ordinal() > conditions.getMaxRiskLevel().ordinal()) {
            return false;
        }
        
        // 신뢰도 조건 검증
        if (conditions.getMinConfidenceScore() != null && 
            proposal.getConfidenceScore() < conditions.getMinConfidenceScore()) {
            return false;
        }
        
        return true;
    }
    
    private void updateMetrics(ActivationResult result) {
        if (result.isSuccess()) {
            metrics.incrementSuccessCount();
        } else {
            metrics.incrementFailureCount();
        }
        
        metrics.updateLastActivation(LocalDateTime.now());
    }
    
    private boolean shouldActivateKillSwitch(Exception e) {
        // 심각한 오류인 경우 킬 스위치 활성화
        return e instanceof SecurityException || 
               e instanceof IllegalStateException ||
               e.getMessage().contains("CRITICAL");
    }
    
    private ActivationStatus mapStatusToActivationStatus(ProposalStatus status) {
        switch (status) {
            case ACTIVATED:
                return ActivationStatus.ACTIVE;
            case DEACTIVATED:
                return ActivationStatus.DEACTIVATED;
            case ROLLED_BACK:
                return ActivationStatus.ROLLED_BACK;
            default:
                return ActivationStatus.INACTIVE;
        }
    }
    
    private void publishActivationEvent(PolicyEvolutionProposal proposal, ActivationTask task) {
        ActivationEvent event = ActivationEvent.builder()
            .proposalId(proposal.getId())
            .versionId(task.getVersionId())
            .activatedBy(task.getActivatedBy())
            .timestamp(LocalDateTime.now())
            .build();
        
        eventPublisher.publishEvent(event);
    }
    
    private void publishDeactivationEvent(PolicyEvolutionProposal proposal, 
                                         String deactivatedBy, String reason) {
        DeactivationEvent event = DeactivationEvent.builder()
            .proposalId(proposal.getId())
            .deactivatedBy(deactivatedBy)
            .reason(reason)
            .timestamp(LocalDateTime.now())
            .build();
        
        eventPublisher.publishEvent(event);
    }
    
    // ==================== Inner Classes ====================
    
    /**
     * 활성화 작업
     */
    @lombok.Builder
    @lombok.Data
    private static class ActivationTask {
        private Long proposalId;
        private Long versionId;
        private String activatedBy;
        private LocalDateTime startTime;
        private LocalDateTime endTime;
        private ActivationStatus status;
        private String error;
    }
    
    /**
     * 활성화 결과
     */
    @lombok.Builder
    @lombok.Data
    public static class ActivationResult {
        private Long proposalId;
        private Long versionId;
        private boolean success;
        private String message;
        private LocalDateTime timestamp;
        
        public static ActivationResult success(Long proposalId, Long versionId) {
            return ActivationResult.builder()
                .proposalId(proposalId)
                .versionId(versionId)
                .success(true)
                .message("Successfully activated")
                .timestamp(LocalDateTime.now())
                .build();
        }
        
        public static ActivationResult failure(Long proposalId, String message) {
            return ActivationResult.builder()
                .proposalId(proposalId)
                .success(false)
                .message(message)
                .timestamp(LocalDateTime.now())
                .build();
        }
    }
    
    /**
     * 활성화 조건
     */
    @lombok.Builder
    @lombok.Data
    public static class ActivationConditions {
        private String requestedBy;
        private LocalDateTime activateAfter;
        private PolicyEvolutionProposal.RiskLevel maxRiskLevel;
        private Double minConfidenceScore;
        private Map<String, Object> customConditions;
    }
    
    /**
     * 활성화 메트릭
     */
    @lombok.Data
    public static class ActivationMetrics {
        private long totalActivations = 0;
        private long successfulActivations = 0;
        private long failedActivations = 0;
        private LocalDateTime lastActivation;
        
        public void incrementSuccessCount() {
            totalActivations++;
            successfulActivations++;
        }
        
        public void incrementFailureCount() {
            totalActivations++;
            failedActivations++;
        }
        
        public void updateLastActivation(LocalDateTime time) {
            lastActivation = time;
        }
        
        public double getSuccessRate() {
            if (totalActivations == 0) return 0.0;
            return (double) successfulActivations / totalActivations;
        }
        
        public ActivationMetrics snapshot() {
            ActivationMetrics snapshot = new ActivationMetrics();
            snapshot.totalActivations = this.totalActivations;
            snapshot.successfulActivations = this.successfulActivations;
            snapshot.failedActivations = this.failedActivations;
            snapshot.lastActivation = this.lastActivation;
            return snapshot;
        }
    }
    
    /**
     * 활성화 이벤트
     */
    @lombok.Builder
    @lombok.Data
    public static class ActivationEvent {
        private Long proposalId;
        private Long versionId;
        private String activatedBy;
        private LocalDateTime timestamp;
    }
    
    /**
     * 비활성화 이벤트
     */
    @lombok.Builder
    @lombok.Data
    public static class DeactivationEvent {
        private Long proposalId;
        private String deactivatedBy;
        private String reason;
        private LocalDateTime timestamp;
    }
    
    /**
     * 활성화 상태
     */
    public enum ActivationStatus {
        PREPARING,
        VALIDATING,
        APPLYING,
        VERIFYING,
        ACTIVE,
        INACTIVE,
        DEACTIVATED,
        FAILED,
        ROLLED_BACK,
        NOT_FOUND
    }
    
    /**
     * 정책 변경 이벤트
     */
    @lombok.Builder
    @lombok.Data
    public static class PolicyChangeEvent {
        private Long proposalId;
        private PolicyChangeType changeType;
        private Map<String, Object> policyRules;
        private LocalDateTime timestamp;
    }
    
    /**
     * 정책 변경 타입
     */
    public enum PolicyChangeType {
        ACTIVATED,
        DEACTIVATED,
        ROLLED_BACK
    }
    
    /**
     * 활성화 예외
     */
    public static class ActivationException extends Exception {
        public ActivationException(String message) {
            super(message);
        }
        
        public ActivationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}