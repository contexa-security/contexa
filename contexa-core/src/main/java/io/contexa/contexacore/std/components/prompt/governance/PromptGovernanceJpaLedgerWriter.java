package io.contexa.contexacore.std.components.prompt.governance;

import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceChangeRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceEvaluationRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceRegistryRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceReleaseApprovalRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceReleaseWorkflowRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceRollbackRecord;
import io.contexa.contexacore.repository.prompt.PromptGovernanceChangeRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceEvaluationRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRegistryRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseApprovalRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseWorkflowRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRollbackRecordRepository;
import java.util.Objects;


import java.time.LocalDateTime;

/**
 * Writes the prompt governance ledgers through their JPA repositories. Every write is flushed at once because the
 * enterprise release and rule flows read the same tables through JDBC within the same transaction.
 */
public class PromptGovernanceJpaLedgerWriter {

    private final PromptGovernanceRegistryRepository registryRepository;
    private final PromptGovernanceChangeRecordRepository changeRepository;
    private final PromptGovernanceEvaluationRecordRepository evaluationRepository;
    private final PromptGovernanceReleaseApprovalRepository releaseApprovalRepository;
    private final PromptGovernanceReleaseWorkflowRepository releaseWorkflowRepository;
    private final PromptGovernanceRollbackRecordRepository rollbackRepository;

    public PromptGovernanceJpaLedgerWriter(
            PromptGovernanceRegistryRepository registryRepository,
            PromptGovernanceChangeRecordRepository changeRepository,
            PromptGovernanceEvaluationRecordRepository evaluationRepository,
            PromptGovernanceReleaseApprovalRepository releaseApprovalRepository,
            PromptGovernanceReleaseWorkflowRepository releaseWorkflowRepository,
            PromptGovernanceRollbackRecordRepository rollbackRepository) {
        this.registryRepository = Objects.requireNonNull(registryRepository, "registryRepository");
        this.changeRepository = Objects.requireNonNull(changeRepository, "changeRepository");
        this.evaluationRepository = Objects.requireNonNull(evaluationRepository, "evaluationRepository");
        this.releaseApprovalRepository = Objects.requireNonNull(releaseApprovalRepository, "releaseApprovalRepository");
        this.releaseWorkflowRepository = Objects.requireNonNull(releaseWorkflowRepository, "releaseWorkflowRepository");
        this.rollbackRepository = Objects.requireNonNull(rollbackRepository, "rollbackRepository");
    }

    public void upsertCandidateRegistry(
            String registryScope,
            String promptKey,
            String templateKey,
            String promptVersion,
            String contractVersion,
            String artifactHash,
            String releaseStatus,
            String owner,
            String releaseApprovalReference,
            String evaluationBaselineReference,
            String rollbackPromptVersion,
            String changeSummary,
            String templateClassName,
            String registrationSource,
            String supportedModelProfilesJson,
            LocalDateTime timestamp) {
        PromptGovernanceRegistryRecord record = registryRepository
                .findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                        registryScope, promptKey, promptVersion)
                .orElseGet(PromptGovernanceRegistryRecord::new);
        record.setRegistryScope(registryScope);
        record.setPromptKey(promptKey);
        record.setTemplateKey(templateKey);
        record.setPromptVersion(promptVersion);
        record.setContractVersion(contractVersion);
        record.setPromptArtifactHashSha256(artifactHash);
        record.setReleaseStatus(releaseStatus);
        record.setOwner(owner);
        record.setReleaseApprovalReference(releaseApprovalReference);
        record.setEvaluationBaselineReference(evaluationBaselineReference);
        record.setRollbackPromptVersion(rollbackPromptVersion);
        record.setChangeSummary(changeSummary);
        record.setTemplateClassName(templateClassName);
        record.setRegistrationSource(registrationSource);
        record.setSupportedModelProfilesJson(supportedModelProfilesJson);
        applyTimestamps(record, timestamp);
        registryRepository.saveAndFlush(record);
    }

    public void upsertCandidateChange(
            String registryScope,
            String promptKey,
            String promptVersion,
            String contractVersion,
            String changeReference,
            String changeType,
            String changeState,
            String changeSummary,
            String changedBy,
            String registrationSource,
            LocalDateTime timestamp) {
        PromptGovernanceChangeRecord record = changeRepository
                .findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                        registryScope, promptKey, promptVersion)
                .orElseGet(PromptGovernanceChangeRecord::new);
        record.setRegistryScope(registryScope);
        record.setPromptKey(promptKey);
        record.setPromptVersion(promptVersion);
        record.setContractVersion(contractVersion);
        record.setChangeReference(changeReference);
        record.setChangeType(changeType);
        record.setChangeState(changeState);
        record.setChangeSummary(changeSummary);
        record.setChangedBy(changedBy);
        record.setRegistrationSource(registrationSource);
        applyTimestamps(record, timestamp);
        changeRepository.saveAndFlush(record);
    }

    public void upsertCandidateEvaluation(
            String registryScope,
            String promptKey,
            String promptVersion,
            String evaluationReference,
            String evaluationMode,
            String evaluationState,
            String empiricalEvidenceState,
            String promptInjectionState,
            String scenarioCoverageState,
            int coveredScenarioCount,
            int requiredScenarioCount,
            String coveredScenarioFamiliesJson,
            String tevvGateState,
            String qualityGateState,
            String latencyGateState,
            String costGateState,
            String evaluationSummary,
            String evaluatedBy,
            String registrationSource,
            LocalDateTime timestamp) {
        PromptGovernanceEvaluationRecord record = evaluationRepository
                .findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                        registryScope, promptKey, promptVersion)
                .orElseGet(PromptGovernanceEvaluationRecord::new);
        record.setRegistryScope(registryScope);
        record.setPromptKey(promptKey);
        record.setPromptVersion(promptVersion);
        record.setEvaluationReference(evaluationReference);
        record.setEvaluationMode(evaluationMode);
        record.setEvaluationState(evaluationState);
        record.setEmpiricalEvidenceState(empiricalEvidenceState);
        record.setPromptInjectionState(promptInjectionState);
        record.setScenarioCoverageState(scenarioCoverageState);
        record.setCoveredScenarioCount(coveredScenarioCount);
        record.setRequiredScenarioCount(requiredScenarioCount);
        record.setCoveredScenarioFamiliesJson(coveredScenarioFamiliesJson);
        record.setTevvGateState(tevvGateState);
        record.setQualityGateState(qualityGateState);
        record.setLatencyGateState(latencyGateState);
        record.setCostGateState(costGateState);
        record.setEvaluationSummary(evaluationSummary);
        record.setEvaluatedBy(evaluatedBy);
        record.setRegistrationSource(registrationSource);
        applyTimestamps(record, timestamp);
        evaluationRepository.saveAndFlush(record);
    }

    public void updatePortfolioEvaluationByReference(
            String evaluationReference,
            String evaluationState,
            String empiricalEvidenceState,
            String scenarioCoverageState,
            int coveredScenarioCount,
            int requiredScenarioCount,
            String tevvGateState,
            String qualityGateState,
            String evaluationSummary,
            LocalDateTime timestamp) {
        evaluationRepository.findFirstByEvaluationReferenceOrderByUpdatedAtDesc(evaluationReference)
                .ifPresent(record -> {
                    record.setEvaluationState(evaluationState);
                    record.setEmpiricalEvidenceState(empiricalEvidenceState);
                    record.setScenarioCoverageState(scenarioCoverageState);
                    record.setCoveredScenarioCount(coveredScenarioCount);
                    record.setRequiredScenarioCount(requiredScenarioCount);
                    record.setTevvGateState(tevvGateState);
                    record.setQualityGateState(qualityGateState);
                    record.setEvaluationSummary(evaluationSummary);
                    record.setUpdatedAt(timestamp);
                    evaluationRepository.saveAndFlush(record);
                });
    }

    public void upsertReleaseApproval(
            String registryScope,
            String promptKey,
            String templateKey,
            String promptVersion,
            String contractVersion,
            String approvalReference,
            String releaseStatus,
            String approvalState,
            String approvalChannel,
            String approvedBy,
            String approvalSummary,
            String registrationSource,
            LocalDateTime timestamp) {
        PromptGovernanceReleaseApprovalRecord record = releaseApprovalRepository
                .findFirstByRegistryScopeAndPromptKeyAndTemplateKeyAndPromptVersionAndContractVersionOrderByUpdatedAtDesc(
                        registryScope, promptKey, templateKey, promptVersion, contractVersion)
                .orElseGet(PromptGovernanceReleaseApprovalRecord::new);
        record.setRegistryScope(registryScope);
        record.setPromptKey(promptKey);
        record.setTemplateKey(templateKey);
        record.setPromptVersion(promptVersion);
        record.setContractVersion(contractVersion);
        record.setReleaseApprovalReference(approvalReference);
        record.setReleaseStatus(releaseStatus);
        record.setApprovalState(approvalState);
        record.setApprovalChannel(approvalChannel);
        record.setApprovedBy(approvedBy);
        record.setApprovalSummary(approvalSummary);
        record.setRegistrationSource(registrationSource);
        applyTimestamps(record, timestamp);
        releaseApprovalRepository.saveAndFlush(record);
    }

    public void upsertRollback(
            String registryScope,
            String promptKey,
            String promptVersion,
            String rollbackReference,
            String rollbackTargetPromptVersion,
            String rollbackState,
            String rollbackReadinessState,
            String rollbackStrategy,
            String rollbackReason,
            String preparedBy,
            String registrationSource,
            LocalDateTime timestamp) {
        PromptGovernanceRollbackRecord record = rollbackRepository
                .findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                        registryScope, promptKey, promptVersion)
                .orElseGet(PromptGovernanceRollbackRecord::new);
        record.setRegistryScope(registryScope);
        record.setPromptKey(promptKey);
        record.setPromptVersion(promptVersion);
        record.setRollbackReference(rollbackReference);
        record.setRollbackTargetPromptVersion(rollbackTargetPromptVersion);
        record.setRollbackState(rollbackState);
        record.setRollbackReadinessState(rollbackReadinessState);
        record.setRollbackStrategy(rollbackStrategy);
        record.setRollbackReason(rollbackReason);
        record.setPreparedBy(preparedBy);
        record.setRegistrationSource(registrationSource);
        applyTimestamps(record, timestamp);
        rollbackRepository.saveAndFlush(record);
    }
    public void activateRegistryRelease(
            String registryScope,
            String promptKey,
            String promptVersion,
            String releaseStatus,
            String approvalReference,
            String registrationSource,
            LocalDateTime timestamp) {
        registryRepository.findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                        registryScope, promptKey, promptVersion)
                .ifPresent(record -> {
                    record.setReleaseStatus(releaseStatus);
                    record.setReleaseApprovalReference(approvalReference);
                    record.setRegistrationSource(registrationSource);
                    record.setUpdatedAt(timestamp);
                    registryRepository.saveAndFlush(record);
                });
    }

    public void recordWorkflow(
            String registryScope,
            String promptKey,
            String promptVersion,
            String currentReleaseStatus,
            String targetReleaseStatus,
            String workflowState,
            String gateState,
            String approvalChannel,
            String actor,
            String rationale,
            String blockersJson,
            LocalDateTime timestamp) {
        PromptGovernanceReleaseWorkflowRecord record = PromptGovernanceReleaseWorkflowRecord.builder()
                .registryScope(registryScope)
                .promptKey(promptKey)
                .promptVersion(promptVersion)
                .currentReleaseStatus(currentReleaseStatus)
                .targetReleaseStatus(targetReleaseStatus)
                .workflowState(workflowState)
                .gateState(gateState)
                .approvalChannel(approvalChannel)
                .actor(actor)
                .rationale(rationale)
                .blockersJson(blockersJson)
                .createdAt(timestamp)
                .build();
        releaseWorkflowRepository.saveAndFlush(record);
    }

    private void applyTimestamps(PromptGovernanceRegistryRecord record, LocalDateTime timestamp) {
        if (record.getCreatedAt() == null) {
            record.setCreatedAt(timestamp);
        }
        record.setUpdatedAt(timestamp);
    }

    private void applyTimestamps(PromptGovernanceChangeRecord record, LocalDateTime timestamp) {
        if (record.getCreatedAt() == null) {
            record.setCreatedAt(timestamp);
        }
        record.setUpdatedAt(timestamp);
    }

    private void applyTimestamps(PromptGovernanceEvaluationRecord record, LocalDateTime timestamp) {
        if (record.getCreatedAt() == null) {
            record.setCreatedAt(timestamp);
        }
        record.setUpdatedAt(timestamp);
    }

    private void applyTimestamps(PromptGovernanceReleaseApprovalRecord record, LocalDateTime timestamp) {
        if (record.getCreatedAt() == null) {
            record.setCreatedAt(timestamp);
        }
        record.setUpdatedAt(timestamp);
    }

    private void applyTimestamps(PromptGovernanceRollbackRecord record, LocalDateTime timestamp) {
        if (record.getCreatedAt() == null) {
            record.setCreatedAt(timestamp);
        }
        record.setUpdatedAt(timestamp);
    }}
