package io.contexa.contexacore.std.components.prompt.governance;


import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceChangeRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceEvaluationRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceReleaseApprovalRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceRollbackRecord;
import io.contexa.contexacore.repository.prompt.PromptGovernanceChangeRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceEvaluationRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseApprovalRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRollbackRecordRepository;
import io.contexa.contexacore.std.components.prompt.PromptGovernanceDescriptor;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleState;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

@Transactional(transactionManager = "contexaTransactionManager")
public class PromptGovernanceLifecycleLedgerService {

    private static final int DEFAULT_LIMIT = 16;
    private static final int MAX_LIMIT = 40;

    private final PromptGovernanceRegistryService promptGovernanceRegistryService;
    private final PromptGovernanceChangeRecordRepository changeRepository;
    private final PromptGovernanceEvaluationRecordRepository evaluationRepository;
    private final PromptGovernanceReleaseApprovalRepository releaseApprovalRepository;
    private final PromptGovernanceRollbackRecordRepository rollbackRepository;

    public PromptGovernanceLifecycleLedgerService(
            PromptGovernanceRegistryService promptGovernanceRegistryService,
            PromptGovernanceChangeRecordRepository changeRepository,
            PromptGovernanceEvaluationRecordRepository evaluationRepository,
            PromptGovernanceReleaseApprovalRepository releaseApprovalRepository,
            PromptGovernanceRollbackRecordRepository rollbackRepository) {
        this.promptGovernanceRegistryService = promptGovernanceRegistryService;
        this.changeRepository = changeRepository;
        this.evaluationRepository = evaluationRepository;
        this.releaseApprovalRepository = releaseApprovalRepository;
        this.rollbackRepository = rollbackRepository;
    }

    /**
     * Records the imported declaration of each platform prompt in the change, evaluation, release approval and rollback
     * ledgers, once. A ledger row that already exists belongs to the release workflow and is left as it is, so an
     * evaluation or approval recorded later is never rewritten by the declaration (version management PV-4, PV-5).
     */
    public void syncPlatformLifecycleLedgers() {
        promptGovernanceRegistryService.syncPlatformRegistry();
        for (PromptGovernanceDescriptor descriptor : PromptGovernanceRegistryService.platformStandardDescriptors()) {
            registerChangeLedger(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE, descriptor, "STANDARD_TEMPLATE_BOOTSTRAP");
            registerEvaluationLedger(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE, descriptor, "STANDARD_TEMPLATE_BOOTSTRAP");
            registerReleaseApprovalLedger(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE, descriptor, "STANDARD_TEMPLATE_BOOTSTRAP");
            registerRollbackLedger(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE, descriptor, "STANDARD_TEMPLATE_BOOTSTRAP");
        }
    }

    public PromptGovernanceView.PromptGovernanceLifecycleLedgerSnapshot getPlatformSnapshot(Integer limit) {
        return getSnapshot(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE, limit);
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public PromptGovernanceView.PromptGovernanceLifecycleLedgerSnapshot getSnapshot(String registryScope, Integer limit) {
        int safeLimit = PaginationHelper.safeLimit(limit, DEFAULT_LIMIT, MAX_LIMIT);
        String safeScope = normalizeRegistryScope(registryScope);
        PromptGovernanceView.PromptGovernanceRegistrySnapshot registrySnapshot =
                promptGovernanceRegistryService.getSnapshot(safeScope, Math.max(safeLimit, DEFAULT_LIMIT));

        Map<String, PromptGovernanceChangeRecord> changeIndex = indexChanges(changeRepository.findByRegistryScopeOrderByUpdatedAtDesc(safeScope));
        Map<String, PromptGovernanceEvaluationRecord> evaluationIndex = indexEvaluations(evaluationRepository.findByRegistryScopeOrderByUpdatedAtDesc(safeScope));
        Map<String, PromptGovernanceReleaseApprovalRecord> releaseIndex =
                indexReleaseApprovals(releaseApprovalRepository.findByRegistryScopeOrderByUpdatedAtDesc(safeScope));
        Map<String, PromptGovernanceRollbackRecord> rollbackIndex = indexRollbacks(rollbackRepository.findByRegistryScopeOrderByUpdatedAtDesc(safeScope));

        List<PromptGovernanceView.PromptGovernanceLifecycleLedgerItem> prompts = registrySnapshot.prompts().stream()
                .limit(safeLimit)
                .map(item -> toItem(
                        item,
                        changeIndex.get(lifecycleKey(item.promptKey(), item.promptVersion())),
                        evaluationIndex.get(lifecycleKey(item.promptKey(), item.promptVersion())),
                        releaseIndex.get(lifecycleKey(item.promptKey(), item.promptVersion())),
                        rollbackIndex.get(lifecycleKey(item.promptKey(), item.promptVersion()))))
                .toList();

        long changeRecordedCount = prompts.stream().filter(PromptGovernanceView.PromptGovernanceLifecycleLedgerItem::changeRecorded).count();
        long empiricalEvalSatisfiedCount = prompts.stream().filter(PromptGovernanceView.PromptGovernanceLifecycleLedgerItem::empiricalEvalSatisfied).count();
        long releaseWorkflowControlledCount = prompts.stream().filter(PromptGovernanceView.PromptGovernanceLifecycleLedgerItem::releaseWorkflowControlled).count();
        long rollbackPreparedCount = prompts.stream().filter(PromptGovernanceView.PromptGovernanceLifecycleLedgerItem::rollbackPrepared).count();
        long modelCompatibleCount = prompts.stream().filter(PromptGovernanceView.PromptGovernanceLifecycleLedgerItem::modelProfilesDeclared).count();
        String lifecycleState = determineLifecycleState(prompts);

        return new PromptGovernanceView.PromptGovernanceLifecycleLedgerSnapshot(
                safeScope,
                prompts.size(),
                changeRecordedCount,
                empiricalEvalSatisfiedCount,
                releaseWorkflowControlledCount,
                rollbackPreparedCount,
                modelCompatibleCount,
                lifecycleState,
                buildLifecycleFacts(prompts, lifecycleState),
                prompts,
                LocalDateTime.now());
    }

    private void registerChangeLedger(String registryScope, PromptGovernanceDescriptor descriptor, String registrationSource) {
        if (changeRepository
                .findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                        registryScope,
                        descriptor.promptKey(),
                        descriptor.promptVersion())
                .isPresent()) {
            return;
        }
        PromptGovernanceChangeRecord record = new PromptGovernanceChangeRecord();
        record.setRegistryScope(registryScope);
        record.setPromptKey(descriptor.promptKey());
        record.setPromptVersion(descriptor.promptVersion());
        record.setContractVersion(descriptor.contractVersion());
        record.setChangeReference(String.format(Locale.ROOT, "IMPORTED-CHANGE:%s", descriptor.promptVersion()));
        record.setChangeType(PromptBundleState.fromReleaseStatus(descriptor.releaseStatus()) == PromptBundleState.ACTIVE
                ? "PROMPT_GOVERNANCE_STANDARDIZATION"
                : "PROMPT_RELEASE_UPDATE");
        record.setChangeState("IMPORTED_DECLARATION");
        record.setChangeSummary(descriptor.changeSummary());
        record.setChangedBy(descriptor.owner());
        record.setRegistrationSource(registrationSource);
        changeRepository.save(record);
    }

    private void registerEvaluationLedger(String registryScope, PromptGovernanceDescriptor descriptor, String registrationSource) {
        if (evaluationRepository
                .findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                        registryScope,
                        descriptor.promptKey(),
                        descriptor.promptVersion())
                .isPresent()) {
            return;
        }
        PromptGovernanceEvaluationRecord record = new PromptGovernanceEvaluationRecord();
        record.setRegistryScope(registryScope);
        record.setPromptKey(descriptor.promptKey());
        record.setPromptVersion(descriptor.promptVersion());
        record.setEvaluationReference(descriptor.evaluationBaselineReference());
        record.setEvaluationMode("POLICY_BASELINE");
        record.setEvaluationState("BASELINE_DECLARED");
        record.setEmpiricalEvidenceState("MISSING");
        record.setPromptInjectionState("NOT_VERIFIED");
        record.setScenarioCoverageState("NOT_RECORDED");
        record.setCoveredScenarioCount(0);
        // N-GOV-2: the declaration row needs the scenario families its bundle's manifest declares, or the default ones.
        record.setRequiredScenarioCount(
                PromptGovernanceEmpiricalEvalService.requiredScenarioFamilies(descriptor.bundle().orElse(null)).size());
        record.setCoveredScenarioFamiliesJson("[]");
        record.setTevvGateState("NOT_READY");
        record.setQualityGateState("NOT_VERIFIED");
        record.setLatencyGateState("NOT_VERIFIED");
        record.setCostGateState("NOT_VERIFIED");
        record.setEvaluationSummary(
                "Core prompt metadata declares a governance baseline, but empirical evaluation evidence is not yet recorded in enterprise workflow.");
        record.setEvaluatedBy(descriptor.owner());
        record.setRegistrationSource(registrationSource);
        evaluationRepository.save(record);
    }

    private void registerReleaseApprovalLedger(String registryScope, PromptGovernanceDescriptor descriptor, String registrationSource) {
        if (releaseApprovalRepository
                .findFirstByRegistryScopeAndPromptKeyAndTemplateKeyAndPromptVersionAndContractVersionOrderByUpdatedAtDesc(
                        registryScope,
                        descriptor.promptKey(),
                        descriptor.templateKey(),
                        descriptor.promptVersion(),
                        descriptor.contractVersion())
                .isPresent()) {
            return;
        }
        PromptGovernanceReleaseApprovalRecord record = new PromptGovernanceReleaseApprovalRecord();
        record.setRegistryScope(registryScope);
        record.setPromptKey(descriptor.promptKey());
        record.setTemplateKey(descriptor.templateKey());
        record.setPromptVersion(descriptor.promptVersion());
        record.setContractVersion(descriptor.contractVersion());
        record.setReleaseApprovalReference(descriptor.releaseApprovalReference());
        record.setReleaseStatus(PromptBundleState.fromReleaseStatus(descriptor.releaseStatus()).name());
        record.setApprovalState("IMPORTED_DECLARATION");
        record.setApprovalChannel("STANDARD_TEMPLATE_BOOTSTRAP");
        record.setApprovedBy(descriptor.owner());
        record.setApprovalSummary(
                "Release status is imported from the core prompt descriptor and must be re-approved through enterprise release governance.");
        record.setRegistrationSource(registrationSource);
        releaseApprovalRepository.save(record);
    }

    private void registerRollbackLedger(String registryScope, PromptGovernanceDescriptor descriptor, String registrationSource) {
        if (descriptor.rollbackPromptVersion() == null) {
            // Without a rollback target there is nothing to declare ready; a READY row would claim a rollback that
            // cannot run (version management PV-3).
            return;
        }
        if (rollbackRepository
                .findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                        registryScope,
                        descriptor.promptKey(),
                        descriptor.promptVersion())
                .isPresent()) {
            return;
        }
        PromptGovernanceRollbackRecord record = new PromptGovernanceRollbackRecord();
        record.setRegistryScope(registryScope);
        record.setPromptKey(descriptor.promptKey());
        record.setPromptVersion(descriptor.promptVersion());
        record.setRollbackReference(String.format(Locale.ROOT, "IMPORTED-ROLLBACK:%s", descriptor.promptVersion()));
        record.setRollbackTargetPromptVersion(descriptor.rollbackPromptVersion());
        record.setRollbackState("TARGET_DECLARED");
        record.setRollbackReadinessState("WORKFLOW_MISSING");
        record.setRollbackStrategy("VERSION_ROLLBACK");
        record.setRollbackReason(
                "Rollback target is declared in the core prompt descriptor, but rollback execution evidence is not yet managed in enterprise control plane.");
        record.setPreparedBy(descriptor.owner());
        record.setRegistrationSource(registrationSource);
        rollbackRepository.save(record);
    }

    private PromptGovernanceView.PromptGovernanceLifecycleLedgerItem toItem(
            PromptGovernanceView.PromptGovernanceRegistryItem registryItem,
            PromptGovernanceChangeRecord changeRecord,
            PromptGovernanceEvaluationRecord evaluationRecord,
            PromptGovernanceReleaseApprovalRecord releaseApprovalRecord,
            PromptGovernanceRollbackRecord rollbackRecord) {
        boolean changeRecorded = changeRecord != null;
        boolean empiricalEvalSatisfied = evaluationRecord != null
                && "PASSED".equals(evaluationRecord.getEvaluationState())
                && "SATISFIED".equals(evaluationRecord.getEmpiricalEvidenceState());
        boolean releaseWorkflowControlled = releaseApprovalRecord != null
                && "APPROVED".equals(releaseApprovalRecord.getApprovalState());
        boolean rollbackPrepared = rollbackRecord != null
                && "READY".equals(rollbackRecord.getRollbackReadinessState());

        List<String> lifecycleFacts = new ArrayList<>();
        lifecycleFacts.add(String.format(
                Locale.ROOT,
                "Release status %s currently maps to modelProfilesDeclared=%s.",
                registryItem.releaseStatus(),
                registryItem.modelProfilesDeclared()));
        if (changeRecord != null) {
            lifecycleFacts.add(String.format(
                    Locale.ROOT,
                    "Change ledger state is %s via %s.",
                    changeRecord.getChangeState(),
                    changeRecord.getChangeReference()));
        }
        else {
            lifecycleFacts.add("Change ledger evidence is missing.");
        }
        if (evaluationRecord != null) {
            lifecycleFacts.add(String.format(
                    Locale.ROOT,
                    "Evaluation state is %s with empiricalEvidenceState=%s, promptInjectionState=%s, scenarioCoverageState=%s and tevvGateState=%s.",
                    evaluationRecord.getEvaluationState(),
                    evaluationRecord.getEmpiricalEvidenceState(),
                    evaluationRecord.getPromptInjectionState(),
                    evaluationRecord.getScenarioCoverageState(),
                    evaluationRecord.getTevvGateState()));
        }
        else {
            lifecycleFacts.add("Evaluation evidence is missing.");
        }
        if (releaseApprovalRecord != null) {
            lifecycleFacts.add(String.format(
                    Locale.ROOT,
                    "Release approval state is %s through channel %s.",
                    releaseApprovalRecord.getApprovalState(),
                    releaseApprovalRecord.getApprovalChannel()));
        }
        else {
            lifecycleFacts.add("Release approval evidence is missing.");
        }
        if (rollbackRecord != null) {
            lifecycleFacts.add(String.format(
                    Locale.ROOT,
                    "Rollback state is %s toward %s with readiness=%s.",
                    rollbackRecord.getRollbackState(),
                    rollbackRecord.getRollbackTargetPromptVersion(),
                    rollbackRecord.getRollbackReadinessState()));
        }
        else {
            lifecycleFacts.add("Rollback preparedness evidence is missing.");
        }
        String lifecycleItemState = determineItemState(
                registryItem.releaseStatus(),
                changeRecorded,
                empiricalEvalSatisfied,
                releaseWorkflowControlled,
                rollbackPrepared);
        String summary = String.format(
                Locale.ROOT,
                "Prompt %s version %s is %s with lifecycle state %s.",
                registryItem.promptKey(),
                registryItem.promptVersion(),
                registryItem.releaseStatus(),
                lifecycleItemState);

        return new PromptGovernanceView.PromptGovernanceLifecycleLedgerItem(
                registryItem.promptKey(),
                registryItem.templateKey(),
                registryItem.promptVersion(),
                registryItem.contractVersion(),
                registryItem.releaseStatus(),
                changeRecord != null ? changeRecord.getChangeReference() : null,
                changeRecord != null ? changeRecord.getChangeType() : null,
                changeRecord != null ? changeRecord.getChangeState() : null,
                changeRecorded,
                evaluationRecord != null ? evaluationRecord.getEvaluationReference() : registryItem.evaluationBaselineReference(),
                evaluationRecord != null ? evaluationRecord.getEvaluationMode() : null,
                evaluationRecord != null ? evaluationRecord.getEvaluationState() : null,
                evaluationRecord != null ? evaluationRecord.getEmpiricalEvidenceState() : null,
                evaluationRecord != null ? evaluationRecord.getPromptInjectionState() : null,
                empiricalEvalSatisfied,
                releaseApprovalRecord != null ? releaseApprovalRecord.getReleaseApprovalReference() : registryItem.releaseApprovalReference(),
                releaseApprovalRecord != null ? releaseApprovalRecord.getApprovalState() : null,
                releaseApprovalRecord != null ? releaseApprovalRecord.getApprovalChannel() : null,
                releaseWorkflowControlled,
                rollbackRecord != null ? rollbackRecord.getRollbackReference() : null,
                rollbackRecord != null ? rollbackRecord.getRollbackTargetPromptVersion() : registryItem.rollbackPromptVersion(),
                rollbackRecord != null ? rollbackRecord.getRollbackState() : null,
                rollbackRecord != null ? rollbackRecord.getRollbackReadinessState() : null,
                rollbackPrepared,
                registryItem.modelProfilesDeclared(),
                registryItem.supportedModelProfiles(),
                lifecycleItemState,
                resolveUpdatedAt(changeRecord, evaluationRecord, releaseApprovalRecord, rollbackRecord, registryItem.updatedAt()),
                List.copyOf(lifecycleFacts),
                summary);
    }

    private String determineLifecycleState(List<PromptGovernanceView.PromptGovernanceLifecycleLedgerItem> items) {
        if (items.isEmpty()) {
            return "EMPTY";
        }
        boolean productionGap = items.stream()
                .filter(item -> PromptBundleState.is(item.currentReleaseStatus(), PromptBundleState.ACTIVE))
                .anyMatch(item -> !item.changeRecorded()
                        || !item.empiricalEvalSatisfied()
                        || !item.releaseWorkflowControlled()
                        || !item.rollbackPrepared()
                        || !item.modelProfilesDeclared());
        if (productionGap) {
            boolean empiricalEvalGap = items.stream()
                    .filter(item -> PromptBundleState.is(item.currentReleaseStatus(), PromptBundleState.ACTIVE))
                    .anyMatch(item -> !item.empiricalEvalSatisfied());
            if (empiricalEvalGap) {
                return "EMPIRICAL_EVAL_GAP";
            }
            boolean releaseGap = items.stream()
                    .filter(item -> PromptBundleState.is(item.currentReleaseStatus(), PromptBundleState.ACTIVE))
                    .anyMatch(item -> !item.releaseWorkflowControlled());
            if (releaseGap) {
                return "RELEASE_APPROVAL_GAP";
            }
            boolean rollbackGap = items.stream()
                    .filter(item -> PromptBundleState.is(item.currentReleaseStatus(), PromptBundleState.ACTIVE))
                    .anyMatch(item -> !item.rollbackPrepared());
            if (rollbackGap) {
                return "ROLLBACK_WORKFLOW_GAP";
            }
            return "LIFECYCLE_GAP";
        }
        boolean canaryActive = items.stream().anyMatch(item -> PromptBundleState.is(item.currentReleaseStatus(), PromptBundleState.CANARY));
        if (canaryActive) {
            return "CANARY_ACTIVE";
        }
        boolean productionPresent = items.stream().anyMatch(item -> PromptBundleState.is(item.currentReleaseStatus(), PromptBundleState.ACTIVE));
        if (productionPresent) {
            return "CONTROLLED_PRODUCTION";
        }
        return "RECORDED";
    }

    private List<String> buildLifecycleFacts(List<PromptGovernanceView.PromptGovernanceLifecycleLedgerItem> items, String lifecycleState) {
        if (items.isEmpty()) {
            return List.of("No prompt governance lifecycle records are registered yet.");
        }
        long productionCount = items.stream().filter(item -> PromptBundleState.is(item.currentReleaseStatus(), PromptBundleState.ACTIVE)).count();
        long empiricalGapCount = items.stream().filter(item -> !item.empiricalEvalSatisfied()).count();
        long releaseGapCount = items.stream().filter(item -> !item.releaseWorkflowControlled()).count();
        long rollbackGapCount = items.stream().filter(item -> !item.rollbackPrepared()).count();
        return List.of(
                String.format(Locale.ROOT, "%d prompts are tracked in lifecycle governance, including %d production prompts.", items.size(), productionCount),
                String.format(Locale.ROOT, "%d prompts still lack empirical prompt evaluation evidence.", empiricalGapCount),
                String.format(Locale.ROOT, "%d prompts still lack controlled release approval workflow evidence.", releaseGapCount),
                String.format(Locale.ROOT, "%d prompts still lack rollback workflow readiness evidence.", rollbackGapCount),
                String.format(Locale.ROOT, "Lifecycle state is %s.", lifecycleState)
        );
    }

    private String determineItemState(
            String releaseStatus,
            boolean changeRecorded,
            boolean empiricalEvalSatisfied,
            boolean releaseWorkflowControlled,
            boolean rollbackPrepared) {
        if (!changeRecorded) {
            return "CHANGE_LEDGER_GAP";
        }
        if (PromptBundleState.is(releaseStatus, PromptBundleState.ACTIVE) && !empiricalEvalSatisfied) {
            return "EMPIRICAL_EVAL_GAP";
        }
        if (PromptBundleState.is(releaseStatus, PromptBundleState.ACTIVE) && !releaseWorkflowControlled) {
            return "RELEASE_APPROVAL_GAP";
        }
        if (PromptBundleState.is(releaseStatus, PromptBundleState.ACTIVE) && !rollbackPrepared) {
            return "ROLLBACK_WORKFLOW_GAP";
        }
        return "CONTROLLED";
    }

    private LocalDateTime resolveUpdatedAt(
            PromptGovernanceChangeRecord changeRecord,
            PromptGovernanceEvaluationRecord evaluationRecord,
            PromptGovernanceReleaseApprovalRecord releaseApprovalRecord,
            PromptGovernanceRollbackRecord rollbackRecord,
            LocalDateTime registryUpdatedAt) {
        return Arrays.asList(
                        changeRecord != null ? changeRecord.getUpdatedAt() : null,
                        evaluationRecord != null ? evaluationRecord.getUpdatedAt() : null,
                        releaseApprovalRecord != null ? releaseApprovalRecord.getUpdatedAt() : null,
                        rollbackRecord != null ? rollbackRecord.getUpdatedAt() : null,
                        registryUpdatedAt)
                .stream()
                .filter(value -> value != null)
                .max(Comparator.naturalOrder())
                .orElse(registryUpdatedAt);
    }

    private Map<String, PromptGovernanceChangeRecord> indexChanges(List<PromptGovernanceChangeRecord> records) {
        Map<String, PromptGovernanceChangeRecord> current = new LinkedHashMap<>();
        records.stream()
                .sorted(Comparator.comparing(PromptGovernanceChangeRecord::getUpdatedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .forEach(record -> current.putIfAbsent(lifecycleKey(record.getPromptKey(), record.getPromptVersion()), record));
        return current;
    }

    private Map<String, PromptGovernanceEvaluationRecord> indexEvaluations(List<PromptGovernanceEvaluationRecord> records) {
        Map<String, PromptGovernanceEvaluationRecord> current = new LinkedHashMap<>();
        records.stream()
                .sorted(Comparator.comparing(PromptGovernanceEvaluationRecord::getUpdatedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .forEach(record -> current.putIfAbsent(lifecycleKey(record.getPromptKey(), record.getPromptVersion()), record));
        return current;
    }

    private Map<String, PromptGovernanceReleaseApprovalRecord> indexReleaseApprovals(List<PromptGovernanceReleaseApprovalRecord> records) {
        Map<String, PromptGovernanceReleaseApprovalRecord> current = new LinkedHashMap<>();
        records.stream()
                .sorted(Comparator.comparing(PromptGovernanceReleaseApprovalRecord::getUpdatedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .forEach(record -> current.putIfAbsent(lifecycleKey(record.getPromptKey(), record.getPromptVersion()), record));
        return current;
    }

    private Map<String, PromptGovernanceRollbackRecord> indexRollbacks(List<PromptGovernanceRollbackRecord> records) {
        Map<String, PromptGovernanceRollbackRecord> current = new LinkedHashMap<>();
        records.stream()
                .sorted(Comparator.comparing(PromptGovernanceRollbackRecord::getUpdatedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .forEach(record -> current.putIfAbsent(lifecycleKey(record.getPromptKey(), record.getPromptVersion()), record));
        return current;
    }

    private String lifecycleKey(String promptKey, String promptVersion) {
        return safeValue(promptKey, "UNKNOWN") + "::" + safeValue(promptVersion, "UNKNOWN");
    }

    private String normalizeRegistryScope(String registryScope) {
        return StringUtils.hasText(registryScope)
                ? registryScope.trim()
                : PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE;
    }

    private String safeValue(String value, String fallback) {
        return StringUtils.hasText(value) ? value.trim() : fallback;
    }
}
