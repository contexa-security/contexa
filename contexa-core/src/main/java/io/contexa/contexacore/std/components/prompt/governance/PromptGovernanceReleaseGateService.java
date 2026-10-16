package io.contexa.contexacore.std.components.prompt.governance;


import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceBudgetProfileRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceEvaluationRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceModelCompatibilityRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceRegistryRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceReleaseApprovalRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceReleaseWorkflowRecord;
import io.contexa.contexacore.domain.entity.prompt.PromptGovernanceRollbackRecord;
import io.contexa.contexacore.repository.prompt.PromptGovernanceBudgetProfileRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceChangeRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceEvaluationRecordRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceModelCompatibilityRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRegistryRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseApprovalRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceReleaseWorkflowRepository;
import io.contexa.contexacore.repository.prompt.PromptGovernanceRollbackRecordRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.contexacore.std.components.prompt.PromptReleaseStatus;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleCatalog;
import io.contexa.contexacore.std.components.prompt.bundle.PromptBundleState;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

@Transactional(transactionManager = "contexaTransactionManager")
public class PromptGovernanceReleaseGateService implements PromptGovernanceReleaseGateReadOperations {

    private static final int DEFAULT_LIMIT = 16;
    private static final int MAX_LIMIT = 40;

    private final PromptGovernanceLifecycleLedgerService lifecycleLedgerService;
    private final PromptGovernanceRegistryRepository registryRepository;
    private final PromptGovernanceChangeRecordRepository changeRepository;
    private final PromptGovernanceEvaluationRecordRepository evaluationRepository;
    private final PromptGovernanceReleaseApprovalRepository releaseApprovalRepository;
    private final PromptGovernanceRollbackRecordRepository rollbackRepository;
    private final PromptGovernanceReleaseWorkflowRepository workflowRepository;
    private final PromptGovernanceModelCompatibilityRepository modelCompatibilityRepository;
    private final PromptGovernanceBudgetProfileRepository budgetProfileRepository;
    private final ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();

    public PromptGovernanceReleaseGateService(
            PromptGovernanceLifecycleLedgerService lifecycleLedgerService,
            PromptGovernanceRegistryRepository registryRepository,
            PromptGovernanceChangeRecordRepository changeRepository,
            PromptGovernanceEvaluationRecordRepository evaluationRepository,
            PromptGovernanceReleaseApprovalRepository releaseApprovalRepository,
            PromptGovernanceRollbackRecordRepository rollbackRepository,
            PromptGovernanceReleaseWorkflowRepository workflowRepository,
            PromptGovernanceModelCompatibilityRepository modelCompatibilityRepository,
            PromptGovernanceBudgetProfileRepository budgetProfileRepository) {
        this.lifecycleLedgerService = lifecycleLedgerService;
        this.registryRepository = registryRepository;
        this.changeRepository = changeRepository;
        this.evaluationRepository = evaluationRepository;
        this.releaseApprovalRepository = releaseApprovalRepository;
        this.rollbackRepository = rollbackRepository;
        this.workflowRepository = workflowRepository;
        this.modelCompatibilityRepository = modelCompatibilityRepository;
        this.budgetProfileRepository = budgetProfileRepository;
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    @Override
    public PromptGovernanceView.PromptGovernanceReleaseGateSnapshot getPlatformSnapshot(Integer limit) {
        return getSnapshot(PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE, limit);
    }

    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    @Override
    public PromptGovernanceView.PromptGovernanceReleaseGateSnapshot getSnapshot(String registryScope, Integer limit) {
        int safeLimit = PaginationHelper.safeLimit(limit, DEFAULT_LIMIT, MAX_LIMIT);
        String safeScope = normalizeRegistryScope(registryScope);
        PromptGovernanceView.PromptGovernanceLifecycleLedgerSnapshot lifecycleSnapshot =
                lifecycleLedgerService.getSnapshot(safeScope, safeLimit);
        Map<String, PromptGovernanceReleaseWorkflowRecord> workflowIndex = indexLatestWorkflows(
                workflowRepository.findByRegistryScopeOrderByCreatedAtDesc(safeScope));

        List<PromptGovernanceView.PromptGovernanceReleaseGateItem> prompts = lifecycleSnapshot.prompts().stream()
                .limit(safeLimit)
                .map(item -> toGateItem(safeScope, item, workflowIndex.get(workflowKey(item.promptKey(), item.promptVersion()))))
                .toList();

        long workflowRecordedCount = prompts.stream().filter(item -> item.latestWorkflowState() != null).count();
        long readyForCanaryCount = prompts.stream().filter(item -> "READY_FOR_CANARY".equals(item.gateState())).count();
        long readyForProductionCount = prompts.stream().filter(item -> "READY_FOR_PRODUCTION".equals(item.gateState())).count();
        long blockedCount = prompts.stream().filter(item -> item.gateState().startsWith("BLOCKED_")).count();
        long controlledProductionCount = prompts.stream().filter(item -> "CONTROLLED_PRODUCTION".equals(item.gateState())).count();
        String gateState = determinePortfolioGateState(prompts);

        return new PromptGovernanceView.PromptGovernanceReleaseGateSnapshot(
                safeScope,
                prompts.size(),
                workflowRecordedCount,
                readyForCanaryCount,
                readyForProductionCount,
                blockedCount,
                controlledProductionCount,
                gateState,
                buildGateFacts(prompts, gateState),
                prompts,
                LocalDateTime.now());
    }

    public ReleaseTransitionReceipt transitionPromptRelease(
            String registryScope,
            String promptKey,
            String promptVersion,
            PromptReleaseStatus targetReleaseStatus,
            String actor,
            String rationale,
            String approvalChannel) {
        String safeScope = normalizeRegistryScope(registryScope);
        validatePromptKey(promptKey);
        validatePromptVersion(promptVersion);
        validateActor(actor);
        PromptLifecycleContext context = resolveContext(safeScope, promptKey, promptVersion);
        PromptBundleState targetState = PromptBundleState.fromReleaseStatus(targetReleaseStatus);
        List<String> blockers = determineBlockers(context, targetState);
        String workflowState = blockers.isEmpty() ? "APPROVED_AND_APPLIED" : "BLOCKED";
        String gateState = determineTransitionGateState(context.currentReleaseStatus(), targetState, blockers);
        String normalizedChannel = normalizeApprovalChannel(approvalChannel);
        String normalizedRationale = normalizeRationale(
                rationale,
                String.format(Locale.ROOT, "Prompt release transition to %s requested by enterprise operator.", targetState.name()));

        PromptGovernanceReleaseWorkflowRecord workflowRecord = PromptGovernanceReleaseWorkflowRecord.builder()
                .registryScope(safeScope)
                .promptKey(promptKey.trim())
                .promptVersion(promptVersion.trim())
                .currentReleaseStatus(PromptBundleState.canonicalName(context.currentReleaseStatus()))
                .targetReleaseStatus(targetState.name())
                .workflowState(workflowState)
                .gateState(gateState)
                .approvalChannel(normalizedChannel)
                .actor(actor.trim())
                .rationale(normalizedRationale)
                .blockersJson(writeJsonList(blockers))
                .build();
        PromptGovernanceReleaseWorkflowRecord savedWorkflow = workflowRepository.save(workflowRecord);

        if (!blockers.isEmpty()) {
            return new ReleaseTransitionReceipt(
                    safeScope,
                    promptKey.trim(),
                    promptVersion.trim(),
                    context.currentReleaseStatus(),
                    targetState.name(),
                    false,
                    gateState,
                    List.copyOf(blockers),
                    savedWorkflow.getCreatedAt());
        }

        PromptGovernanceRegistryRecord registryRecord = context.registryRecord();
        registryRecord.setReleaseStatus(targetState.name());
        registryRecord.setReleaseApprovalReference(workflowReference(savedWorkflow));
        registryRecord.setRegistrationSource("PROMPT_RELEASE_GATE_WORKFLOW");
        registryRepository.save(registryRecord);

        upsertReleaseApproval(context, targetState, actor, normalizedRationale, normalizedChannel, savedWorkflow);
        upsertRollbackState(context, targetState, actor, normalizedRationale, savedWorkflow);

        return new ReleaseTransitionReceipt(
                safeScope,
                promptKey.trim(),
                promptVersion.trim(),
                context.currentReleaseStatus(),
                targetState.name(),
                true,
                gateState,
                List.of(),
                savedWorkflow.getCreatedAt());
    }

    /**
     * W7-14 (PV-8): the gate's answer for every state the bundle may take next, read without writing: the blockers a
     * transition to that state meets now and the evidence the gate reads for them. A state is ready exactly when a
     * transition to it would be applied, so a screen's 'ready' is this answer and follows no rule of its own.
     */
    @Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
    public ReleaseGateAssessment assessPromptRelease(String registryScope, String promptKey, String promptVersion) {
        String safeScope = normalizeRegistryScope(registryScope);
        validatePromptKey(promptKey);
        validatePromptVersion(promptVersion);
        PromptLifecycleContext context = resolveContext(safeScope, promptKey, promptVersion);
        List<ReleaseGateTarget> targets = new ArrayList<>();
        for (String next : allowedNextReleaseStatuses(context.currentReleaseStatus())) {
            PromptBundleState target = PromptBundleState.valueOf(next);
            List<String> blockers = determineBlockers(context, target);
            targets.add(new ReleaseGateTarget(target.name(), blockers.isEmpty(),
                    determineTransitionGateState(context.currentReleaseStatus(), target, blockers),
                    List.copyOf(blockers)));
        }
        PromptGovernanceEvaluationRecord evaluation = evaluationRepository
                .findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(safeScope, promptKey.trim(),
                        promptVersion.trim())
                .orElse(null);
        PromptGovernanceReleaseApprovalRecord approval = context.releaseApprovalRecord();
        ReleaseGateEvidence evidence = new ReleaseGateEvidence(
                context.changeRecorded(),
                evaluation != null ? evaluation.getEvaluationReference() : null,
                evaluation != null ? evaluation.getEvaluationState() : null,
                evaluation != null ? evaluation.getEmpiricalEvidenceState() : null,
                context.tevvGateState(),
                context.promptInjectionState(),
                context.latencyGateState(),
                context.costGateState(),
                evaluation != null ? evaluation.getQualityGateState() : null,
                evaluation != null ? evaluation.getScenarioCoverageState() : null,
                evaluation != null ? evaluation.getCoveredScenarioCount() : 0,
                evaluation != null ? evaluation.getRequiredScenarioCount() : 0,
                evaluation != null ? evaluation.getBundleHash() : null,
                evaluation != null ? evaluation.getRunReference() : null,
                evaluation != null && !context.evaluationOfAnotherBundle(),
                evaluation != null ? evaluation.getUpdatedAt() : null,
                approval != null ? approval.getApprovalState() : null,
                approval != null ? approval.getApprovedBy() : null,
                resolveRollbackTarget(context),
                context.rollbackRecord() != null ? context.rollbackRecord().getRollbackReadinessState() : null,
                context.supportedModelProfiles(),
                context.providerCompatibilityDeclared(),
                context.budgetProfileKeys(),
                context.tokenCountingPolicyDeclared(),
                context.cachePolicyGoverned(),
                context.compactionPolicyGoverned());
        return new ReleaseGateAssessment(safeScope, promptKey.trim(), promptVersion.trim(),
                PromptBundleState.canonicalName(context.currentReleaseStatus()), List.copyOf(targets), evidence);
    }

    private PromptGovernanceView.PromptGovernanceReleaseGateItem toGateItem(
            String registryScope,
            PromptGovernanceView.PromptGovernanceLifecycleLedgerItem lifecycleItem,
            PromptGovernanceReleaseWorkflowRecord latestWorkflow) {
        String expectedNextReleaseStatus = determineExpectedNextReleaseStatus(lifecycleItem);
        List<String> allowedNextReleaseStatuses = allowedNextReleaseStatuses(lifecycleItem.currentReleaseStatus());
        List<String> blockers = expectedNextReleaseStatus != null
                ? determineBlockers(registryScope, lifecycleItem, PromptBundleState.valueOf(expectedNextReleaseStatus))
                : List.of();
        String gateState = determineGateState(lifecycleItem, expectedNextReleaseStatus, blockers);
        List<String> budgetProfileKeys = currentBudgetProfileRecords(
                budgetProfileRepository.findByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                        registryScope,
                        lifecycleItem.promptKey(),
                        lifecycleItem.promptVersion()))
                .stream()
                .map(PromptGovernanceBudgetProfileRecord::getBudgetProfileKey)
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
        boolean budgetProfilesGoverned = !budgetProfileKeys.isEmpty();
        List<String> gateFacts = new ArrayList<>();
        gateFacts.add(String.format(
                Locale.ROOT,
                "Current release status is %s and expected next status is %s.",
                lifecycleItem.currentReleaseStatus(),
                safeValue(expectedNextReleaseStatus, "NONE")));
        gateFacts.add(String.format(
                Locale.ROOT,
                "Approval state=%s, rollbackReadiness=%s, modelProfilesDeclared=%s, budgetProfilesGoverned=%s.",
                safeValue(lifecycleItem.approvalState(), "MISSING"),
                safeValue(lifecycleItem.rollbackReadinessState(), "MISSING"),
                lifecycleItem.modelProfilesDeclared(),
                budgetProfilesGoverned));
        gateFacts.addAll(blockers);
        if (latestWorkflow != null) {
            gateFacts.add(String.format(
                    Locale.ROOT,
                    "Latest workflow was %s toward %s by %s.",
                    latestWorkflow.getWorkflowState(),
                    latestWorkflow.getTargetReleaseStatus(),
                    latestWorkflow.getActor()));
        }
        String summary = String.format(
                Locale.ROOT,
                "Prompt %s version %s is in %s with gate state %s.",
                lifecycleItem.promptKey(),
                lifecycleItem.promptVersion(),
                lifecycleItem.currentReleaseStatus(),
                gateState);

        return new PromptGovernanceView.PromptGovernanceReleaseGateItem(
                lifecycleItem.promptKey(),
                lifecycleItem.promptVersion(),
                lifecycleItem.currentReleaseStatus(),
                expectedNextReleaseStatus,
                allowedNextReleaseStatuses,
                gateState,
                List.copyOf(blockers),
                latestWorkflow != null ? latestWorkflow.getWorkflowState() : null,
                latestWorkflow != null ? latestWorkflow.getTargetReleaseStatus() : null,
                latestWorkflow != null ? latestWorkflow.getActor() : null,
                latestWorkflow != null ? latestWorkflow.getCreatedAt() : null,
                lifecycleItem.approvalState(),
                lifecycleItem.rollbackReadinessState(),
                lifecycleItem.modelProfilesDeclared(),
                lifecycleItem.supportedModelProfiles(),
                budgetProfilesGoverned,
                budgetProfileKeys,
                List.copyOf(gateFacts),
                summary);
    }

    private String determinePortfolioGateState(List<PromptGovernanceView.PromptGovernanceReleaseGateItem> prompts) {
        if (prompts.isEmpty()) {
            return "EMPTY";
        }
        if (prompts.stream().anyMatch(item -> item.gateState().startsWith("BLOCKED_"))) {
            return "BLOCKED";
        }
        if (prompts.stream().anyMatch(item -> "READY_FOR_PRODUCTION".equals(item.gateState()))) {
            return "READY_FOR_PRODUCTION";
        }
        if (prompts.stream().anyMatch(item -> "READY_FOR_CANARY".equals(item.gateState()))) {
            return "READY_FOR_CANARY";
        }
        if (prompts.stream().allMatch(item -> "CONTROLLED_PRODUCTION".equals(item.gateState()))) {
            return "CONTROLLED_PRODUCTION";
        }
        if (prompts.stream().anyMatch(item -> "UNCONTROLLED_PRODUCTION".equals(item.gateState()))) {
            return "UNCONTROLLED_PRODUCTION";
        }
        return "RECORDED";
    }

    private List<String> buildGateFacts(List<PromptGovernanceView.PromptGovernanceReleaseGateItem> prompts, String gateState) {
        if (prompts.isEmpty()) {
            return List.of("No prompt governance release gate items are registered yet.");
        }
        long uncontrolledProductionCount = prompts.stream().filter(item -> "UNCONTROLLED_PRODUCTION".equals(item.gateState())).count();
        return List.of(
                String.format(Locale.ROOT, "%d prompts are currently visible in release governance.", prompts.size()),
                String.format(Locale.ROOT, "%d prompts are still in uncontrolled imported production.", uncontrolledProductionCount),
                String.format(Locale.ROOT, "Release gate portfolio state is %s.", gateState)
        );
    }

    private PromptLifecycleContext resolveContext(String registryScope, String promptKey, String promptVersion) {
        PromptGovernanceRegistryRecord registryRecord = registryRepository
                .findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(registryScope, promptKey.trim(), promptVersion.trim())
                .orElseThrow(() -> new IllegalArgumentException("Unknown prompt governance artifact: " + promptKey + "@" + promptVersion));
        boolean changeRecorded = changeRepository
                .findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(registryScope, promptKey.trim(), promptVersion.trim())
                .isPresent();
        PromptGovernanceEvaluationRecord evaluationRecord = evaluationRepository
                .findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(registryScope, promptKey.trim(), promptVersion.trim())
                .orElse(null);
        PromptGovernanceReleaseApprovalRecord releaseApprovalRecord = releaseApprovalRepository
                .findFirstByRegistryScopeAndPromptKeyAndTemplateKeyAndPromptVersionAndContractVersionOrderByUpdatedAtDesc(
                        registryScope,
                        promptKey.trim(),
                        registryRecord.getTemplateKey(),
                        promptVersion.trim(),
                        registryRecord.getContractVersion())
                .orElse(null);
        PromptGovernanceRollbackRecord rollbackRecord = rollbackRepository
                .findFirstByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(registryScope, promptKey.trim(), promptVersion.trim())
                .orElse(null);
        List<PromptGovernanceModelCompatibilityRecord> compatibilityRecords = currentModelCompatibilityRecords(
                modelCompatibilityRepository.findByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                        registryScope,
                        promptKey.trim(),
                        promptVersion.trim()));
        List<PromptGovernanceBudgetProfileRecord> budgetProfileRecords = currentBudgetProfileRecords(
                budgetProfileRepository.findByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                        registryScope,
                        promptKey.trim(),
                        promptVersion.trim()));
        return new PromptLifecycleContext(
                registryRecord,
                registryRecord.getReleaseStatus(),
                changeRecorded,
                evaluationRecord != null
                        && evaluationOfThisBundle(evaluationRecord, promptKey, promptVersion)
                        && "PASSED".equals(evaluationRecord.getEvaluationState())
                        && "SATISFIED".equals(evaluationRecord.getEmpiricalEvidenceState())
                        && "READY_FOR_PRODUCTION".equals(evaluationRecord.getTevvGateState()),
                evaluationRecord != null && !evaluationOfThisBundle(evaluationRecord, promptKey, promptVersion),
                releaseApprovalRecord != null && "APPROVED".equals(releaseApprovalRecord.getApprovalState()),
                rollbackRecord != null && "READY".equals(rollbackRecord.getRollbackReadinessState()),
                rollbackTargetDeclared(registryRecord, rollbackRecord),
                evaluationRecord != null ? evaluationRecord.getTevvGateState() : "NOT_READY",
                evaluationRecord != null ? evaluationRecord.getPromptInjectionState() : "NOT_VERIFIED",
                evaluationRecord != null ? evaluationRecord.getLatencyGateState() : "NOT_VERIFIED",
                evaluationRecord != null ? evaluationRecord.getCostGateState() : "NOT_VERIFIED",
                releaseApprovalRecord,
                rollbackRecord,
                readJsonList(registryRecord.getSupportedModelProfilesJson()),
                compatibilityRecords.stream().anyMatch(record -> "PROVIDER_COMPATIBILITY".equals(record.getProfileCategory())),
                !budgetProfileRecords.isEmpty(),
                !budgetProfileRecords.isEmpty()
                        && budgetProfileRecords.stream().allMatch(record -> StringUtils.hasText(record.getTokenCountingPolicyKey())),
                !budgetProfileRecords.isEmpty()
                        && budgetProfileRecords.stream().allMatch(record -> StringUtils.hasText(record.getCachePolicyKey())
                        && StringUtils.hasText(record.getCachePolicyState())),
                !budgetProfileRecords.isEmpty()
                        && budgetProfileRecords.stream().allMatch(record -> StringUtils.hasText(record.getCompactionPolicyKey())
                        && StringUtils.hasText(record.getCompactionPolicyState())),
                budgetProfileRecords.stream()
                        .map(PromptGovernanceBudgetProfileRecord::getBudgetProfileKey)
                        .filter(StringUtils::hasText)
                        .distinct()
                        .toList());
    }

    private List<String> determineBlockers(PromptLifecycleContext context, PromptBundleState targetReleaseStatus) {
        List<String> blockers = new ArrayList<>();
        if (!allowedNextReleaseStatuses(context.currentReleaseStatus()).contains(targetReleaseStatus.name())) {
            blockers.add(String.format(
                    Locale.ROOT,
                    "ILLEGAL_STATE_TRANSITION current=%s target=%s.",
                    context.currentReleaseStatus(),
                    targetReleaseStatus.name()));
            return blockers;
        }
        // W6-8 (PV-5, PV-6): the evidence of a bundle of this build is the evaluation made with its own hash.
        if (context.evaluationOfAnotherBundle()
                && (targetReleaseStatus == PromptBundleState.CANARY || targetReleaseStatus == PromptBundleState.ACTIVE)) {
            blockers.add("EVALUATION_NOT_FOR_BUNDLE_HASH the evaluation was not made with this bundle's hash.");
        }
        if (targetReleaseStatus == PromptBundleState.SHADOW && !context.changeRecorded()) {
            blockers.add("CHANGE_LEDGER_MISSING enterprise change evidence must exist before opening eval-only release.");
        }
        if (targetReleaseStatus == PromptBundleState.CANARY) {
            if (!context.changeRecorded()) {
                blockers.add("CHANGE_LEDGER_MISSING enterprise change evidence must exist before canary rollout.");
            }
            if (!context.providerCompatibilityDeclared()) {
                blockers.add("MODEL_COMPATIBILITY_MISSING provider compatibility registry entries must exist before canary rollout.");
            }
            if (!context.budgetProfilesGoverned()) {
                blockers.add("BUDGET_PROFILE_MISSING governed budget profiles must exist before canary rollout.");
            }
            if (!context.rollbackTargetDeclared()) {
                blockers.add("ROLLBACK_TARGET_MISSING rollback target prompt version must be declared before canary rollout.");
            }
        }
        if (targetReleaseStatus == PromptBundleState.ACTIVE) {
            if (!context.changeRecorded()) {
                blockers.add("CHANGE_LEDGER_MISSING enterprise change evidence must exist before production release.");
            }
            if ("PROMPT_INJECTION_BLOCK".equals(context.tevvGateState()) || "FAILED".equals(context.promptInjectionState())) {
                blockers.add("PROMPT_INJECTION_GATE_FAILED prompt injection gate must pass before production release.");
            }
            if ("FAILED".equals(context.latencyGateState()) || "FAILED".equals(context.costGateState())
                    || "NON_FUNCTIONAL_BLOCK".equals(context.tevvGateState())) {
                blockers.add("NON_FUNCTIONAL_GATE_FAILED latency and cost gates must pass before production release.");
            }
            if (!context.empiricalEvalSatisfied()) {
                blockers.add("EMPIRICAL_EVAL_MISSING empirical prompt evaluation must pass before production release.");
            }
            if (!"READY_FOR_PRODUCTION".equals(context.tevvGateState())) {
                blockers.add("TEVV_GATE_NOT_READY prompt TEVV gate must be READY_FOR_PRODUCTION before production release.");
            }
            if (!context.providerCompatibilityDeclared()) {
                blockers.add("MODEL_COMPATIBILITY_MISSING provider compatibility registry entries must exist before production release.");
            }
            if (!context.budgetProfilesGoverned()) {
                blockers.add("BUDGET_PROFILE_MISSING governed budget profiles must exist before production release.");
            }
            if (!context.tokenCountingPolicyDeclared()) {
                blockers.add("TOKEN_COUNTING_POLICY_MISSING model-aware token counting policy must be declared before production release.");
            }
            if (!context.cachePolicyGoverned()) {
                blockers.add("CACHE_POLICY_MISSING cache policy must be governed before production release.");
            }
            if (!context.compactionPolicyGoverned()) {
                blockers.add("COMPACTION_POLICY_MISSING compaction policy must be governed before production release.");
            }
            if (!context.rollbackTargetDeclared()) {
                blockers.add("ROLLBACK_TARGET_MISSING rollback target prompt version must be declared before production release.");
            }
        }
        if (targetReleaseStatus == PromptBundleState.DEPRECATED && !context.rollbackTargetDeclared()) {
            blockers.add("ROLLBACK_TARGET_MISSING rollback target prompt version must be declared before rollback execution.");
        }
        return blockers;
    }

    private List<String> determineBlockers(
            String registryScope,
            PromptGovernanceView.PromptGovernanceLifecycleLedgerItem lifecycleItem,
            PromptBundleState targetReleaseStatus) {
        List<String> blockers = new ArrayList<>();
        List<String> budgetProfileKeys = currentBudgetProfileRecords(
                budgetProfileRepository.findByRegistryScopeAndPromptKeyAndPromptVersionOrderByUpdatedAtDesc(
                        registryScope,
                        lifecycleItem.promptKey(),
                        lifecycleItem.promptVersion()))
                .stream()
                .map(PromptGovernanceBudgetProfileRecord::getBudgetProfileKey)
                .filter(StringUtils::hasText)
                .distinct()
                .toList();
        boolean budgetProfilesGoverned = !budgetProfileKeys.isEmpty();
        if (!allowedNextReleaseStatuses(lifecycleItem.currentReleaseStatus()).contains(targetReleaseStatus.name())) {
            blockers.add(String.format(
                    Locale.ROOT,
                    "ILLEGAL_STATE_TRANSITION current=%s target=%s.",
                    lifecycleItem.currentReleaseStatus(),
                    targetReleaseStatus.name()));
            return blockers;
        }
        if (targetReleaseStatus == PromptBundleState.SHADOW && !lifecycleItem.changeRecorded()) {
            blockers.add("CHANGE_LEDGER_MISSING enterprise change evidence must exist before opening eval-only release.");
        }
        if (targetReleaseStatus == PromptBundleState.CANARY) {
            if (!lifecycleItem.changeRecorded()) {
                blockers.add("CHANGE_LEDGER_MISSING enterprise change evidence must exist before canary rollout.");
            }
            if (!lifecycleItem.modelProfilesDeclared()) {
                blockers.add("MODEL_COMPATIBILITY_MISSING supported model profiles must be declared before canary rollout.");
            }
            if (!budgetProfilesGoverned) {
                blockers.add("BUDGET_PROFILE_MISSING governed budget profiles must exist before canary rollout.");
            }
            if (!StringUtils.hasText(lifecycleItem.rollbackTargetPromptVersion())) {
                blockers.add("ROLLBACK_TARGET_MISSING rollback target prompt version must be declared before canary rollout.");
            }
        }
        if (targetReleaseStatus == PromptBundleState.ACTIVE) {
            if (!lifecycleItem.changeRecorded()) {
                blockers.add("CHANGE_LEDGER_MISSING enterprise change evidence must exist before production release.");
            }
            if (!lifecycleItem.empiricalEvalSatisfied()) {
                blockers.add("EMPIRICAL_EVAL_MISSING empirical prompt evaluation must pass before production release.");
            }
            if (!lifecycleItem.modelProfilesDeclared()) {
                blockers.add("MODEL_COMPATIBILITY_MISSING supported model profiles must be declared before production release.");
            }
            if (!budgetProfilesGoverned) {
                blockers.add("BUDGET_PROFILE_MISSING governed budget profiles must exist before production release.");
            }
            if (!StringUtils.hasText(lifecycleItem.rollbackTargetPromptVersion())) {
                blockers.add("ROLLBACK_TARGET_MISSING rollback target prompt version must be declared before production release.");
            }
        }
        if (targetReleaseStatus == PromptBundleState.DEPRECATED && !StringUtils.hasText(lifecycleItem.rollbackTargetPromptVersion())) {
            blockers.add("ROLLBACK_TARGET_MISSING rollback target prompt version must be declared before rollback execution.");
        }
        return blockers;
    }

    private String determineExpectedNextReleaseStatus(PromptGovernanceView.PromptGovernanceLifecycleLedgerItem lifecycleItem) {
        PromptBundleState current = PromptBundleState.fromStoredValue(lifecycleItem.currentReleaseStatus()).orElse(null);
        if (current == null) {
            return null;
        }
        return switch (current) {
            case AVAILABLE -> PromptBundleState.SHADOW.name();
            case SHADOW -> PromptBundleState.CANARY.name();
            case CANARY -> PromptBundleState.ACTIVE.name();
            case ACTIVE -> lifecycleItem.empiricalEvalSatisfied()
                    && lifecycleItem.releaseWorkflowControlled()
                    && lifecycleItem.rollbackPrepared()
                    ? null
                    : PromptBundleState.CANARY.name();
            case DEPRECATED -> PromptBundleState.CANARY.name();
            case RETIRED -> null;
        };
    }

    private String determineGateState(
            PromptGovernanceView.PromptGovernanceLifecycleLedgerItem lifecycleItem,
            String expectedNextReleaseStatus,
            List<String> blockers) {
        if (PromptBundleState.is(lifecycleItem.currentReleaseStatus(), PromptBundleState.ACTIVE)
                && lifecycleItem.empiricalEvalSatisfied()
                && lifecycleItem.releaseWorkflowControlled()
                && lifecycleItem.rollbackPrepared()) {
            return "CONTROLLED_PRODUCTION";
        }
        if (PromptBundleState.is(lifecycleItem.currentReleaseStatus(), PromptBundleState.ACTIVE)
                && (!lifecycleItem.empiricalEvalSatisfied()
                || !lifecycleItem.releaseWorkflowControlled()
                || !lifecycleItem.rollbackPrepared())) {
            return "UNCONTROLLED_PRODUCTION";
        }
        if (!blockers.isEmpty()) {
            if (blockers.stream().anyMatch(blocker -> blocker.startsWith("EMPIRICAL_EVAL_MISSING"))) {
                return "BLOCKED_BY_EMPIRICAL_EVAL_GAP";
            }
            if (blockers.stream().anyMatch(blocker -> blocker.startsWith("MODEL_COMPATIBILITY_MISSING"))) {
                return "BLOCKED_BY_MODEL_COMPATIBILITY_GAP";
            }
            if (blockers.stream().anyMatch(blocker -> blocker.startsWith("BUDGET_PROFILE_MISSING"))) {
                return "BLOCKED_BY_BUDGET_GOVERNANCE_GAP";
            }
            if (blockers.stream().anyMatch(blocker -> blocker.startsWith("TOKEN_COUNTING_POLICY_MISSING"))) {
                return "BLOCKED_BY_TOKEN_COUNTING_GAP";
            }
            if (blockers.stream().anyMatch(blocker -> blocker.startsWith("CACHE_POLICY_MISSING"))) {
                return "BLOCKED_BY_CACHE_POLICY_GAP";
            }
            if (blockers.stream().anyMatch(blocker -> blocker.startsWith("COMPACTION_POLICY_MISSING"))) {
                return "BLOCKED_BY_COMPACTION_POLICY_GAP";
            }
            if (blockers.stream().anyMatch(blocker -> blocker.startsWith("ROLLBACK_TARGET_MISSING"))) {
                return "BLOCKED_BY_ROLLBACK_GAP";
            }
            return "BLOCKED_BY_CHANGE_GAP";
        }
        if (PromptBundleState.CANARY.name().equals(expectedNextReleaseStatus)) {
            return "READY_FOR_CANARY";
        }
        if (PromptBundleState.ACTIVE.name().equals(expectedNextReleaseStatus)) {
            return "READY_FOR_PRODUCTION";
        }
        if (PromptBundleState.SHADOW.name().equals(expectedNextReleaseStatus)) {
            return "READY_FOR_EVAL_ONLY";
        }
        return "RECORDED";
    }

    private String determineTransitionGateState(
            String currentReleaseStatus,
            PromptBundleState targetReleaseStatus,
            List<String> blockers) {
        if (!blockers.isEmpty()) {
            if (blockers.stream().anyMatch(blocker -> blocker.startsWith("EMPIRICAL_EVAL_MISSING"))) {
                return "BLOCKED_BY_EMPIRICAL_EVAL_GAP";
            }
            if (blockers.stream().anyMatch(blocker -> blocker.startsWith("MODEL_COMPATIBILITY_MISSING"))) {
                return "BLOCKED_BY_MODEL_COMPATIBILITY_GAP";
            }
            if (blockers.stream().anyMatch(blocker -> blocker.startsWith("BUDGET_PROFILE_MISSING"))) {
                return "BLOCKED_BY_BUDGET_GOVERNANCE_GAP";
            }
            if (blockers.stream().anyMatch(blocker -> blocker.startsWith("TOKEN_COUNTING_POLICY_MISSING"))) {
                return "BLOCKED_BY_TOKEN_COUNTING_GAP";
            }
            if (blockers.stream().anyMatch(blocker -> blocker.startsWith("CACHE_POLICY_MISSING"))) {
                return "BLOCKED_BY_CACHE_POLICY_GAP";
            }
            if (blockers.stream().anyMatch(blocker -> blocker.startsWith("COMPACTION_POLICY_MISSING"))) {
                return "BLOCKED_BY_COMPACTION_POLICY_GAP";
            }
            if (blockers.stream().anyMatch(blocker -> blocker.startsWith("ROLLBACK_TARGET_MISSING"))) {
                return "BLOCKED_BY_ROLLBACK_GAP";
            }
            return "BLOCKED_BY_CHANGE_GAP";
        }
        if (PromptBundleState.CANARY == targetReleaseStatus) {
            return PromptBundleState.is(currentReleaseStatus, PromptBundleState.ACTIVE)
                    ? "DEGRADED_TO_CONTROLLED_CANARY"
                    : "READY_FOR_CANARY";
        }
        if (PromptBundleState.ACTIVE == targetReleaseStatus) {
            return "READY_FOR_PRODUCTION";
        }
        if (PromptBundleState.DEPRECATED == targetReleaseStatus) {
            return "ROLLBACK_EXECUTED";
        }
        if (PromptBundleState.SHADOW == targetReleaseStatus) {
            return "READY_FOR_EVAL_ONLY";
        }
        return "RELEASE_STATE_UPDATED";
    }

    /**
     * Allowed next canonical states. A stored status of any vocabulary reads through the canonical table, so a row
     * written as ACTIVE_FOR_SCOPE is a canary here instead of an unknown name; a status of no vocabulary reads as a new
     * bundle.
     */
    private List<String> allowedNextReleaseStatuses(String currentReleaseStatus) {
        PromptBundleState current = PromptBundleState.fromStoredValue(currentReleaseStatus).orElse(PromptBundleState.AVAILABLE);
        return switch (current) {
            case AVAILABLE -> List.of(PromptBundleState.SHADOW.name(), PromptBundleState.RETIRED.name());
            case SHADOW -> List.of(PromptBundleState.CANARY.name(), PromptBundleState.RETIRED.name());
            case CANARY -> List.of(PromptBundleState.ACTIVE.name(), PromptBundleState.DEPRECATED.name(), PromptBundleState.RETIRED.name());
            case ACTIVE -> List.of(PromptBundleState.CANARY.name(), PromptBundleState.DEPRECATED.name(), PromptBundleState.RETIRED.name());
            case DEPRECATED -> List.of(PromptBundleState.CANARY.name(), PromptBundleState.RETIRED.name());
            case RETIRED -> List.of();
        };
    }

    private void upsertReleaseApproval(
            PromptLifecycleContext context,
            PromptBundleState targetReleaseStatus,
            String actor,
            String rationale,
            String approvalChannel,
            PromptGovernanceReleaseWorkflowRecord workflowRecord) {
        PromptGovernanceReleaseApprovalRecord approvalRecord = Optional.ofNullable(context.releaseApprovalRecord())
                .orElseGet(PromptGovernanceReleaseApprovalRecord::new);
        approvalRecord.setRegistryScope(context.registryRecord().getRegistryScope());
        approvalRecord.setPromptKey(context.registryRecord().getPromptKey());
        approvalRecord.setTemplateKey(context.registryRecord().getTemplateKey());
        approvalRecord.setPromptVersion(context.registryRecord().getPromptVersion());
        approvalRecord.setContractVersion(context.registryRecord().getContractVersion());
        approvalRecord.setReleaseApprovalReference(workflowReference(workflowRecord));
        approvalRecord.setReleaseStatus(targetReleaseStatus.name());
        approvalRecord.setApprovalState(targetReleaseStatus == PromptBundleState.DEPRECATED ? "ROLLED_BACK_EXECUTED" : "APPROVED");
        approvalRecord.setApprovalChannel(approvalChannel);
        approvalRecord.setApprovedBy(actor);
        approvalRecord.setApprovalSummary(rationale);
        approvalRecord.setRegistrationSource("PROMPT_RELEASE_GATE_WORKFLOW");
        releaseApprovalRepository.save(approvalRecord);
    }

    private void upsertRollbackState(
            PromptLifecycleContext context,
            PromptBundleState targetReleaseStatus,
            String actor,
            String rationale,
            PromptGovernanceReleaseWorkflowRecord workflowRecord) {
        // N-GOV-1: the ledger keeps the rollback of a declared target; a retirement, or a release without a target,
        // has no rollback state to write, and its row would break the ledger's NOT NULL columns.
        if (targetReleaseStatus == PromptBundleState.RETIRED || !StringUtils.hasText(resolveRollbackTarget(context))) {
            return;
        }
        PromptGovernanceRollbackRecord rollbackRecord = Optional.ofNullable(context.rollbackRecord())
                .orElseGet(PromptGovernanceRollbackRecord::new);
        rollbackRecord.setRegistryScope(context.registryRecord().getRegistryScope());
        rollbackRecord.setPromptKey(context.registryRecord().getPromptKey());
        rollbackRecord.setPromptVersion(context.registryRecord().getPromptVersion());
        rollbackRecord.setRollbackReference(workflowReference(workflowRecord));
        rollbackRecord.setRollbackTargetPromptVersion(resolveRollbackTarget(context));
        rollbackRecord.setRollbackStrategy("VERSION_ROLLBACK");
        rollbackRecord.setPreparedBy(actor);
        rollbackRecord.setRegistrationSource("PROMPT_RELEASE_GATE_WORKFLOW");
        if (targetReleaseStatus == PromptBundleState.DEPRECATED) {
            rollbackRecord.setRollbackState("EXECUTED");
            rollbackRecord.setRollbackReadinessState("EXECUTED");
            rollbackRecord.setRollbackReason(rationale);
        }
        else if (targetReleaseStatus == PromptBundleState.CANARY || targetReleaseStatus == PromptBundleState.ACTIVE) {
            rollbackRecord.setRollbackState("TARGET_DECLARED");
            rollbackRecord.setRollbackReadinessState("READY");
            rollbackRecord.setRollbackReason("Rollback workflow is prepared for governed release transitions.");
        }
        else if (targetReleaseStatus == PromptBundleState.SHADOW) {
            rollbackRecord.setRollbackState("TARGET_DECLARED");
            rollbackRecord.setRollbackReadinessState("PLANNED");
            rollbackRecord.setRollbackReason("Rollback workflow is declared and will become ready before canary or production.");
        }
        rollbackRepository.save(rollbackRecord);
    }

    private String resolveRollbackTarget(PromptLifecycleContext context) {
        if (context.rollbackRecord() != null && StringUtils.hasText(context.rollbackRecord().getRollbackTargetPromptVersion())) {
            return context.rollbackRecord().getRollbackTargetPromptVersion();
        }
        return context.registryRecord().getRollbackPromptVersion();
    }

    private boolean rollbackTargetDeclared(PromptGovernanceRegistryRecord registryRecord, PromptGovernanceRollbackRecord rollbackRecord) {
        return rollbackRecord != null && StringUtils.hasText(rollbackRecord.getRollbackTargetPromptVersion())
                || StringUtils.hasText(registryRecord.getRollbackPromptVersion());
    }

    private Map<String, PromptGovernanceReleaseWorkflowRecord> indexLatestWorkflows(List<PromptGovernanceReleaseWorkflowRecord> workflows) {
        Map<String, PromptGovernanceReleaseWorkflowRecord> latest = new LinkedHashMap<>();
        workflows.stream()
                .sorted(Comparator.comparing(PromptGovernanceReleaseWorkflowRecord::getCreatedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .forEach(record -> latest.putIfAbsent(workflowKey(record.getPromptKey(), record.getPromptVersion()), record));
        return latest;
    }

    private String workflowKey(String promptKey, String promptVersion) {
        return safeValue(promptKey, "UNKNOWN") + "::" + safeValue(promptVersion, "UNKNOWN");
    }

    private String workflowReference(PromptGovernanceReleaseWorkflowRecord workflowRecord) {
        return String.format(
                Locale.ROOT,
                "PROMPT-RELEASE-WORKFLOW:%s:%s:%s:%s",
                safeValue(workflowRecord.getRegistryScope(), "GLOBAL"),
                safeValue(workflowRecord.getPromptKey(), "UNKNOWN"),
                safeValue(workflowRecord.getPromptVersion(), "UNKNOWN"),
                safeValue(workflowRecord.getTargetReleaseStatus(), "UNKNOWN"));
    }

    private String normalizeRegistryScope(String registryScope) {
        return StringUtils.hasText(registryScope) ? registryScope.trim() : PromptGovernanceRegistryService.PLATFORM_GLOBAL_SCOPE;
    }

    private String normalizeApprovalChannel(String approvalChannel) {
        return StringUtils.hasText(approvalChannel) ? approvalChannel.trim() : "ENTERPRISE_RELEASE_GATE";
    }

    private String normalizeRationale(String rationale, String fallback) {
        return StringUtils.hasText(rationale) ? rationale.trim() : fallback;
    }

    private void validatePromptKey(String promptKey) {
        if (!StringUtils.hasText(promptKey)) {
            throw new IllegalArgumentException("Prompt key is required.");
        }
    }

    private void validatePromptVersion(String promptVersion) {
        if (!StringUtils.hasText(promptVersion)) {
            throw new IllegalArgumentException("Prompt version is required.");
        }
    }

    private void validateActor(String actor) {
        if (!StringUtils.hasText(actor)) {
            throw new IllegalArgumentException("Actor is required.");
        }
    }

    private List<String> readJsonList(String json) {
        if (!StringUtils.hasText(json)) {
            return List.of();
        }
        try {
            return objectMapper.readValue(json, objectMapper.getTypeFactory().constructCollectionType(List.class, String.class));
        }
        catch (JsonProcessingException ex) {
            return List.of();
        }
    }

    private String writeJsonList(List<String> values) {
        try {
            return objectMapper.writeValueAsString(values == null ? List.of() : values);
        }
        catch (JsonProcessingException ex) {
            throw new IllegalStateException("Failed to serialize prompt release workflow blockers", ex);
        }
    }

    private String safeValue(String value, String fallback) {
        return StringUtils.hasText(value) ? value.trim() : fallback;
    }

    private List<PromptGovernanceModelCompatibilityRecord> currentModelCompatibilityRecords(
            List<PromptGovernanceModelCompatibilityRecord> records) {
        Map<String, PromptGovernanceModelCompatibilityRecord> latest = new LinkedHashMap<>();
        records.stream()
                .sorted(Comparator.comparing(PromptGovernanceModelCompatibilityRecord::getUpdatedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .forEach(record -> latest.putIfAbsent(safeValue(record.getModelProfileKey(), "UNKNOWN"), record));
        return new ArrayList<>(latest.values());
    }

    private List<PromptGovernanceBudgetProfileRecord> currentBudgetProfileRecords(
            List<PromptGovernanceBudgetProfileRecord> records) {
        Map<String, PromptGovernanceBudgetProfileRecord> latest = new LinkedHashMap<>();
        records.stream()
                .sorted(Comparator.comparing(PromptGovernanceBudgetProfileRecord::getUpdatedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .forEach(record -> latest.putIfAbsent(safeValue(record.getBudgetProfileKey(), "UNKNOWN"), record));
        return new ArrayList<>(latest.values());
    }

    /** W7-14: one state the bundle may take next, whether the gate would apply it now and what blocks it. */
    public record ReleaseGateTarget(String targetState, boolean ready, String gateState, List<String> blockers) {
    }

    /** W7-14: the gate evidence of a bundle as the gate reads it for its blockers. */
    public record ReleaseGateEvidence(
            boolean changeRecorded,
            String evaluationReference,
            String evaluationState,
            String empiricalEvidenceState,
            String tevvGateState,
            String promptInjectionState,
            String latencyGateState,
            String costGateState,
            String qualityGateState,
            String scenarioCoverageState,
            int coveredScenarioCount,
            int requiredScenarioCount,
            String evaluationBundleHash,
            String evaluationRunReference,
            boolean evaluationForThisBundle,
            LocalDateTime evaluatedAt,
            String approvalState,
            String approvedBy,
            String rollbackTargetPromptVersion,
            String rollbackReadinessState,
            List<String> supportedModelProfiles,
            boolean providerCompatibilityDeclared,
            List<String> budgetProfileKeys,
            boolean tokenCountingPolicyDeclared,
            boolean cachePolicyGoverned,
            boolean compactionPolicyGoverned) {
    }

    /** W7-14: the gate's answer for a bundle: its canonical state, every next state the gate allows, the evidence. */
    public record ReleaseGateAssessment(String registryScope, String promptKey, String promptVersion,
                                        String currentState, List<ReleaseGateTarget> targets,
                                        ReleaseGateEvidence evidence) {
    }

    public record ReleaseTransitionReceipt(
            String registryScope,
            String promptKey,
            String promptVersion,
            String previousReleaseStatus,
            String targetReleaseStatus,
            boolean applied,
            String gateState,
            List<String> blockers,
            LocalDateTime recordedAt) {
    }

    /**
     * W6-8: an evaluation of a bundle of this build counts only when it names that bundle's hash; a version the build
     * does not hold as a bundle keeps the evaluation it has.
     */
    private static boolean evaluationOfThisBundle(PromptGovernanceEvaluationRecord evaluation, String promptKey,
                                                  String promptVersion) {
        return PromptBundleCatalog.shared().find(promptKey, promptVersion)
                .map(manifest -> manifest.bundleHash().equals(evaluation.getBundleHash()))
                .orElse(true);
    }

    private record PromptLifecycleContext(
            PromptGovernanceRegistryRecord registryRecord,
            String currentReleaseStatus,
            boolean changeRecorded,
            boolean empiricalEvalSatisfied,
            boolean evaluationOfAnotherBundle,
            boolean releaseWorkflowControlled,
            boolean rollbackPrepared,
            boolean rollbackTargetDeclared,
            String tevvGateState,
            String promptInjectionState,
            String latencyGateState,
            String costGateState,
            PromptGovernanceReleaseApprovalRecord releaseApprovalRecord,
            PromptGovernanceRollbackRecord rollbackRecord,
            List<String> supportedModelProfiles,
            boolean providerCompatibilityDeclared,
            boolean budgetProfilesGoverned,
            boolean tokenCountingPolicyDeclared,
            boolean cachePolicyGoverned,
            boolean compactionPolicyGoverned,
            List<String> budgetProfileKeys) {

        private boolean modelProfilesDeclared() {
            return supportedModelProfiles != null && !supportedModelProfiles.isEmpty();
        }
    }
}
