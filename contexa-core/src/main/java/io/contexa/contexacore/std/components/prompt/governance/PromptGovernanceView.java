package io.contexa.contexacore.std.components.prompt.governance;

import java.time.LocalDateTime;
import java.util.List;

public final class PromptGovernanceView {

    private PromptGovernanceView() {
    }

    public record PromptGovernanceRegistrySnapshot(
            String registryScope,
            long promptCount,
            long productionCount,
            long approvalLinkedCount,
            long evalLinkedCount,
            long rollbackReadyCount,
            long modelCompatibleCount,
            String registryState,
            List<PromptGovernanceRegistryItem> prompts,
            LocalDateTime generatedAt) {
    }

    public record PromptGovernanceRegistryItem(
            String promptKey,
            String templateKey,
            String promptVersion,
            String contractVersion,
            String promptArtifactHashSha256,
            String releaseStatus,
            String owner,
            String releaseApprovalReference,
            String evaluationBaselineReference,
            String rollbackPromptVersion,
            boolean releaseApproved,
            boolean evalLinked,
            boolean rollbackReady,
            boolean modelProfilesDeclared,
            List<String> supportedModelProfiles,
            String templateClassName,
            String registrationSource,
            LocalDateTime updatedAt,
            List<String> governanceFacts,
            String summary) {
    }

    public record PromptGovernanceLifecycleLedgerSnapshot(
            String registryScope,
            long promptCount,
            long changeRecordedCount,
            long empiricalEvalSatisfiedCount,
            long releaseWorkflowControlledCount,
            long rollbackPreparedCount,
            long modelCompatibleCount,
            String lifecycleState,
            List<String> lifecycleFacts,
            List<PromptGovernanceLifecycleLedgerItem> prompts,
            LocalDateTime generatedAt) {
    }

    public record PromptGovernanceLifecycleLedgerItem(
            String promptKey,
            String templateKey,
            String promptVersion,
            String contractVersion,
            String currentReleaseStatus,
            String changeReference,
            String changeType,
            String changeState,
            boolean changeRecorded,
            String evaluationReference,
            String evaluationMode,
            String evaluationState,
            String empiricalEvidenceState,
            String promptInjectionState,
            boolean empiricalEvalSatisfied,
            String releaseApprovalReference,
            String approvalState,
            String approvalChannel,
            boolean releaseWorkflowControlled,
            String rollbackReference,
            String rollbackTargetPromptVersion,
            String rollbackState,
            String rollbackReadinessState,
            boolean rollbackPrepared,
            boolean modelProfilesDeclared,
            List<String> supportedModelProfiles,
            String lifecycleItemState,
            LocalDateTime updatedAt,
            List<String> lifecycleFacts,
            String summary) {
    }

    public record PromptGovernanceEmpiricalEvalSnapshot(
            String registryScope,
            long promptCount,
            long productionReadyCount,
            long canaryReadyCount,
            long evidenceGapCount,
            long promptInjectionBlockedCount,
            long nonFunctionalBlockedCount,
            String evalPortfolioState,
            List<String> evalFacts,
            List<PromptGovernanceEmpiricalEvalItem> prompts,
            LocalDateTime generatedAt) {
    }

    public record PromptGovernanceEmpiricalEvalItem(
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
            List<String> coveredScenarioFamilies,
            String tevvGateState,
            String qualityGateState,
            String latencyGateState,
            String costGateState,
            String evaluatedBy,
            LocalDateTime updatedAt,
            List<String> evalFacts,
            String summary) {
    }

    public record PromptGovernanceModelCompatibilitySnapshot(
            String registryScope,
            long promptCount,
            long declaredModelProfileCount,
            long providerCompatibilityDeclaredCount,
            long budgetProfileGovernedCount,
            long cachePolicyGovernedCount,
            long compactionPolicyGovernedCount,
            String compatibilityRegistryState,
            List<String> registryFacts,
            List<PromptGovernanceModelCompatibilityItem> prompts,
            LocalDateTime generatedAt) {
    }

    public record PromptGovernanceModelCompatibilityItem(
            String promptKey,
            String promptVersion,
            boolean providerCompatibilityDeclared,
            boolean tokenCountingPolicyDeclared,
            boolean budgetProfilesGoverned,
            boolean cachePolicyGoverned,
            boolean compactionPolicyGoverned,
            String compatibilityState,
            List<PromptGovernanceModelProfileItem> modelProfiles,
            List<PromptGovernanceBudgetProfileItem> budgetProfiles,
            LocalDateTime updatedAt,
            List<String> compatibilityFacts,
            String summary) {
    }

    public record PromptGovernanceModelProfileItem(
            String modelProfileKey,
            String profileCategory,
            String providerScope,
            String compatibilityState,
            String tokenCountingPolicyKey,
            String cachePolicyKey,
            String compactionPolicyKey,
            String registrationSource) {
    }

    public record PromptGovernanceBudgetProfileItem(
            String budgetProfileKey,
            int maxInputTokens,
            String budgetState,
            String tokenCountingPolicyKey,
            String cachePolicyKey,
            String cachePolicyState,
            String compactionPolicyKey,
            String compactionPolicyState,
            String registrationSource) {
    }

    public record PromptGovernanceReleaseGateSnapshot(
            String registryScope,
            long promptCount,
            long workflowRecordedCount,
            long readyForCanaryCount,
            long readyForProductionCount,
            long blockedCount,
            long controlledProductionCount,
            String gateState,
            List<String> gateFacts,
            List<PromptGovernanceReleaseGateItem> prompts,
            LocalDateTime generatedAt) {
    }

    public record PromptGovernanceReleaseGateItem(
            String promptKey,
            String promptVersion,
            String currentReleaseStatus,
            String expectedNextReleaseStatus,
            List<String> allowedNextReleaseStatuses,
            String gateState,
            List<String> blockers,
            String latestWorkflowState,
            String latestWorkflowTargetStatus,
            String latestWorkflowActor,
            LocalDateTime latestWorkflowAt,
            String approvalState,
            String rollbackReadinessState,
            boolean modelProfilesDeclared,
            List<String> supportedModelProfiles,
            boolean budgetProfilesGoverned,
            List<String> budgetProfileKeys,
            List<String> gateFacts,
            String summary) {
    }

    public record PromptRuntimeGovernanceReconciliationSnapshot(
            String registryScope,
            long observedExecutionCount,
            long telemetryMissingCount,
            long controlledExecutionCount,
            long uncontrolledProductionCount,
            long budgetDriftCount,
            long omissionRiskCount,
            String reconciliationState,
            List<String> reconciliationFacts,
            List<PromptRuntimeGovernanceReconciliationItem> executions,
            LocalDateTime generatedAt) {
    }

    public record PromptRuntimeGovernanceReconciliationItem(
            String tenantId,
            String correlationId,
            String promptKey,
            String promptVersion,
            String promptTemplateKey,
            String runtimePromptHash,
            String runtimeReleaseStatus,
            String governedReleaseStatus,
            boolean governanceRegistered,
            boolean releaseStateAligned,
            String gateState,
            String compatibilityState,
            String runtimeBudgetProfile,
            boolean budgetProfileAligned,
            List<String> governedBudgetProfiles,
            String promptEvidenceCompleteness,
            int promptOmissionCount,
            List<String> omittedSections,
            boolean controlledExecution,
            boolean uncontrolledProduction,
            boolean omissionRisk,
            String reconciliationState,
            LocalDateTime observedAt,
            List<String> reconciliationFacts,
            String summary) {
    }

    public record PromptRuntimeGovernanceAlertFeedSnapshot(
            String registryScope,
            long alertCount,
            long criticalCount,
            long highCount,
            long mediumCount,
            long actionRequiredCount,
            String portfolioSeverity,
            String feedState,
            List<String> feedFacts,
            List<PromptRuntimeGovernanceAlertItem> alerts,
            LocalDateTime generatedAt) {
    }

    public record PromptRuntimeGovernanceAlertItem(
            String tenantId,
            String correlationId,
            String promptKey,
            String promptVersion,
            String promptTemplateKey,
            String runtimePromptHash,
            String runtimeReleaseStatus,
            String governedReleaseStatus,
            String runtimeBudgetProfile,
            String promptEvidenceCompleteness,
            int promptOmissionCount,
            List<String> omittedSections,
            String alertType,
            String severity,
            String operatorAction,
            boolean actionRequired,
            String rationale,
            String reconciliationState,
            String gateState,
            String compatibilityState,
            LocalDateTime observedAt,
            List<String> feedFacts,
            String summary) {
    }

    public record PromptContextAuditSnapshot(
            String tenantId,
            String correlationId,
            String retrievalPurpose,
            String executionId,
            int requestedDocumentCount,
            int allowedDocumentCount,
            int deniedDocumentCount,
            List<String> deniedReasons,
            List<PromptContextAuditItem> items,
            LocalDateTime generatedAt) {
    }

    public record PromptContextAuditItem(
            String contextType,
            String sourceType,
            String artifactId,
            String artifactVersion,
            String artifactFamily,
            String artifactLineageState,
            String artifactGovernanceState,
            String authorizationDecision,
            String tenantPolicyDecision,
            boolean purposeMatch,
            String provenanceSummary,
            boolean includedInPrompt,
            String tenantAccessState,
            boolean runtimeAllowed,
            boolean runtimeReadyArtifact,
            boolean quarantinedArtifact,
            String promptSafetyDecision,
            String memoryReadDecision,
            String accessScope,
            boolean tenantBound,
            Double similarityScore,
            LocalDateTime createdAt) {
    }
}
