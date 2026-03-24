package io.contexa.contexacore.autonomous.execution;

import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public record DelegatedExecutionLineageSummary(
        String executionMode,
        String lineageState,
        String actorUserId,
        String agentId,
        String delegationId,
        String taskIntent,
        String taskPurpose,
        String objectiveId,
        String objectiveFamily,
        boolean delegatedExecution,
        boolean declaredLineage,
        boolean objectiveBound,
        boolean scopeBound,
        boolean permitBound,
        boolean approvalBound,
        boolean timeBound,
        boolean containmentOnly,
        boolean privilegedExportAllowed,
        int toolChainDepth,
        List<String> facts,
        String summary) {

    public DelegatedExecutionLineageSummary {
        facts = facts == null ? List.of() : List.copyOf(facts);
    }

    public static DelegatedExecutionLineageSummary from(DelegatedExecutionContext context) {
        DelegatedExecutionContext safeContext = context != null ? context : DelegatedExecutionContext.directUser(null);
        List<String> facts = new ArrayList<>();
        boolean delegatedExecution = safeContext.delegatedAgentExecution();
        boolean declaredLineage = safeContext.declaredLineage();
        boolean objectiveBound = safeContext.objectiveBound();
        boolean scopeBound = !safeContext.approvedScopes().isEmpty();
        boolean permitBound = StringUtils.hasText(safeContext.permitId());
        boolean approvalBound = StringUtils.hasText(safeContext.approvalId());
        boolean timeBound = safeContext.expiresAt() != null;
        int toolChainDepth = safeContext.toolChain() != null ? safeContext.toolChain().size() : 0;

        facts.add(delegatedExecution ? "DELEGATED_AGENT_EXECUTION" : "DIRECT_USER_EXECUTION");
        if (declaredLineage) {
            facts.add("DECLARED_LINEAGE");
        }
        else if (DelegatedExecutionContext.LINEAGE_STATE_IMPUTED_SERVICE_CLIENT.equals(safeContext.lineageState())) {
            facts.add("IMPUTED_SERVICE_CLIENT_LINEAGE");
        }
        else {
            facts.add("DIRECT_LINEAGE");
        }
        facts.add(scopeBound ? "APPROVED_SCOPE_BOUND" : "UNSCOPED_EXECUTION");
        if (objectiveBound) {
            facts.add("OBJECTIVE_BOUND");
            facts.add("OBJECTIVE_OPERATION_BOUND");
            if (!safeContext.allowedResourceFamilies().isEmpty()) {
                facts.add("OBJECTIVE_RESOURCE_BOUND");
            }
            if (!safeContext.allowedToolChain().isEmpty()) {
                facts.add("OBJECTIVE_TOOL_CHAIN_BOUND");
            }
            if (safeContext.containmentOnly()) {
                facts.add("CONTAINMENT_ONLY_OBJECTIVE");
            }
            facts.add(safeContext.privilegedExportAllowed() ? "PRIVILEGED_EXPORT_ALLOWED" : "PRIVILEGED_EXPORT_DISABLED");
        }
        else if (delegatedExecution) {
            facts.add("OBJECTIVE_MISSING");
        }
        if (StringUtils.hasText(safeContext.taskPurpose())) {
            facts.add("PURPOSE_BOUND");
        }
        else if (delegatedExecution) {
            facts.add("PURPOSE_MISSING");
        }
        if (permitBound) {
            facts.add("PERMIT_BOUND");
        }
        if (approvalBound) {
            facts.add("APPROVAL_BOUND");
        }
        if (timeBound) {
            facts.add("TIME_BOUND");
        }
        if (toolChainDepth > 0) {
            facts.add("TOOL_CHAIN_DECLARED");
        }
        if (!StringUtils.hasText(safeContext.actorUserId())) {
            facts.add("ACTOR_USER_IMPUTED");
        }

        String subject = delegatedExecution ? "delegated agent" : "direct user";
        String lineage = declaredLineage
                ? "declared lineage"
                : defaultText(safeContext.lineageState(), "unclassified lineage").toLowerCase(Locale.ROOT);
        List<String> clauses = new ArrayList<>();
        clauses.add(subject + " execution with " + lineage);
        if (objectiveBound) {
            clauses.add("objective " + defaultText(safeContext.objectiveFamily(), defaultText(safeContext.objectiveId(), "unspecified objective")));
        }
        if (StringUtils.hasText(safeContext.taskPurpose())) {
            clauses.add("purpose " + safeContext.taskPurpose());
        }
        if (scopeBound) {
            clauses.add("approved scopes " + String.join(",", safeContext.approvedScopes()));
        }
        if (permitBound) {
            clauses.add("permit linked");
        }
        if (approvalBound) {
            clauses.add("approval linked");
        }
        if (timeBound) {
            clauses.add("bounded until " + safeContext.expiresAt());
        }
        if (toolChainDepth > 0) {
            clauses.add("tool chain depth " + toolChainDepth);
        }

        return new DelegatedExecutionLineageSummary(
                safeContext.executionMode(),
                safeContext.lineageState(),
                safeContext.actorUserId(),
                safeContext.agentId(),
                safeContext.delegationId(),
                safeContext.taskIntent(),
                safeContext.taskPurpose(),
                safeContext.objectiveId(),
                safeContext.objectiveFamily(),
                delegatedExecution,
                declaredLineage,
                objectiveBound,
                scopeBound,
                permitBound,
                approvalBound,
                timeBound,
                safeContext.containmentOnly(),
                safeContext.privilegedExportAllowed(),
                toolChainDepth,
                facts,
                String.join(", ", clauses) + ".");
    }

    public static DelegatedExecutionLineageSummary from(DelegatedExecutionGraph graph) {
        return from(graph != null ? graph.context() : null);
    }

    private static String defaultText(String value, String fallback) {
        return StringUtils.hasText(value) ? value.trim() : fallback;
    }
}