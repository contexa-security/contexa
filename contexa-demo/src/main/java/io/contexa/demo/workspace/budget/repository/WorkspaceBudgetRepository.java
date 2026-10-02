package io.contexa.demo.workspace.budget.repository;

import io.contexa.demo.workspace.budget.dto.WorkspaceBudgetKind;

import java.util.UUID;

public interface WorkspaceBudgetRepository {

    boolean consume(UUID workspaceId, WorkspaceBudgetKind kind, UUID attemptId, UUID sourceId);
}
