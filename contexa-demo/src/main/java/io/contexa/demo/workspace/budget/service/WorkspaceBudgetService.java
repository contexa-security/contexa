package io.contexa.demo.workspace.budget.service;

import io.contexa.demo.workspace.budget.dto.WorkspaceBudgetKind;

import java.util.UUID;

public interface WorkspaceBudgetService {

    void require(UUID workspaceId, WorkspaceBudgetKind kind, UUID attemptId, UUID sourceId);
}
