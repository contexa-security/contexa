package io.contexa.demo.workspace.budget.service.impl;

import io.contexa.demo.workspace.budget.dto.WorkspaceBudgetKind;
import io.contexa.demo.workspace.budget.repository.WorkspaceBudgetRepository;
import io.contexa.demo.workspace.budget.service.WorkspaceBudgetService;
import io.contexa.demo.workspace.configuration.WorkspaceAccessProperties;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;

@Service
public class DefaultWorkspaceBudgetService implements WorkspaceBudgetService {

    private final WorkspaceAccessProperties properties;
    private final WorkspaceBudgetRepository budgets;

    public DefaultWorkspaceBudgetService(WorkspaceAccessProperties properties, WorkspaceBudgetRepository budgets) {
        this.properties = properties;
        this.budgets = budgets;
    }

    @Override
    public void require(UUID workspaceId, WorkspaceBudgetKind kind, UUID attemptId, UUID sourceId) {
        if (properties.enabled() && !budgets.consume(workspaceId, kind, attemptId, sourceId)) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "WORKSPACE_LIMIT_" + kind.name());
        }
    }
}
