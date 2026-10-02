package io.contexa.demo.workspace.budget.http;

import io.contexa.demo.workspace.budget.dto.WorkspaceBudgetKind;
import io.contexa.demo.workspace.budget.service.WorkspaceBudgetService;
import io.contexa.demo.workspace.configuration.WorkspaceAccessProperties;
import io.contexa.demo.workspace.lease.service.WorkspaceLeaseService;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.util.Set;
import java.util.UUID;

@Component
@Profile("contexa")
public class WorkspaceProviderBudgetInterceptor implements ClientHttpRequestInterceptor {

    private static final Set<String> CHAT_PATHS = Set.of("/v1/chat/completions", "/api/chat", "/api/generate");
    private static final Set<String> EMBEDDING_PATHS = Set.of("/v1/embeddings", "/api/embed", "/api/embeddings");
    private final WorkspaceAccessProperties properties;
    private final WorkspaceLeaseService leases;
    private final WorkspaceBudgetService budgets;

    public WorkspaceProviderBudgetInterceptor(WorkspaceAccessProperties properties, WorkspaceLeaseService leases,
            WorkspaceBudgetService budgets) {
        this.properties = properties;
        this.leases = leases;
        this.budgets = budgets;
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {
        if (properties.enabled() && request.getMethod() == HttpMethod.POST) {
            String path = request.getURI().getPath();
            WorkspaceBudgetKind kind = CHAT_PATHS.stream().anyMatch(path::endsWith) ? WorkspaceBudgetKind.CHAT
                    : EMBEDDING_PATHS.stream().anyMatch(path::endsWith) ? WorkspaceBudgetKind.EMBEDDING : null;
            if (kind != null) {
                var lease = leases.activeWorker();
                if (body.length > properties.maxProviderRequestBytes()) {
                    throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE, "WORKSPACE_PROVIDER_INPUT_LIMIT");
                }
                budgets.require(lease.workspaceId(), kind, UUID.randomUUID(), null);
            }
        }
        return execution.execute(request, body);
    }
}
