package io.contexa.demo.workspace.evidence.service.impl;

import io.contexa.demo.workspace.configuration.WorkspaceAccessProperties;
import io.contexa.demo.workspace.evidence.dto.WorkspaceEvidenceStores;
import io.contexa.demo.workspace.evidence.repository.WorkspaceEvidenceStoreRepository;
import io.contexa.demo.workspace.evidence.service.WorkspaceEvidenceScope;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;
import java.util.function.Supplier;

@Service
public class DefaultWorkspaceEvidenceScope implements WorkspaceEvidenceScope {

    private final WorkspaceAccessProperties properties;
    private final WorkspaceEvidenceStoreRepository stores;
    private final ThreadLocal<WorkspaceEvidenceStores> current = new ThreadLocal<>();

    public DefaultWorkspaceEvidenceScope(WorkspaceAccessProperties properties, WorkspaceEvidenceStoreRepository stores) {
        this.properties = properties;
        this.stores = stores;
    }

    @Override
    public <T> T withOwner(UUID visitorId, Supplier<T> query) {
        if (!properties.enabled()) {
            return query.get();
        }
        WorkspaceEvidenceStores selected = stores.find(visitorId);
        if (selected == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "WORKSPACE_NOT_ASSIGNED");
        }
        WorkspaceEvidenceStores previous = current.get();
        current.set(selected);
        try {
            return query.get();
        } finally {
            if (previous == null) {
                current.remove();
            } else {
                current.set(previous);
            }
        }
    }

    @Override
    public String currentUrl(String role) {
        WorkspaceEvidenceStores selected = current.get();
        return selected == null ? null : selected.url(role);
    }
}
