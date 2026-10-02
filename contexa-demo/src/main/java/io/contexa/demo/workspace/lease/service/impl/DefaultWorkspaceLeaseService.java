package io.contexa.demo.workspace.lease.service.impl;

import io.contexa.demo.workspace.configuration.WorkspaceAccessProperties;
import io.contexa.demo.workspace.dto.WorkspaceView;
import io.contexa.demo.workspace.lease.dto.WorkspaceLease;
import io.contexa.demo.workspace.lease.repository.WorkspaceLeaseRepository;
import io.contexa.demo.workspace.lease.service.WorkspaceLeaseService;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.UUID;

@Service
public class DefaultWorkspaceLeaseService implements WorkspaceLeaseService {

    private final WorkspaceAccessProperties properties;
    private final WorkspaceLeaseRepository leases;

    public DefaultWorkspaceLeaseService(WorkspaceAccessProperties properties, WorkspaceLeaseRepository leases) {
        this.properties = properties;
        this.leases = leases;
    }

    @Override
    public WorkspaceLease acquire(WorkspaceView workspace) {
        if (!properties.enabled()) {
            return null;
        }
        leases.expire();
        return active(leases.acquire(workspace));
    }

    @Override
    public WorkspaceLease current(UUID visitorId) {
        if (!properties.enabled()) {
            return null;
        }
        leases.expire();
        return leases.find(visitorId);
    }

    @Override
    public WorkspaceLease cancel(UUID visitorId) {
        if (!properties.enabled()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "WORKSPACE_LIMITS_DISABLED");
        }
        leases.expire();
        return leases.cancel(visitorId);
    }

    @Override
    public WorkspaceLease requireWorker(UUID visitorId) {
        WorkspaceLease lease = activeWorker();
        if (!lease.visitorId().equals(visitorId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "WORKSPACE_NOT_ASSIGNED");
        }
        return lease;
    }

    @Override
    public WorkspaceLease activeWorker() {
        if (properties.workerSlotId().isBlank() || properties.workerGeneration() == null) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "WORKSPACE_WORKER_UNCONFIGURED");
        }
        return active(leases.findWorker(properties.workerSlotId(), properties.workerGeneration()));
    }

    private WorkspaceLease active(WorkspaceLease lease) {
        if (lease == null || !"ACTIVE".equals(lease.state()) || !lease.expiresAt().isAfter(Instant.now())) {
            throw new ResponseStatusException(HttpStatus.GONE, "WORKSPACE_EXPIRED");
        }
        return lease;
    }
}
