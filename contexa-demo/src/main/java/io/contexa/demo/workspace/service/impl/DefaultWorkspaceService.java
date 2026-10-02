package io.contexa.demo.workspace.service.impl;

import io.contexa.demo.identity.configuration.IdentityProperties;
import io.contexa.demo.workspace.dto.WorkspaceView;
import io.contexa.demo.workspace.lease.service.WorkspaceLeaseService;
import io.contexa.demo.workspace.repository.WorkspaceRepository;
import io.contexa.demo.workspace.service.WorkspaceService;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@Profile("portal")
public class DefaultWorkspaceService implements WorkspaceService {

    private final WorkspaceRepository repository;
    private final IdentityProperties identities;
    private final WorkspaceLeaseService leases;

    public DefaultWorkspaceService(WorkspaceRepository repository, IdentityProperties identities,
            WorkspaceLeaseService leases) {
        this.repository = repository;
        this.identities = identities;
        this.leases = leases;
    }

    public WorkspaceView prepare(UUID id, Instant expiry) {
        var workspace = repository.getOrCreate(id, identities.usernames(), expiry);
        leases.acquire(workspace);
        return repository.find(id);
    }

    public WorkspaceView current(UUID id) {
        return repository.find(id);
    }
}
