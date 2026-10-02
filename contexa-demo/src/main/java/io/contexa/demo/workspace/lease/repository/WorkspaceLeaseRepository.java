package io.contexa.demo.workspace.lease.repository;

import io.contexa.demo.workspace.dto.WorkspaceView;
import io.contexa.demo.workspace.lease.dto.WorkspaceLease;

import java.util.UUID;

public interface WorkspaceLeaseRepository {

    WorkspaceLease acquire(WorkspaceView workspace);

    WorkspaceLease find(UUID visitorId);

    WorkspaceLease findWorker(String slotId, UUID generation);

    int expire();

    WorkspaceLease cancel(UUID visitorId);
}
