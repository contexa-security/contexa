package io.contexa.demo.workspace.lease.service;

import io.contexa.demo.workspace.dto.WorkspaceView;
import io.contexa.demo.workspace.lease.dto.WorkspaceLease;

import java.util.UUID;

public interface WorkspaceLeaseService {

    WorkspaceLease acquire(WorkspaceView workspace);

    WorkspaceLease current(UUID visitorId);

    WorkspaceLease requireWorker(UUID visitorId);

    WorkspaceLease activeWorker();

    WorkspaceLease cancel(UUID visitorId);
}
