package io.contexa.demo.workspace.service;

import io.contexa.demo.workspace.dto.WorkspaceView;

import java.time.Instant;
import java.util.UUID;

public interface WorkspaceService {

    WorkspaceView prepare(UUID visitorId, Instant expiry);

    WorkspaceView current(UUID visitorId);
}
