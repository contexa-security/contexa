package io.contexa.demo.workspace.repository;

import io.contexa.demo.workspace.dto.WorkspaceView;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public interface WorkspaceRepository {

    WorkspaceView getOrCreate(UUID visitorId, List<String> accounts, Instant expiresAt);

    WorkspaceView find(UUID visitorId);
}
