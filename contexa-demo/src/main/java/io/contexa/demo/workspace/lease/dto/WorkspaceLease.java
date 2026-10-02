package io.contexa.demo.workspace.lease.dto;

import io.contexa.demo.configuration.properties.LabEndpoints;

import java.time.Instant;
import java.util.UUID;

public record WorkspaceLease(
        UUID id,
        UUID workspaceId,
        UUID visitorId,
        String slotId,
        UUID generation,
        String state,
        Instant createdAt,
        Instant expiresAt,
        LabEndpoints endpoints,
        WorkspaceUsage usage
) {

}
