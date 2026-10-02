package io.contexa.demo.workspace.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record WorkspaceView(
        UUID id,
        UUID visitorId,
        String state,
        Instant createdAt,
        Instant expiresAt,
        List<String> allowedAccounts
) {

}
