package io.contexa.demo.work.participant.dto;

import java.util.UUID;

public record WorkParticipant(UUID visitorId, UUID workspaceId, String username) {
}
