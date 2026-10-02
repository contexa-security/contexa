package io.contexa.demo.work.participant.repository;

import io.contexa.demo.work.participant.dto.WorkParticipant;

import java.util.UUID;

public interface WorkMembershipRepository {

    WorkParticipant find(UUID visitorId, String username);
}
