package io.contexa.demo.work.participant.service;

import io.contexa.demo.work.participant.dto.WorkParticipant;

import java.util.UUID;

public interface WorkParticipantQuery {

    WorkParticipant require(UUID visitorId, String username);
}
