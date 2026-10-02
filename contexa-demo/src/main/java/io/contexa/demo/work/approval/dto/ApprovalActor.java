package io.contexa.demo.work.approval.dto;

import io.contexa.demo.work.participant.dto.WorkParticipant;

public record ApprovalActor(
        WorkParticipant participant,
        boolean administrator) {
}
