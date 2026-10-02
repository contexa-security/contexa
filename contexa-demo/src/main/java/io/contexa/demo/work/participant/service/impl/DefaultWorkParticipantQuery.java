package io.contexa.demo.work.participant.service.impl;

import io.contexa.demo.work.participant.dto.WorkParticipant;
import io.contexa.demo.work.participant.repository.WorkMembershipRepository;
import io.contexa.demo.work.participant.service.WorkParticipantQuery;
import org.springframework.context.annotation.Profile;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@Profile({"baseline", "contexa"})
public class DefaultWorkParticipantQuery implements WorkParticipantQuery {

    private final WorkMembershipRepository repository;

    public DefaultWorkParticipantQuery(WorkMembershipRepository repository) {
        this.repository = repository;
    }

    public WorkParticipant require(UUID visitorId, String username) {
        WorkParticipant participant = repository.find(visitorId, username);
        if (participant == null) {
            throw new AccessDeniedException("No current workspace for this business account");
        }
        return participant;
    }
}
