package io.contexa.demo.work.shared.web;

import io.contexa.demo.entry.domain.Visitor;
import io.contexa.demo.shared.web.AbstractQueryController;
import io.contexa.demo.work.participant.dto.WorkParticipant;
import io.contexa.demo.work.participant.service.WorkParticipantQuery;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;

public abstract class AbstractWorkController extends AbstractQueryController {

    private final WorkParticipantQuery participants;

    protected AbstractWorkController(WorkParticipantQuery participants) {
        this.participants = participants;
    }

    protected WorkParticipant participant(HttpServletRequest request, Authentication authentication) {
        Visitor visitor = (Visitor) request.getAttribute(Visitor.class.getName());
        return participants.require(visitor.id(), authentication.getName());
    }
}
