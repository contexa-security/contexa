package io.contexa.demo.work.approval.controller;

import io.contexa.demo.work.approval.dto.ApprovalActor;
import io.contexa.demo.work.participant.service.WorkParticipantQuery;
import io.contexa.demo.work.shared.web.AbstractWorkController;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;

public abstract class AbstractApprovalController extends AbstractWorkController {

    protected AbstractApprovalController(WorkParticipantQuery participants) {
        super(participants);
    }

    protected ApprovalActor actor(HttpServletRequest request, Authentication authentication) {
        return new ApprovalActor(participant(request, authentication), authentication.getAuthorities().stream()
                .anyMatch(authority -> "ROLE_ADMIN".equals(authority.getAuthority())));
    }
}
