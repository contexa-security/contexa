package io.contexa.demo.observation.request.controller;

import io.contexa.demo.observation.request.dto.RequestEvidenceView;
import io.contexa.demo.observation.request.service.RequestEvidenceQuery;
import io.contexa.demo.work.participant.service.WorkParticipantQuery;
import io.contexa.demo.work.shared.web.AbstractWorkController;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@Profile({"baseline", "contexa"})
@RequestMapping("/api/work/requests")
public class RequestEvidenceController extends AbstractWorkController {

    private final RequestEvidenceQuery evidence;

    public RequestEvidenceController(WorkParticipantQuery participants, RequestEvidenceQuery evidence) {
        super(participants);
        this.evidence = evidence;
    }

    @GetMapping("/{id}")
    public ResponseEntity<RequestEvidenceView> request(@PathVariable UUID id,
            HttpServletRequest request, Authentication authentication) {
        return result(evidence.find(id, participant(request, authentication).visitorId()));
    }
}
