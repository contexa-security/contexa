package io.contexa.demo.observation.request.controller;

import io.contexa.demo.observation.request.dto.RequestEvidenceView;
import io.contexa.demo.observation.request.service.WorkspaceEvidenceQuery;
import io.contexa.demo.shared.web.AbstractVisitorController;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@Profile("portal")
@RequestMapping("/api/lab/workspaces/requests")
public class WorkspaceEvidenceController extends AbstractVisitorController {

    private final WorkspaceEvidenceQuery evidence;

    public WorkspaceEvidenceController(WorkspaceEvidenceQuery evidence) {
        this.evidence = evidence;
    }

    @GetMapping("/{arm}/{id}")
    public ResponseEntity<RequestEvidenceView> find(@PathVariable String arm, @PathVariable UUID id,
            HttpServletRequest request) {
        return result(evidence.find(arm, id, visitorId(request)));
    }
}
