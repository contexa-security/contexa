package io.contexa.demo.work.catalog.controller;

import io.contexa.demo.work.catalog.service.WorkCatalog;
import io.contexa.demo.work.document.dto.DocumentSummary;
import io.contexa.demo.work.participant.service.WorkParticipantQuery;
import io.contexa.demo.work.project.dto.ProjectView;
import io.contexa.demo.work.shared.web.AbstractWorkController;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@Profile({"baseline", "contexa"})
@RequestMapping("/api/work")
public class WorkCatalogController extends AbstractWorkController {

    private final WorkCatalog catalog;

    public WorkCatalogController(WorkParticipantQuery participants, WorkCatalog catalog) {
        super(participants);
        this.catalog = catalog;
    }

    @GetMapping("/projects")
    public ResponseEntity<List<ProjectView>> projects(HttpServletRequest request, Authentication authentication) {
        return result(catalog.projects(participant(request, authentication).username()));
    }

    @GetMapping("/projects/{projectId}/documents")
    public ResponseEntity<List<DocumentSummary>> documents(@PathVariable String projectId,
            @RequestParam(defaultValue = "") String search, HttpServletRequest request, Authentication authentication) {
        participant(request, authentication);
        return result(catalog.documents(projectId, search));
    }

    @GetMapping("/documents/{id}")
    public ResponseEntity<DocumentSummary> document(@PathVariable String id,
            HttpServletRequest request, Authentication authentication) {
        participant(request, authentication);
        return result(catalog.document(id));
    }
}
