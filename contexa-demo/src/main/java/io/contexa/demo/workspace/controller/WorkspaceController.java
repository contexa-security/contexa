package io.contexa.demo.workspace.controller;

import io.contexa.demo.entry.domain.Visitor;
import io.contexa.demo.shared.web.AbstractQueryController;
import io.contexa.demo.workspace.dto.WorkspaceView;
import io.contexa.demo.workspace.service.WorkspaceService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Profile("portal")
@RequestMapping("/api/lab/workspaces")
public class WorkspaceController extends AbstractQueryController {

    private final WorkspaceService service;

    public WorkspaceController(WorkspaceService service) {
        this.service = service;
    }

    @PostMapping
    public ResponseEntity<WorkspaceView> prepare(HttpServletRequest request) {
        var visitor = (Visitor) request.getAttribute(Visitor.class.getName());
        if (visitor == null || !visitor.verified()) {
            return ResponseEntity.status(403).build();
        }
        return result(service.prepare(visitor.id(), visitor.expiresAt()));
    }

    @GetMapping("/current")
    public ResponseEntity<WorkspaceView> current(HttpServletRequest request) {
        var visitor = (Visitor) request.getAttribute(Visitor.class.getName());
        if (visitor == null || !visitor.verified()) {
            return ResponseEntity.status(403).build();
        }
        return result(service.current(visitor.id()));
    }
}
