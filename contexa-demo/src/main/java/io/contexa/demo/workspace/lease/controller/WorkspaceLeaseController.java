package io.contexa.demo.workspace.lease.controller;

import io.contexa.demo.shared.web.AbstractVisitorController;
import io.contexa.demo.workspace.configuration.WorkspaceAccessProperties;
import io.contexa.demo.workspace.lease.dto.WorkspaceLeaseState;
import io.contexa.demo.workspace.lease.service.WorkspaceLeaseService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

@RestController
@Profile("portal")
@RequestMapping("/api/lab/workspaces/current/lease")
public class WorkspaceLeaseController extends AbstractVisitorController {

    private final WorkspaceLeaseService leases;
    private final WorkspaceAccessProperties properties;

    public WorkspaceLeaseController(WorkspaceLeaseService leases, WorkspaceAccessProperties properties) {
        this.leases = leases;
        this.properties = properties;
    }

    @GetMapping
    public WorkspaceLeaseState current(HttpServletRequest request) {
        return new WorkspaceLeaseState(properties.enabled(), Instant.now(), leases.current(visitorId(request)));
    }

    @PostMapping("/cancel")
    public WorkspaceLeaseState cancel(HttpServletRequest request) {
        return new WorkspaceLeaseState(properties.enabled(), Instant.now(), leases.cancel(visitorId(request)));
    }
}
