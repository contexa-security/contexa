package io.contexa.demo.comparison.run.controller;

import io.contexa.demo.comparison.run.dto.RunCommand;
import io.contexa.demo.comparison.run.dto.RunView;
import io.contexa.demo.comparison.run.dto.RunSummary;
import io.contexa.demo.comparison.run.service.ComparisonRunService;
import io.contexa.demo.shared.web.AbstractVisitorController;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.UUID;
import java.util.List;

@RestController
@Profile("portal")
@RequestMapping("/api/lab/runs")
public class ComparisonRunController extends AbstractVisitorController {

    private final ComparisonRunService service;

    public ComparisonRunController(ComparisonRunService service) {
        this.service = service;
    }

    @PostMapping
    public ResponseEntity<RunView> create(@Valid @RequestBody RunCommand command, HttpServletRequest request) {
        return result(service.create(visitorId(request), command));
    }

    @GetMapping
    public ResponseEntity<List<RunSummary>> recent(HttpServletRequest request) {
        return result(service.recent(visitorId(request)));
    }

    @GetMapping("/{id}")
    public ResponseEntity<RunView> find(@PathVariable UUID id, HttpServletRequest request) {
        return result(service.find(visitorId(request), id));
    }

    @PostMapping("/{id}/cancel")
    public ResponseEntity<RunView> cancel(@PathVariable UUID id, HttpServletRequest request) {
        return result(service.cancel(visitorId(request), id));
    }
}
