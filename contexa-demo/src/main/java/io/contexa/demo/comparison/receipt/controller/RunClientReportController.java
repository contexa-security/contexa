package io.contexa.demo.comparison.receipt.controller;

import io.contexa.demo.comparison.receipt.dto.RunClientReport;
import io.contexa.demo.comparison.receipt.dto.RunClientReportInput;
import io.contexa.demo.comparison.receipt.service.RunClientReportService;
import io.contexa.demo.shared.web.AbstractVisitorController;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import java.util.UUID;

@RestController
@Profile("portal")
public class RunClientReportController extends AbstractVisitorController {

    private final RunClientReportService service;

    public RunClientReportController(RunClientReportService service) {
        this.service = service;
    }

    @PostMapping("/api/lab/runs/{id}/client-reports")
    public ResponseEntity<RunClientReport> record(@PathVariable UUID id,
            @Valid @RequestBody RunClientReportInput input, HttpServletRequest request) {
        return result(service.record(visitorId(request), id, input));
    }
}
