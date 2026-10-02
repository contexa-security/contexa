package io.contexa.demo.comparison.submission.controller;

import io.contexa.demo.comparison.submission.dto.RunSubmission;
import io.contexa.demo.comparison.submission.service.RunSubmissionService;
import io.contexa.demo.shared.web.AbstractVisitorController;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
@Profile("portal")
@RequestMapping("/api/lab/comparisons/preparations/{preparationId}/run-submissions")
public class RunSubmissionController extends AbstractVisitorController {

    private final RunSubmissionService submissions;

    public RunSubmissionController(RunSubmissionService submissions) {
        this.submissions = submissions;
    }

    @GetMapping
    public ResponseEntity<List<RunSubmission>> find(@PathVariable UUID preparationId, HttpServletRequest request) {
        return result(submissions.find(visitorId(request), preparationId));
    }
}
