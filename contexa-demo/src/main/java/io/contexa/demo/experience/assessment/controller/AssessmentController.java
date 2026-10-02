package io.contexa.demo.experience.assessment.controller;

import io.contexa.demo.experience.assessment.dto.AssessmentCommand;
import io.contexa.demo.experience.assessment.dto.StoredAssessment;
import io.contexa.demo.experience.assessment.service.AssessmentService;
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
import java.util.List;
import java.util.UUID;

@RestController
@Profile("portal")
@RequestMapping("/api/lab/reports/{reportId}/assessments")
public class AssessmentController extends AbstractVisitorController {

    private final AssessmentService service;

    public AssessmentController(AssessmentService service) {
        this.service = service;
    }

    @GetMapping
    public ResponseEntity<List<StoredAssessment>> list(@PathVariable UUID reportId, HttpServletRequest request) {
        return result(service.list(visitorId(request), reportId));
    }

    @PostMapping
    public ResponseEntity<StoredAssessment> submit(@PathVariable UUID reportId,
            @Valid @RequestBody AssessmentCommand command, HttpServletRequest request) {
        return result(service.submit(visitorId(request), reportId, command));
    }
}
