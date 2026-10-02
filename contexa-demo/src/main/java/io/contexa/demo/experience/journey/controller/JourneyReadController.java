package io.contexa.demo.experience.journey.controller;

import io.contexa.demo.experience.journey.dto.JourneyReadCommand;
import io.contexa.demo.experience.journey.dto.JourneyReadRecord;
import io.contexa.demo.experience.journey.service.JourneyReadService;
import io.contexa.demo.shared.web.AbstractVisitorController;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.UUID;

@RestController
@Profile("portal")
@RequestMapping("/api/lab/journeys/{id}/reads")
public class JourneyReadController extends AbstractVisitorController {

    private final JourneyReadService reads;

    public JourneyReadController(JourneyReadService reads) {
        this.reads = reads;
    }

    @PostMapping
    public ResponseEntity<JourneyReadRecord> record(@PathVariable UUID id,
            @Valid @RequestBody JourneyReadCommand command, HttpServletRequest request) {
        return result(reads.record(visitorId(request), id, command));
    }
}
