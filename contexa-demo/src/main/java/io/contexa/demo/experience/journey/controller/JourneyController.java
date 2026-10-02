package io.contexa.demo.experience.journey.controller;

import io.contexa.demo.experience.journey.dto.JourneyCommand;
import io.contexa.demo.experience.journey.dto.JourneyRecord;
import io.contexa.demo.experience.journey.dto.JourneyView;
import io.contexa.demo.experience.journey.service.JourneyService;
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
@RequestMapping("/api/lab/journeys")
public class JourneyController extends AbstractVisitorController {

    private final JourneyService journeys;

    public JourneyController(JourneyService journeys) {
        this.journeys = journeys;
    }

    @PostMapping
    public ResponseEntity<JourneyRecord> start(@Valid @RequestBody JourneyCommand command,
            HttpServletRequest request) {
        return result(journeys.start(visitorId(request), command));
    }

    @GetMapping
    public ResponseEntity<List<JourneyRecord>> recent(HttpServletRequest request) {
        return result(journeys.recent(visitorId(request)));
    }

    @GetMapping("/{id}")
    public ResponseEntity<JourneyView> find(@PathVariable UUID id, HttpServletRequest request) {
        return result(journeys.find(visitorId(request), id));
    }
}
