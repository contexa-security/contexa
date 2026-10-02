package io.contexa.demo.experience.journey.service.impl;

import io.contexa.demo.experience.journey.dto.JourneyReadCommand;
import io.contexa.demo.experience.journey.dto.JourneyReadRecord;
import io.contexa.demo.experience.journey.repository.JourneyReadRepository;
import io.contexa.demo.experience.journey.repository.JourneyRepository;
import io.contexa.demo.experience.journey.service.JourneyReadService;
import io.contexa.demo.shared.document.DocumentCodec;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@Profile("portal")
public class DefaultJourneyReadService implements JourneyReadService {

    private final JourneyRepository journeys;
    private final JourneyReadRepository reads;
    private final DocumentCodec documents;

    public DefaultJourneyReadService(JourneyRepository journeys, JourneyReadRepository reads, DocumentCodec documents) {
        this.journeys = journeys;
        this.reads = reads;
        this.documents = documents;
    }

    @Override
    public JourneyReadRecord record(UUID visitorId, UUID journeyId, JourneyReadCommand command) {
        var journey = journeys.find(visitorId, journeyId);
        if (journey == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        var step = journey.snapshot().scenario().definition().requestPlan().stream()
                .filter(value -> value.stepId().equals(command.stepId())).findFirst()
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "JOURNEY_STEP_UNKNOWN"));
        String path = switch (step.operation()) {
            case LIST_PROJECTS -> "/api/work/projects";
            case READ_APPROVAL -> "/api/work/approvals";
            default -> throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "JOURNEY_STEP_PLAN_MISMATCH");
        };
        if (!command.observations().stream().map(value -> value.arm()).collect(Collectors.toSet())
                .equals(Set.of("baseline", "contexa"))
                || command.observations().stream().anyMatch(value -> !path.equals(value.path()))) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "JOURNEY_STEP_PLAN_MISMATCH");
        }
        String inputHash = documents.hash(documents.write(command));
        var stored = reads.save(visitorId, new JourneyReadRecord(UUID.randomUUID(), journeyId,
                Instant.now(), inputHash, command));
        if (!stored.journeyId().equals(journeyId) || !stored.inputSha256().equals(inputHash)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "COMMAND_INPUT_CHANGED");
        }
        return stored;
    }
}
