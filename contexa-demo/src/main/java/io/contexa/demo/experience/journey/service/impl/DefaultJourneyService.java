package io.contexa.demo.experience.journey.service.impl;

import io.contexa.demo.comparison.run.repository.RunQuery;
import io.contexa.demo.experience.journey.dto.JourneyCommand;
import io.contexa.demo.experience.journey.dto.JourneyRecord;
import io.contexa.demo.experience.journey.dto.JourneyRun;
import io.contexa.demo.experience.journey.dto.JourneySnapshot;
import io.contexa.demo.experience.journey.dto.JourneyView;
import io.contexa.demo.experience.journey.repository.JourneyRepository;
import io.contexa.demo.experience.journey.repository.JourneyReadRepository;
import io.contexa.demo.experience.journey.service.JourneyService;
import io.contexa.demo.scenario.service.ScenarioCatalog;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.workspace.service.WorkspaceService;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
@Profile("portal")
public class DefaultJourneyService implements JourneyService {

    private final JourneyRepository repository;
    private final ScenarioCatalog scenarios;
    private final WorkspaceService workspaces;
    private final RunQuery runs;
    private final DocumentCodec documents;
    private final JourneyReadRepository reads;

    public DefaultJourneyService(JourneyRepository repository, ScenarioCatalog scenarios,
            WorkspaceService workspaces, RunQuery runs, DocumentCodec documents, JourneyReadRepository reads) {
        this.repository = repository;
        this.scenarios = scenarios;
        this.workspaces = workspaces;
        this.runs = runs;
        this.documents = documents;
        this.reads = reads;
    }

    @Override
    public JourneyRecord start(UUID visitorId, JourneyCommand command) {
        String inputHash = documents.hash(documents.write(command));
        var previous = repository.findCommand(visitorId, command.commandId());
        if (previous != null) {
            return requireSameInput(previous, inputHash);
        }
        var workspace = workspaces.current(visitorId);
        if (workspace == null || !workspace.expiresAt().isAfter(Instant.now())) {
            throw new ResponseStatusException(HttpStatus.GONE, "WORKSPACE_EXPIRED");
        }
        if (!workspace.allowedAccounts().contains(command.account())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "ACCOUNT_NOT_ASSIGNED");
        }
        var snapshot = new JourneySnapshot("SCENARIO_JOURNEY_V1", command.account(),
                scenarios.find(command.scenarioId()), scenarios.evaluation(command.scenarioId()),
                List.of("DECLARED_INITIAL_STATE_REQUIRES_ACTUAL_RUN_ATTESTATION",
                        "SELECTORS_AND_PACE_REQUIRE_REVIEW_AGAINST_REQUEST_FACTS",
                        "HTTP_COMPLETION_IS_NOT_SECURITY_EFFECTIVENESS",
                        "CRITERIA_ARE_NOT_SENT_TO_THE_MODEL"));
        var candidate = new JourneyRecord(UUID.randomUUID(), Instant.now(), inputHash,
                documents.hash(documents.write(snapshot)), snapshot);
        return requireSameInput(repository.save(visitorId, command.commandId(), candidate), inputHash);
    }

    @Override
    public JourneyView find(UUID visitorId, UUID id) {
        var journey = repository.find(visitorId, id);
        if (journey == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        var history = repository.runIds(visitorId, id).stream().map(runId -> {
            var run = runs.find(visitorId, runId);
            return new JourneyRun(runId, run.manifest().plan().journeyStep().stepId(), run.createdAt(),
                    run.state(), run.manifestSha256(), runs.steps(runId));
        }).toList();
        return new JourneyView(journey, history.stream().limit(100).toList(), 100,
                history.size() > 100, reads.list(visitorId, id));
    }

    @Override
    public List<JourneyRecord> recent(UUID visitorId) {
        return repository.recent(visitorId);
    }

    private JourneyRecord requireSameInput(JourneyRecord record, String inputHash) {
        if (!record.inputSha256().equals(inputHash)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "COMMAND_INPUT_CHANGED");
        }
        return record;
    }
}
