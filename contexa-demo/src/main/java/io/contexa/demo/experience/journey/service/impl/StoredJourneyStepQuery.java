package io.contexa.demo.experience.journey.service.impl;

import io.contexa.demo.comparison.preparation.dto.ComparisonRequestPlan;
import io.contexa.demo.experience.journey.dto.FrozenJourneyStep;
import io.contexa.demo.experience.journey.repository.JourneyRepository;
import io.contexa.demo.experience.journey.service.JourneyStepQuery;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import java.util.UUID;

@Component
@Profile("portal")
public class StoredJourneyStepQuery implements JourneyStepQuery {

    private final JourneyRepository journeys;

    public StoredJourneyStepQuery(JourneyRepository journeys) {
        this.journeys = journeys;
    }

    @Override
    public FrozenJourneyStep capture(UUID visitorId, ComparisonRequestPlan plan) {
        var reference = plan.journeyStep();
        if (reference == null) {
            return null;
        }
        var journey = journeys.find(visitorId, reference.journeyId());
        if (journey == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        if (!journey.snapshot().account().equals(plan.requestedAccount())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "JOURNEY_ACCOUNT_CHANGED");
        }
        var step = journey.snapshot().scenario().definition().requestPlan().stream()
                .filter(value -> value.stepId().equals(reference.stepId())).findFirst()
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "JOURNEY_STEP_UNKNOWN"));
        var export = plan.exportSelection();
        boolean matches = switch (step.operation()) {
            case READ_DOCUMENTS -> "DOCUMENT_READ_PAIR".equals(plan.kind());
            case READ_CUSTOMERS -> "CUSTOMER_READ_PAIR".equals(plan.kind());
            case EXPORT_DOCUMENTS -> export != null && "DOCUMENT".equals(export.resourceType().name());
            case EXPORT_CUSTOMERS -> export != null && "CUSTOMER".equals(export.resourceType().name());
            default -> false;
        };
        if (!matches || (export != null && export.targetIds().size() > step.maxItems())) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "JOURNEY_STEP_PLAN_MISMATCH");
        }
        return new FrozenJourneyStep(journey, reference.stepId());
    }
}
